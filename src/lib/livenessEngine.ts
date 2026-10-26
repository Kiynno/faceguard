/**
 * FaceGuard liveness & Presentation Attack Detection (PAD) engine (browser).
 *
 * Session flow (plan issued and signed by the server):
 *   1. Positioning      — one centred, well-lit, frontal face.
 *   2. Passive window   — micro-motion, blinks, pulse (rPPG), moiré, texture,
 *                         glare; best frontal frame kept as reference image.
 *   3. Screen flash     — random colour sequence; the face must reflect it.
 *   4. Challenges       — random order, ≥1 head turn; each head turn is
 *                         checked for 3D (non-planar) landmark motion.
 *   5. Decision         — fused by padCore.decidePad (the server recomputes
 *                         it independently), written to a hash-chained trail.
 *
 * Privacy: frames never leave this module. The only image produced is one
 * face crop for a BONA_FIDE result, handed to the host via onReferenceImage
 * for 1:1 matching (e.g. MOSIP); the audit trail stores only its SHA-256.
 */

import type { FaceLandmarker, FaceLandmarkerResult } from "@mediapipe/tasks-vision";
import {
  DEFAULT_CONFIG,
  ENGINE_VERSION,
  analysePhotometric,
  canonicalJson,
  clamp,
  decidePad,
  estimatePulse,
  isVirtualCameraLabel,
  moirePeakiness,
  planarResidual,
  randomHex,
  round,
  sha256Hex,
  type ColorSample,
} from "@/lib/padCore";
import type {
  ActiveChallengeView,
  AuditEvent,
  AuditEventType,
  AuditReport,
  AuditSeverity,
  Challenge,
  ChallengeFailureReason,
  ChallengeResult,
  ChallengeType,
  DeviceContext,
  EnginePhase,
  EngineSnapshot,
  FaceMeasurements,
  FlashColor,
  FrameMetrics,
  InjectionSignals,
  JsonObject,
  JsonValue,
  LivenessConfig,
  NormalizedBox,
  PadInput,
  PadResult,
  PassiveSummary,
  PhotometricResult,
  PhotometricStep,
  ReferenceImageMeta,
  SignedSessionPlan,
} from "@/types";

export { DEFAULT_CONFIG, ENGINE_VERSION, canonicalJson, sha256Hex, verifyAuditChain } from "@/lib/padCore";

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

/** Must match the exact version pinned in package.json. */
export const MEDIAPIPE_VERSION = "0.10.21";

const WASM_BASE_URL = `https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@${MEDIAPIPE_VERSION}/wasm`;
const MODEL_URL =
  "https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/1/face_landmarker.task";
const MODEL_ID = "mediapipe/face_landmarker/float16/1";

const GENESIS_HASH = "0".repeat(64);
const ROI_SIZE = 128; // must be 2× a power of two (moiré FFT runs at ROI_SIZE / 2)
const SPECTRUM_SIZE = ROI_SIZE / 2;
const REFERENCE_SIZE = 256;

/** MediaPipe Face Mesh landmark indices. */
const LM = {
  noseTip: 1,
  forehead: 10,
  chin: 152,
  faceLeft: 234, // image-left (subject's right cheek)
  faceRight: 454, // image-right (subject's left cheek)
  eyeOuterLeft: 33,
  eyeOuterRight: 263,
} as const;

/** Landmarks spread across depths (nose, eyes, brows, mouth, cheeks, jaw) for the planarity check. */
const DEPTH_LANDMARKS = [
  1, 4, 5, 6, 10, 168, 197, 195, 33, 133, 362, 263, 70, 105, 300, 334, 61, 291, 0, 17, 152, 199,
  234, 454, 127, 356, 93, 323, 58, 288, 172, 397, 136, 365, 149, 378, 98, 327, 50, 280,
] as const;

const CHALLENGE_INSTRUCTIONS: Record<ChallengeType, string> = {
  BLINK: "Blink both eyes",
  TURN_LEFT: "Slowly turn your head to your left",
  TURN_RIGHT: "Slowly turn your head to your right",
  SMILE: "Smile naturally",
  OPEN_MOUTH: "Open your mouth",
};

/* ------------------------------------------------------------------ */
/* Small utilities                                                     */
/* ------------------------------------------------------------------ */

type Point = { x: number; y: number; z: number };
const toDeg = (rad: number): number => (rad * 180) / Math.PI;

class RunningMean {
  private sum = 0;
  private n = 0;
  push(v: number): void {
    if (Number.isFinite(v)) {
      this.sum += v;
      this.n += 1;
    }
  }
  get mean(): number {
    return this.n === 0 ? 0 : this.sum / this.n;
  }
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/* ------------------------------------------------------------------ */
/* Audit trail                                                         */
/* ------------------------------------------------------------------ */

type UnsignedEvent = Omit<AuditEvent, "hash">;

class AuditTrail {
  private readonly events: AuditEvent[] = [];
  private head = GENESIS_HASH;
  private queue: Promise<void> = Promise.resolve();

  constructor(
    private readonly sessionId: string,
    private readonly onEvent: (event: AuditEvent) => void,
  ) {}

  append(type: AuditEventType, severity: AuditSeverity, message: string, data: JsonObject | null = null): Promise<void> {
    const timestamp = new Date().toISOString();
    // Serialise appends so seq/prevHash ordering is guaranteed.
    this.queue = this.queue.then(async () => {
      const unsigned: UnsignedEvent = {
        seq: this.events.length,
        timestamp,
        sessionId: this.sessionId,
        type,
        severity,
        message,
        data,
        prevHash: this.head,
      };
      const hash = await sha256Hex(canonicalJson(unsigned));
      const event: AuditEvent = { ...unsigned, hash };
      this.events.push(event);
      this.head = hash;
      this.onEvent(event);
    });
    return this.queue;
  }

  flush(): Promise<void> {
    return this.queue;
  }

  get all(): AuditEvent[] {
    return [...this.events];
  }

  get chainHead(): string {
    return this.head;
  }
}

/* ------------------------------------------------------------------ */
/* Engine                                                              */
/* ------------------------------------------------------------------ */

export interface LivenessEngineListeners {
  onSnapshot?: (snapshot: EngineSnapshot) => void;
  onAuditEvent?: (event: AuditEvent) => void;
  onReport?: (report: AuditReport) => void;
  /** Fired only for BONA_FIDE results: the face crop to send for 1:1 matching. */
  onReferenceImage?: (image: Blob, meta: ReferenceImageMeta) => void;
}

export type LivenessConfigOverrides = Partial<Omit<LivenessConfig, "thresholds" | "pad" | "photometric">> & {
  thresholds?: Partial<LivenessConfig["thresholds"]>;
  photometric?: Partial<LivenessConfig["photometric"]>;
  pad?: Partial<LivenessConfig["pad"]>;
};

interface ActiveChallengeState {
  challenge: Challenge;
  index: number;
  issuedAt: number;
  issuedAtIso: string;
  armed: boolean;
  armedAt: number | null;
  eyesClosed: boolean;
  holdCount: number;
  peak: number;
  refLandmarks: Float32Array | null;
  refIod: number;
}

interface RoiStats {
  sharpness: number;
  specularRatio: number;
  brightness: number;
  rgb: [number, number, number];
  moire: number | null;
  duplicate: boolean;
}

interface PhotometricState {
  index: number;
  stepStartedAt: number;
  sum: [number, number, number];
  frames: number;
  steps: PhotometricStep[];
}

export class LivenessEngine {
  readonly config: LivenessConfig;

  private landmarker: FaceLandmarker | null = null;
  private configDigest = "";
  private video: HTMLVideoElement | null = null;
  private rafId: number | null = null;
  private running = false;
  private lastVideoTime = -1;
  private lastDetectTs = 0;
  private lastSnapshotAt = 0;
  private fpsWindow: number[] = [];

  private roiCanvas: HTMLCanvasElement | null = null;
  private roiCtx: CanvasRenderingContext2D | null = null;
  private refCanvas: HTMLCanvasElement | null = null;

  // Session state
  private phase: EnginePhase = "uninitialized";
  private guidance = "Initialising liveness engine…";
  private error: string | null = null;
  private signedPlan: SignedSessionPlan | null = null;
  private sessionId: string | null = null;
  private nonce = "";
  private startedAt = 0;
  private startedAtIso = "";
  private trail: AuditTrail | null = null;
  private device: DeviceContext | null = null;
  private injection: InjectionSignals | null = null;
  private plannedChallenges: ChallengeType[] = [];
  private flashSequence: FlashColor[] = [];
  private challengeResults: ChallengeResult[] = [];
  private active: ActiveChallengeState | null = null;
  private photo: PhotometricState | null = null;
  private photometric: PhotometricResult | null = null;
  private result: PadResult | null = null;
  private report: AuditReport | null = null;
  private referenceMeta: ReferenceImageMeta | null = null;
  private lastMetrics: FrameMetrics | null = null;

  // Per-frame geometry (primary face)
  private landmarkPx: Float32Array | null = null;
  private iodPx = 0;
  private lastRgb: [number, number, number] | null = null;

  // Phase bookkeeping
  private stableFrames = 0;
  private passiveStartedAt = 0;
  private lastFaceSeenAt = 0;
  private lastMultiFaceLogAt = 0;
  private prevNormLandmarks: Float32Array | null = null;
  private prevGray: Float32Array | null = null;
  private prevBox: { box: NormalizedBox; ts: number } | null = null;
  private spontaneousEyesClosed = false;
  private frameCounter = 0;
  private bestReferenceSharpness = 0;
  private referenceCapturedAt = "";

  // Accumulators
  private framesAnalyzed = 0;
  private multiFaceFrames = 0;
  private spontaneousBlinks = 0;
  private faceDiscontinuities = 0;
  private comparedFrames = 0;
  private duplicateFrames = 0;
  private sharpness = new RunningMean();
  private specular = new RunningMean();
  private nonRigid = new RunningMean();
  private moire = new RunningMean();
  private pulseSamples: ColorSample[] = [];
  private pulse: { snr: number; bpm: number | null } = { snr: 0, bpm: null };

  constructor(
    overrides: LivenessConfigOverrides = {},
    private readonly listeners: LivenessEngineListeners = {},
  ) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...overrides,
      thresholds: { ...DEFAULT_CONFIG.thresholds, ...overrides.thresholds },
      photometric: { ...DEFAULT_CONFIG.photometric, ...overrides.photometric },
      pad: { ...DEFAULT_CONFIG.pad, ...overrides.pad },
    };
  }

  /* ---------------------------- lifecycle --------------------------- */

  async init(): Promise<void> {
    if (this.landmarker || this.phase === "initializing") return;
    if (typeof window === "undefined") throw new Error("LivenessEngine must run in the browser");
    if (!window.isSecureContext) {
      this.setError("A secure context (HTTPS or localhost) is required for camera and crypto APIs.");
      return;
    }

    this.phase = "initializing";
    this.guidance = "Loading face landmark model…";
    this.emit(true);

    try {
      const { FilesetResolver, FaceLandmarker: FL } = await import("@mediapipe/tasks-vision");
      const fileset = await FilesetResolver.forVisionTasks(WASM_BASE_URL);
      const options = (delegate: "GPU" | "CPU") => ({
        baseOptions: { modelAssetPath: MODEL_URL, delegate },
        runningMode: "VIDEO" as const,
        numFaces: 2, // >1 so we can detect multiple-subject presentations
        outputFaceBlendshapes: true,
        outputFacialTransformationMatrixes: false,
        minFaceDetectionConfidence: 0.6,
        minFacePresenceConfidence: 0.6,
        minTrackingConfidence: 0.5,
      });
      try {
        this.landmarker = await FL.createFromOptions(fileset, options("GPU"));
      } catch {
        this.landmarker = await FL.createFromOptions(fileset, options("CPU"));
      }
      this.configDigest = await sha256Hex(canonicalJson(this.config));
      this.phase = "ready";
      this.guidance = "Ready. Start a liveness check when the camera is on.";
      this.emit(true);
    } catch (err) {
      this.setError(`Failed to load liveness model: ${errorMessage(err)}`);
    }
  }

  get isReady(): boolean {
    return this.landmarker !== null;
  }

  /** Begin a session against a playing <video>, using a plan signed by the server. */
  async start(video: HTMLVideoElement, signedPlan: SignedSessionPlan): Promise<void> {
    if (!this.landmarker) throw new Error("Engine not initialised — call init() first");
    const { plan } = signedPlan;
    if (Date.parse(plan.expiresAt) <= Date.now()) throw new Error("Session plan has expired");
    if (plan.engineVersion !== ENGINE_VERSION) {
      throw new Error(`Server expects engine ${plan.engineVersion}, client is ${ENGINE_VERSION}`);
    }

    this.stopLoop();
    this.resetSession();

    this.video = video;
    this.signedPlan = signedPlan;
    this.sessionId = plan.sessionId;
    this.nonce = plan.nonce;
    this.plannedChallenges = [...plan.challenges];
    this.flashSequence = [...plan.flashSequence];
    this.startedAt = performance.now();
    this.startedAtIso = new Date().toISOString();
    this.device = collectDeviceContext(video);
    this.injection = collectInjectionSignals(video);
    this.trail = new AuditTrail(plan.sessionId, (e) => this.listeners.onAuditEvent?.(e));

    void this.log("SESSION_START", "info", "Liveness session started", {
      nonce: this.nonce,
      engineVersion: ENGINE_VERSION,
      model: MODEL_ID,
      configDigest: this.configDigest,
      plannedChallenges: this.plannedChallenges,
      flashSteps: this.flashSequence.length,
      planIssuedAt: plan.issuedAt,
      device: this.device as unknown as JsonValue,
    });
    void this.log("ENGINE_READY", "info", "PAD subsystem armed", {
      passiveWindowMs: this.config.passiveWindowMs,
      challengeTimeoutMs: this.config.challengeTimeoutMs,
    });
    if (this.injection.virtualCameraSuspected) {
      void this.log("INJECTION_SUSPECTED", "critical", `Virtual camera suspected: "${this.injection.cameraLabel}"`, {
        cameraLabel: this.injection.cameraLabel,
      });
    }

    this.phase = "positioning";
    this.guidance = "Position your face inside the oval";
    this.running = true;
    this.emit(true);
    this.rafId = requestAnimationFrame(this.loop);
  }

  /** Cancel the current session (logged as SESSION_ABORTED). */
  async abort(reason = "Aborted by operator"): Promise<void> {
    if (!this.trail || this.phase === "complete" || this.phase === "ready" || this.phase === "evaluating") return;
    this.stopLoop();
    await this.log("SESSION_ABORTED", "warn", reason, { phase: this.phase });
    await this.trail.flush();
    this.active = null;
    this.photo = null;
    this.report = this.buildReport();
    this.phase = "ready";
    this.guidance = "Session aborted. Start again when ready.";
    this.emit(true);
    if (this.report) this.listeners.onReport?.(this.report);
  }

  dispose(): void {
    this.stopLoop();
    this.landmarker?.close();
    this.landmarker = null;
    this.video = null;
    this.roiCanvas = null;
    this.roiCtx = null;
    this.refCanvas = null;
    this.phase = "uninitialized";
  }

  getReport(): AuditReport | null {
    return this.report;
  }

  getSnapshot(): EngineSnapshot {
    const now = performance.now();
    const view: ActiveChallengeView | null = this.active
      ? {
          type: this.active.challenge.type,
          instruction: this.active.armed ? this.active.challenge.instruction : "Look straight ahead with a neutral face",
          index: this.active.index,
          total: this.plannedChallenges.length,
          timeoutMs: this.active.challenge.timeoutMs,
          remainingMs: Math.max(0, this.active.challenge.timeoutMs - (now - this.active.issuedAt)),
          armed: this.active.armed,
        }
      : null;

    let phaseProgress = 0;
    if (this.phase === "positioning") phaseProgress = this.stableFrames / this.config.stableFramesRequired;
    else if (this.phase === "passive") phaseProgress = (now - this.passiveStartedAt) / this.config.passiveWindowMs;
    else if (this.phase === "photometric" && this.photo) phaseProgress = this.photo.index / this.flashSequence.length;
    else if (this.phase === "challenge") phaseProgress = this.challengeResults.length / Math.max(1, this.plannedChallenges.length);
    else if (this.phase === "complete") phaseProgress = 1;

    return {
      phase: this.phase,
      sessionId: this.sessionId,
      guidance: this.guidance,
      challenge: view,
      completedChallenges: [...this.challengeResults],
      plannedChallenges: [...this.plannedChallenges],
      flashColor: this.phase === "photometric" && this.photo ? (this.flashSequence[this.photo.index] ?? null) : null,
      metrics: this.lastMetrics,
      phaseProgress: clamp(phaseProgress, 0, 1),
      result: this.result,
      error: this.error,
      fps: this.fpsWindow.length,
    };
  }

  /* ---------------------------- main loop --------------------------- */

  private loop = (): void => {
    if (!this.running) return;
    this.rafId = requestAnimationFrame(this.loop);

    const video = this.video;
    const landmarker = this.landmarker;
    if (!video || !landmarker || video.readyState < HTMLMediaElement.HAVE_CURRENT_DATA) return;
    if (video.currentTime === this.lastVideoTime) return; // same frame, skip
    this.lastVideoTime = video.currentTime;

    // detectForVideo requires strictly increasing timestamps.
    let ts = performance.now();
    if (ts <= this.lastDetectTs) ts = this.lastDetectTs + 1;
    this.lastDetectTs = ts;
    this.fpsWindow.push(ts);
    while (this.fpsWindow.length > 0 && ts - this.fpsWindow[0] > 1000) this.fpsWindow.shift();
    this.frameCounter++;

    let detection: FaceLandmarkerResult;
    try {
      detection = landmarker.detectForVideo(video, ts);
    } catch (err) {
      void this.log("ERROR", "critical", "Landmark inference failed", { error: errorMessage(err) });
      this.setError(`Inference failed: ${errorMessage(err)}`);
      return;
    }

    const metrics = this.measure(detection, video, ts);
    this.lastMetrics = metrics;
    this.step(metrics, ts);
    this.emit(false);
  };

  private stopLoop(): void {
    this.running = false;
    if (this.rafId !== null) cancelAnimationFrame(this.rafId);
    this.rafId = null;
  }

  /* --------------------------- measurement -------------------------- */

  private measure(result: FaceLandmarkerResult, video: HTMLVideoElement, ts: number): FrameMetrics {
    const faceCount = result.faceLandmarks.length;
    if (faceCount === 0) {
      this.prevNormLandmarks = null;
      this.landmarkPx = null;
      this.lastRgb = null;
      return { timestamp: ts, faceCount: 0, face: null };
    }

    // Use the largest face as the primary subject.
    let primary = 0;
    let largest = -1;
    result.faceLandmarks.forEach((lm, i) => {
      const w = boxOf(lm).width;
      if (w > largest) {
        largest = w;
        primary = i;
      }
    });

    const lm = result.faceLandmarks[primary] as Point[];
    const vw = video.videoWidth || 1;
    const vh = video.videoHeight || 1;
    const box = boxOf(lm);

    const shapes = new Map<string, number>();
    for (const c of result.faceBlendshapes?.[primary]?.categories ?? []) shapes.set(c.categoryName, c.score);
    const bs = (name: string): number => shapes.get(name) ?? 0;

    // Head pose from landmark geometry (pixel space to respect aspect ratio)
    const px = (p: Point) => ({ x: p.x * vw, y: p.y * vh });
    const nose = px(lm[LM.noseTip]);
    const cheekL = px(lm[LM.faceLeft]);
    const cheekR = px(lm[LM.faceRight]);
    const top = px(lm[LM.forehead]);
    const chin = px(lm[LM.chin]);
    const eyeL = px(lm[LM.eyeOuterLeft]);
    const eyeR = px(lm[LM.eyeOuterRight]);

    const halfW = Math.max(1, (cheekR.x - cheekL.x) / 2);
    const halfH = Math.max(1, (chin.y - top.y) / 2);
    // Un-mirrored image: nose moving to image-right = subject turning to their left.
    const yawDeg = toDeg(Math.asin(clamp((nose.x - (cheekL.x + cheekR.x) / 2) / halfW, -1, 1)));
    const pitchDeg = toDeg(Math.asin(clamp((nose.y - (top.y + chin.y) / 2) / halfH, -1, 1)));
    const rollDeg = toDeg(Math.atan2(eyeR.y - eyeL.y, eyeR.x - eyeL.x));

    // Landmarks used by the planarity (depth) check
    const depthPx = new Float32Array(DEPTH_LANDMARKS.length * 2);
    DEPTH_LANDMARKS.forEach((idx, i) => {
      depthPx[2 * i] = lm[idx].x * vw;
      depthPx[2 * i + 1] = lm[idx].y * vh;
    });
    this.landmarkPx = depthPx;
    this.iodPx = Math.hypot(eyeR.x - eyeL.x, eyeR.y - eyeL.y);

    // Non-rigid motion: landmarks normalised for translation, scale and roll.
    const norm = normaliseLandmarks(lm, vw, vh);
    let nonRigidMotion: number | null = null;
    if (this.prevNormLandmarks && this.prevNormLandmarks.length === norm.length) {
      let acc = 0;
      for (let i = 0; i < norm.length; i += 2) {
        acc += Math.hypot(norm[i] - this.prevNormLandmarks[i], norm[i + 1] - this.prevNormLandmarks[i + 1]);
      }
      nonRigidMotion = acc / (norm.length / 2);
    }
    this.prevNormLandmarks = norm;

    const wantSpectrum = this.phase === "passive" && this.frameCounter % 3 === 0;
    const roi = this.analyseRoi(video, box, wantSpectrum);
    this.lastRgb = roi.rgb;
    if (this.phase === "passive" || this.phase === "photometric" || this.phase === "challenge") {
      this.comparedFrames++;
      if (roi.duplicate) this.duplicateFrames++;
    }
    if (roi.moire !== null) this.moire.push(roi.moire);

    const face: FaceMeasurements = {
      box,
      yawDeg: round(yawDeg, 2),
      pitchDeg: round(pitchDeg, 2),
      rollDeg: round(rollDeg, 2),
      blink: round((bs("eyeBlinkLeft") + bs("eyeBlinkRight")) / 2),
      smile: round((bs("mouthSmileLeft") + bs("mouthSmileRight")) / 2),
      jawOpen: round(bs("jawOpen")),
      sharpness: round(roi.sharpness, 2),
      specularRatio: round(roi.specularRatio),
      brightness: round(roi.brightness, 1),
      nonRigidMotion: nonRigidMotion === null ? null : round(nonRigidMotion, 5),
    };

    return { timestamp: ts, faceCount, face };
  }

  /** Texture, glare, colour, moiré and duplicate-frame analysis on the inner face. */
  private analyseRoi(video: HTMLVideoElement, box: NormalizedBox, wantSpectrum: boolean): RoiStats {
    if (!this.roiCtx) {
      this.roiCanvas = document.createElement("canvas");
      this.roiCanvas.width = ROI_SIZE;
      this.roiCanvas.height = ROI_SIZE;
      this.roiCtx = this.roiCanvas.getContext("2d", { willReadFrequently: true });
    }
    const ctx = this.roiCtx;
    if (!ctx) return { sharpness: 0, specularRatio: 0, brightness: 0, rgb: [0, 0, 0], moire: null, duplicate: false };

    const vw = video.videoWidth;
    const vh = video.videoHeight;
    const inset = 0.1;
    const sx = clamp((box.x + box.width * inset) * vw, 0, vw - 1);
    const sy = clamp((box.y + box.height * inset) * vh, 0, vh - 1);
    const sw = clamp(box.width * (1 - 2 * inset) * vw, 1, vw - sx);
    const sh = clamp(box.height * (1 - 2 * inset) * vh, 1, vh - sy);

    ctx.drawImage(video, sx, sy, sw, sh, 0, 0, ROI_SIZE, ROI_SIZE);
    const { data } = ctx.getImageData(0, 0, ROI_SIZE, ROI_SIZE);

    const n = ROI_SIZE * ROI_SIZE;
    const gray = new Float32Array(n);
    let lumSum = 0, specular = 0, rSum = 0, gSum = 0, bSum = 0;
    for (let i = 0, p = 0; i < n; i++, p += 4) {
      const r = data[p], g = data[p + 1], b = data[p + 2];
      const y = 0.299 * r + 0.587 * g + 0.114 * b;
      gray[i] = y;
      lumSum += y;
      rSum += r;
      gSum += g;
      bSum += b;
      if (y > 245) specular++;
    }

    // Laplacian variance (focus measure)
    let lapSum = 0, lapSq = 0, lapN = 0;
    for (let y = 1; y < ROI_SIZE - 1; y++) {
      for (let x = 1; x < ROI_SIZE - 1; x++) {
        const i = y * ROI_SIZE + x;
        const l = 4 * gray[i] - gray[i - 1] - gray[i + 1] - gray[i - ROI_SIZE] - gray[i + ROI_SIZE];
        lapSum += l;
        lapSq += l * l;
        lapN++;
      }
    }
    const lapMean = lapSum / lapN;

    // Duplicate frame: real sensors always add noise, so identical pixels mean a repeated frame.
    let duplicate = false;
    if (this.prevGray) {
      let diff = 0;
      for (let i = 0; i < n; i += 7) diff += Math.abs(gray[i] - this.prevGray[i]);
      duplicate = diff / Math.ceil(n / 7) < 0.25;
    }
    this.prevGray = gray;

    let moire: number | null = null;
    if (wantSpectrum) {
      const small = new Float32Array(SPECTRUM_SIZE * SPECTRUM_SIZE);
      for (let y = 0; y < SPECTRUM_SIZE; y++) {
        for (let x = 0; x < SPECTRUM_SIZE; x++) {
          const i = 2 * y * ROI_SIZE + 2 * x;
          small[y * SPECTRUM_SIZE + x] = (gray[i] + gray[i + 1] + gray[i + ROI_SIZE] + gray[i + ROI_SIZE + 1]) / 4;
        }
      }
      moire = moirePeakiness(small, SPECTRUM_SIZE);
    }

    return {
      sharpness: lapSq / lapN - lapMean * lapMean,
      specularRatio: specular / n,
      brightness: lumSum / n,
      rgb: [rSum / n, gSum / n, bSum / n],
      moire,
      duplicate,
    };
  }

  /** Keeps the sharpest frontal face crop seen during the passive window. */
  private maybeCaptureReference(face: FaceMeasurements): void {
    const video = this.video;
    if (!video || Math.abs(face.yawDeg) > 6 || Math.abs(face.rollDeg) > 8) return;
    if (face.sharpness <= this.bestReferenceSharpness * 1.05) return;

    if (!this.refCanvas) {
      this.refCanvas = document.createElement("canvas");
      this.refCanvas.width = REFERENCE_SIZE;
      this.refCanvas.height = REFERENCE_SIZE;
    }
    const ctx = this.refCanvas.getContext("2d");
    if (!ctx) return;

    const vw = video.videoWidth;
    const vh = video.videoHeight;
    const side = Math.max(face.box.width * vw, face.box.height * vh) * 1.35;
    const cx = (face.box.x + face.box.width / 2) * vw;
    const cy = (face.box.y + face.box.height / 2) * vh;
    const sx = clamp(cx - side / 2, 0, Math.max(0, vw - side));
    const sy = clamp(cy - side / 2, 0, Math.max(0, vh - side));
    const s = Math.min(side, vw, vh);
    ctx.drawImage(video, sx, sy, s, s, 0, 0, REFERENCE_SIZE, REFERENCE_SIZE);

    this.bestReferenceSharpness = face.sharpness;
    this.referenceCapturedAt = new Date().toISOString();
  }

  /* --------------------------- state machine ------------------------ */

  private step(m: FrameMetrics, ts: number): void {
    if (m.face) this.lastFaceSeenAt = ts;
    if (m.faceCount > 1) this.noteMultipleFaces(m.faceCount, ts);
    if (m.face && m.faceCount === 1) this.checkContinuity(m.face.box, ts);
    else this.prevBox = null;

    switch (this.phase) {
      case "positioning":
        this.stepPositioning(m, ts);
        break;
      case "passive":
        this.stepPassive(m, ts);
        break;
      case "photometric":
        this.stepPhotometric(m, ts);
        break;
      case "challenge":
        this.stepChallenge(m, ts);
        break;
      default:
        break;
    }
  }

  private positioningIssue(m: FrameMetrics): string | null {
    const c = this.config;
    if (!m.face || m.faceCount === 0) return "No face detected — look at the camera";
    if (m.faceCount > 1) return "Multiple faces detected — only one person may be in frame";
    const f = m.face;
    if (f.box.width < c.minFaceWidthRatio) return "Move closer to the camera";
    if (f.box.width > c.maxFaceWidthRatio) return "Move further from the camera";
    const dx = f.box.x + f.box.width / 2 - 0.5;
    const dy = f.box.y + f.box.height / 2 - 0.5;
    if (Math.hypot(dx, dy) > c.maxCenterOffset) return "Center your face inside the oval";
    if (f.brightness < c.minBrightness) return "Too dark — face a light source";
    if (f.brightness > c.maxBrightness) return "Too bright — avoid strong backlight or glare";
    if (Math.abs(f.yawDeg) > c.thresholds.neutralYawDeg * 1.5 || Math.abs(f.rollDeg) > c.thresholds.maxRollDeg) {
      return "Look straight at the camera";
    }
    return null;
  }

  private stepPositioning(m: FrameMetrics, ts: number): void {
    const issue = this.positioningIssue(m);
    if (issue) {
      this.stableFrames = 0;
      this.guidance = issue;
      return;
    }
    this.stableFrames++;
    this.guidance = "Hold still…";
    if (this.stableFrames >= this.config.stableFramesRequired && m.face) {
      void this.log("FACE_ACQUIRED", "info", "Single compliant face acquired", {
        box: m.face.box as unknown as JsonValue,
        brightness: m.face.brightness,
        yawDeg: m.face.yawDeg,
      });
      this.phase = "passive";
      this.passiveStartedAt = ts;
      this.prevNormLandmarks = null;
      this.pulseSamples = [];
      this.guidance = "Analysing — keep still and look at the camera";
      this.emit(true);
    }
  }

  private stepPassive(m: FrameMetrics, ts: number): void {
    if (!m.face || m.faceCount !== 1) {
      if (ts - this.lastFaceSeenAt > this.config.faceLostGraceMs || m.faceCount > 1) {
        void this.log("FACE_LOST", "warn", "Face lost during passive analysis; restarting positioning", {
          faceCount: m.faceCount,
        });
        this.phase = "positioning";
        this.stableFrames = 0;
        this.emit(true);
      }
      return;
    }

    this.accumulate(m, true);
    if (this.lastRgb) this.pulseSamples.push({ t: ts, r: this.lastRgb[0], g: this.lastRgb[1], b: this.lastRgb[2] });
    this.maybeCaptureReference(m.face);

    if (ts - this.passiveStartedAt >= this.config.passiveWindowMs) {
      this.pulse = estimatePulse(this.pulseSamples);
      this.pulseSamples = [];
      void this.log("PASSIVE_COMPLETE", "info", "Passive PAD window complete", this.passiveSummary() as unknown as JsonObject);
      this.phase = "photometric";
      this.photo = { index: 0, stepStartedAt: ts, sum: [0, 0, 0], frames: 0, steps: [] };
      this.guidance = "Keep looking at the screen while it changes colour";
      this.emit(true);
    }
  }

  private stepPhotometric(m: FrameMetrics, ts: number): void {
    const photo = this.photo;
    if (!photo) return;
    const cfg = this.config.photometric;
    const elapsed = ts - photo.stepStartedAt;

    if (m.face && m.faceCount === 1 && this.lastRgb) {
      this.accumulate(m, false);
      if (elapsed >= cfg.settleMs) {
        const [r, g, b] = this.lastRgb;
        const sum = r + g + b || 1;
        photo.sum[0] += r / sum;
        photo.sum[1] += g / sum;
        photo.sum[2] += b / sum;
        photo.frames++;
      }
    }

    if (elapsed < cfg.stepMs) return;

    const color = this.flashSequence[photo.index];
    const f = Math.max(1, photo.frames);
    photo.steps.push({
      color,
      chroma: [round(photo.sum[0] / f, 5), round(photo.sum[1] / f, 5), round(photo.sum[2] / f, 5)],
      frames: photo.frames,
    });
    photo.index++;
    photo.stepStartedAt = ts;
    photo.sum = [0, 0, 0];
    photo.frames = 0;

    if (photo.index < this.flashSequence.length) {
      this.emit(true); // switch colour immediately
      return;
    }

    const analysis = analysePhotometric(photo.steps, cfg.minAmplitude);
    this.photometric = { sequence: [...this.flashSequence], steps: photo.steps, ...analysis };
    this.photo = null;
    void this.log(
      "PHOTOMETRIC_COMPLETE",
      analysis.conclusive && analysis.correlation < cfg.failCorrelation ? "critical" : analysis.conclusive ? "info" : "warn",
      analysis.conclusive
        ? `Screen-flash response correlation ${analysis.correlation.toFixed(2)}`
        : "Screen-flash reflection too weak to judge",
      this.photometric as unknown as JsonObject,
    );
    this.phase = "challenge";
    this.issueNextChallenge(ts);
    this.emit(true);
  }

  private stepChallenge(m: FrameMetrics, ts: number): void {
    const a = this.active;
    if (!a) return;

    if (ts - a.issuedAt > a.challenge.timeoutMs) {
      this.completeChallenge(false, a.armed ? "TIMEOUT" : "NEVER_NEUTRAL", ts);
      return;
    }
    if (!m.face || m.faceCount === 0) {
      if (ts - this.lastFaceSeenAt > this.config.faceLostGraceMs) {
        void this.log("FACE_LOST", "warn", "Face lost during challenge", { challenge: a.challenge.type });
        this.completeChallenge(false, "FACE_LOST", ts);
      }
      return;
    }

    this.accumulate(m, false);
    const f = m.face;
    const th = this.config.thresholds;

    // Anti-replay gate: the subject must first return to neutral, so a
    // pre-recorded pose present at issue time cannot satisfy the challenge.
    if (!a.armed) {
      const neutral =
        Math.abs(f.yawDeg) < th.neutralYawDeg &&
        f.smile < th.neutralExpression &&
        f.jawOpen < th.neutralExpression &&
        f.blink < th.blinkClosed;
      if (neutral) {
        a.armed = true;
        a.armedAt = ts;
        a.refLandmarks = this.landmarkPx ? Float32Array.from(this.landmarkPx) : null;
        a.refIod = this.iodPx;
        this.guidance = a.challenge.instruction;
      }
      return;
    }

    const hold = (signal: number, threshold: number): boolean => {
      a.peak = Math.max(a.peak, signal);
      a.holdCount = signal >= threshold ? a.holdCount + 1 : 0;
      return a.holdCount >= this.config.holdFrames;
    };

    let passed = false;
    switch (a.challenge.type) {
      case "BLINK":
        a.peak = Math.max(a.peak, f.blink);
        if (!a.eyesClosed && f.blink >= th.blinkClosed) a.eyesClosed = true;
        else if (a.eyesClosed && f.blink <= th.blinkOpen) passed = true;
        break;
      case "TURN_LEFT":
        passed = hold(f.yawDeg, th.yawDeg);
        break;
      case "TURN_RIGHT":
        passed = hold(-f.yawDeg, th.yawDeg);
        break;
      case "SMILE":
        passed = hold(f.smile, th.smile);
        break;
      case "OPEN_MOUTH":
        passed = hold(f.jawOpen, th.jawOpen);
        break;
    }
    if (passed) this.completeChallenge(true, null, ts);
  }

  private issueNextChallenge(ts: number): void {
    const index = this.challengeResults.length;
    const type = this.plannedChallenges[index];
    if (type === undefined) {
      void this.finalize();
      return;
    }
    const challenge: Challenge = {
      id: `${this.nonce.slice(0, 8)}-${index}-${randomHex(4)}`,
      type,
      instruction: CHALLENGE_INSTRUCTIONS[type],
      timeoutMs: this.config.challengeTimeoutMs,
    };
    this.active = {
      challenge,
      index,
      issuedAt: ts,
      issuedAtIso: new Date().toISOString(),
      armed: false,
      armedAt: null,
      eyesClosed: false,
      holdCount: 0,
      peak: 0,
      refLandmarks: null,
      refIod: 0,
    };
    this.guidance = "Look straight ahead with a neutral face";
    void this.log("CHALLENGE_ISSUED", "info", `Challenge ${index + 1}/${this.plannedChallenges.length}: ${type}`, {
      challengeId: challenge.id,
      type,
      timeoutMs: challenge.timeoutMs,
    });
  }

  private completeChallenge(passed: boolean, reason: ChallengeFailureReason | null, ts: number): void {
    const a = this.active;
    if (!a) return;
    const responseTimeMs = passed && a.armedAt !== null ? Math.round(ts - a.armedAt) : null;

    let depthResidual: number | null = null;
    const isTurn = a.challenge.type === "TURN_LEFT" || a.challenge.type === "TURN_RIGHT";
    if (passed && isTurn && a.refLandmarks && this.landmarkPx) {
      depthResidual = round(planarResidual(a.refLandmarks, this.landmarkPx, a.refIod), 5);
    }

    const result: ChallengeResult = {
      challenge: a.challenge,
      status: passed ? "passed" : "failed",
      failureReason: reason,
      issuedAt: a.issuedAtIso,
      completedAt: new Date().toISOString(),
      responseTimeMs,
      peakSignal: round(a.peak, 3),
      depthResidual,
    };
    this.challengeResults.push(result);
    this.active = null;

    void this.log(
      passed ? "CHALLENGE_PASSED" : "CHALLENGE_FAILED",
      passed ? "info" : "warn",
      `${a.challenge.type} ${passed ? "passed" : `failed (${reason})`}`,
      {
        challengeId: a.challenge.id,
        type: a.challenge.type,
        responseTimeMs,
        peakSignal: result.peakSignal,
        depthResidual,
        failureReason: reason,
      },
    );

    // Fail fast: a failed challenge ends the session.
    if (!passed) {
      void this.finalize();
      return;
    }
    this.issueNextChallenge(ts);
    this.emit(true);
  }

  /* ------------------------- accumulation --------------------------- */

  private accumulate(m: FrameMetrics, passiveWindow: boolean): void {
    const f = m.face;
    if (!f) return;
    this.framesAnalyzed++;
    if (passiveWindow) {
      // Texture and glare are judged on unlit, steady frames only.
      this.sharpness.push(f.sharpness);
      this.specular.push(f.specularRatio);
      if (f.nonRigidMotion !== null) this.nonRigid.push(f.nonRigidMotion);
    }

    // Spontaneous blinks (excluding the explicit BLINK challenge).
    if (this.active?.challenge.type === "BLINK") return;
    const th = this.config.thresholds;
    if (!this.spontaneousEyesClosed && f.blink >= th.blinkClosed) this.spontaneousEyesClosed = true;
    else if (this.spontaneousEyesClosed && f.blink <= th.blinkOpen) {
      this.spontaneousEyesClosed = false;
      this.spontaneousBlinks++;
    }
  }

  private noteMultipleFaces(count: number, ts: number): void {
    const live = this.phase === "passive" || this.phase === "photometric" || this.phase === "challenge";
    if (live) this.multiFaceFrames++;
    if (ts - this.lastMultiFaceLogAt > 2000 && (live || this.phase === "positioning")) {
      this.lastMultiFaceLogAt = ts;
      void this.log("MULTIPLE_FACES", "warn", `${count} faces in frame`, { faceCount: count, phase: this.phase });
    }
  }

  /** Detects a sudden subject swap (e.g. photo slid in front of the face). */
  private checkContinuity(box: NormalizedBox, ts: number): void {
    const prev = this.prevBox;
    this.prevBox = { box, ts };
    if (!prev || ts - prev.ts > 150) return;
    if (this.phase !== "passive" && this.phase !== "photometric" && this.phase !== "challenge") return;
    const jump = Math.hypot(
      box.x + box.width / 2 - (prev.box.x + prev.box.width / 2),
      box.y + box.height / 2 - (prev.box.y + prev.box.height / 2),
    );
    const scaleChange = Math.abs(box.width - prev.box.width) / Math.max(prev.box.width, 1e-6);
    if (jump > prev.box.width * 0.35 || scaleChange > 0.3) {
      this.faceDiscontinuities++;
      void this.log("FACE_DISCONTINUITY", "critical", "Abrupt change in face position/scale", {
        jump: round(jump),
        scaleChange: round(scaleChange),
      });
    }
  }

  private passiveSummary(): PassiveSummary {
    return {
      framesAnalyzed: this.framesAnalyzed,
      multiFaceFrames: this.multiFaceFrames,
      meanSharpness: round(this.sharpness.mean, 2),
      meanSpecularRatio: round(this.specular.mean),
      meanNonRigidMotion: round(this.nonRigid.mean, 5),
      meanMoirePeakiness: round(this.moire.mean, 3),
      pulseSnr: this.pulse.snr,
      pulseBpm: this.pulse.bpm,
      spontaneousBlinks: this.spontaneousBlinks,
      faceDiscontinuities: this.faceDiscontinuities,
    };
  }

  private currentInjection(): InjectionSignals {
    const base = this.injection ?? {
      cameraLabel: "unknown",
      virtualCameraSuspected: false,
      duplicateFrameRatio: 0,
      noHardwareCapabilities: false,
    };
    return {
      ...base,
      duplicateFrameRatio: this.comparedFrames > 0 ? round(this.duplicateFrames / this.comparedFrames, 4) : 0,
    };
  }

  private padInput(): PadInput {
    return {
      plannedChallenges: [...this.plannedChallenges],
      challenges: [...this.challengeResults],
      passive: this.passiveSummary(),
      photometric: this.photometric ?? {
        sequence: [...this.flashSequence],
        steps: [],
        correlation: 0,
        amplitude: 0,
        conclusive: false,
      },
      injection: this.currentInjection(),
    };
  }

  /* --------------------------- decision ----------------------------- */

  private async finalize(): Promise<void> {
    this.stopLoop();
    this.active = null;
    this.phase = "evaluating";
    this.guidance = "Evaluating…";
    this.emit(true);

    const result = decidePad(this.padInput(), this.config);
    this.result = result;

    let referenceBlob: Blob | null = null;
    if (result.decision === "BONA_FIDE" && this.refCanvas) {
      referenceBlob = await canvasToJpeg(this.refCanvas);
      if (referenceBlob) {
        this.referenceMeta = {
          sha256: await sha256Hex(await referenceBlob.arrayBuffer()),
          mimeType: "image/jpeg",
          width: REFERENCE_SIZE,
          height: REFERENCE_SIZE,
          capturedAt: this.referenceCapturedAt,
          sharpness: round(this.bestReferenceSharpness, 2),
        };
        void this.log("REFERENCE_CAPTURED", "info", "Reference face crop bound to session", {
          ...(this.referenceMeta as unknown as JsonObject),
        });
      }
    }

    await this.log(
      "DECISION",
      result.decision === "BONA_FIDE" ? "info" : result.decision === "ATTACK" ? "critical" : "warn",
      `PAD decision: ${result.decision} (score ${result.score.toFixed(3)})`,
      { ...(result as unknown as JsonObject), referenceImageSha256: this.referenceMeta?.sha256 ?? null },
    );
    await this.trail?.flush();

    this.report = this.buildReport();
    this.phase = "complete";
    this.guidance =
      result.decision === "BONA_FIDE"
        ? "Liveness confirmed"
        : result.decision === "ATTACK"
          ? "Presentation attack suspected"
          : "Result inconclusive — please retry";
    this.emit(true);
    if (this.report) this.listeners.onReport?.(this.report);
    if (referenceBlob && this.referenceMeta) this.listeners.onReferenceImage?.(referenceBlob, this.referenceMeta);
  }

  private buildReport(): AuditReport | null {
    if (!this.trail || !this.sessionId || !this.device || !this.signedPlan) return null;
    return {
      schemaVersion: "faceguard.audit/2.0",
      standardReference: {
        framework: "ISO/IEC 30107-1:2023",
        testingReporting: "ISO/IEC 30107-3:2023",
        note:
          "Per-session record. APCER/BPCER must be computed offline across a labelled " +
          "evaluation set; a single session does not constitute conformance.",
      },
      engineVersion: ENGINE_VERSION,
      modelVersion: `${MODEL_ID} (tasks-vision ${MEDIAPIPE_VERSION})`,
      configDigest: this.configDigest,
      config: this.config,
      signedPlan: this.signedPlan,
      sessionId: this.sessionId,
      nonce: this.nonce,
      startedAt: this.startedAtIso,
      completedAt: new Date().toISOString(),
      durationMs: Math.round(performance.now() - this.startedAt),
      device: this.device,
      plannedChallenges: [...this.plannedChallenges],
      challenges: [...this.challengeResults],
      passive: this.passiveSummary(),
      photometric: this.photometric,
      injection: this.currentInjection(),
      referenceImage: this.referenceMeta,
      result: this.result,
      evaluation: { groundTruth: null, paiSpeciesUnderTest: null },
      privacy: {
        rawBiometricsStored: false,
        retained: [
          "Derived scalar quality/PAD measurements",
          "Challenge outcomes and timings",
          "Device and camera capability metadata",
          "SHA-256 of the reference face crop (the crop itself is not in this report)",
        ],
      },
      events: this.trail.all,
      chainHead: this.trail.chainHead,
    };
  }

  /* ----------------------------- helpers ---------------------------- */

  private log(type: AuditEventType, severity: AuditSeverity, message: string, data: JsonObject | null = null): Promise<void> {
    return this.trail ? this.trail.append(type, severity, message, data) : Promise.resolve();
  }

  private resetSession(): void {
    this.signedPlan = null;
    this.sessionId = null;
    this.nonce = "";
    this.trail = null;
    this.device = null;
    this.injection = null;
    this.plannedChallenges = [];
    this.flashSequence = [];
    this.challengeResults = [];
    this.active = null;
    this.photo = null;
    this.photometric = null;
    this.result = null;
    this.report = null;
    this.referenceMeta = null;
    this.error = null;
    this.lastMetrics = null;
    this.landmarkPx = null;
    this.iodPx = 0;
    this.lastRgb = null;
    this.stableFrames = 0;
    this.passiveStartedAt = 0;
    this.lastFaceSeenAt = 0;
    this.lastMultiFaceLogAt = 0;
    this.prevNormLandmarks = null;
    this.prevGray = null;
    this.prevBox = null;
    this.spontaneousEyesClosed = false;
    this.frameCounter = 0;
    this.bestReferenceSharpness = 0;
    this.referenceCapturedAt = "";
    this.framesAnalyzed = 0;
    this.multiFaceFrames = 0;
    this.spontaneousBlinks = 0;
    this.faceDiscontinuities = 0;
    this.comparedFrames = 0;
    this.duplicateFrames = 0;
    this.sharpness = new RunningMean();
    this.specular = new RunningMean();
    this.nonRigid = new RunningMean();
    this.moire = new RunningMean();
    this.pulseSamples = [];
    this.pulse = { snr: 0, bpm: null };
    this.lastVideoTime = -1;
    this.fpsWindow = [];
  }

  private setError(message: string): void {
    this.stopLoop();
    this.phase = "error";
    this.error = message;
    this.guidance = message;
    this.emit(true);
  }

  private emit(force: boolean): void {
    const now = performance.now();
    if (!force && now - this.lastSnapshotAt < this.config.snapshotIntervalMs) return;
    this.lastSnapshotAt = now;
    this.listeners.onSnapshot?.(this.getSnapshot());
  }
}

/* ------------------------------------------------------------------ */
/* Free functions                                                      */
/* ------------------------------------------------------------------ */

function boxOf(lm: readonly Point[]): NormalizedBox {
  let minX = 1, minY = 1, maxX = 0, maxY = 0;
  for (const p of lm) {
    if (p.x < minX) minX = p.x;
    if (p.y < minY) minY = p.y;
    if (p.x > maxX) maxX = p.x;
    if (p.y > maxY) maxY = p.y;
  }
  minX = clamp(minX, 0, 1);
  minY = clamp(minY, 0, 1);
  return {
    x: round(minX),
    y: round(minY),
    width: round(clamp(maxX, 0, 1) - minX),
    height: round(clamp(maxY, 0, 1) - minY),
  };
}

/** Centre on centroid, de-rotate by roll and scale by inter-ocular distance. */
function normaliseLandmarks(lm: readonly Point[], w: number, h: number): Float32Array {
  const eL = lm[LM.eyeOuterLeft];
  const eR = lm[LM.eyeOuterRight];
  const dx = (eR.x - eL.x) * w;
  const dy = (eR.y - eL.y) * h;
  const iod = Math.max(1e-6, Math.hypot(dx, dy));
  const angle = -Math.atan2(dy, dx);
  const cos = Math.cos(angle);
  const sin = Math.sin(angle);

  let cx = 0, cy = 0;
  for (const p of lm) {
    cx += p.x * w;
    cy += p.y * h;
  }
  cx /= lm.length;
  cy /= lm.length;

  const out = new Float32Array(lm.length * 2);
  lm.forEach((p, i) => {
    const x = p.x * w - cx;
    const y = p.y * h - cy;
    out[i * 2] = (x * cos - y * sin) / iod;
    out[i * 2 + 1] = (x * sin + y * cos) / iod;
  });
  return out;
}

function videoTrack(video: HTMLVideoElement): MediaStreamTrack | undefined {
  const stream = video.srcObject instanceof MediaStream ? video.srcObject : null;
  return stream?.getVideoTracks()[0];
}

function collectDeviceContext(video: HTMLVideoElement): DeviceContext {
  const track = videoTrack(video);
  const s = track?.getSettings();
  return {
    userAgent: navigator.userAgent,
    language: navigator.language,
    hardwareConcurrency: navigator.hardwareConcurrency ?? null,
    screen: { width: window.screen.width, height: window.screen.height, pixelRatio: window.devicePixelRatio },
    camera: {
      label: track?.label ?? "unknown",
      width: s?.width ?? video.videoWidth ?? null,
      height: s?.height ?? video.videoHeight ?? null,
      frameRate: s?.frameRate ?? null,
      facingMode: s?.facingMode ?? null,
    },
  };
}

function collectInjectionSignals(video: HTMLVideoElement): InjectionSignals {
  const track = videoTrack(video);
  const label = track?.label ?? "unknown";
  let noHardwareCapabilities = false;
  if (track && typeof track.getCapabilities === "function") {
    const caps = track.getCapabilities() as Record<string, unknown>;
    const hardwareKeys = ["exposureMode", "focusMode", "whiteBalanceMode", "brightness", "contrast", "sharpness", "zoom"];
    noHardwareCapabilities = !hardwareKeys.some((k) => k in caps);
  }
  return {
    cameraLabel: label,
    virtualCameraSuspected: isVirtualCameraLabel(label),
    duplicateFrameRatio: 0,
    noHardwareCapabilities,
  };
}

function canvasToJpeg(canvas: HTMLCanvasElement): Promise<Blob | null> {
  return new Promise((resolve) => canvas.toBlob((b) => resolve(b), "image/jpeg", 0.92));
}
