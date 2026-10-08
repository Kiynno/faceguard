/**
 * FaceGuard liveness & Presentation Attack Detection (PAD) engine.
 *
 * Pipeline per video frame:
 *   1. MediaPipe Face Landmarker → 478 landmarks + 52 blendshapes.
 *   2. Geometry: head pose (yaw/pitch/roll), face box, non-rigid motion.
 *   3. Pixel analysis on the face ROI: sharpness, specular glare, chroma.
 *   4. State machine: positioning → passive window → randomised challenges.
 *   5. Fusion → PAD decision, written to a SHA-256 hash-chained audit trail.
 *
 * Privacy: no frames, crops or landmarks leave this module. The audit
 * trail stores only derived scalar measurements and decisions.
 *
 * NOTE: The passive thresholds below are sensible starting points, not
 * certified values. Calibrate them on your own bona fide / attack dataset
 * and report APCER/BPCER per ISO/IEC 30107-3 before any production claim.
 */

import type { FaceLandmarker, FaceLandmarkerResult } from "@mediapipe/tasks-vision";
import type {
  ActiveChallengeView,
  AuditEvent,
  AuditEventType,
  AuditReport,
  AuditSeverity,
  ChainVerification,
  Challenge,
  ChallengeFailureReason,
  ChallengeResult,
  ChallengeType,
  DeviceContext,
  EnginePhase,
  EngineSnapshot,
  FaceMeasurements,
  FrameMetrics,
  JsonObject,
  JsonValue,
  LivenessConfig,
  NormalizedBox,
  PadResult,
  PadSubscores,
  PaiSpecies,
  PassiveSummary,
} from "@/types";

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

export const ENGINE_VERSION = "1.0.0";
/** Must match the exact version pinned in package.json. */
export const MEDIAPIPE_VERSION = "0.10.21";

const WASM_BASE_URL = `https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@${MEDIAPIPE_VERSION}/wasm`;
const MODEL_URL =
  "https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/1/face_landmarker.task";
const MODEL_ID = "mediapipe/face_landmarker/float16/1";

const GENESIS_HASH = "0".repeat(64);
const ROI_SIZE = 112;

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

const CHALLENGE_INSTRUCTIONS: Record<ChallengeType, string> = {
  BLINK: "Blink both eyes",
  TURN_LEFT: "Slowly turn your head to your left",
  TURN_RIGHT: "Slowly turn your head to your right",
  SMILE: "Smile naturally",
  OPEN_MOUTH: "Open your mouth",
};

export const DEFAULT_CONFIG: LivenessConfig = {
  challengeCount: 3,
  challengeTimeoutMs: 7000,
  passiveWindowMs: 3000,
  stableFramesRequired: 12,
  faceLostGraceMs: 1200,
  minFaceWidthRatio: 0.2,
  maxFaceWidthRatio: 0.75,
  maxCenterOffset: 0.2,
  minBrightness: 55,
  maxBrightness: 215,
  maxMultiFaceRatio: 0.1,
  holdFrames: 3,
  snapshotIntervalMs: 80,
  thresholds: {
    blinkClosed: 0.5,
    blinkOpen: 0.25,
    smile: 0.55,
    jawOpen: 0.4,
    yawDeg: 18,
    neutralYawDeg: 9,
    neutralExpression: 0.3,
    maxRollDeg: 15,
  },
  pad: {
    bonaFideThreshold: 0.65,
    attackThreshold: 0.4,
    weights: { texture: 0.15, specular: 0.1, color: 0.05, motion: 0.2, challenge: 0.5 },
    sharpnessRange: [25, 90],
    specularRange: [0.02, 0.1],
    chromaRange: [3, 9],
    nonRigidRange: [0.0015, 0.006],
  },
};

/* ------------------------------------------------------------------ */
/* Small utilities                                                     */
/* ------------------------------------------------------------------ */

type Point = { x: number; y: number; z: number };

const clamp = (v: number, lo: number, hi: number): number => Math.min(hi, Math.max(lo, v));
const ramp = (v: number, lo: number, hi: number): number => clamp((v - lo) / (hi - lo), 0, 1);
const round = (v: number, digits = 4): number => {
  const f = 10 ** digits;
  return Math.round(v * f) / f;
};
const toDeg = (rad: number): number => (rad * 180) / Math.PI;

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

function secureShuffle<T>(items: readonly T[]): T[] {
  const out = [...items];
  const rand = new Uint32Array(out.length);
  crypto.getRandomValues(rand);
  for (let i = out.length - 1; i > 0; i--) {
    const j = rand[i] % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/** Deterministic JSON with sorted keys — required for reproducible hashes. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

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
  get count(): number {
    return this.n;
  }
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

  append(
    type: AuditEventType,
    severity: AuditSeverity,
    message: string,
    data: JsonObject | null = null,
  ): Promise<void> {
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

/** Recompute every hash and link; detects any edit, insertion or deletion. */
export async function verifyAuditChain(events: readonly AuditEvent[]): Promise<ChainVerification> {
  let prev = GENESIS_HASH;
  for (let i = 0; i < events.length; i++) {
    const { hash, ...unsigned } = events[i];
    if (unsigned.seq !== i || unsigned.prevHash !== prev) {
      return { valid: false, checked: i, brokenAt: i };
    }
    const expected = await sha256Hex(canonicalJson(unsigned));
    if (expected !== hash) return { valid: false, checked: i, brokenAt: i };
    prev = hash;
  }
  return { valid: true, checked: events.length, brokenAt: null };
}

/* ------------------------------------------------------------------ */
/* Engine                                                              */
/* ------------------------------------------------------------------ */

export interface LivenessEngineListeners {
  onSnapshot?: (snapshot: EngineSnapshot) => void;
  onAuditEvent?: (event: AuditEvent) => void;
  onReport?: (report: AuditReport) => void;
}

export type LivenessConfigOverrides = Partial<
  Omit<LivenessConfig, "thresholds" | "pad">
> & {
  thresholds?: Partial<LivenessConfig["thresholds"]>;
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
}

interface RoiStats {
  sharpness: number;
  specularRatio: number;
  chromaStd: number;
  brightness: number;
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

  // Session state
  private phase: EnginePhase = "uninitialized";
  private guidance = "Initialising liveness engine…";
  private error: string | null = null;
  private sessionId: string | null = null;
  private nonce = "";
  private startedAt = 0;
  private startedAtIso = "";
  private trail: AuditTrail | null = null;
  private device: DeviceContext | null = null;
  private plannedChallenges: ChallengeType[] = [];
  private challengeResults: ChallengeResult[] = [];
  private active: ActiveChallengeState | null = null;
  private result: PadResult | null = null;
  private report: AuditReport | null = null;
  private lastMetrics: FrameMetrics | null = null;

  // Phase bookkeeping
  private stableFrames = 0;
  private passiveStartedAt = 0;
  private lastFaceSeenAt = 0;
  private lastMultiFaceLogAt = 0;
  private prevNormLandmarks: Float32Array | null = null;
  private prevBox: { box: NormalizedBox; ts: number } | null = null;
  private spontaneousEyesClosed = false;

  // Accumulators
  private framesAnalyzed = 0;
  private multiFaceFrames = 0;
  private spontaneousBlinks = 0;
  private faceDiscontinuities = 0;
  private sharpness = new RunningMean();
  private specular = new RunningMean();
  private chroma = new RunningMean();
  private nonRigid = new RunningMean();

  constructor(
    overrides: LivenessConfigOverrides = {},
    private readonly listeners: LivenessEngineListeners = {},
  ) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...overrides,
      thresholds: { ...DEFAULT_CONFIG.thresholds, ...overrides.thresholds },
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

  /** Begin a new liveness session against a playing <video> element. */
  async start(video: HTMLVideoElement): Promise<void> {
    if (!this.landmarker) throw new Error("Engine not initialised — call init() first");
    this.stopLoop();
    this.resetSession();

    this.video = video;
    this.sessionId = crypto.randomUUID();
    this.nonce = randomHex(16);
    this.startedAt = performance.now();
    this.startedAtIso = new Date().toISOString();
    this.device = collectDeviceContext(video);
    this.plannedChallenges = secureShuffle(Object.keys(CHALLENGE_INSTRUCTIONS) as ChallengeType[]).slice(
      0,
      clamp(this.config.challengeCount, 1, 5),
    );
    this.trail = new AuditTrail(this.sessionId, (e) => this.listeners.onAuditEvent?.(e));

    void this.log("SESSION_START", "info", "Liveness session started", {
      nonce: this.nonce,
      engineVersion: ENGINE_VERSION,
      model: MODEL_ID,
      configDigest: this.configDigest,
      plannedChallenges: this.plannedChallenges,
      device: this.device as unknown as JsonValue,
    });
    void this.log("ENGINE_READY", "info", "PAD subsystem armed", {
      passiveWindowMs: this.config.passiveWindowMs,
      challengeTimeoutMs: this.config.challengeTimeoutMs,
    });

    this.phase = "positioning";
    this.guidance = "Position your face inside the oval";
    this.running = true;
    this.emit(true);
    this.rafId = requestAnimationFrame(this.loop);
  }

  /** Cancel the current session (logged as SESSION_ABORTED). */
  async abort(reason = "Aborted by operator"): Promise<void> {
    if (!this.trail || this.phase === "complete" || this.phase === "ready") return;
    this.stopLoop();
    await this.log("SESSION_ABORTED", "warn", reason, { phase: this.phase });
    await this.trail.flush();
    this.report = this.buildReport();
    this.phase = "ready";
    this.guidance = "Session aborted. Start again when ready.";
    this.active = null;
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
    this.phase = "uninitialized";
  }

  getReport(): AuditReport | null {
    return this.report;
  }

  getSnapshot(): EngineSnapshot {
    const view: ActiveChallengeView | null = this.active
      ? {
          type: this.active.challenge.type,
          instruction: this.active.armed
            ? this.active.challenge.instruction
            : "Look straight ahead with a neutral face",
          index: this.active.index,
          total: this.plannedChallenges.length,
          timeoutMs: this.active.challenge.timeoutMs,
          remainingMs: Math.max(
            0,
            this.active.challenge.timeoutMs - (performance.now() - this.active.issuedAt),
          ),
          armed: this.active.armed,
        }
      : null;

    let phaseProgress = 0;
    if (this.phase === "positioning") {
      phaseProgress = this.stableFrames / this.config.stableFramesRequired;
    } else if (this.phase === "passive") {
      phaseProgress = (performance.now() - this.passiveStartedAt) / this.config.passiveWindowMs;
    } else if (this.phase === "challenge") {
      phaseProgress = this.challengeResults.length / Math.max(1, this.plannedChallenges.length);
    } else if (this.phase === "complete") {
      phaseProgress = 1;
    }

    return {
      phase: this.phase,
      sessionId: this.sessionId,
      guidance: this.guidance,
      challenge: view,
      completedChallenges: [...this.challengeResults],
      plannedChallenges: [...this.plannedChallenges],
      metrics: this.lastMetrics,
      phaseProgress: clamp(phaseProgress, 0, 1),
      result: this.result,
      error: this.error,
      fps: this.currentFps(),
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
    this.trackFps(ts);

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

    // Blendshapes
    const shapes = new Map<string, number>();
    for (const c of result.faceBlendshapes?.[primary]?.categories ?? []) {
      shapes.set(c.categoryName, c.score);
    }
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

    const roi = this.analyseRoi(video, box);

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
      chromaStd: round(roi.chromaStd, 3),
      brightness: round(roi.brightness, 1),
      nonRigidMotion: nonRigidMotion === null ? null : round(nonRigidMotion, 5),
    };

    return { timestamp: ts, faceCount, face };
  }

  /** Texture / colour analysis on the inner 80% of the face box. */
  private analyseRoi(video: HTMLVideoElement, box: NormalizedBox): RoiStats {
    if (!this.roiCtx) {
      this.roiCanvas = document.createElement("canvas");
      this.roiCanvas.width = ROI_SIZE;
      this.roiCanvas.height = ROI_SIZE;
      this.roiCtx = this.roiCanvas.getContext("2d", { willReadFrequently: true });
    }
    const ctx = this.roiCtx;
    if (!ctx) return { sharpness: 0, specularRatio: 0, chromaStd: 0, brightness: 0 };

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
    let lumSum = 0;
    let specular = 0;
    let cbSum = 0;
    let cbSq = 0;
    let crSum = 0;
    let crSq = 0;

    for (let i = 0, p = 0; i < n; i++, p += 4) {
      const r = data[p];
      const g = data[p + 1];
      const b = data[p + 2];
      const y = 0.299 * r + 0.587 * g + 0.114 * b;
      const cb = 128 - 0.168736 * r - 0.331264 * g + 0.5 * b;
      const cr = 128 + 0.5 * r - 0.418688 * g - 0.081312 * b;
      gray[i] = y;
      lumSum += y;
      if (y > 245) specular++;
      cbSum += cb;
      cbSq += cb * cb;
      crSum += cr;
      crSq += cr * cr;
    }

    // Laplacian variance (focus measure)
    let lapSum = 0;
    let lapSq = 0;
    let lapN = 0;
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
    const cbMean = cbSum / n;
    const crMean = crSum / n;
    const cbStd = Math.sqrt(Math.max(0, cbSq / n - cbMean * cbMean));
    const crStd = Math.sqrt(Math.max(0, crSq / n - crMean * crMean));

    return {
      sharpness: lapSq / lapN - lapMean * lapMean,
      specularRatio: specular / n,
      chromaStd: (cbStd + crStd) / 2,
      brightness: lumSum / n,
    };
  }

  /* --------------------------- state machine ------------------------ */

  private step(m: FrameMetrics, ts: number): void {
    const face = m.face;
    if (face) this.lastFaceSeenAt = ts;
    if (m.faceCount > 1) this.noteMultipleFaces(m.faceCount, ts);
    if (face && m.faceCount === 1) this.checkContinuity(face.box, ts);
    else this.prevBox = null;

    switch (this.phase) {
      case "positioning":
        this.stepPositioning(m, ts);
        break;
      case "passive":
        this.stepPassive(m, ts);
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
      this.guidance = "Analysing — keep looking at the camera";
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
    if (ts - this.passiveStartedAt >= this.config.passiveWindowMs) {
      const summary = this.passiveSummary();
      void this.log("PASSIVE_COMPLETE", "info", "Passive PAD window complete", summary as unknown as JsonObject);
      this.phase = "challenge";
      this.issueNextChallenge(ts);
      this.emit(true);
    }
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
    const result: ChallengeResult = {
      challenge: a.challenge,
      status: passed ? "passed" : "failed",
      failureReason: reason,
      issuedAt: a.issuedAtIso,
      completedAt: new Date().toISOString(),
      responseTimeMs,
      peakSignal: round(a.peak, 3),
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
    this.sharpness.push(f.sharpness);
    this.specular.push(f.specularRatio);
    this.chroma.push(f.chromaStd);
    if (passiveWindow && f.nonRigidMotion !== null) this.nonRigid.push(f.nonRigidMotion);

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
    if (this.phase === "passive" || this.phase === "challenge") this.multiFaceFrames++;
    if (ts - this.lastMultiFaceLogAt > 2000 && this.phase !== "ready" && this.phase !== "complete") {
      this.lastMultiFaceLogAt = ts;
      void this.log("MULTIPLE_FACES", "warn", `${count} faces in frame`, { faceCount: count, phase: this.phase });
    }
  }

  /** Detects a sudden subject swap (e.g. photo slid in front of the face). */
  private checkContinuity(box: NormalizedBox, ts: number): void {
    const prev = this.prevBox;
    this.prevBox = { box, ts };
    if (!prev || ts - prev.ts > 150) return;
    if (this.phase !== "passive" && this.phase !== "challenge") return;
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
      meanChromaStd: round(this.chroma.mean, 3),
      meanNonRigidMotion: round(this.nonRigid.mean, 5),
      spontaneousBlinks: this.spontaneousBlinks,
      faceDiscontinuities: this.faceDiscontinuities,
    };
  }

  /* --------------------------- decision ----------------------------- */

  private evaluate(): PadResult {
    const p = this.passiveSummary();
    const pad = this.config.pad;
    const total = this.plannedChallenges.length;
    const passed = this.challengeResults.filter((r) => r.status === "passed").length;
    const allPassed = passed === total && total > 0;

    const subscores: PadSubscores = {
      texture: ramp(p.meanSharpness, ...pad.sharpnessRange),
      specular: 1 - ramp(p.meanSpecularRatio, ...pad.specularRange),
      color: ramp(p.meanChromaStd, ...pad.chromaRange),
      motion: Math.max(ramp(p.meanNonRigidMotion, ...pad.nonRigidRange), p.spontaneousBlinks > 0 ? 1 : 0),
      challenge: total === 0 ? 0 : passed / total,
    };
    let weighted = 0;
    let weightSum = 0;
    for (const key of Object.keys(subscores) as (keyof PadSubscores)[]) {
      subscores[key] = round(subscores[key], 3);
      weighted += subscores[key] * pad.weights[key];
      weightSum += pad.weights[key];
    }
    const score = round(weightSum > 0 ? weighted / weightSum : 0, 4);

    const suspected = new Set<PaiSpecies>();
    const reasons: string[] = [];
    const multiRatio = p.framesAnalyzed > 0 ? p.multiFaceFrames / p.framesAnalyzed : 0;

    if (!allPassed) reasons.push(`Active challenges: ${passed}/${total} passed`);
    if (subscores.texture < 0.35 && subscores.color < 0.5) {
      suspected.add("PRINT");
      reasons.push("Low texture detail and colour gamut (consistent with printed media)");
    }
    if (subscores.specular < 0.4) {
      suspected.add("REPLAY_SCREEN");
      reasons.push("Elevated specular glare (consistent with a display screen)");
    }
    if (subscores.motion < 0.25) {
      suspected.add("STATIC_IMAGE");
      reasons.push("Negligible non-rigid facial motion and no spontaneous blink");
    }
    if (multiRatio > this.config.maxMultiFaceRatio) {
      suspected.add("MULTIPLE_SUBJECTS");
      reasons.push(`Multiple faces in ${(multiRatio * 100).toFixed(1)}% of frames`);
    }
    if (p.faceDiscontinuities > 0) {
      suspected.add("SUBJECT_SWAP");
      reasons.push(`${p.faceDiscontinuities} abrupt face discontinuity event(s)`);
    }

    let decision: PadResult["decision"];
    if (score < pad.attackThreshold || (!allPassed && suspected.size > 0)) {
      decision = "ATTACK";
      if (suspected.size === 0) suspected.add("UNKNOWN");
    } else if (
      allPassed &&
      score >= pad.bonaFideThreshold &&
      !suspected.has("MULTIPLE_SUBJECTS") &&
      !suspected.has("SUBJECT_SWAP")
    ) {
      decision = "BONA_FIDE";
    } else {
      decision = "INCONCLUSIVE";
    }
    if (decision === "BONA_FIDE" && reasons.length === 0) {
      reasons.push("All challenges passed and passive signals within bona fide range");
    }

    return {
      decision,
      score,
      bonaFideThreshold: pad.bonaFideThreshold,
      attackThreshold: pad.attackThreshold,
      subscores,
      suspectedPai: [...suspected],
      reasons,
    };
  }

  private async finalize(): Promise<void> {
    this.stopLoop();
    this.active = null;
    this.phase = "evaluating";
    this.guidance = "Evaluating…";
    this.emit(true);

    this.result = this.evaluate();
    await this.log(
      "DECISION",
      this.result.decision === "BONA_FIDE" ? "info" : this.result.decision === "ATTACK" ? "critical" : "warn",
      `PAD decision: ${this.result.decision} (score ${this.result.score.toFixed(3)})`,
      this.result as unknown as JsonObject,
    );
    await this.trail?.flush();

    this.report = this.buildReport();
    this.phase = "complete";
    this.guidance =
      this.result.decision === "BONA_FIDE"
        ? "Liveness confirmed"
        : this.result.decision === "ATTACK"
          ? "Presentation attack suspected"
          : "Result inconclusive — please retry";
    this.emit(true);
    if (this.report) this.listeners.onReport?.(this.report);
  }

  private buildReport(): AuditReport | null {
    if (!this.trail || !this.sessionId || !this.device) return null;
    return {
      schemaVersion: "faceguard.audit/1.0",
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
      sessionId: this.sessionId,
      nonce: this.nonce,
      startedAt: this.startedAtIso,
      completedAt: new Date().toISOString(),
      durationMs: Math.round(performance.now() - this.startedAt),
      device: this.device,
      plannedChallenges: [...this.plannedChallenges],
      challenges: [...this.challengeResults],
      passive: this.passiveSummary(),
      result: this.result,
      evaluation: { groundTruth: null, paiSpeciesUnderTest: null },
      privacy: {
        rawBiometricsStored: false,
        retained: [
          "Derived scalar quality/PAD measurements",
          "Challenge outcomes and timings",
          "Device and camera capability metadata",
        ],
      },
      events: this.trail.all,
      chainHead: this.trail.chainHead,
    };
  }

  /* ----------------------------- helpers ---------------------------- */

  private log(
    type: AuditEventType,
    severity: AuditSeverity,
    message: string,
    data: JsonObject | null = null,
  ): Promise<void> {
    return this.trail ? this.trail.append(type, severity, message, data) : Promise.resolve();
  }

  private resetSession(): void {
    this.sessionId = null;
    this.nonce = "";
    this.trail = null;
    this.device = null;
    this.plannedChallenges = [];
    this.challengeResults = [];
    this.active = null;
    this.result = null;
    this.report = null;
    this.error = null;
    this.lastMetrics = null;
    this.stableFrames = 0;
    this.passiveStartedAt = 0;
    this.lastFaceSeenAt = 0;
    this.lastMultiFaceLogAt = 0;
    this.prevNormLandmarks = null;
    this.prevBox = null;
    this.spontaneousEyesClosed = false;
    this.framesAnalyzed = 0;
    this.multiFaceFrames = 0;
    this.spontaneousBlinks = 0;
    this.faceDiscontinuities = 0;
    this.sharpness = new RunningMean();
    this.specular = new RunningMean();
    this.chroma = new RunningMean();
    this.nonRigid = new RunningMean();
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

  private trackFps(ts: number): void {
    this.fpsWindow.push(ts);
    while (this.fpsWindow.length > 0 && ts - this.fpsWindow[0] > 1000) this.fpsWindow.shift();
  }

  private currentFps(): number {
    return this.fpsWindow.length;
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
  let minX = 1;
  let minY = 1;
  let maxX = 0;
  let maxY = 0;
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

  let cx = 0;
  let cy = 0;
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

function collectDeviceContext(video: HTMLVideoElement): DeviceContext {
  const stream = video.srcObject instanceof MediaStream ? video.srcObject : null;
  const track = stream?.getVideoTracks()[0];
  const s = track?.getSettings();
  return {
    userAgent: navigator.userAgent,
    language: navigator.language,
    hardwareConcurrency: navigator.hardwareConcurrency ?? null,
    screen: {
      width: window.screen.width,
      height: window.screen.height,
      pixelRatio: window.devicePixelRatio,
    },
    camera: {
      label: track?.label ?? "unknown",
      width: s?.width ?? video.videoWidth ?? null,
      height: s?.height ?? video.videoHeight ?? null,
      frameRate: s?.frameRate ?? null,
      facingMode: s?.facingMode ?? null,
    },
  };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
