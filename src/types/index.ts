/**
 * FaceGuard — shared domain types.
 *
 * Terminology follows ISO/IEC 30107-1 (framework) and ISO/IEC 30107-3
 * (testing & reporting): "bona fide presentation", "attack presentation",
 * "presentation attack instrument (PAI)", "PAD subsystem".
 */

/* ------------------------------------------------------------------ */
/* JSON helpers (audit payloads must be serialisable & hashable)       */
/* ------------------------------------------------------------------ */

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

/* ------------------------------------------------------------------ */
/* Active challenge–response                                           */
/* ------------------------------------------------------------------ */

export type ChallengeType = "BLINK" | "TURN_LEFT" | "TURN_RIGHT" | "SMILE" | "OPEN_MOUTH";

export interface Challenge {
  /** Unique, nonce-bound identifier for this issued challenge. */
  id: string;
  type: ChallengeType;
  instruction: string;
  timeoutMs: number;
}

export type ChallengeFailureReason = "TIMEOUT" | "FACE_LOST" | "NEVER_NEUTRAL";

export interface ChallengeResult {
  challenge: Challenge;
  status: "passed" | "failed";
  failureReason: ChallengeFailureReason | null;
  issuedAt: string;
  completedAt: string;
  /** Time from the subject reaching a neutral pose to completing the action. */
  responseTimeMs: number | null;
  /** Strongest signal observed (blendshape score or yaw degrees). */
  peakSignal: number;
}

export interface ActiveChallengeView {
  type: ChallengeType;
  instruction: string;
  index: number;
  total: number;
  timeoutMs: number;
  remainingMs: number;
  /** False until the subject returns to a neutral pose (anti-replay gate). */
  armed: boolean;
}

/* ------------------------------------------------------------------ */
/* Per-frame measurements                                              */
/* ------------------------------------------------------------------ */

/** Box in raw (un-mirrored) camera coordinates, normalised to 0..1. */
export interface NormalizedBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface FaceMeasurements {
  box: NormalizedBox;
  /** Positive = subject turned towards their own left. */
  yawDeg: number;
  pitchDeg: number;
  rollDeg: number;
  /** Blendshape scores, 0..1. */
  blink: number;
  smile: number;
  jawOpen: number;
  /** Laplacian variance of the face ROI (focus / recapture blur). */
  sharpness: number;
  /** Fraction of near-saturated pixels in the face ROI (screen glare). */
  specularRatio: number;
  /** Mean std-dev of Cb/Cr chroma channels (colour gamut richness). */
  chromaStd: number;
  /** Mean luminance of the face ROI, 0..255. */
  brightness: number;
  /** Non-rigid landmark motion vs previous frame (null on first frame). */
  nonRigidMotion: number | null;
}

export interface FrameMetrics {
  timestamp: number;
  faceCount: number;
  face: FaceMeasurements | null;
}

/* ------------------------------------------------------------------ */
/* PAD outcome                                                         */
/* ------------------------------------------------------------------ */

export type PadSignal = "texture" | "specular" | "color" | "motion" | "challenge";

/** Each sub-score is a 0..1 bona-fide likelihood (1 = looks live). */
export type PadSubscores = Record<PadSignal, number>;

export type PadDecision = "BONA_FIDE" | "ATTACK" | "INCONCLUSIVE";

export type PaiSpecies =
  | "PRINT"
  | "REPLAY_SCREEN"
  | "STATIC_IMAGE"
  | "MULTIPLE_SUBJECTS"
  | "SUBJECT_SWAP"
  | "UNKNOWN";

export interface PadResult {
  decision: PadDecision;
  /** Fused bona-fide score, 0..1. */
  score: number;
  bonaFideThreshold: number;
  attackThreshold: number;
  subscores: PadSubscores;
  suspectedPai: PaiSpecies[];
  reasons: string[];
}

export interface PassiveSummary {
  framesAnalyzed: number;
  multiFaceFrames: number;
  meanSharpness: number;
  meanSpecularRatio: number;
  meanChromaStd: number;
  meanNonRigidMotion: number;
  spontaneousBlinks: number;
  faceDiscontinuities: number;
}

/* ------------------------------------------------------------------ */
/* Engine configuration & state                                        */
/* ------------------------------------------------------------------ */

export interface LivenessConfig {
  challengeCount: number;
  challengeTimeoutMs: number;
  passiveWindowMs: number;
  stableFramesRequired: number;
  faceLostGraceMs: number;
  minFaceWidthRatio: number;
  maxFaceWidthRatio: number;
  maxCenterOffset: number;
  minBrightness: number;
  maxBrightness: number;
  maxMultiFaceRatio: number;
  holdFrames: number;
  snapshotIntervalMs: number;
  thresholds: {
    blinkClosed: number;
    blinkOpen: number;
    smile: number;
    jawOpen: number;
    yawDeg: number;
    neutralYawDeg: number;
    neutralExpression: number;
    maxRollDeg: number;
  };
  pad: {
    bonaFideThreshold: number;
    attackThreshold: number;
    weights: Record<PadSignal, number>;
    /** [low, high] ramps mapping raw signal → 0..1 score. */
    sharpnessRange: [number, number];
    specularRange: [number, number];
    chromaRange: [number, number];
    nonRigidRange: [number, number];
  };
}

export type EnginePhase =
  | "uninitialized"
  | "initializing"
  | "ready"
  | "positioning"
  | "passive"
  | "challenge"
  | "evaluating"
  | "complete"
  | "error";

export interface EngineSnapshot {
  phase: EnginePhase;
  sessionId: string | null;
  guidance: string;
  challenge: ActiveChallengeView | null;
  completedChallenges: ChallengeResult[];
  plannedChallenges: ChallengeType[];
  metrics: FrameMetrics | null;
  /** 0..1 progress of the current phase (positioning / passive). */
  phaseProgress: number;
  result: PadResult | null;
  error: string | null;
  fps: number;
}

/* ------------------------------------------------------------------ */
/* Audit trail (tamper-evident, hash-chained)                          */
/* ------------------------------------------------------------------ */

export type AuditEventType =
  | "SESSION_START"
  | "ENGINE_READY"
  | "FACE_ACQUIRED"
  | "FACE_LOST"
  | "FACE_DISCONTINUITY"
  | "MULTIPLE_FACES"
  | "PASSIVE_COMPLETE"
  | "CHALLENGE_ISSUED"
  | "CHALLENGE_PASSED"
  | "CHALLENGE_FAILED"
  | "DECISION"
  | "SESSION_ABORTED"
  | "ERROR";

export type AuditSeverity = "info" | "warn" | "critical";

export interface AuditEvent {
  seq: number;
  timestamp: string;
  sessionId: string;
  type: AuditEventType;
  severity: AuditSeverity;
  message: string;
  data: JsonObject | null;
  /** SHA-256 of the previous event (genesis = 64 zeros). */
  prevHash: string;
  /** SHA-256 over the canonical JSON of every field above. */
  hash: string;
}

export interface DeviceContext {
  userAgent: string;
  language: string;
  hardwareConcurrency: number | null;
  screen: { width: number; height: number; pixelRatio: number };
  camera: {
    label: string;
    width: number | null;
    height: number | null;
    frameRate: number | null;
    facingMode: string | null;
  };
}

export interface AuditReport {
  schemaVersion: "faceguard.audit/1.0";
  standardReference: {
    framework: "ISO/IEC 30107-1:2023";
    testingReporting: "ISO/IEC 30107-3:2023";
    note: string;
  };
  engineVersion: string;
  modelVersion: string;
  configDigest: string;
  config: LivenessConfig;
  sessionId: string;
  nonce: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  device: DeviceContext;
  plannedChallenges: ChallengeType[];
  challenges: ChallengeResult[];
  passive: PassiveSummary;
  result: PadResult | null;
  /**
   * Fields for offline APCER/BPCER computation per ISO/IEC 30107-3.
   * Populate `groundTruth` during evaluation campaigns only.
   */
  evaluation: {
    groundTruth: "BONA_FIDE" | "ATTACK" | null;
    paiSpeciesUnderTest: string | null;
  };
  privacy: {
    rawBiometricsStored: false;
    retained: string[];
  };
  events: AuditEvent[];
  chainHead: string;
}

export interface ChainVerification {
  valid: boolean;
  checked: number;
  brokenAt: number | null;
}
