/**
 * Synthetic test data shared by the test suites.
 * Documented in docs/TEST_DATA.md.
 */

import { analysePhotometric, buildSessionPlan, canonicalJson, decidePad, DEFAULT_CONFIG, sha256Hex } from "@/lib/padCore";
import { signJws } from "@/lib/server/attestation";
import type {
  AuditEvent,
  AuditReport,
  ChallengeResult,
  ChallengeType,
  FlashColor,
  InjectionSignals,
  PassiveSummary,
  PhotometricResult,
  PhotometricStep,
} from "@/types";

/** Deterministic pseudo-random numbers so results are reproducible. */
export function seededRandom(seed = 7): () => number {
  let s = seed;
  return () => (s = (s * 16807) % 2147483647) / 2147483647;
}

/* ------------------------------------------------------------------ */
/* Synthetic 3D face for the depth (planarity) check                   */
/* ------------------------------------------------------------------ */

const rnd = seededRandom(7);
const FACE_POINTS: [number, number, number][] = Array.from({ length: 40 }, () => {
  const x = (rnd() - 0.5) * 14; // cm
  const y = (rnd() - 0.5) * 18;
  const z = 3 * Math.exp(-(x * x) / 8 - (y * y) / 30) - 0.02 * x * x; // nose bump, curved cheeks
  return [x, y, z];
});

/** Projects the face (or a flat copy of it) after turning `yawDeg`, with pixel noise. */
export function projectFace(yawDeg: number, flat: boolean, noisePx = 0, distanceCm = 45): number[] {
  const noise = seededRandom(11 + Math.round(yawDeg));
  const a = (yawDeg * Math.PI) / 180;
  const focal = 60;
  return FACE_POINTS.flatMap(([x, y, z]) => {
    const depth = flat ? 0 : z;
    const X = x * Math.cos(a) + depth * Math.sin(a);
    const Z = -x * Math.sin(a) + depth * Math.cos(a);
    const s = (focal / (distanceCm - Z)) * 10;
    return [X * s + (noise() - 0.5) * noisePx, y * s + (noise() - 0.5) * noisePx];
  });
}

/** Inter-ocular distance in the same pixel units as projectFace(). */
export const FACE_IOD_PX = 9 * (60 / 45) * 10;

/* ------------------------------------------------------------------ */
/* Screen-flash steps                                                  */
/* ------------------------------------------------------------------ */

const BASE_CHROMA: [number, number, number] = [0.45, 0.33, 0.22];

/** A live face: chroma shifts towards each flashed colour. */
export function liveFlashSteps(sequence: FlashColor[]): PhotometricStep[] {
  const noise = seededRandom(3);
  return sequence.map((color) => {
    const k = ["RED", "GREEN", "BLUE"].indexOf(color);
    return {
      color,
      frames: 10,
      chroma: BASE_CHROMA.map((v, i) => v + (i === k ? 0.008 : -0.004) + (noise() - 0.5) * 0.002) as [number, number, number],
    };
  });
}

/** A replayed recording: chroma changes that ignore the flashed colours. */
export function replayFlashSteps(sequence: FlashColor[], amplitude = 0.012): PhotometricStep[] {
  const noise = seededRandom(5);
  return sequence.map((color) => ({
    color,
    frames: 10,
    chroma: BASE_CHROMA.map((v) => v + (noise() - 0.5) * amplitude) as [number, number, number],
  }));
}

export function photometricFrom(steps: PhotometricStep[], sequence: FlashColor[]): PhotometricResult {
  return { sequence, steps, ...analysePhotometric(steps, DEFAULT_CONFIG.photometric.minAmplitude) };
}

/* ------------------------------------------------------------------ */
/* Passive signals, camera, challenges                                 */
/* ------------------------------------------------------------------ */

export const LIVE_PASSIVE: PassiveSummary = {
  framesAnalyzed: 300,
  multiFaceFrames: 0,
  meanSharpness: 70,
  meanSpecularRatio: 0.01,
  meanNonRigidMotion: 0.004,
  meanMoirePeakiness: 5,
  pulseSnr: 20,
  pulseBpm: 72,
  spontaneousBlinks: 1,
  faceDiscontinuities: 0,
};

export const REAL_CAMERA: InjectionSignals = {
  cameraLabel: "Integrated Webcam",
  virtualCameraSuspected: false,
  duplicateFrameRatio: 0,
  noHardwareCapabilities: false,
};

export function challengeResult(
  type: ChallengeType,
  opts: { status?: "passed" | "failed"; depth?: number | null; responseTimeMs?: number } = {},
): ChallengeResult {
  const status = opts.status ?? "passed";
  const isTurn = type === "TURN_LEFT" || type === "TURN_RIGHT";
  return {
    challenge: { id: `test-${type}`, type, instruction: "", timeoutMs: 7000 },
    status,
    failureReason: status === "failed" ? "TIMEOUT" : null,
    issuedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    responseTimeMs: status === "passed" ? (opts.responseTimeMs ?? 850) : null,
    peakSignal: 0.8,
    depthResidual: opts.depth !== undefined ? opts.depth : status === "passed" && isTurn ? 0.03 : null,
  };
}

/* ------------------------------------------------------------------ */
/* Complete signed report, as the browser would submit it              */
/* ------------------------------------------------------------------ */

export async function buildSignedReport(): Promise<AuditReport> {
  const plan = buildSessionPlan(crypto.randomUUID(), "ab".repeat(16));
  const signedPlan = { plan, token: signJws(plan) };
  const photometric = photometricFrom(liveFlashSteps(plan.flashSequence), plan.flashSequence);
  const challenges = plan.challenges.map((t) => challengeResult(t));
  const passive = LIVE_PASSIVE;
  const injection = REAL_CAMERA;
  const result = decidePad({ plannedChallenges: plan.challenges, challenges, passive, photometric, injection });

  const events: AuditEvent[] = [];
  let prev = "0".repeat(64);
  const entries: [AuditEvent["type"], AuditEvent["data"]][] = [
    ["SESSION_START", { nonce: plan.nonce }],
    ["PHOTOMETRIC_COMPLETE", { correlation: photometric.correlation }],
    ["DECISION", { decision: result.decision }],
  ];
  for (const [type, data] of entries) {
    const unsigned = {
      seq: events.length,
      timestamp: new Date().toISOString(),
      sessionId: plan.sessionId,
      type,
      severity: "info" as const,
      message: type,
      data,
      prevHash: prev,
    };
    const hash = await sha256Hex(canonicalJson(unsigned));
    events.push({ ...unsigned, hash });
    prev = hash;
  }

  return {
    schemaVersion: "faceguard.audit/2.0",
    standardReference: {
      framework: "ISO/IEC 30107-1:2023",
      testingReporting: "ISO/IEC 30107-3:2023",
      note: "test fixture",
    },
    engineVersion: plan.engineVersion,
    modelVersion: "test",
    configDigest: await sha256Hex(canonicalJson(DEFAULT_CONFIG)),
    config: DEFAULT_CONFIG,
    signedPlan,
    sessionId: plan.sessionId,
    nonce: plan.nonce,
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: 15_000,
    device: {
      userAgent: "test",
      language: "en",
      hardwareConcurrency: 8,
      screen: { width: 1920, height: 1080, pixelRatio: 1 },
      camera: { label: "Integrated Webcam", width: 1280, height: 720, frameRate: 30, facingMode: "user" },
    },
    plannedChallenges: plan.challenges,
    challenges,
    passive,
    photometric,
    injection,
    referenceImage: {
      sha256: "f".repeat(64),
      mimeType: "image/jpeg",
      width: 256,
      height: 256,
      capturedAt: new Date().toISOString(),
      sharpness: 80,
    },
    result,
    evaluation: { groundTruth: null, paiSpeciesUnderTest: null },
    privacy: { rawBiometricsStored: false, retained: [] },
    events,
    chainHead: prev,
  };
}
