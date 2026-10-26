/**
 * FaceGuard PAD core — pure, environment-agnostic functions shared by the
 * browser engine and the server verifier. Nothing here touches the DOM, so
 * the server can recompute the decision from submitted signals.
 *
 * NOTE: Ranges and thresholds are uncalibrated starting points. Calibrate on
 * a labelled bona fide / attack dataset and report APCER/BPCER per
 * ISO/IEC 30107-3 before making any performance claim.
 */

import type {
  AuditEvent,
  ChainVerification,
  ChallengeType,
  FlashColor,
  LivenessConfig,
  PadInput,
  PadResult,
  PadSignal,
  PadSubscores,
  PaiSpecies,
  PhotometricStep,
  SessionPlan,
} from "@/types";

/* ------------------------------------------------------------------ */
/* Versions & configuration                                            */
/* ------------------------------------------------------------------ */

export const ENGINE_VERSION = "2.0.0";
export const SESSION_TTL_MS = 3 * 60 * 1000;
export const CHALLENGE_COUNT = 3;
export const FLASH_STEPS = 5;
const GENESIS_HASH = "0".repeat(64);

export const DEFAULT_CONFIG: LivenessConfig = {
  challengeTimeoutMs: 7000,
  passiveWindowMs: 5000,
  stableFramesRequired: 12,
  faceLostGraceMs: 1200,
  minFaceWidthRatio: 0.22,
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
    minHumanResponseMs: 150,
  },
  photometric: {
    stepMs: 700,
    settleMs: 300,
    minAmplitude: 0.003,
    failCorrelation: 0.05,
  },
  pad: {
    bonaFideThreshold: 0.65,
    attackThreshold: 0.4,
    weights: {
      challenge: 0.3,
      depth: 0.15,
      photometric: 0.15,
      motion: 0.1,
      injection: 0.1,
      pulse: 0.05,
      moire: 0.05,
      texture: 0.05,
      specular: 0.05,
    },
    sharpnessRange: [25, 90],
    specularRange: [0.02, 0.1],
    nonRigidRange: [0.0015, 0.006],
    depthRange: [0.01, 0.025],
    photometricRange: [0.05, 0.4],
    pulseSnrRange: [5, 15],
    moireRange: [8, 20],
    duplicateRange: [0.1, 0.4],
  },
};

/* ------------------------------------------------------------------ */
/* Small utilities                                                     */
/* ------------------------------------------------------------------ */

export const clamp = (v: number, lo: number, hi: number): number => Math.min(hi, Math.max(lo, v));
export const ramp = (v: number, lo: number, hi: number): number => clamp((v - lo) / (hi - lo), 0, 1);
export const round = (v: number, digits = 4): number => {
  const f = 10 ** digits;
  return Math.round(v * f) / f;
};

export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

function randomInt(maxExclusive: number): number {
  // Rejection sampling to avoid modulo bias.
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf);
  while (buf[0] >= limit);
  return buf[0] % maxExclusive;
}

export function secureShuffle<T>(items: readonly T[]): T[] {
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
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

export async function sha256Hex(input: string | ArrayBuffer | Uint8Array): Promise<string> {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
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
/* Session plan (issued by the server)                                 */
/* ------------------------------------------------------------------ */

const ALL_CHALLENGES: ChallengeType[] = ["BLINK", "TURN_LEFT", "TURN_RIGHT", "SMILE", "OPEN_MOUTH"];
const TURNS: ChallengeType[] = ["TURN_LEFT", "TURN_RIGHT"];
const FLASH_COLORS: FlashColor[] = ["RED", "GREEN", "BLUE"];

/**
 * Always includes at least one head turn — the only challenge a cut-out photo
 * or flat screen cannot perform — plus a random screen-flash colour sequence
 * that uses every colour and never repeats a colour back to back.
 */
export function buildSessionPlan(sessionId: string, nonce: string, now = Date.now()): SessionPlan {
  const turn = TURNS[randomInt(TURNS.length)];
  const others = secureShuffle(ALL_CHALLENGES.filter((c) => c !== turn)).slice(0, CHALLENGE_COUNT - 1);
  const challenges = secureShuffle([turn, ...others]);

  let flashSequence: FlashColor[] = [];
  do {
    flashSequence = [];
    for (let i = 0; i < FLASH_STEPS; i++) {
      const options = FLASH_COLORS.filter((c) => c !== flashSequence[i - 1]);
      flashSequence.push(options[randomInt(options.length)]);
    }
  } while (!FLASH_COLORS.every((c) => flashSequence.includes(c)));

  return {
    sessionId,
    nonce,
    challenges,
    flashSequence,
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + SESSION_TTL_MS).toISOString(),
    engineVersion: ENGINE_VERSION,
  };
}

/* ------------------------------------------------------------------ */
/* Depth: is the face moving like a flat surface?                      */
/* ------------------------------------------------------------------ */

/**
 * Fits the best homography (the exact image-to-image mapping of any flat
 * surface under perspective) from reference to current landmark positions
 * (interleaved x,y pixel coordinates) and returns the RMS residual divided by
 * `scale` (inter-ocular distance). A photo, cut-out print or phone screen fits
 * almost perfectly however it is tilted; a real 3D face turning ~20° does not,
 * because the nose and cheeks sit at different depths.
 */
export function planarResidual(ref: ArrayLike<number>, cur: ArrayLike<number>, scale: number): number {
  const n = Math.min(ref.length, cur.length) / 2;
  if (n < 6 || scale <= 0) return 0;

  // Normalise both point sets (centroid 0, mean distance √2) for conditioning.
  const norm = (pts: ArrayLike<number>) => {
    let cx = 0, cy = 0;
    for (let i = 0; i < n; i++) { cx += pts[2 * i]; cy += pts[2 * i + 1]; }
    cx /= n; cy /= n;
    let d = 0;
    for (let i = 0; i < n; i++) d += Math.hypot(pts[2 * i] - cx, pts[2 * i + 1] - cy);
    const s = d > 0 ? (Math.SQRT2 * n) / d : 1;
    const out = new Float64Array(2 * n);
    for (let i = 0; i < n; i++) { out[2 * i] = (pts[2 * i] - cx) * s; out[2 * i + 1] = (pts[2 * i + 1] - cy) * s; }
    return { out, cx, cy, s };
  };
  const a = norm(ref);
  const b = norm(cur);

  // Least squares for h (8 unknowns, h33 = 1): normal equations AᵀA h = Aᵀy.
  const ata = Array.from({ length: 8 }, () => new Float64Array(8));
  const aty = new Float64Array(8);
  const addRow = (row: number[], y: number) => {
    for (let r = 0; r < 8; r++) {
      aty[r] += row[r] * y;
      for (let c = 0; c < 8; c++) ata[r][c] += row[r] * row[c];
    }
  };
  for (let i = 0; i < n; i++) {
    const x = a.out[2 * i], y = a.out[2 * i + 1];
    const u = b.out[2 * i], v = b.out[2 * i + 1];
    addRow([x, y, 1, 0, 0, 0, -u * x, -u * y], u);
    addRow([0, 0, 0, x, y, 1, -v * x, -v * y], v);
  }
  const h = solveLinear(ata, aty);
  if (!h) return 0;

  let sq = 0;
  for (let i = 0; i < n; i++) {
    const x = a.out[2 * i], y = a.out[2 * i + 1];
    const w = h[6] * x + h[7] * y + 1;
    if (Math.abs(w) < 1e-9) return 0;
    // Map back to pixel units of the current frame before measuring error.
    const u = (h[0] * x + h[1] * y + h[2]) / w / b.s + b.cx;
    const v = (h[3] * x + h[4] * y + h[5]) / w / b.s + b.cy;
    sq += (u - cur[2 * i]) ** 2 + (v - cur[2 * i + 1]) ** 2;
  }
  return Math.sqrt(sq / n) / scale;
}

/** Gaussian elimination with partial pivoting. */
function solveLinear(m: Float64Array[], rhs: Float64Array): Float64Array | null {
  const n = rhs.length;
  const A = m.map((row) => Float64Array.from(row));
  const b = Float64Array.from(rhs);
  for (let col = 0; col < n; col++) {
    let pivot = col;
    for (let r = col + 1; r < n; r++) if (Math.abs(A[r][col]) > Math.abs(A[pivot][col])) pivot = r;
    if (Math.abs(A[pivot][col]) < 1e-12) return null;
    [A[col], A[pivot]] = [A[pivot], A[col]];
    [b[col], b[pivot]] = [b[pivot], b[col]];
    for (let r = col + 1; r < n; r++) {
      const f = A[r][col] / A[col][col];
      for (let c = col; c < n; c++) A[r][c] -= f * A[col][c];
      b[r] -= f * b[col];
    }
  }
  const x = new Float64Array(n);
  for (let r = n - 1; r >= 0; r--) {
    let s = b[r];
    for (let c = r + 1; c < n; c++) s -= A[r][c] * x[c];
    x[r] = s / A[r][r];
  }
  return x;
}

/* ------------------------------------------------------------------ */
/* Moiré: periodic high-frequency patterns from recaptured screens     */
/* ------------------------------------------------------------------ */

function fft1d(re: Float64Array, im: Float64Array): void {
  const n = re.length;
  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      [re[i], re[j]] = [re[j], re[i]];
      [im[i], im[j]] = [im[j], im[i]];
    }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const ang = (-2 * Math.PI) / len;
    const wr = Math.cos(ang), wi = Math.sin(ang);
    for (let i = 0; i < n; i += len) {
      let cr = 1, ci = 0;
      for (let k = 0; k < len / 2; k++) {
        const ar = re[i + k + len / 2] * cr - im[i + k + len / 2] * ci;
        const ai = re[i + k + len / 2] * ci + im[i + k + len / 2] * cr;
        re[i + k + len / 2] = re[i + k] - ar;
        im[i + k + len / 2] = im[i + k] - ai;
        re[i + k] += ar;
        im[i + k] += ai;
        const t = cr * wr - ci * wi;
        ci = cr * wi + ci * wr;
        cr = t;
      }
    }
  }
}

/**
 * Peak-to-median ratio of the high-frequency spectrum of a square grayscale
 * patch (side must be a power of two). Natural skin has a smooth spectrum;
 * moiré from a recaptured display produces isolated sharp peaks.
 */
export function moirePeakiness(gray: ArrayLike<number>, size: number): number {
  const n = size * size;
  const re = new Float64Array(n);
  const im = new Float64Array(n);
  let mean = 0;
  for (let i = 0; i < n; i++) mean += gray[i];
  mean /= n;
  for (let y = 0; y < size; y++) {
    const wy = 0.5 - 0.5 * Math.cos((2 * Math.PI * y) / (size - 1));
    for (let x = 0; x < size; x++) {
      const wx = 0.5 - 0.5 * Math.cos((2 * Math.PI * x) / (size - 1));
      re[y * size + x] = (gray[y * size + x] - mean) * wx * wy;
    }
  }
  const rowRe = new Float64Array(size), rowIm = new Float64Array(size);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) { rowRe[x] = re[y * size + x]; rowIm[x] = im[y * size + x]; }
    fft1d(rowRe, rowIm);
    for (let x = 0; x < size; x++) { re[y * size + x] = rowRe[x]; im[y * size + x] = rowIm[x]; }
  }
  for (let x = 0; x < size; x++) {
    for (let y = 0; y < size; y++) { rowRe[y] = re[y * size + x]; rowIm[y] = im[y * size + x]; }
    fft1d(rowRe, rowIm);
    for (let y = 0; y < size; y++) { re[y * size + x] = rowRe[y]; im[y * size + x] = rowIm[y]; }
  }

  const half = size / 2;
  const mags: number[] = [];
  for (let v = 0; v < size; v++) {
    for (let u = 0; u < size; u++) {
      const fu = u <= half ? u : u - size;
      const fv = v <= half ? v : v - size;
      if (Math.abs(fu) <= 1 || Math.abs(fv) <= 1) continue; // axis artefacts
      const r = Math.hypot(fu, fv);
      if (r < size * 0.2 || r > half) continue; // high band only
      mags.push(Math.hypot(re[v * size + u], im[v * size + u]));
    }
  }
  if (mags.length === 0) return 0;
  mags.sort((a, b) => a - b);
  const median = mags[Math.floor(mags.length / 2)];
  return median > 1e-9 ? mags[mags.length - 1] / median : 0;
}

/* ------------------------------------------------------------------ */
/* Pulse (remote photoplethysmography, CHROM method)                   */
/* ------------------------------------------------------------------ */

export interface ColorSample {
  t: number; // ms
  r: number;
  g: number;
  b: number;
}

function detrend(values: number[], times: number[]): number[] {
  const n = values.length;
  const mt = times.reduce((a, b) => a + b, 0) / n;
  const mv = values.reduce((a, b) => a + b, 0) / n;
  let num = 0, den = 0;
  for (let i = 0; i < n; i++) { num += (times[i] - mt) * (values[i] - mv); den += (times[i] - mt) ** 2; }
  const slope = den > 0 ? num / den : 0;
  return values.map((v, i) => v - mv - slope * (times[i] - mt));
}

const std = (a: number[]): number => {
  const m = a.reduce((x, y) => x + y, 0) / a.length;
  return Math.sqrt(a.reduce((x, y) => x + (y - m) ** 2, 0) / a.length);
};

/**
 * Looks for a heartbeat-frequency colour oscillation in facial skin.
 * Photos and most masks show none. Webcam compression and motion make this
 * a weak signal on its own, so it carries a small weight.
 */
export function estimatePulse(samples: readonly ColorSample[]): { snr: number; bpm: number | null } {
  if (samples.length < 60) return { snr: 0, bpm: null };
  const t = samples.map((s) => (s.t - samples[0].t) / 1000);
  const duration = t[t.length - 1];
  if (duration < 4) return { snr: 0, bpm: null };

  const mean = (k: "r" | "g" | "b") => samples.reduce((a, s) => a + s[k], 0) / samples.length;
  const mr = mean("r") || 1, mg = mean("g") || 1, mb = mean("b") || 1;
  const xs = detrend(samples.map((s) => 3 * (s.r / mr) - 2 * (s.g / mg)), t);
  const ys = detrend(samples.map((s) => 1.5 * (s.r / mr) + s.g / mg - 1.5 * (s.b / mb)), t);
  const sy = std(ys);
  const alpha = sy > 1e-9 ? std(xs) / sy : 0;
  const sig = detrend(xs.map((x, i) => x - alpha * ys[i]), t);

  const freqs: number[] = [];
  const power: number[] = [];
  for (let f = 0.75; f <= 3.0001; f += 0.025) {
    let re = 0, im = 0;
    for (let i = 0; i < sig.length; i++) {
      const w = 0.5 - 0.5 * Math.cos((2 * Math.PI * t[i]) / duration);
      re += sig[i] * w * Math.cos(2 * Math.PI * f * t[i]);
      im -= sig[i] * w * Math.sin(2 * Math.PI * f * t[i]);
    }
    freqs.push(f);
    power.push(re * re + im * im);
  }
  let peak = 0;
  for (let i = 1; i < power.length; i++) if (power[i] > power[peak]) peak = i;
  const rest = power.filter((_, i) => Math.abs(freqs[i] - freqs[peak]) > 0.2);
  const restMean = rest.reduce((a, b) => a + b, 0) / Math.max(1, rest.length);
  return {
    snr: restMean > 0 ? round(power[peak] / restMean, 3) : 0,
    bpm: round(freqs[peak] * 60, 1),
  };
}

/* ------------------------------------------------------------------ */
/* Photometric (screen-flash) challenge                                */
/* ------------------------------------------------------------------ */

const EMITTED: Record<FlashColor, [number, number, number]> = {
  RED: [1, 0, 0],
  GREEN: [0, 1, 0],
  BLUE: [0, 0, 1],
};

/**
 * Correlates the colours flashed on screen with the colour shifts measured on
 * the face. A real face lit by the screen follows the random sequence; a
 * replayed video or injected stream recorded earlier cannot.
 */
export function analysePhotometric(
  steps: readonly PhotometricStep[],
  minAmplitude: number,
): { correlation: number; amplitude: number; conclusive: boolean } {
  const valid = steps.filter((s) => s.frames >= 2);
  if (valid.length < 4) return { correlation: 0, amplitude: 0, conclusive: false };

  const centre = (rows: [number, number, number][]) => {
    const m = [0, 1, 2].map((c) => rows.reduce((a, r) => a + r[c], 0) / rows.length);
    return rows.flatMap((r) => r.map((v, c) => v - m[c]));
  };
  const e = centre(valid.map((s) => EMITTED[s.color]));
  const m = centre(valid.map((s) => s.chroma));

  const amplitude = Math.sqrt(m.reduce((a, v) => a + v * v, 0) / m.length);
  const se = Math.sqrt(e.reduce((a, v) => a + v * v, 0));
  const sm = Math.sqrt(m.reduce((a, v) => a + v * v, 0));
  const correlation = se > 0 && sm > 0 ? e.reduce((a, v, i) => a + v * m[i], 0) / (se * sm) : 0;

  return {
    correlation: round(correlation, 4),
    amplitude: round(amplitude, 5),
    conclusive: amplitude >= minAmplitude,
  };
}

/* ------------------------------------------------------------------ */
/* Injection heuristics                                                */
/* ------------------------------------------------------------------ */

const VIRTUAL_CAMERA_PATTERN =
  /virtual|obs|manycam|xsplit|snap camera|droidcam|iriun|epoccam|e2esoft|splitcam|camtwist|v4l2loopback|dummy|fake|unity video|vcam|deepfake|avatarify|nvidia broadcast/i;

export function isVirtualCameraLabel(label: string): boolean {
  return VIRTUAL_CAMERA_PATTERN.test(label);
}

/* ------------------------------------------------------------------ */
/* Decision                                                            */
/* ------------------------------------------------------------------ */

export function decidePad(input: PadInput, config: LivenessConfig = DEFAULT_CONFIG): PadResult {
  const { passive: p, photometric: ph, injection: inj, challenges, plannedChallenges } = input;
  const pad = config.pad;
  const total = plannedChallenges.length;
  const passed = challenges.filter((c) => c.status === "passed").length;
  const allPassed = total > 0 && passed === total;

  const depths = challenges
    .filter((c) => c.status === "passed" && c.depthResidual !== null)
    .map((c) => c.depthResidual as number);
  const depthMeasured = depths.length > 0;
  // Every head turn must look 3D, so one flat turn cannot hide behind a real one.
  const depthResidual = depthMeasured ? Math.min(...depths) : 0;

  const subscores: PadSubscores = {
    challenge: total === 0 ? 0 : passed / total,
    depth: depthMeasured ? ramp(depthResidual, ...pad.depthRange) : 0,
    photometric: ph.conclusive ? ramp(ph.correlation, ...pad.photometricRange) : 0.5,
    motion: Math.max(ramp(p.meanNonRigidMotion, ...pad.nonRigidRange), p.spontaneousBlinks > 0 ? 1 : 0),
    injection: inj.virtualCameraSuspected ? 0 : 1 - ramp(inj.duplicateFrameRatio, ...pad.duplicateRange),
    pulse: ramp(p.pulseSnr, ...pad.pulseSnrRange),
    moire: 1 - ramp(p.meanMoirePeakiness, ...pad.moireRange),
    texture: ramp(p.meanSharpness, ...pad.sharpnessRange),
    specular: 1 - ramp(p.meanSpecularRatio, ...pad.specularRange),
  };

  let weighted = 0;
  let weightSum = 0;
  for (const key of Object.keys(subscores) as PadSignal[]) {
    subscores[key] = round(subscores[key], 3);
    weighted += subscores[key] * pad.weights[key];
    weightSum += pad.weights[key];
  }
  const score = round(weightSum > 0 ? weighted / weightSum : 0, 4);

  const suspected = new Set<PaiSpecies>();
  const reasons: string[] = [];
  const multiRatio = p.framesAnalyzed > 0 ? p.multiFaceFrames / p.framesAnalyzed : 0;

  if (!allPassed) reasons.push(`Active challenges: ${passed}/${total} passed`);

  const planar = depthMeasured && subscores.depth < 0.25;
  if (planar) {
    suspected.add("PRINT");
    reasons.push("Face moved like a flat surface during the head turn (print, cut-out or screen)");
  }
  const noReflection = ph.conclusive && ph.correlation < config.photometric.failCorrelation;
  if (noReflection) {
    suspected.add("REPLAY_SCREEN");
    suspected.add("INJECTED_STREAM");
    reasons.push("Face did not reflect the random screen-flash colour sequence");
  }
  if (!ph.conclusive) {
    reasons.push("Screen-flash reflection too weak to judge — raise screen brightness or dim the room");
  }
  if (inj.virtualCameraSuspected) {
    suspected.add("INJECTED_STREAM");
    reasons.push(`Camera "${inj.cameraLabel}" looks like a virtual camera`);
  } else if (subscores.injection < 0.4) {
    suspected.add("INJECTED_STREAM");
    reasons.push(`${(inj.duplicateFrameRatio * 100).toFixed(0)}% of frames were exact duplicates`);
  }
  if (subscores.moire < 0.3) {
    suspected.add("REPLAY_SCREEN");
    reasons.push("Periodic moiré pattern detected on the face");
  }
  if (subscores.specular < 0.4) {
    suspected.add("REPLAY_SCREEN");
    reasons.push("Elevated specular glare (consistent with a display screen)");
  }
  if (subscores.motion < 0.25) {
    suspected.add("STATIC_IMAGE");
    reasons.push("Negligible natural facial motion and no spontaneous blink");
  }
  if (depthMeasured && !planar && subscores.pulse < 0.2 && subscores.motion < 0.5) {
    suspected.add("MASK");
    reasons.push("3D face with no pulse signal and little natural motion (consistent with a mask)");
  }
  if (multiRatio > config.maxMultiFaceRatio) {
    suspected.add("MULTIPLE_SUBJECTS");
    reasons.push(`Multiple faces in ${(multiRatio * 100).toFixed(1)}% of frames`);
  }
  if (p.faceDiscontinuities > 0) {
    suspected.add("SUBJECT_SWAP");
    reasons.push(`${p.faceDiscontinuities} abrupt face discontinuity event(s)`);
  }

  const hardAttack = planar || noReflection || inj.virtualCameraSuspected;
  let decision: PadResult["decision"];
  if (score < pad.attackThreshold || hardAttack || (!allPassed && suspected.size > 0)) {
    decision = "ATTACK";
    if (suspected.size === 0) suspected.add("UNKNOWN");
  } else if (allPassed && depthMeasured && ph.conclusive && suspected.size === 0 && score >= pad.bonaFideThreshold) {
    decision = "BONA_FIDE";
    reasons.push("All challenges passed; depth, screen-flash and passive signals within bona fide range");
  } else {
    decision = "INCONCLUSIVE";
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
