/**
 * Unit tests for the shared PAD logic (src/lib/padCore.ts).
 * Test IDs (TC-xx) match docs/TEST_CASES.md.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  DEFAULT_CONFIG,
  analysePhotometric,
  buildSessionPlan,
  canonicalJson,
  decidePad,
  estimatePulse,
  isVirtualCameraLabel,
  moirePeakiness,
  planarResidual,
  ramp,
  sha256Hex,
  verifyAuditChain,
} from "@/lib/padCore";
import type { AuditEvent, ChallengeType, PadInput } from "@/types";
import {
  FACE_IOD_PX,
  LIVE_PASSIVE,
  REAL_CAMERA,
  challengeResult,
  liveFlashSteps,
  photometricFrom,
  projectFace,
  replayFlashSteps,
  seededRandom,
} from "./fixtures";

const SEQUENCE = ["RED", "GREEN", "BLUE", "RED", "GREEN"] as const;
const PLANNED: ChallengeType[] = ["TURN_LEFT", "BLINK", "SMILE"];

function liveInput(overrides: Partial<PadInput> = {}): PadInput {
  return {
    plannedChallenges: PLANNED,
    challenges: PLANNED.map((t) => challengeResult(t)),
    passive: LIVE_PASSIVE,
    photometric: photometricFrom(liveFlashSteps([...SEQUENCE]), [...SEQUENCE]),
    injection: REAL_CAMERA,
    ...overrides,
  };
}

describe("Session plan", () => {
  test("TC-01 every plan has 3 distinct challenges including a head turn", () => {
    for (let i = 0; i < 2000; i++) {
      const plan = buildSessionPlan("s", "n");
      assert.equal(new Set(plan.challenges).size, 3);
      assert.ok(plan.challenges.some((c) => c === "TURN_LEFT" || c === "TURN_RIGHT"));
    }
  });

  test("TC-02 flash sequence uses all colours with no colour repeated back to back", () => {
    for (let i = 0; i < 2000; i++) {
      const { flashSequence } = buildSessionPlan("s", "n");
      assert.equal(flashSequence.length, 5);
      for (const c of ["RED", "GREEN", "BLUE"] as const) assert.ok(flashSequence.includes(c));
      flashSequence.forEach((c, j) => j > 0 && assert.notEqual(c, flashSequence[j - 1]));
    }
  });
});

describe("3D depth check", () => {
  test("TC-03 a real 3D face turning 20° is not planar", () => {
    const r = planarResidual(projectFace(0, false), projectFace(20, false, 2), FACE_IOD_PX);
    assert.ok(r > 0.025, `residual ${r}`);
  });

  test("TC-04 a flat photo turning 20° is planar, even at close range", () => {
    for (const distance of [45, 30]) {
      const r = planarResidual(projectFace(0, true, 0, distance), projectFace(20, true, 2, distance), FACE_IOD_PX);
      assert.ok(r < 0.01, `residual ${r} at ${distance} cm`);
    }
  });
});

describe("Screen-flash check", () => {
  test("TC-05 a live face follows the flashed colours", () => {
    const r = analysePhotometric(liveFlashSteps([...SEQUENCE]), 0.003);
    assert.ok(r.conclusive);
    assert.ok(r.correlation > 0.9, `correlation ${r.correlation}`);
  });

  test("TC-06 a replay with strong colour changes is conclusive but uncorrelated", () => {
    const r = analysePhotometric(replayFlashSteps([...SEQUENCE], 0.03), 0.003);
    assert.ok(r.conclusive);
    assert.ok(r.correlation < 0.4, `correlation ${r.correlation}`);
  });

  test("TC-07 too few usable steps is inconclusive", () => {
    const steps = liveFlashSteps([...SEQUENCE]).map((s, i) => ({ ...s, frames: i < 2 ? 10 : 0 }));
    assert.equal(analysePhotometric(steps, 0.003).conclusive, false);
  });
});

describe("Pulse, moiré and camera checks", () => {
  const signal = (amp: number, seed: number) => {
    const noise = seededRandom(seed);
    return Array.from({ length: 150 }, (_, i) => {
      const t = i * 33.3;
      const p = amp * Math.sin((2 * Math.PI * 1.2 * t) / 1000);
      return { t, r: 150 + 0.4 * p + (noise() - 0.5) * 0.6, g: 110 + p + (noise() - 0.5) * 0.6, b: 90 + 0.2 * p + (noise() - 0.5) * 0.6 };
    });
  };
  const [lo, hi] = DEFAULT_CONFIG.pad.pulseSnrRange;
  const pulseScores = (amp: number) =>
    Array.from({ length: 200 }, (_, k) => ramp(estimatePulse(signal(amp, k + 1)).snr, lo, hi)).sort((a, b) => a - b);

  test("TC-08 a 72 bpm pulse is detected at the right rate and scores high", () => {
    assert.equal(estimatePulse(signal(0.3, 1)).bpm, 72);
    const scores = pulseScores(0.3);
    assert.ok(scores[20] >= 0.8, `10th percentile score ${scores[20]}`);
  });

  test("TC-09 noise without a pulse scores low in at least 90% of trials", () => {
    const scores = pulseScores(0);
    assert.ok(scores[100] === 0, `median score ${scores[100]}`);
    assert.ok(scores[180] <= 0.3, `90th percentile score ${scores[180]}`);
  });

  test("TC-10 moiré stripes score far higher than skin-like noise", () => {
    const noise = seededRandom(4);
    const n = 64;
    const skin = Array.from({ length: n * n }, () => 120 + (noise() - 0.5) * 20);
    const stripes = skin.map((v, i) => v + 15 * Math.sin(2 * Math.PI * ((i % n) * 0.37 + Math.floor(i / n) * 0.11)));
    assert.ok(moirePeakiness(skin, n) < 8);
    assert.ok(moirePeakiness(stripes, n) > 20);
  });

  test("TC-11 virtual camera names are flagged, real webcams are not", () => {
    for (const label of ["OBS Virtual Camera", "ManyCam Virtual Webcam", "XSplit VCam", "Snap Camera"]) {
      assert.ok(isVirtualCameraLabel(label), label);
    }
    for (const label of ["Integrated Webcam", "FaceTime HD Camera", "Logitech C920"]) {
      assert.equal(isVirtualCameraLabel(label), false, label);
    }
  });
});

describe("PAD decision", () => {
  test("TC-12 genuine user is BONA_FIDE", () => {
    const r = decidePad(liveInput());
    assert.equal(r.decision, "BONA_FIDE");
    assert.deepEqual(r.suspectedPai, []);
  });

  test("TC-13 cut-out print (flat head turn) is ATTACK / PRINT", () => {
    const r = decidePad(liveInput({ challenges: PLANNED.map((t) => challengeResult(t, t === "TURN_LEFT" ? { depth: 0.005 } : {})) }));
    assert.equal(r.decision, "ATTACK");
    assert.ok(r.suspectedPai.includes("PRINT"));
  });

  test("TC-13b one flat turn is caught even when a second turn looks 3D", () => {
    const planned: ChallengeType[] = ["TURN_LEFT", "TURN_RIGHT", "BLINK"];
    const r = decidePad(
      liveInput({
        plannedChallenges: planned,
        challenges: [challengeResult("TURN_LEFT", { depth: 0.03 }), challengeResult("TURN_RIGHT", { depth: 0.004 }), challengeResult("BLINK")],
      }),
    );
    assert.equal(r.decision, "ATTACK");
    assert.ok(r.suspectedPai.includes("PRINT"));
  });

  test("TC-14 video replay (no flash response) is ATTACK / REPLAY_SCREEN", () => {
    const steps = replayFlashSteps([...SEQUENCE], 0.03);
    const r = decidePad(liveInput({ photometric: { ...photometricFrom(steps, [...SEQUENCE]), correlation: -0.05 } }));
    assert.equal(r.decision, "ATTACK");
    assert.ok(r.suspectedPai.includes("REPLAY_SCREEN"));
  });

  test("TC-15 virtual camera is ATTACK / INJECTED_STREAM", () => {
    const r = decidePad(liveInput({ injection: { ...REAL_CAMERA, cameraLabel: "OBS Virtual Camera", virtualCameraSuspected: true } }));
    assert.equal(r.decision, "ATTACK");
    assert.ok(r.suspectedPai.includes("INJECTED_STREAM"));
  });

  test("TC-16 mask (3D, no pulse, rigid) is never BONA_FIDE", () => {
    const r = decidePad(liveInput({ passive: { ...LIVE_PASSIVE, pulseSnr: 1, meanNonRigidMotion: 0.0015, spontaneousBlinks: 0 } }));
    assert.notEqual(r.decision, "BONA_FIDE");
    assert.ok(r.suspectedPai.includes("MASK"));
  });

  test("TC-17 phone replay with moiré and glare is never BONA_FIDE", () => {
    const r = decidePad(liveInput({ passive: { ...LIVE_PASSIVE, meanMoirePeakiness: 30, meanSpecularRatio: 0.12 } }));
    assert.notEqual(r.decision, "BONA_FIDE");
    assert.ok(r.suspectedPai.includes("REPLAY_SCREEN"));
  });

  test("TC-18 weak flash reflection (bright room) is INCONCLUSIVE, not ATTACK", () => {
    const ph = { ...photometricFrom(liveFlashSteps([...SEQUENCE]), [...SEQUENCE]), conclusive: false };
    assert.equal(decidePad(liveInput({ photometric: ph })).decision, "INCONCLUSIVE");
  });

  test("TC-19 second person in frame is never BONA_FIDE", () => {
    const r = decidePad(liveInput({ passive: { ...LIVE_PASSIVE, multiFaceFrames: 60 } }));
    assert.notEqual(r.decision, "BONA_FIDE");
    assert.ok(r.suspectedPai.includes("MULTIPLE_SUBJECTS"));
  });

  test("TC-20 face swap during the session is never BONA_FIDE", () => {
    const r = decidePad(liveInput({ passive: { ...LIVE_PASSIVE, faceDiscontinuities: 1 } }));
    assert.notEqual(r.decision, "BONA_FIDE");
    assert.ok(r.suspectedPai.includes("SUBJECT_SWAP"));
  });

  test("TC-21 static photo that fails the challenge is ATTACK", () => {
    const r = decidePad(
      liveInput({
        challenges: [challengeResult("TURN_LEFT", { status: "failed" })],
        passive: { ...LIVE_PASSIVE, meanNonRigidMotion: 0.0005, spontaneousBlinks: 0 },
      }),
    );
    assert.equal(r.decision, "ATTACK");
  });
});

describe("Audit trail", () => {
  async function chain(n: number): Promise<AuditEvent[]> {
    const events: AuditEvent[] = [];
    let prev = "0".repeat(64);
    for (let i = 0; i < n; i++) {
      const u = { seq: i, timestamp: new Date().toISOString(), sessionId: "s", type: "SESSION_START" as const, severity: "info" as const, message: `m${i}`, data: { b: 1, a: [i] }, prevHash: prev };
      const hash = await sha256Hex(canonicalJson(u));
      events.push({ ...u, hash });
      prev = hash;
    }
    return events;
  }

  test("TC-22 canonical JSON is independent of key order", () => {
    assert.equal(canonicalJson({ b: 1, a: { d: 2, c: [3] } }), canonicalJson({ a: { c: [3], d: 2 }, b: 1 }));
  });

  test("TC-23 an intact chain verifies", async () => {
    assert.deepEqual(await verifyAuditChain(await chain(5)), { valid: true, checked: 5, brokenAt: null });
  });

  test("TC-24 an edited event is detected at its position", async () => {
    const events = await chain(5);
    events[2] = { ...events[2], message: "tampered" };
    const r = await verifyAuditChain(events);
    assert.equal(r.valid, false);
    assert.equal(r.brokenAt, 2);
  });

  test("TC-25 a deleted event is detected", async () => {
    const events = await chain(5);
    events.splice(1, 1);
    assert.equal((await verifyAuditChain(events)).valid, false);
  });
});
