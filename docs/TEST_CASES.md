# FaceGuard Test Cases and Results

Testing has two parts:

1. **Automated tests:** 36 tests covering the detection algorithms, the decision logic, the audit trail and server verification, using synthetic data. Run with `npm test`.
2. **Manual tests:** end-to-end tests in the browser with a real webcam and real attack artefacts (printed photos, phone replays, virtual cameras).

Test data is described in [TEST_DATA.md](TEST_DATA.md).

---

## 1. Automated tests

**Run:** `npm test`
**Files:** `tests/padCore.test.ts`, `tests/verifyReport.test.ts`, fixtures in `tests/fixtures.ts`
**Last run:** 26 October 2026 · Node.js 22.23.4 · tsx 4.23.12
**Result:** ✅ **36 passed, 0 failed** (stable across 10 consecutive runs)

### 1.1 Session plan

| ID | Test case | Expected result | Result |
|---|---|---|---|
| TC-01 | Generate 2,000 session plans | Every plan has 3 distinct challenges including at least one head turn | ✅ Pass |
| TC-02 | Generate 2,000 flash sequences | 5 steps, all 3 colours used, no colour repeated back to back | ✅ Pass |

### 1.2 Detection algorithms

| ID | Test case | Expected result | Result |
|---|---|---|---|
| TC-03 | 3D face model turns 20° (2 px noise) | Depth residual > 0.025 (not flat) | ✅ Pass |
| TC-04 | Flat photo turns 20° at 45 cm and 30 cm (2 px noise) | Depth residual < 0.01 (flat) | ✅ Pass |
| TC-05 | Face reflects the flashed colour sequence | Conclusive, correlation > 0.9 | ✅ Pass |
| TC-06 | Replay: strong colour changes unrelated to the flashes | Conclusive, correlation < 0.4 | ✅ Pass |
| TC-07 | Only 2 of 5 flash steps have usable frames | Inconclusive | ✅ Pass |
| TC-08 | Pulse signal at 72 bpm, 200 noise seeds | Rate detected as 72 bpm; 90% of trials score ≥ 0.8 | ✅ Pass |
| TC-09 | Noise with no pulse, 200 noise seeds | Median score 0; 90% of trials score ≤ 0.3 | ✅ Pass |
| TC-10 | Moiré stripes vs skin-like texture | Stripes > 20, skin < 8 | ✅ Pass |
| TC-11 | Camera names | OBS, ManyCam, XSplit, Snap Camera flagged; built-in and Logitech webcams not flagged | ✅ Pass |

### 1.3 Decision logic (attack scenarios)

| ID | Scenario | Expected decision | Result |
|---|---|---|---|
| TC-12 | Genuine user, all signals normal | BONA_FIDE, no suspected attack | ✅ Pass |
| TC-13 | Cut-out print: flat motion on head turn | ATTACK · PRINT | ✅ Pass |
| TC-13b | Two head turns, one 3D and one flat | ATTACK · PRINT (every turn must be 3D) | ✅ Pass |
| TC-14 | Video replay: no reaction to flash | ATTACK · REPLAY_SCREEN | ✅ Pass |
| TC-15 | Virtual camera (OBS) | ATTACK · INJECTED_STREAM | ✅ Pass |
| TC-16 | Mask: 3D face, no pulse, rigid | Not BONA_FIDE · MASK | ✅ Pass |
| TC-17 | Phone replay: moiré and glare | Not BONA_FIDE · REPLAY_SCREEN | ✅ Pass |
| TC-18 | Bright room: flash reflection too weak | INCONCLUSIVE (retry), not ATTACK | ✅ Pass |
| TC-19 | Second person in 20% of frames | Not BONA_FIDE · MULTIPLE_SUBJECTS | ✅ Pass |
| TC-20 | Face swapped mid-session | Not BONA_FIDE · SUBJECT_SWAP | ✅ Pass |
| TC-21 | Static photo fails the head turn | ATTACK | ✅ Pass |

### 1.4 Audit trail

| ID | Test case | Expected result | Result |
|---|---|---|---|
| TC-22 | Hash the same object with keys in different orders | Identical canonical JSON | ✅ Pass |
| TC-23 | Verify an untouched 5-event chain | Valid, 5 events checked | ✅ Pass |
| TC-24 | Edit the message of event #2 | Invalid, broken at #2 | ✅ Pass |
| TC-25 | Delete an event | Invalid | ✅ Pass |

### 1.5 Server verification

| ID | Test case | Expected result | Result |
|---|---|---|---|
| TC-26 | Submit a valid report | Verified; BONA_FIDE; attestation signature valid; image hash bound | ✅ Pass |
| TC-27 | Submit the same report twice | Second attempt rejected: Single use | ✅ Pass |
| TC-28 | Edit an audit event | Rejected: Audit hash chain | ✅ Pass |
| TC-29 | Corrupt the plan signature | Rejected: Plan signature | ✅ Pass |
| TC-30 | Client substitutes its own challenges | Rejected: Plan binding | ✅ Pass |
| TC-31 | Flash data inconsistent with claimed correlation | Rejected: Screen-flash recomputation | ✅ Pass |
| TC-32 | A challenge "completed" in 40 ms | Rejected: Human response times | ✅ Pass |
| TC-33 | Submit 1 hour after plan expiry | Rejected: Plan not expired | ✅ Pass |
| TC-34 | Client claims BONA_FIDE but head turns are flat | Server decides ATTACK; no image hash in attestation | ✅ Pass |
| TC-35 | Alter a signed token's payload | Signature check fails; public key is Ed25519 | ✅ Pass |

### 1.6 Issues found and fixed during testing

| Issue | Found by | Fix |
|---|---|---|
| Pure noise scored as a pulse in about 50% of trials (median SNR 3.9 vs old upper bound 4) | TC-09 | Pulse range raised to SNR 5–15; noise now scores 0 at the median |
| With two head turns, one 3D turn could hide a flat one | TC-34 | Decision now uses the lowest depth across all turns; regression test TC-13b added |
| Flat photos at close range gave a residual near real faces with an affine fit | Synthetic depth tests | Switched to a homography fit, which is exact for flat surfaces under perspective |

---

## 2. Manual end-to-end tests

**How to run:** `npm run dev`, open <http://localhost:3000>, screen brightness at maximum, user about an arm's length from the camera. Record the decision and the key values from the right-hand panel.

**Pass rule for attacks:** the result must never be BONA_FIDE. ATTACK and INCONCLUSIVE both count as blocked.

> Results below are **to be filled in by the team** after testing with real devices and artefacts.

### 2.1 Genuine users

| ID | Test case | Steps | Expected | Decision | Depth | Flash corr. | Pulse | Tester / date |
|---|---|---|---|---|---|---|---|---|
| M-01 | Genuine user, normal indoor light | Run 10 sessions | BONA_FIDE in most runs | _/10 BONA_FIDE | | | | |
| M-02 | Genuine user wearing glasses | Run 5 sessions | BONA_FIDE in most runs | _/5 | | | | |
| M-03 | Different users (skin tones, ages) | 3+ users × 3 sessions | BONA_FIDE in most runs | | | | | |
| M-04 | Dim room | Run 3 sessions | BONA_FIDE or "Too dark" guidance | | | | | |
| M-05 | Bright room / window behind | Run 3 sessions | INCONCLUSIVE with "flash too weak" reason is acceptable | | | | | |

### 2.2 Presentation attacks

| ID | Attack | Steps | Expected | Decision | PAI tags | Key evidence | Tester / date |
|---|---|---|---|---|---|---|---|
| M-06 | Printed photo | Hold an A4 print of a face to the camera | ATTACK or failed turn | | | Depth < 0.01 | |
| M-07 | Cut-out photo | Print with eye and mouth holes, tester's eyes behind | ATTACK · PRINT | | | Depth < 0.01 on turn | |
| M-08 | Phone video replay | Play a selfie video (with head turns) on a phone | ATTACK or INCONCLUSIVE | | | Flash corr. ≈ 0 | |
| M-09 | Laptop/tablet replay | Play the same video on a larger screen | ATTACK or INCONCLUSIVE | | | Flash corr., moiré | |
| M-10 | Photo on a phone screen | Show a still photo on a phone | ATTACK | | | Fails challenges | |
| M-11 | Virtual camera | OBS Virtual Camera with a photo or video; select it in browser camera settings | ATTACK · INJECTED_STREAM | | | INJECTION_SUSPECTED event | |
| M-12 | Second person | Second face in frame during the check | Not BONA_FIDE · MULTIPLE_SUBJECTS | | | | |
| M-13 | Face swap | Slide a photo in front of the face during challenges | Not BONA_FIDE · SUBJECT_SWAP | | | FACE_DISCONTINUITY event | |
| M-14 | Mask (if available) | Paper or 3D mask with eye holes | Not BONA_FIDE | | | Pulse, motion | |

### 2.3 Server and integrity

| ID | Test case | Steps | Expected | Result | Tester / date |
|---|---|---|---|---|---|
| M-15 | Server attestation | Complete a genuine session | Server attestation card: all checks ✓, signed | | |
| M-16 | Report replay | Export JSON, then `curl -X POST localhost:3000/api/verify -H "Content-Type: application/json" --data @<file>` | `"verified":false` (Single use or Plan not expired) | | |
| M-17 | Report tampering | Edit an event `message` in the exported file, resend | `"verified":false`, Audit hash chain ✗ | | |
| M-18 | Chain check in UI | Click **Verify chain** after a session | "Hash chain intact" | | |
| M-19 | Public key | `curl localhost:3000/api/session` | JWK with `crv: "Ed25519"` | | |

### 2.4 Robustness and edge cases

| ID | Test case | Steps | Expected | Result | Tester / date |
|---|---|---|---|---|---|
| M-20 | Camera permission denied | Block camera in browser | Clear message and **Retry camera** button | | |
| M-21 | Camera in use elsewhere | Open camera in another app first | "Camera is in use" message | | |
| M-22 | Abort mid-session | Click **Abort session** during challenges | SESSION_ABORTED logged, back to ready, no attestation | | |
| M-23 | Leave the frame | Walk away during passive phase | Returns to positioning, FACE_LOST logged | | |
| M-24 | Challenge timeout | Ignore a challenge for 7 s | Session ends, CHALLENGE_FAILED (TIMEOUT) | | |
| M-25 | Run again | Click **Run again** after a result | New session ID; log and results reset | | |
| M-26 | Offline model load | Disconnect internet before first load | Error message about loading the model | | |
| M-27 | Mobile browser over HTTPS | Open on a phone via HTTPS | Front camera works; flash fills the screen | | |

---

## 3. ISO/IEC 30107-3 metrics (to be computed from manual results)

| Metric | Definition | Formula | Value |
|---|---|---|---|
| APCER (per attack type) | Share of attack attempts wrongly accepted as BONA_FIDE | accepted attacks ÷ attack attempts | |
| BPCER | Share of genuine attempts not accepted | (ATTACK + INCONCLUSIVE genuine) ÷ genuine attempts | |

Report APCER separately for each attack type (print, cut-out, phone replay, screen replay, virtual camera, mask). These figures come from a small hackathon sample and are indicative only, not a certified evaluation.
