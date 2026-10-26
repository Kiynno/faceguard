# FaceGuard Test Data

## Accounts and credentials

FaceGuard has **no user accounts, logins or passwords**, so no credentials are needed to evaluate it. Anyone who opens the app can run a liveness check.

| Item | Value |
|---|---|
| App URL (local) | <http://localhost:3000> |
| Signing key | Not required. If `FACEGUARD_ED25519_PRIVATE_KEY` is unset, the server generates a temporary key on start. |
| Camera | Any webcam; allow access when the browser asks |

To test with a fixed signing key, generate one locally (never commit it):

```bash
openssl genpkey -algorithm ed25519 -out faceguard.pem
```

---

## 1. Synthetic data for automated tests

All automated test data is generated in code (`tests/fixtures.ts`) with fixed random seeds, so every run is reproducible. No real face images or biometric data are used.

### 1.1 Synthetic 3D face (depth check)

| Property | Value |
|---|---|
| Points | 40 points spread over a 14 cm × 18 cm face |
| Depth | Nose bump up to 3 cm, curved cheeks |
| Camera | Focal length 60, subject at 45 cm (and 30 cm for close-range tests) |
| Turns tested | 20° yaw |
| Noise | ±1 px uniform (2 px range) |
| Flat photo | Same points with depth set to 0 |

| Case | Expected depth residual (× inter-ocular distance) |
|---|---|
| Real face, 20° turn | > 0.025 |
| Flat photo, 20° turn, 45 cm or 30 cm | < 0.01 |

### 1.2 Screen-flash steps

| Case | Data |
|---|---|
| Base face colour (chromaticity r, g, b) | 0.45, 0.33, 0.22 |
| Live face | +0.008 on the flashed colour channel, −0.004 on the others, ±0.001 noise |
| Replay | Random shifts of ±0.015 unrelated to the flashed colour |
| Sequence used | RED, GREEN, BLUE, RED, GREEN |

### 1.3 Pulse signal

| Case | Data |
|---|---|
| Duration / rate | 150 samples at 30 fps (5 s) |
| Base colour (R, G, B) | 150, 110, 90 |
| Pulse | 1.2 Hz (72 bpm) sine; amplitude 0.3 on green, 0.4× on red, 0.2× on blue |
| Noise | ±0.3 per channel, 200 different seeds |
| No-pulse case | Same noise, amplitude 0 |

### 1.4 Moiré

| Case | Data |
|---|---|
| Skin-like texture | 64 × 64 grey levels, 120 ± 10 random |
| Moiré | Same texture plus a diagonal stripe pattern of amplitude 15 |

### 1.5 Passive signals and camera (genuine baseline)

| Field | Value |
|---|---|
| Frames analysed | 300 |
| Mean sharpness | 70 |
| Mean glare (specular ratio) | 0.01 |
| Mean micro-motion | 0.004 |
| Moiré peakiness | 5 |
| Pulse SNR / rate | 20 / 72 bpm |
| Spontaneous blinks | 1 |
| Multi-face frames / face discontinuities | 0 / 0 |
| Camera label | "Integrated Webcam" |

Attack scenarios change one or more of these values; see [TEST_CASES.md](TEST_CASES.md), section 1.3.

### 1.6 Camera names

| Expected: flagged as virtual | Expected: real camera |
|---|---|
| OBS Virtual Camera | Integrated Webcam |
| ManyCam Virtual Webcam | FaceTime HD Camera |
| XSplit VCam | Logitech C920 |
| Snap Camera | |

### 1.7 Signed reports

`buildSignedReport()` creates a complete, valid report exactly as the browser would submit it: a fresh server-signed plan, live flash data, passed challenges (head turns with depth 0.03), the genuine baseline above, and a 3-event hash chain. Server tests then alter one part of it at a time (see TEST_CASES.md, section 1.5).

---

## 2. Artefacts for manual attack testing

The team prepares these physical and digital artefacts. Use only photos and videos of team members who have agreed to it.

| ID | Artefact | How to prepare | Used in |
|---|---|---|---|
| A-01 | Printed photo | Front-facing photo of a team member, printed on A4, colour | M-06 |
| A-02 | Cut-out photo | Copy of A-01 with eye and mouth holes cut out | M-07 |
| A-03 | Selfie video | 15–20 s phone video of a team member looking at the camera, blinking, smiling and turning left and right | M-08, M-09 |
| A-04 | Still photo on screen | A-01's photo displayed full-screen on a phone | M-10 |
| A-05 | Virtual camera | OBS Studio → Sources: A-01 photo or A-03 video → **Start Virtual Camera**; in the browser's camera settings for localhost, choose "OBS Virtual Camera" | M-11 |
| A-06 | Mask (optional) | Paper mask made from A-01, or any available 3D mask, with eye holes | M-14 |

---

## 3. Sample API data

### 3.1 Request a session plan

```bash
curl -X POST http://localhost:3000/api/session
```

### 3.2 Get the public key

```bash
curl http://localhost:3000/api/session
```

### 3.3 Resubmit an exported report

After a session, click **Export JSON** in the audit panel. The file (`faceguard-audit-<sessionId>.json`) contains `{ report, serverVerification }` and can be sent directly to the verify endpoint:

```bash
curl -X POST http://localhost:3000/api/verify \
  -H "Content-Type: application/json" \
  --data @faceguard-audit-<sessionId>.json
```

Expected result: rejected (`"verified": false`) because the session was already verified when it completed.

### 3.4 Tampered report

Open an exported file, change any event's `"message"` text, save it and resubmit as above. Expected: `"verified": false` with the **Audit hash chain** check failed.

See [API.md](API.md) for full request and response formats.
