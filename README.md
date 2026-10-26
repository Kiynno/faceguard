# FaceGuard

Face **liveness detection** and **Presentation Attack Detection (PAD)** with server-side verification and an ISO/IEC 30107-aligned, hash-chained audit trail. Built for **MOSIP Decode 2026**.

FaceGuard checks that the face in front of the camera belongs to a live person physically present, not a printed photo, a screen replay, a mask or an injected video stream. The browser runs the checks; the server issues each session, re-verifies the result and signs an attestation that other systems (such as MOSIP onboarding) can trust.

> **Status: hackathon prototype.** Thresholds are uncalibrated starting points. See [Known limitations](#known-limitations).

---

## Attack coverage

| Attack / requirement | How FaceGuard handles it |
|---|---|
| **Active liveness** | Server-chosen sequence of 3 challenges (blink, smile, open mouth, turn left/right), always including at least one head turn. Each challenge only counts after the face returns to neutral. |
| **Micro-expressions** | Measures natural facial micro-motion and spontaneous blinks during a 5-second still window. |
| **Skin texture** | Face sharpness, plus moiré detection (frequency analysis) for recaptured screens. |
| **Lighting reflections** | **Screen-flash challenge:** the screen flashes a random red/green/blue sequence and the face must reflect it. Also measures glare. |
| **Print attacks** (incl. cut-outs) | **3D depth check:** during the head turn, landmarks are tested for flat-surface motion. A photo, cut-out print or screen moves like a plane; a real face doesn't. |
| **Video / replay attacks** | Screen-flash reflection (a recording can't react to colours chosen now), moiré, glare, random challenge order. |
| **3D masks** | Pulse detection from skin colour (rPPG) plus natural-motion checks. A 3D face with no pulse and little motion is flagged and never accepted. |
| **Deepfakes / injection** | Screen-flash reflection, virtual-camera detection (OBS, ManyCam etc.), duplicate-frame detection. |
| **Onboarding** | Captures the best frontal face crop for 1:1 matching and binds its SHA-256 into the signed attestation, so the image can't be swapped after the liveness check. |
| **Secure authentication** | The server issues a signed single-use plan, re-verifies every report, recomputes the decision itself and signs the result (Ed25519). |

## How a session works

1. **Plan:** the browser asks the server for a session. The server picks the challenges and flash sequence and signs them.
2. **Positioning:** one centred, well-lit, frontal face, held steady.
3. **Passive window (5 s):** micro-motion, blinks, pulse, moiré, sharpness and glare. The sharpest frontal frame is kept as the reference image.
4. **Screen flash (~3.5 s):** 5 random colour steps; the face colour is measured after each change.
5. **Challenges:** 3 actions, 7 s each. Head turns are checked for 3D motion. A failed challenge ends the session.
6. **Decision:** signals are combined into BONA_FIDE, ATTACK or INCONCLUSIVE.
7. **Server verification:** the report goes to the server, which checks it and returns a signed attestation.

### Decision rules

- **ATTACK:** score below 0.40, or any strong attack signal: flat motion during a head turn, no reaction to the screen flash, a virtual camera, or a failed challenge combined with any suspected attack.
- **BONA_FIDE:** all challenges passed, depth and screen-flash checks conclusive and passing, no suspected attack of any kind, and score at least 0.65.
- **INCONCLUSIVE:** anything else, including weak screen-flash reflection (bright room or dim screen). The user should retry.

### Score weights

| Signal | Weight | Signal | Weight |
|---|---|---|---|
| Active challenges | 0.30 | Pulse (rPPG) | 0.05 |
| 3D depth (head turn) | 0.15 | Moiré | 0.05 |
| Screen-flash reflection | 0.15 | Texture sharpness | 0.05 |
| Micro-motion / blink | 0.10 | Specular glare | 0.05 |
| Camera integrity | 0.10 | | |

All thresholds live in `DEFAULT_CONFIG` in `src/lib/padCore.ts`.

## Getting started

**Requirements:** Node.js 20.9 or newer and a webcam.

```bash
npm install
npm run dev
```

Open <http://localhost:3000>, allow camera access and click **Start liveness check**.

- The camera and Web Crypto APIs need `localhost` or HTTPS.
- The MediaPipe model loads from public CDNs on first use.
- For the screen-flash check, turn screen brightness up and avoid very bright rooms. The screen flashes red, green and blue at under 2 flashes per second; users with photosensitive epilepsy should be warned.

### Signing key

Without a key, the server generates a temporary one on each start (fine for a demo, but attestations stop verifying after a restart). For anything persistent:

```bash
openssl genpkey -algorithm ed25519 -out faceguard.pem
```

Put the PEM in `.env.local` as `FACEGUARD_ED25519_PRIVATE_KEY` (newlines may be written as `\n`). Never commit it; `.gitignore` already excludes `.env*` files.

| Script | What it does |
|---|---|
| `npm run dev` | Start the development server |
| `npm run build` | Production build |
| `npm start` | Serve the production build |
| `npm run typecheck` | Type-check with `tsc` |

## API

| Route | Method | Purpose |
|---|---|---|
| `/api/session` | `POST` | Issues a signed, single-use session plan (challenges + flash sequence, valid 3 minutes). |
| `/api/session` | `GET` | Returns the public key (JWK) for verifying attestations. |
| `/api/verify` | `POST` | Body `{ report }`. Verifies the report and returns `VerificationResponse` with a signed attestation. |

### What `/api/verify` checks

1. The plan carries this server's signature and has not expired.
2. Session ID, nonce, challenges and flash sequence match the signed plan.
3. The audit hash chain is intact and every event belongs to the session and its time window.
4. The session lasted a plausible time and every response was humanly possible (≥ 150 ms).
5. The screen-flash statistic is recomputed from the raw step data.
6. The decision is **recomputed with the server's own configuration**, not the client's.
7. The session has not been verified before (single use).

The attestation is a compact JWS (EdDSA) containing the session ID, server decision, score, suspected attack types, audit chain head, reference image hash (BONA_FIDE only) and a 5-minute expiry.

### MOSIP integration

Send the reference image and the attestation to the matcher together. The relying service should:

1. verify the attestation signature with the key from `GET /api/session`;
2. check `decision === "BONA_FIDE"` and that `exp` hasn't passed;
3. check that the image's SHA-256 equals `referenceImageSha256`;
4. then run 1:1 matching against the enrolled or document photo.

## Project structure

```
faceguard/
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── session/route.ts    # Issues signed session plans; serves the public key
│   │   │   └── verify/route.ts     # Verifies reports; returns signed attestations
│   │   ├── layout.tsx
│   │   ├── page.tsx                # Wires server plan → engine → verification → panel
│   │   └── globals.css
│   ├── components/
│   │   ├── WebcamCapture.tsx       # Camera, overlay, challenge prompt, screen-flash overlay
│   │   ├── AuditPanel.tsx          # Decision, attestation, reference capture, telemetry, log
│   │   └── Header.tsx
│   ├── lib/
│   │   ├── padCore.ts              # Shared pure logic: decision, depth, flash, pulse, moiré, plans
│   │   ├── livenessEngine.ts       # Browser engine: MediaPipe, measurements, state machine
│   │   └── server/
│   │       ├── attestation.ts      # Ed25519 signing, JWS, single-use sessions (server only)
│   │       └── verifyReport.ts     # Report verification logic
│   └── types/
│       └── index.ts
├── next.config.ts
├── postcss.config.mjs
├── tsconfig.json
└── package.json
```

## Audit trail

Every event is hashed with SHA-256 and linked to the previous one; the UI can re-verify the chain, and **Export JSON** downloads the report together with the server's verification.

**Event types:** `SESSION_START`, `ENGINE_READY`, `FACE_ACQUIRED`, `FACE_LOST`, `FACE_DISCONTINUITY`, `MULTIPLE_FACES`, `INJECTION_SUSPECTED`, `PASSIVE_COMPLETE`, `PHOTOMETRIC_COMPLETE`, `CHALLENGE_ISSUED`, `CHALLENGE_PASSED`, `CHALLENGE_FAILED`, `REFERENCE_CAPTURED`, `DECISION`, `SESSION_ABORTED`, `ERROR`.

## ISO/IEC 30107 alignment

FaceGuard uses ISO/IEC 30107-1 terminology and records what ISO/IEC 30107-3 testing needs. **A single session does not show conformance:** 30107-3 requires measuring APCER (attacks wrongly accepted, per attack type) and BPCER (genuine users wrongly rejected) across a labelled test set. Each report has an `evaluation` block for labelling sessions during a test campaign. Until that's done, describe FaceGuard as **"30107-aligned"**, not "30107 compliant".

## Known limitations

- **The server can't see the video.** It verifies the plan, timing, consistency and audit chain and recomputes the decision, but a determined attacker who rewrites the browser code could still submit fabricated measurements. Closing this fully means running the analysis server-side on uploaded frames, or a native app with device attestation.
- **Uncalibrated thresholds.** The depth check was tuned on synthetic geometry and every other range is a starting guess. Test with real prints, cut-outs, phone and laptop replays, masks and virtual cameras, then adjust `DEFAULT_CONFIG`.
- **Masks are only partly covered.** Webcam pulse detection is noisy, so a missing pulse leads to INCONCLUSIVE rather than ATTACK. Strong mask defence needs a trained PAD model or depth/infrared hardware.
- **Live face-swap deepfakes** applied to the attacker's real camera may carry the screen-flash reflection through. The flash check mainly stops pre-recorded and synthetic streams.
- **Single-instance server state.** Used sessions are tracked in memory; use a shared store such as Redis when running more than one server.
- **No face matching.** FaceGuard produces the bound reference image; matching is MOSIP's job.
- **MediaPipe version pin:** `@mediapipe/tasks-vision` in `package.json` must match `MEDIAPIPE_VERSION` in `livenessEngine.ts`.

## Roadmap

1. Server-side analysis of uploaded frames for high-assurance flows.
2. A trained passive PAD model (e.g. MiniFASNet) via ONNX Runtime Web.
3. Calibration campaign and APCER/BPCER report per ISO/IEC 30107-3.
4. Shared session store and key rotation.

## Privacy

- Frames are processed on-device and never uploaded.
- The only image produced is one face crop for a BONA_FIDE result, kept in memory and handed to the host page for matching. The audit report stores only its hash.
- Audit reports contain derived numbers, challenge outcomes and device details only.

## License

Add a license before publishing.
