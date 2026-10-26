# Submission Details

| Team Name | Problem Statement |
| --------- | ----------------- |
| The GOAT  | Face Liveness Detection and Presentation Attack Detection for Registration and Biometric Authentication |

--- 

## Submission Materials

| Item | Link |
|---|---|
| Pitch deck | [Google Drive](https://drive.google.com/drive/folders/1XBJKaGMNHPnxNfJUa6l2kE52_T8waVnU?usp=sharing) |

# FaceGuard

FaceGuard is a web-based **face liveness detection** and **Presentation Attack Detection (PAD)** system built for **MOSIP Decode 2026**. It checks that the face in front of the camera belongs to a live person who is physically present, and not a printed photo, a screen replay, a mask or an injected video stream, before a registration or authentication is allowed to proceed.

The browser runs the checks; the server issues each session, re-verifies the result and signs an attestation that other systems, such as MOSIP onboarding and authentication, can trust. Every session produces a tamper-evident audit trail aligned with ISO/IEC 30107.

## Documentation

| Document | Contents |
|---|---|
| [Installation and usage](#installation-and-usage) | Setup and running the prototype (below) |
| [docs/API.md](docs/API.md) | Endpoints, request/response formats, authentication, examples |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture, data flow and sequence diagrams |
| [docs/TEST_CASES.md](docs/TEST_CASES.md) | Automated and manual test cases with results |
| [docs/TEST_DATA.md](docs/TEST_DATA.md) | Test data, fixtures and attack artefacts |

## Problem

Face biometrics are increasingly used to register people and authenticate them, but a camera alone can't tell a real person from a photo, a video on a phone, a mask or a manipulated video stream. Without Presentation Attack Detection, anyone with a picture of a victim could register or log in as them.

## Solution

FaceGuard combines several independent checks, so defeating one isn't enough:

| Attack | How FaceGuard detects it |
|---|---|
| **Printed photo / cut-out** | **3D depth check:** during a head turn, a photo moves like a flat sheet; a real face doesn't. |
| **Video replay on a screen** | **Screen-flash check:** the screen flashes a random colour sequence and the face must reflect it. Also moiré and glare detection. |
| **3D mask** | **Pulse detection (rPPG)** and natural micro-motion; a 3D face with no pulse and little motion is never accepted. |
| **Deepfake / injected stream** | Screen-flash check, virtual-camera detection (OBS, ManyCam etc.) and duplicate-frame detection. |
| **Tampering with the result** | The server issues a **signed, single-use session plan**, re-checks the report, recalculates the decision itself and signs the result (Ed25519). |

Active liveness challenges (blink, smile, open mouth, turn left/right) are chosen by the server for each session and always include at least one head turn.

For a successful check, FaceGuard also captures the best front-facing photo for 1:1 matching and binds its SHA-256 hash into the signed attestation, so the photo can't be swapped after the liveness check.

## Technology stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 16 (App Router), React 19, TypeScript (strict), Tailwind CSS 4 |
| Face tracking | MediaPipe Face Landmarker (478 landmarks, 52 expression scores), running in the browser |
| Server | Next.js route handlers on Node.js |
| Cryptography | Ed25519 signatures (compact JWS), SHA-256 hash chain, Web Crypto API |
| Testing | Node.js test runner with `tsx` |

## Installation and usage

### Requirements

- Node.js **20.9 or newer** and npm
- A webcam
- A modern browser (Chrome, Edge or Firefox)
- Internet access on first run (the face model loads from a CDN)

### Install and run

```bash
git clone https://github.com/jfajarillo/faceguard.git
cd faceguard
npm install
npm run dev
```

Open <http://localhost:3000>, allow camera access and click **Start liveness check**.

The camera and Web Crypto APIs only work on `localhost` or over HTTPS. To test on another device, serve the app over HTTPS.

### Running a liveness check

1. **Position** your face inside the oval until the ring fills.
2. **Hold still** for 5 seconds while passive checks run.
3. **Keep looking at the screen** while it flashes red, green and blue (about 3.5 seconds).
4. **Follow the prompts** for 3 actions, such as "turn your head to your left". Return to a neutral face before each one.
5. **Read the result** in the right-hand panel: the decision, each check's score, and the server's verification.

For best results, turn screen brightness up, sit about an arm's length from the camera, and avoid a bright window behind or beside you.

> **Photosensitivity warning:** the screen flashes saturated colours at under 2 flashes per second.

### Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Start the development server |
| `npm run build` | Create a production build |
| `npm start` | Serve the production build |
| `npm test` | Run the automated test suite (36 tests) |
| `npm run typecheck` | Type-check the project |

### Signing key (optional)

Without a key, the server generates a temporary one each time it starts. That's fine for a demo, but attestations stop verifying after a restart. To use a permanent key:

```bash
openssl genpkey -algorithm ed25519 -out faceguard.pem
```

Put the contents of the PEM file in `.env.local` as `FACEGUARD_ED25519_PRIVATE_KEY` (newlines may be written as `\n`). Never commit this file; `.gitignore` already excludes `.env*`.

## Results summary

| Area | Result |
|---|---|
| Automated tests | **36 / 36 passing** (see [docs/TEST_CASES.md](docs/TEST_CASES.md)) |
| Synthetic attack scenarios | No attack scenario reaches BONA_FIDE |
| Manual testing with real attack artefacts | In progress (see the manual test section of [docs/TEST_CASES.md](docs/TEST_CASES.md)) |

## Project structure

```
faceguard/
├── src/
│   ├── app/
│   │   ├── api/session/route.ts   # Issues signed session plans; serves the public key
│   │   ├── api/verify/route.ts    # Verifies reports; returns signed attestations
│   │   ├── layout.tsx             # Root layout and fonts
│   │   ├── page.tsx               # Wires server plan → engine → verification → panel
│   │   └── globals.css
│   ├── components/
│   │   ├── WebcamCapture.tsx      # Camera, overlay, prompts, screen-flash overlay
│   │   ├── AuditPanel.tsx         # Decision, attestation, telemetry, audit log
│   │   └── Header.tsx
│   ├── lib/
│   │   ├── padCore.ts             # Shared decision logic and signal analysis
│   │   ├── livenessEngine.ts      # Browser engine: face tracking, state machine
│   │   └── server/
│   │       ├── attestation.ts     # Ed25519 signing, JWS, single-use sessions
│   │       └── verifyReport.ts    # Server-side report verification
│   └── types/index.ts             # Shared types
├── tests/                         # Automated tests and fixtures
├── docs/                          # API, architecture, test cases, test data
└── package.json
```

## ISO/IEC 30107 alignment

FaceGuard uses ISO/IEC 30107-1 terminology (bona fide presentation, attack presentation, presentation attack instrument) and records what ISO/IEC 30107-3 evaluation needs. Conformance requires measuring **APCER** (attacks wrongly accepted, per attack type) and **BPCER** (genuine users wrongly rejected) over a labelled test set; each audit report includes an `evaluation` block for this. FaceGuard should therefore be described as **ISO/IEC 30107-aligned**, not certified.

## Known limitations

- **The server can't see the video.** It verifies the plan, timing, consistency and audit chain, and recalculates the decision, but a modified browser could still submit invented measurements. Full protection requires server-side analysis of frames or a native app with device attestation.
- **Thresholds are uncalibrated.** Values in `DEFAULT_CONFIG` (`src/lib/padCore.ts`) are starting points tuned on synthetic data and need tuning with real attack artefacts.
- **Masks and live deepfakes are only partly covered.** Webcam pulse detection is noisy, and a live face-swap filter on a real camera may carry the screen-flash reflection through.
- **No face matching.** FaceGuard produces a liveness-verified, hash-bound photo; 1:1 matching against the registered face is performed by MOSIP or a matcher.
- **Single-instance server state.** Used sessions are tracked in memory; multiple servers would need a shared store such as Redis.

## Privacy

- Video frames are processed in the browser and never uploaded.
- The only image produced is one face crop after a successful check, kept in memory for matching; the audit report stores only its hash.
- Audit reports contain derived measurements, challenge outcomes and device details only.

## Contributors

| Name | GitHub | Contribution |
|---|---|---|
| J. Fajarillo | [@jfajarillo](https://github.com/jfajarillo) | Documentation |

<!-- Add the remaining team members and their contributions. -->

## License

To be confirmed by the team before publication.
