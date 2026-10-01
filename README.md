# FaceGuard

Browser-based face **liveness detection** and **Presentation Attack Detection (PAD)** with an ISO/IEC 30107-aligned, hash-chained audit trail. Built for **MOSIP Decode 2026**.

FaceGuard checks that the face in front of the camera belongs to a live person physically present, not a photo, a screen replay or another stand-in. Every session produces a structured, tamper-evident audit report that can be exported as JSON.

> **Status: hackathon prototype.** PAD thresholds are uncalibrated and the decision currently runs client-side. See [Known limitations](#known-limitations) before using this for anything beyond a demo.

---

## Features

- **Active liveness:** a random, single-use sequence of 3 challenges drawn from blink, smile, open mouth, turn left and turn right. Each challenge only counts after the subject returns to a neutral pose, so a pose already held up to the camera can't pass.
- **Passive PAD checks:** face sharpness, screen glare, colour richness, natural micro-movement and spontaneous blinks, measured during a 3-second still window.
- **Capture-quality gate:** one face only, centred, at a usable distance, with adequate lighting and a frontal pose.
- **Attack hints:** flags suspected attack types (print, screen replay, static image, multiple faces, sudden face swap).
- **Three-way decision:** `BONA_FIDE`, `ATTACK` or `INCONCLUSIVE`, with a fused score and per-signal sub-scores.
- **Tamper-evident audit trail:** every event is hashed with SHA-256 and linked to the previous one. The UI can re-verify the chain and export the full report.
- **Privacy by design:** frames are processed on-device and never stored or transmitted. The report holds only derived numbers and outcomes.

## Tech stack

- [Next.js](https://nextjs.org/) (App Router) + React + TypeScript (strict)
- [Tailwind CSS v4](https://tailwindcss.com/)
- [MediaPipe Face Landmarker](https://ai.google.dev/edge/mediapipe/solutions/vision/face_landmarker) (`@mediapipe/tasks-vision`) for 478 face landmarks and 52 expression scores
- Web Crypto API for SHA-256 hashing and secure randomness

## Getting started

**Requirements:** Node.js 20.9 or newer, and a webcam.

```bash
npm install
npm run dev
```

Open <http://localhost:3000> and allow camera access, then click **Start liveness check**.

The camera and Web Crypto APIs only work on `localhost` or over HTTPS. To test on a phone, serve the app over HTTPS (e.g. a tunnel or a deployed preview).

The MediaPipe model and WebAssembly files load from public CDNs on first use, so the browser needs internet access.

| Script | What it does |
|---|---|
| `npm run dev` | Start the development server |
| `npm run build` | Production build |
| `npm start` | Serve the production build |
| `npm run typecheck` | Type-check the project with `tsc` |

## How a session works

1. **Positioning:** the engine waits for a single, centred, well-lit, frontal face held steady for about 12 frames.
2. **Passive window (3 s):** the subject looks at the camera while passive signals are collected.
3. **Active challenges:** 3 challenges in random order, 7 seconds each. A failed challenge ends the session immediately.
4. **Decision:** signals are combined into a score and decision, which is logged and added to the audit report.

### Scoring

Each signal is mapped to a 0–1 "looks live" sub-score and combined with these weights:

| Signal | Weight | Source |
|---|---|---|
| Active challenges | 0.50 | Fraction of challenges passed |
| Micro-motion / blink | 0.20 | Landmark movement after removing head position, size and tilt; spontaneous blinks |
| Texture sharpness | 0.15 | Sharpness (Laplacian variance) of the face region |
| Specular glare | 0.10 | Share of near-white pixels on the face |
| Chroma richness | 0.05 | Spread of colour values on the face |

- **BONA_FIDE:** all challenges passed, score ≥ 0.65, and no multiple-face or face-swap flags.
- **ATTACK:** score < 0.40, or a challenge failed while an attack type is suspected.
- **INCONCLUSIVE:** anything else; the user should retry.

All thresholds live in `DEFAULT_CONFIG` in `src/lib/livenessEngine.ts` and can be overridden when the engine is created.

## Project structure

```
faceguard/
├── src/
│   ├── app/
│   │   ├── layout.tsx          # Root layout, fonts, metadata
│   │   ├── page.tsx            # Creates the engine and wires camera → engine → panel
│   │   └── globals.css         # Tailwind v4 import and theme
│   ├── components/
│   │   ├── WebcamCapture.tsx   # Camera access, preview, overlay, challenge prompt
│   │   ├── AuditPanel.tsx      # Decision, challenges, telemetry, audit log, export
│   │   └── Header.tsx          # Branding and session status
│   ├── lib/
│   │   └── livenessEngine.ts   # Face tracking, PAD checks, state machine, audit trail
│   └── types/
│       └── index.ts            # Shared types and the audit report schema
├── next.config.ts              # Security headers (camera limited to this site)
├── postcss.config.mjs          # Tailwind v4 PostCSS plugin
├── tsconfig.json               # Strict TypeScript, `@/*` path alias
└── package.json
```

## Using the engine directly

```ts
import { LivenessEngine } from "@/lib/livenessEngine";

const engine = new LivenessEngine(
  { challengeCount: 3, pad: { bonaFideThreshold: 0.7 } }, // optional overrides
  {
    onSnapshot: (s) => console.log(s.phase, s.guidance),
    onAuditEvent: (e) => console.log(e.seq, e.type, e.hash),
    onReport: (r) => console.log(r.result?.decision),
  },
);

await engine.init();              // loads the MediaPipe model
await engine.start(videoElement); // a playing <video> with the camera stream
// …later
await engine.abort();             // optional: cancel the session
engine.dispose();                 // release the model
```

## Audit trail

Each event records its sequence number, timestamp, session ID, type, severity, message, data, the previous event's hash and its own SHA-256 hash. Hashes are computed over JSON with sorted keys, so they are reproducible.

To check a report offline:

```ts
import { verifyAuditChain } from "@/lib/livenessEngine";

const { valid, brokenAt } = await verifyAuditChain(report.events);
```

**Event types:** `SESSION_START`, `ENGINE_READY`, `FACE_ACQUIRED`, `FACE_LOST`, `FACE_DISCONTINUITY`, `MULTIPLE_FACES`, `PASSIVE_COMPLETE`, `CHALLENGE_ISSUED`, `CHALLENGE_PASSED`, `CHALLENGE_FAILED`, `DECISION`, `SESSION_ABORTED`, `ERROR`.

The exported report (`faceguard.audit/1.0`) also includes the engine and model versions, a SHA-256 digest of the config, device and camera details, challenge results, passive measurements, the decision, and a privacy statement.

## ISO/IEC 30107 alignment

FaceGuard uses the terminology of ISO/IEC 30107-1 (bona fide presentation, attack presentation, presentation attack instrument) and records what ISO/IEC 30107-3 testing needs.

**A single session does not show conformance.** 30107-3 requires measuring error rates across a labelled set of genuine and attack attempts:

- **APCER:** the share of attacks wrongly accepted, reported per attack type.
- **BPCER:** the share of genuine users wrongly rejected.

Each report has an `evaluation` block (`groundTruth`, `paiSpeciesUnderTest`) for labelling sessions during a test campaign, so these rates can be computed offline. Until that is done, describe FaceGuard as **"30107-aligned audit logging"**, not "30107 compliant".

## Attack coverage

| Attack type | Coverage | Notes |
|---|---|---|
| Printed photo | 🟡 Moderate | Head turns defeat flat photos. A photo with eye and mouth cut-outs can pass when no turn is drawn (about 1 in 10 sessions). |
| Video / screen replay | 🟡 Moderate | Random challenges defeat a single recording. Switching between clips on cue, or a live puppet, is not stopped. Screen detection uses glare only. |
| 3D mask / silicone | ❌ Not covered | No depth, pulse or material analysis. |
| Deepfake / stream injection | ❌ Not covered | Virtual cameras look like real webcams to the browser; the camera name is logged but not checked. |

## Known limitations

- **The decision runs in the browser.** A modified client can force a `BONA_FIDE` result or submit a forged report. The hash chain shows whether a report was edited after export, but it is not signed, so it can't prove the session was genuine.
- **Thresholds are uncalibrated.** The passive ranges in `DEFAULT_CONFIG` are starting guesses and need tuning on real genuine and attack data.
- **Liveness only, no identity check.** There is no face matching against an ID document or enrolled template; that must be handled elsewhere in the pipeline.
- **Ordinary webcam only.** No depth or infrared sensors are used.
- **MediaPipe version pin.** `@mediapipe/tasks-vision` is pinned in `package.json` and must match `MEDIAPIPE_VERSION` in `livenessEngine.ts`, because the WebAssembly files load from a CDN at that version.

## Roadmap

1. Move challenge issuing and the decision server-side, with signed results.
2. Always include at least one head-turn challenge, plus a depth-consistency check while turning.
3. Add a trained passive PAD model (e.g. MiniFASNet) via ONNX Runtime Web.
4. Add a screen-flash challenge that checks for reflected colours on the face.
5. Add pulse detection from the face video (rPPG) against masks.
6. Add injection signals (virtual-camera names, frame-timing checks) and device attestation in native apps.
7. Add moiré-pattern detection against screen replays.

## Privacy

- No images, face crops or landmarks are stored or sent anywhere.
- Audit reports contain only derived numbers, challenge outcomes and device details.
- `next.config.ts` limits camera access to this site and disables framing and referrers.

## License

Add a license before publishing.
