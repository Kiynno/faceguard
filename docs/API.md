# FaceGuard API Documentation

FaceGuard exposes three HTTP endpoints, implemented as Next.js route handlers on the Node.js runtime. All requests and responses use JSON.

| Endpoint | Method | Purpose |
|---|---|---|
| [`/api/session`](#post-apisession) | `POST` | Start a session: returns a signed, single-use session plan |
| [`/api/session`](#get-apisession) | `GET` | Get the public key for verifying attestations |
| [`/api/verify`](#post-apiverify) | `POST` | Verify a completed session and receive a signed attestation |

Base URL in development: `http://localhost:3000`

---

## Authentication and trust model

The endpoints do not use API keys or user logins. Trust comes from **digital signatures** instead:

- The server signs every **session plan** with its Ed25519 private key. The client cannot change the challenges or flash colours without breaking the signature.
- The server signs every **attestation** (the verified result). Relying parties verify it with the public key from `GET /api/session`.
- Each session can be verified **only once**, and plans expire **3 minutes** after issue.

Signatures use **compact JWS** (`header.payload.signature`, base64url) with `alg: "EdDSA"` and a `kid` (key ID: the first 16 hex characters of the SHA-256 of the public key).

> **Production note:** add rate limiting and, where appropriate, caller authentication (for example mutual TLS or an API gateway) in front of these endpoints.

### Signing key

| Environment variable | Description |
|---|---|
| `FACEGUARD_ED25519_PRIVATE_KEY` | Ed25519 private key in PKCS#8 PEM format. `\n` may be used for newlines. If unset, a temporary key is generated each time the server starts. |

---

## `POST /api/session`

Starts a liveness session. The server randomly selects:

- **3 distinct challenges** from `BLINK`, `TURN_LEFT`, `TURN_RIGHT`, `SMILE`, `OPEN_MOUTH`, always including at least one head turn;
- a **5-step flash sequence** using all of `RED`, `GREEN`, `BLUE`, with no colour repeated back to back.

### Request

No body.

```bash
curl -X POST http://localhost:3000/api/session
```

### Response `200 OK`

```json
{
  "plan": {
    "sessionId": "3f0c2a8e-6b7d-4f6e-9a51-2a8c5d1e7b90",
    "nonce": "9b1f0c7e4a2d6f8b3c5e7a9d1f2b4c6e",
    "challenges": ["SMILE", "TURN_LEFT", "BLINK"],
    "flashSequence": ["GREEN", "RED", "BLUE", "GREEN", "RED"],
    "issuedAt": "2026-10-26T08:00:00.000Z",
    "expiresAt": "2026-10-26T08:03:00.000Z",
    "engineVersion": "2.0.0"
  },
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6IjFhMmIzYzRkNWU2ZjcwODEifQ.eyJzZXNzaW9uSWQiOi..."
}
```

| Field | Type | Description |
|---|---|---|
| `plan.sessionId` | string (UUID) | Unique session identifier |
| `plan.nonce` | string (32 hex) | Random value bound into the audit trail |
| `plan.challenges` | string[3] | Challenges, in the order the user must perform them |
| `plan.flashSequence` | string[5] | Screen colours, in order |
| `plan.issuedAt` / `plan.expiresAt` | ISO 8601 | Validity window (3 minutes) |
| `plan.engineVersion` | string | Engine version the client must run |
| `token` | string | Compact JWS over `plan`; the client returns it unchanged inside the report |

Responses carry `Cache-Control: no-store`.

---

## `GET /api/session`

Returns the public key used to verify plans and attestations.

```bash
curl http://localhost:3000/api/session
```

### Response `200 OK`

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
      "kid": "1a2b3c4d5e6f7081",
      "alg": "EdDSA",
      "use": "sig"
    }
  ],
  "keyId": "1a2b3c4d5e6f7081",
  "ephemeral": true
}
```

| Field | Description |
|---|---|
| `keys` | JSON Web Key Set containing the server's public key |
| `keyId` | Key ID that appears as `kid` in every JWS header |
| `ephemeral` | `true` if no permanent key is configured (the key changes when the server restarts) |

---

## `POST /api/verify`

Verifies a completed session report and, if it passes every check, returns a signed attestation. The server **recalculates the decision itself** using its own configuration; the client's decision is only used for comparison.

### Request

Body: `{ "report": AuditReport }`, maximum 512 KB. The browser sends this automatically when a session completes. The file downloaded with **Export JSON** in the UI has the same shape and can be sent directly.

```bash
curl -X POST http://localhost:3000/api/verify \
  -H "Content-Type: application/json" \
  --data @faceguard-audit-<sessionId>.json
```

Main fields of `AuditReport` (full definition in `src/types/index.ts`):

| Field | Description |
|---|---|
| `signedPlan` | `{ plan, token }` exactly as received from `POST /api/session` |
| `sessionId`, `nonce` | Must match the signed plan |
| `plannedChallenges` | Must match `plan.challenges` |
| `challenges[]` | Result of each challenge: `status`, `responseTimeMs`, `depthResidual` (head turns) |
| `passive` | Passive measurements: sharpness, glare, micro-motion, moiré, pulse SNR/bpm, blinks, multi-face frames, face discontinuities |
| `photometric` | Flash sequence, per-step face colour (`steps[].chroma`), `correlation`, `amplitude`, `conclusive` |
| `injection` | Camera label, virtual-camera flag, duplicate-frame ratio |
| `referenceImage` | SHA-256 and metadata of the captured face crop (null unless BONA_FIDE) |
| `result` | The client's decision |
| `events[]`, `chainHead` | Hash-chained audit events and the hash of the last one |

### Verification checks

| # | Check | Fails when |
|---|---|---|
| 1 | Plan signature | The token is missing, altered or signed by another key |
| 2 | Plan binding | Session ID, nonce, challenges or flash sequence differ from the signed plan |
| 3 | Plan not expired | The report arrives after `expiresAt` |
| 4 | Audit hash chain | Any event was edited, inserted, removed or reordered, or `chainHead` doesn't match |
| 5 | Event timeline | An event belongs to another session or falls outside the plan's time window (±30 s) |
| 6 | Session start | The first event isn't `SESSION_START` carrying the plan nonce |
| 7 | Plausible duration | The session took under 8 seconds |
| 8 | Challenge order | Results don't follow the signed challenge order |
| 9 | Human response times | A passed challenge was completed in under 150 ms |
| 10 | Screen-flash recomputation | The server's recalculation from raw `steps` doesn't match the client's values |
| 11 | Decision recomputed | Informational: shows server vs client decision |
| 12 | Single use | The session was already verified |

### Response `200 OK` (verified)

```json
{
  "verified": true,
  "serverResult": {
    "decision": "BONA_FIDE",
    "score": 0.9653,
    "bonaFideThreshold": 0.65,
    "attackThreshold": 0.4,
    "subscores": {
      "challenge": 1, "depth": 1, "photometric": 1, "motion": 1, "injection": 1,
      "pulse": 1, "moire": 1, "texture": 0.692, "specular": 1
    },
    "suspectedPai": [],
    "reasons": ["All challenges passed; depth, screen-flash and passive signals within bona fide range"]
  },
  "clientServerAgree": true,
  "checks": [
    { "name": "Plan signature", "passed": true, "detail": "Issued by this server" },
    { "name": "Audit hash chain", "passed": true, "detail": "14 events, head matches" }
  ],
  "attestation": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6IjFhMmIzYzRkNWU2ZjcwODEifQ.eyJpc3MiOiJmYWNlZ3VhcmQi...",
  "claims": {
    "iss": "faceguard",
    "sub": "3f0c2a8e-6b7d-4f6e-9a51-2a8c5d1e7b90",
    "decision": "BONA_FIDE",
    "score": 0.9653,
    "suspectedPai": [],
    "chainHead": "c0ffee…",
    "referenceImageSha256": "5d41402abc4b2a76b9719d911017c592…",
    "engineVersion": "2.0.0",
    "iat": 1793001600,
    "exp": 1793001900
  },
  "keyId": "1a2b3c4d5e6f7081"
}
```

(`checks` shortened; a real response lists all 12.)

`decision` is one of:

| Decision | Meaning |
|---|---|
| `BONA_FIDE` | A live person was present; safe to proceed |
| `ATTACK` | A presentation attack was detected; reject |
| `INCONCLUSIVE` | Not enough evidence either way; ask the user to retry |

`suspectedPai` (suspected presentation attack instrument) may contain `PRINT`, `REPLAY_SCREEN`, `STATIC_IMAGE`, `MASK`, `INJECTED_STREAM`, `MULTIPLE_SUBJECTS`, `SUBJECT_SWAP` or `UNKNOWN`.

A verified report always returns an attestation, even when the decision is `ATTACK`. **Relying parties must check `claims.decision`**, not just `verified`.

### Attestation claims

| Claim | Description |
|---|---|
| `iss` | Always `"faceguard"` |
| `sub` | Session ID |
| `decision`, `score`, `suspectedPai` | The server's recalculated result |
| `chainHead` | Hash of the last audit event, linking the attestation to the full audit trail |
| `referenceImageSha256` | SHA-256 of the captured face crop; `null` unless the decision is `BONA_FIDE` |
| `engineVersion` | Engine version that produced the report |
| `iat`, `exp` | Issued-at and expiry (Unix seconds); attestations are valid for 5 minutes |

### Error responses

| Status | Body | Cause |
|---|---|---|
| `422 Unprocessable Entity` | Same shape as above, `verified: false`, `attestation: null` | One or more checks failed; failed checks have `passed: false` |
| `400 Bad Request` | `{ "error": "Invalid JSON" }` | The body isn't valid JSON |
| `400 Bad Request` | `{ "error": "Body must be { report: AuditReport }" }` | Missing `report`, `events` or `signedPlan` |
| `400 Bad Request` | `{ "error": "Verification failed" }` | The report is malformed in a way that prevented verification |
| `413 Payload Too Large` | `{ "error": "Report too large" }` | Body over 512 KB |

Example of a rejected replay (the same report sent twice):

```json
{
  "verified": false,
  "checks": [{ "name": "Single use", "passed": false, "detail": "Session not previously verified" }],
  "attestation": null,
  "claims": null
}
```

---

## Example use case: MOSIP registration or authentication

1. The client calls `POST /api/session` and runs the liveness check with the returned plan.
2. The client sends the report to `POST /api/verify` and receives the attestation and claims.
3. The client sends the **attestation** and the **reference face image** to the relying service (e.g. a MOSIP integration).
4. The relying service:
   1. fetches the public key from `GET /api/session` (cache it by `kid`);
   2. verifies the attestation's Ed25519 signature;
   3. checks `iss === "faceguard"`, `decision === "BONA_FIDE"` and that `exp` is in the future;
   4. checks that SHA-256 of the received image equals `referenceImageSha256`;
   5. only then performs 1:1 face matching against the registered or document photo.

### Verifying an attestation (Node.js)

```ts
import { createPublicKey, createHash, verify } from "node:crypto";

async function verifyAttestation(token: string, imageBytes: Buffer) {
  const { keys } = await fetch("http://localhost:3000/api/session").then((r) => r.json());
  const [header, payload, signature] = token.split(".");
  const { kid } = JSON.parse(Buffer.from(header, "base64url").toString());
  const jwk = keys.find((k: { kid: string }) => k.kid === kid);
  if (!jwk) throw new Error("Unknown signing key");

  const key = createPublicKey({ key: jwk, format: "jwk" });
  const valid = verify(null, Buffer.from(`${header}.${payload}`), key, Buffer.from(signature, "base64url"));
  if (!valid) throw new Error("Invalid signature");

  const claims = JSON.parse(Buffer.from(payload, "base64url").toString());
  if (claims.iss !== "faceguard" || claims.decision !== "BONA_FIDE") throw new Error("Not a live person");
  if (claims.exp * 1000 < Date.now()) throw new Error("Attestation expired");

  const imageHash = createHash("sha256").update(imageBytes).digest("hex");
  if (imageHash !== claims.referenceImageSha256) throw new Error("Image does not match attestation");
  return claims;
}
```

---

## Browser engine API

The liveness engine (`src/lib/livenessEngine.ts`) can also be used directly in other front-ends:

```ts
import { LivenessEngine } from "@/lib/livenessEngine";

const engine = new LivenessEngine(
  {}, // optional configuration overrides
  {
    onSnapshot: (s) => render(s),                 // live state for the UI
    onAuditEvent: (e) => appendToLog(e),          // each hash-chained event
    onReport: (report) => sendToVerify(report),   // final report → POST /api/verify
    onReferenceImage: (blob, meta) => keep(blob), // face crop for matching (BONA_FIDE only)
  },
);

await engine.init();                                 // load the face model
const signedPlan = await fetch("/api/session", { method: "POST" }).then((r) => r.json());
await engine.start(videoElement, signedPlan);        // run a session
await engine.abort();                                // optional: cancel
engine.dispose();                                    // release resources
```

When the screen-flash phase is active, `snapshot.flashColor` is `"RED"`, `"GREEN"` or `"BLUE"`; the host page must fill the screen with that colour.
