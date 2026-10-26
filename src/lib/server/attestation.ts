/**
 * Server-only signing and verification (Ed25519, compact JWS).
 *
 * Never import this file from a client component — it holds the private key.
 *
 * Key: set FACEGUARD_ED25519_PRIVATE_KEY to a PKCS#8 PEM, e.g.
 *   openssl genpkey -algorithm ed25519 -out faceguard.pem
 * Without it, an ephemeral key is generated per server process (fine for a
 * demo, but attestations stop verifying after a restart).
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

interface ServerState {
  privateKey: KeyObject;
  publicKey: KeyObject;
  keyId: string;
  ephemeral: boolean;
  /** sessionId → expiry (ms). Single-use protection against replayed reports. */
  usedSessions: Map<string, number>;
}

// Kept on globalThis so every route bundle (and dev hot reloads) share one key.
const g = globalThis as typeof globalThis & { __faceguardServer?: ServerState };

function state(): ServerState {
  if (g.__faceguardServer) return g.__faceguardServer;

  const pem = process.env.FACEGUARD_ED25519_PRIVATE_KEY?.replace(/\\n/g, "\n");
  let privateKey: KeyObject;
  let ephemeral = false;
  if (pem) {
    privateKey = createPrivateKey(pem);
    if (privateKey.asymmetricKeyType !== "ed25519") {
      throw new Error("FACEGUARD_ED25519_PRIVATE_KEY must be an Ed25519 key");
    }
  } else {
    privateKey = generateKeyPairSync("ed25519").privateKey;
    ephemeral = true;
    console.warn("[faceguard] FACEGUARD_ED25519_PRIVATE_KEY not set — using an ephemeral signing key.");
  }
  const publicKey = createPublicKey(privateKey);
  const der = publicKey.export({ type: "spki", format: "der" });
  const keyId = createHash("sha256").update(der).digest("hex").slice(0, 16);

  g.__faceguardServer = { privateKey, publicKey, keyId, ephemeral, usedSessions: new Map() };
  return g.__faceguardServer;
}

const b64url = (buf: Buffer | string): string =>
  (typeof buf === "string" ? Buffer.from(buf) : buf).toString("base64url");

export function signJws(payload: object): string {
  const s = state();
  const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: s.keyId }));
  const body = b64url(JSON.stringify(payload));
  const signature = sign(null, Buffer.from(`${header}.${body}`), s.privateKey);
  return `${header}.${body}.${b64url(signature)}`;
}

/** Returns the payload if the signature is valid for this server's key, otherwise null. */
export function verifyJws<T>(token: string): T | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, body, signature] = parts;
  try {
    const h = JSON.parse(Buffer.from(header, "base64url").toString()) as { alg?: string; kid?: string };
    if (h.alg !== "EdDSA" || h.kid !== state().keyId) return null;
    const ok = verify(null, Buffer.from(`${header}.${body}`), state().publicKey, Buffer.from(signature, "base64url"));
    return ok ? (JSON.parse(Buffer.from(body, "base64url").toString()) as T) : null;
  } catch {
    return null;
  }
}

/** Public key as a JWK so relying parties can verify attestations offline. */
export function publicJwk(): { kty: string; crv: string; x: string; kid: string; alg: "EdDSA"; use: "sig" } {
  const s = state();
  const jwk = s.publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
  return { ...jwk, kid: s.keyId, alg: "EdDSA", use: "sig" };
}

export function keyInfo(): { keyId: string; ephemeral: boolean } {
  const s = state();
  return { keyId: s.keyId, ephemeral: s.ephemeral };
}

/**
 * Marks a session as consumed. Returns false if it was already used.
 * In-memory: use a shared store (e.g. Redis) when running more than one instance.
 */
export function consumeSession(sessionId: string, expiresAtMs: number): boolean {
  const used = state().usedSessions;
  const now = Date.now();
  for (const [id, exp] of used) if (exp < now) used.delete(id);
  if (used.has(sessionId)) return false;
  used.set(sessionId, expiresAtMs);
  return true;
}
