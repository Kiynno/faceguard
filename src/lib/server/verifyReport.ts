/**
 * Server-side verification of a client audit report.
 *
 * The browser is not trusted. This re-checks everything the server can check
 * without seeing video, recomputes the PAD decision from the submitted
 * signals with the server's own configuration, and only then signs an
 * attestation. What it cannot check: whether the submitted measurements were
 * honestly computed from a real camera (see README → Known limitations).
 */

import { DEFAULT_CONFIG, analysePhotometric, decidePad, verifyAuditChain } from "@/lib/padCore";
import { consumeSession, keyInfo, signJws, verifyJws } from "@/lib/server/attestation";
import type {
  AttestationClaims,
  AuditReport,
  SessionPlan,
  VerificationCheck,
  VerificationResponse,
} from "@/types";

const ATTESTATION_TTL_S = 5 * 60;
const CLOCK_SKEW_MS = 30_000;
const MIN_SESSION_MS = 8_000;

const sameList = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((v, i) => v === b[i]);

export async function verifyReport(report: AuditReport, now = Date.now()): Promise<VerificationResponse> {
  const checks: VerificationCheck[] = [];
  const check = (name: string, passed: boolean, detail: string) => {
    checks.push({ name, passed, detail });
    return passed;
  };
  const fail = (): VerificationResponse => ({
    verified: false,
    serverResult: null,
    clientServerAgree: false,
    checks,
    attestation: null,
    claims: null,
    keyId: keyInfo().keyId,
  });

  // 1. The plan must be ours, unmodified and unexpired.
  const plan = report.signedPlan?.token ? verifyJws<SessionPlan>(report.signedPlan.token) : null;
  if (!check("Plan signature", plan !== null, plan ? "Issued by this server" : "Missing or forged session plan")) return fail();
  const p = plan as SessionPlan;
  check(
    "Plan binding",
    p.sessionId === report.sessionId &&
      p.nonce === report.nonce &&
      sameList(p.challenges, report.plannedChallenges) &&
      sameList(p.flashSequence, report.photometric?.sequence ?? []),
    "Session ID, nonce, challenges and flash sequence match the signed plan",
  );
  check("Plan not expired", now <= Date.parse(p.expiresAt), `Expires ${p.expiresAt}`);

  // 2. The audit trail must be intact and belong to this session.
  const chain = await verifyAuditChain(report.events ?? []);
  check(
    "Audit hash chain",
    chain.valid && report.events.length > 0 && report.events.at(-1)?.hash === report.chainHead,
    chain.valid ? `${chain.checked} events, head matches` : `Broken at event #${chain.brokenAt}`,
  );
  const issued = Date.parse(p.issuedAt);
  const inWindow = report.events.every((e) => {
    const t = Date.parse(e.timestamp);
    return e.sessionId === p.sessionId && t >= issued - CLOCK_SKEW_MS && t <= now + CLOCK_SKEW_MS;
  });
  check("Event timeline", inWindow, "All events belong to this session and fall inside the plan window");
  const start = report.events[0];
  check(
    "Session start",
    start?.type === "SESSION_START" && start.data?.nonce === p.nonce,
    "First event is SESSION_START carrying the plan nonce",
  );
  check("Plausible duration", report.durationMs >= MIN_SESSION_MS, `${report.durationMs} ms (minimum ${MIN_SESSION_MS})`);

  // 3. Challenges must follow the plan and be humanly possible.
  const ordered = report.challenges.every((c, i) => c.challenge.type === p.challenges[i]);
  check("Challenge order", ordered, "Results follow the signed challenge order");
  const minRt = DEFAULT_CONFIG.thresholds.minHumanResponseMs;
  const tooFast = report.challenges.filter((c) => c.status === "passed" && (c.responseTimeMs ?? 0) < minRt);
  check("Human response times", tooFast.length === 0, tooFast.length ? `${tooFast.length} response(s) under ${minRt} ms` : `All ≥ ${minRt} ms`);

  // 4. Recompute the photometric statistic from raw step data.
  const ph = report.photometric;
  const recomputed = ph ? analysePhotometric(ph.steps, DEFAULT_CONFIG.photometric.minAmplitude) : null;
  check(
    "Screen-flash recomputation",
    !!ph && !!recomputed && Math.abs(recomputed.correlation - ph.correlation) < 1e-3 && recomputed.conclusive === ph.conclusive,
    recomputed ? `Server correlation ${recomputed.correlation.toFixed(3)}` : "No screen-flash data",
  );

  const integrityOk = checks.every((c) => c.passed);

  // 5. Recompute the decision with the server's configuration, not the client's.
  const serverResult = decidePad(
    {
      plannedChallenges: p.challenges,
      challenges: report.challenges,
      passive: report.passive,
      photometric: ph && recomputed ? { ...ph, ...recomputed } : { sequence: p.flashSequence, steps: [], correlation: 0, amplitude: 0, conclusive: false },
      injection: report.injection,
    },
    DEFAULT_CONFIG,
  );
  const clientServerAgree = report.result?.decision === serverResult.decision;
  check(
    "Decision recomputed",
    true,
    `Server: ${serverResult.decision} (${serverResult.score.toFixed(3)}); client: ${report.result?.decision ?? "none"}`,
  );

  if (!integrityOk) return { ...fail(), serverResult, clientServerAgree };

  // 6. Single use — a verified report can never be replayed.
  if (!check("Single use", consumeSession(p.sessionId, Date.parse(p.expiresAt) + CLOCK_SKEW_MS), "Session not previously verified")) {
    return { ...fail(), serverResult, clientServerAgree };
  }

  const iat = Math.floor(now / 1000);
  const claims: AttestationClaims = {
    iss: "faceguard",
    sub: p.sessionId,
    decision: serverResult.decision,
    score: serverResult.score,
    suspectedPai: serverResult.suspectedPai,
    chainHead: report.chainHead,
    // Only a BONA_FIDE result may vouch for a reference image.
    referenceImageSha256: serverResult.decision === "BONA_FIDE" ? (report.referenceImage?.sha256 ?? null) : null,
    engineVersion: p.engineVersion,
    iat,
    exp: iat + ATTESTATION_TTL_S,
  };

  return {
    verified: true,
    serverResult,
    clientServerAgree,
    checks,
    attestation: signJws(claims),
    claims,
    keyId: keyInfo().keyId,
  };
}
