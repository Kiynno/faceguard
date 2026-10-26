"use client";

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { verifyAuditChain } from "@/lib/livenessEngine";
import type {
  AuditEvent,
  AuditReport,
  AuditSeverity,
  ChainVerification,
  ChallengeType,
  EngineSnapshot,
  PadDecision,
  PadResult,
  PadSignal,
  ReferenceImageMeta,
  VerificationResponse,
} from "@/types";

export type VerifyState = "idle" | "verifying" | "done" | "error";

interface AuditPanelProps {
  snapshot: EngineSnapshot;
  events: AuditEvent[];
  report: AuditReport | null;
  verification: VerificationResponse | null;
  verifyState: VerifyState;
  verifyError: string | null;
  reference: { url: string; meta: ReferenceImageMeta } | null;
}

const DECISION_STYLE: Record<PadDecision, { label: string; ring: string; text: string; bg: string }> = {
  BONA_FIDE: { label: "Bona fide presentation", ring: "border-emerald-400/40", text: "text-emerald-300", bg: "bg-emerald-400/10" },
  ATTACK: { label: "Attack presentation", ring: "border-rose-400/40", text: "text-rose-300", bg: "bg-rose-500/10" },
  INCONCLUSIVE: { label: "Inconclusive", ring: "border-amber-400/40", text: "text-amber-300", bg: "bg-amber-400/10" },
};

const SEVERITY_STYLE: Record<AuditSeverity, string> = {
  info: "text-slate-400",
  warn: "text-amber-300",
  critical: "text-rose-300",
};

/** Ordered by weight in the fused score. */
const SIGNAL_LABEL: Record<PadSignal, string> = {
  challenge: "Active challenges",
  depth: "3D depth (head turn)",
  photometric: "Screen-flash reflection",
  motion: "Micro-motion / blink",
  injection: "Camera integrity",
  pulse: "Pulse signal (rPPG)",
  moire: "Moiré (screen replay)",
  texture: "Texture sharpness",
  specular: "Specular glare",
};

const CHALLENGE_LABEL: Record<ChallengeType, string> = {
  BLINK: "Blink",
  TURN_LEFT: "Turn left",
  TURN_RIGHT: "Turn right",
  SMILE: "Smile",
  OPEN_MOUTH: "Open mouth",
};

function Card({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-900/60">
      <div className="flex items-center justify-between gap-2 border-b border-white/5 px-4 py-2.5">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">{title}</h2>
        {action}
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

function Stat({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="rounded-lg bg-white/[0.03] px-3 py-2">
      <dt className="text-[10px] uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className={`font-mono text-sm tabular-nums ${warn ? "text-amber-300" : "text-slate-200"}`}>{value}</dd>
    </div>
  );
}

function DecisionBody({ result, source }: { result: PadResult; source: string }) {
  const style = DECISION_STYLE[result.decision];
  return (
    <div className={`rounded-xl border p-4 ${style.ring} ${style.bg}`}>
      <div className="flex items-baseline justify-between gap-2">
        <p className={`text-lg font-semibold ${style.text}`}>{style.label}</p>
        <p className="font-mono text-2xl font-semibold tabular-nums text-white">{result.score.toFixed(3)}</p>
      </div>
      <p className="mt-1 font-mono text-[11px] text-slate-400">
        {source} · bona fide ≥ {result.bonaFideThreshold} · attack &lt; {result.attackThreshold}
      </p>
      <ul className="mt-4 space-y-2">
        {(Object.keys(SIGNAL_LABEL) as PadSignal[]).map((key) => {
          const v = result.subscores[key];
          return (
            <li key={key}>
              <div className="flex justify-between text-xs">
                <span className="text-slate-300">{SIGNAL_LABEL[key]}</span>
                <span className="font-mono tabular-nums text-slate-400">{v.toFixed(2)}</span>
              </div>
              <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/10">
                <div
                  className={`h-full rounded-full ${v >= 0.65 ? "bg-emerald-400" : v >= 0.4 ? "bg-amber-400" : "bg-rose-400"}`}
                  style={{ width: `${v * 100}%` }}
                />
              </div>
            </li>
          );
        })}
      </ul>
      {result.suspectedPai.length > 0 && (
        <div className="mt-4 flex flex-wrap gap-1.5">
          {result.suspectedPai.map((pai) => (
            <span key={pai} className="rounded-md border border-rose-400/30 bg-rose-500/10 px-2 py-0.5 font-mono text-[10px] text-rose-200">
              PAI: {pai}
            </span>
          ))}
        </div>
      )}
      <ul className="mt-3 list-disc space-y-1 pl-4 text-xs text-slate-400">
        {result.reasons.map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>
    </div>
  );
}

export default function AuditPanel({
  snapshot,
  events,
  report,
  verification,
  verifyState,
  verifyError,
  reference,
}: AuditPanelProps) {
  const logRef = useRef<HTMLOListElement>(null);
  const [chainCheck, setChainCheck] = useState<ChainVerification | null>(null);
  const [checkingChain, setCheckingChain] = useState(false);
  const [copied, setCopied] = useState(false);

  const clientResult = snapshot.result ?? report?.result ?? null;
  const serverResult = verification?.verified ? verification.serverResult : null;
  const face = snapshot.metrics?.face ?? null;
  const chainHead = events.at(-1)?.hash ?? null;

  // Auto-scroll the event log and invalidate a stale chain check.
  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
    setChainCheck(null);
  }, [events.length]);

  const challengeRows = useMemo(
    () =>
      snapshot.plannedChallenges.map((type, i) => {
        const done = snapshot.completedChallenges[i];
        const isActive = snapshot.challenge?.index === i;
        return {
          type,
          status: done?.status ?? (isActive ? "active" : "pending"),
          rt: done?.responseTimeMs ?? null,
          depth: done?.depthResidual ?? null,
        };
      }),
    [snapshot.plannedChallenges, snapshot.completedChallenges, snapshot.challenge],
  );

  const handleVerifyChain = async () => {
    setCheckingChain(true);
    try {
      setChainCheck(await verifyAuditChain(events));
    } finally {
      setCheckingChain(false);
    }
  };

  const handleExport = () => {
    if (!report) return;
    const payload = { report, serverVerification: verification };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `faceguard-audit-${report.sessionId}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleCopyAttestation = async () => {
    if (!verification?.attestation) return;
    try {
      await navigator.clipboard.writeText(verification.attestation);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };

  return (
    <aside className="flex flex-col gap-4" aria-label="PAD audit panel">
      {/* Decision — the server's verdict is authoritative once available */}
      <Card title="PAD decision">
        {serverResult ? (
          <DecisionBody result={serverResult} source="server-verified" />
        ) : clientResult ? (
          <DecisionBody result={clientResult} source={verifyState === "verifying" ? "client · verifying…" : "client · unverified"} />
        ) : (
          <p className="text-sm text-slate-500">
            {snapshot.phase === "error" ? snapshot.error : "Awaiting a completed session."}
          </p>
        )}
      </Card>

      {/* Server verification */}
      <Card title="Server attestation">
        {verifyState === "idle" && <p className="text-sm text-slate-500">Sent to the server when a session completes.</p>}
        {verifyState === "verifying" && <p className="animate-pulse text-sm text-slate-400">Verifying with server…</p>}
        {verifyState === "error" && <p className="text-sm text-rose-300">{verifyError ?? "Verification failed."}</p>}
        {verifyState === "done" && verification && (
          <div className="space-y-3">
            <p className={`text-sm font-medium ${verification.verified ? "text-emerald-300" : "text-rose-300"}`}>
              {verification.verified ? "✓ Verified and signed by server" : "✗ Rejected by server"}
              {verification.verified && !verification.clientServerAgree && (
                <span className="ml-2 text-xs text-amber-300">(client and server decisions differ)</span>
              )}
            </p>
            <ul className="space-y-1 text-[11px]">
              {verification.checks.map((c) => (
                <li key={c.name} className="flex gap-2">
                  <span className={c.passed ? "text-emerald-400" : "text-rose-400"}>{c.passed ? "✓" : "✗"}</span>
                  <span className="text-slate-300">{c.name}</span>
                  <span className="min-w-0 flex-1 truncate text-right text-slate-500" title={c.detail}>
                    {c.detail}
                  </span>
                </li>
              ))}
            </ul>
            {verification.attestation && (
              <div className="rounded-lg bg-black/30 p-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase tracking-wider text-slate-500">
                    Attestation (EdDSA · key {verification.keyId})
                  </span>
                  <button
                    type="button"
                    onClick={() => void handleCopyAttestation()}
                    className="rounded border border-white/10 px-1.5 py-0.5 text-[10px] text-slate-300 hover:bg-white/5"
                  >
                    {copied ? "Copied" : "Copy"}
                  </button>
                </div>
                <p className="mt-1 break-all font-mono text-[10px] leading-snug text-slate-400">
                  {verification.attestation.slice(0, 120)}…
                </p>
              </div>
            )}
          </div>
        )}
      </Card>

      {/* Reference capture for 1:1 matching */}
      {reference && (
        <Card title="Reference capture">
          <div className="flex gap-3">
            {/* eslint-disable-next-line @next/next/no-img-element -- local blob URL */}
            <img
              src={reference.url}
              alt="Reference face crop"
              width={72}
              height={72}
              className="h-18 w-18 shrink-0 rounded-lg border border-white/10 object-cover"
            />
            <div className="min-w-0 text-[11px] text-slate-400">
              <p>Best frontal frame, ready for 1:1 matching (e.g. MOSIP). Kept in memory only.</p>
              <p className="mt-1 truncate font-mono text-slate-500" title={reference.meta.sha256}>
                sha256 {reference.meta.sha256.slice(0, 24)}…
              </p>
              <p className={verification?.claims?.referenceImageSha256 === reference.meta.sha256 ? "text-emerald-300" : "text-slate-500"}>
                {verification?.claims?.referenceImageSha256 === reference.meta.sha256
                  ? "✓ Hash bound into the signed attestation"
                  : "Not yet bound to an attestation"}
              </p>
            </div>
          </div>
        </Card>
      )}

      {/* Challenges */}
      <Card title="Challenge–response">
        {challengeRows.length === 0 ? (
          <p className="text-sm text-slate-500">The server issues a random sequence with at least one head turn.</p>
        ) : (
          <ol className="space-y-1.5">
            {challengeRows.map((row, i) => (
              <li key={`${row.type}-${i}`} className="flex items-center justify-between rounded-lg bg-white/[0.03] px-3 py-2 text-sm">
                <span className="text-slate-300">
                  <span className="mr-2 font-mono text-xs text-slate-500">{i + 1}</span>
                  {CHALLENGE_LABEL[row.type]}
                </span>
                <span
                  className={`font-mono text-xs ${
                    row.status === "passed"
                      ? "text-emerald-300"
                      : row.status === "failed"
                        ? "text-rose-300"
                        : row.status === "active"
                          ? "animate-pulse text-cyan-300"
                          : "text-slate-500"
                  }`}
                >
                  {row.status}
                  {row.rt !== null && ` · ${row.rt} ms`}
                  {row.depth !== null && ` · depth ${row.depth.toFixed(3)}`}
                </span>
              </li>
            ))}
          </ol>
        )}
      </Card>

      {/* Telemetry */}
      <Card title="Live telemetry">
        <dl className="grid grid-cols-3 gap-2">
          <Stat label="Faces" value={String(snapshot.metrics?.faceCount ?? 0)} warn={(snapshot.metrics?.faceCount ?? 0) > 1} />
          <Stat label="Yaw°" value={face ? face.yawDeg.toFixed(1) : "—"} />
          <Stat label="Roll°" value={face ? face.rollDeg.toFixed(1) : "—"} />
          <Stat label="Blink" value={face ? face.blink.toFixed(2) : "—"} />
          <Stat label="Smile" value={face ? face.smile.toFixed(2) : "—"} />
          <Stat label="Jaw" value={face ? face.jawOpen.toFixed(2) : "—"} />
          <Stat label="Sharpness" value={face ? face.sharpness.toFixed(0) : "—"} />
          <Stat label="Specular" value={face ? `${(face.specularRatio * 100).toFixed(1)}%` : "—"} warn={!!face && face.specularRatio > 0.05} />
          <Stat label="Luma" value={face ? face.brightness.toFixed(0) : "—"} />
        </dl>
        {report && (
          <dl className="mt-2 grid grid-cols-3 gap-2">
            <Stat
              label="Pulse"
              value={report.passive.pulseBpm !== null && report.passive.pulseSnr > 1.5 ? `${report.passive.pulseBpm.toFixed(0)} bpm` : "—"}
            />
            <Stat
              label="Flash corr."
              value={report.photometric ? report.photometric.correlation.toFixed(2) : "—"}
              warn={!!report.photometric && !report.photometric.conclusive}
            />
            <Stat label="Dup. frames" value={`${(report.injection.duplicateFrameRatio * 100).toFixed(0)}%`} warn={report.injection.duplicateFrameRatio > 0.1} />
          </dl>
        )}
      </Card>

      {/* Audit log */}
      <Card
        title={`Audit trail · ${events.length}`}
        action={
          <div className="flex gap-1.5">
            <button
              type="button"
              onClick={() => void handleVerifyChain()}
              disabled={events.length === 0 || checkingChain}
              className="rounded-md border border-white/10 px-2 py-1 text-[11px] text-slate-300 hover:bg-white/5 disabled:opacity-40"
            >
              {checkingChain ? "Verifying…" : "Verify chain"}
            </button>
            <button
              type="button"
              onClick={handleExport}
              disabled={!report}
              className="rounded-md bg-cyan-400/90 px-2 py-1 text-[11px] font-semibold text-slate-950 hover:bg-cyan-300 disabled:bg-slate-700 disabled:text-slate-400"
            >
              Export JSON
            </button>
          </div>
        }
      >
        <ol ref={logRef} className="max-h-72 space-y-1 overflow-y-auto pr-1 font-mono text-[11px] leading-relaxed">
          {events.length === 0 && <li className="text-slate-500">No events recorded.</li>}
          {events.map((e) => (
            <li key={e.hash} className="grid grid-cols-[2rem_4.5rem_1fr] gap-2 border-b border-white/[0.04] pb-1">
              <span className="text-slate-600">#{e.seq}</span>
              <span className="text-slate-500">{e.timestamp.slice(11, 23)}</span>
              <span className="min-w-0">
                <span className={`font-semibold ${SEVERITY_STYLE[e.severity]}`}>{e.type}</span>{" "}
                <span className="text-slate-400">{e.message}</span>
                <span className="block truncate text-slate-600" title={e.hash}>
                  {e.hash.slice(0, 16)}…
                </span>
              </span>
            </li>
          ))}
        </ol>
        <div className="mt-3 space-y-1 border-t border-white/5 pt-3 text-[11px]">
          <p className="truncate font-mono text-slate-500" title={chainHead ?? undefined}>
            chain head: {chainHead ? `${chainHead.slice(0, 24)}…` : "—"}
          </p>
          {chainCheck && (
            <p className={chainCheck.valid ? "text-emerald-300" : "text-rose-300"} role="status">
              {chainCheck.valid
                ? `✓ Hash chain intact (${chainCheck.checked} events)`
                : `✗ Chain broken at event #${chainCheck.brokenAt}`}
            </p>
          )}
          {report && (
            <p className="text-slate-500">
              config sha256 <span className="font-mono">{report.configDigest.slice(0, 16)}…</span>
            </p>
          )}
        </div>
      </Card>
    </aside>
  );
}
