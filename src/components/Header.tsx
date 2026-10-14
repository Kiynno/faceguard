import type { EnginePhase } from "@/types";

interface HeaderProps {
  phase: EnginePhase;
  sessionId: string | null;
  fps: number;
}

const PHASE_STYLE: Record<EnginePhase, { label: string; dot: string; text: string }> = {
  uninitialized: { label: "Offline", dot: "bg-slate-500", text: "text-slate-400" },
  initializing: { label: "Loading model", dot: "bg-amber-400 animate-pulse", text: "text-amber-300" },
  ready: { label: "Ready", dot: "bg-sky-400", text: "text-sky-300" },
  positioning: { label: "Positioning", dot: "bg-sky-400 animate-pulse", text: "text-sky-300" },
  passive: { label: "Passive PAD", dot: "bg-violet-400 animate-pulse", text: "text-violet-300" },
  challenge: { label: "Challenge", dot: "bg-cyan-400 animate-pulse", text: "text-cyan-300" },
  evaluating: { label: "Evaluating", dot: "bg-amber-400 animate-pulse", text: "text-amber-300" },
  complete: { label: "Complete", dot: "bg-emerald-400", text: "text-emerald-300" },
  error: { label: "Error", dot: "bg-rose-500", text: "text-rose-300" },
};

export default function Header({ phase, sessionId, fps }: HeaderProps) {
  const style = PHASE_STYLE[phase];
  const live = phase === "positioning" || phase === "passive" || phase === "challenge";

  return (
    <header className="sticky top-0 z-20 border-b border-white/10 bg-slate-950/80 backdrop-blur">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-3 sm:px-6">
        <div className="flex items-center gap-3">
          <div className="grid h-9 w-9 place-items-center rounded-lg border border-cyan-400/40 bg-cyan-400/10">
            <svg viewBox="0 0 24 24" className="h-5 w-5 text-cyan-300" fill="none" stroke="currentColor" strokeWidth={1.8} aria-hidden>
              <path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z" strokeLinejoin="round" />
              <circle cx="12" cy="10.5" r="2.5" />
              <path d="M8.5 16c.9-1.4 2.1-2 3.5-2s2.6.6 3.5 2" strokeLinecap="round" />
            </svg>
          </div>
          <div className="leading-tight">
            <h1 className="text-base font-semibold tracking-tight text-white">
              FaceGuard
            </h1>
            <p className="text-xs text-slate-400">Liveness &amp; PAD · ISO/IEC 30107 audit trail</p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs">
          {sessionId && (
            <span className="hidden font-mono text-slate-500 md:inline" title={sessionId}>
              session {sessionId.slice(0, 8)}
            </span>
          )}
          {live && (
            <span className="hidden font-mono tabular-nums text-slate-500 sm:inline">{fps} fps</span>
          )}
          <span
            className={`inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 font-medium ${style.text}`}
            role="status"
            aria-live="polite"
          >
            <span className={`h-2 w-2 rounded-full ${style.dot}`} />
            {style.label}
          </span>
        </div>
      </div>
    </header>
  );
}
