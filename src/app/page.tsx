"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import AuditPanel from "@/components/AuditPanel";
import Header from "@/components/Header";
import WebcamCapture from "@/components/WebcamCapture";
import { LivenessEngine } from "@/lib/livenessEngine";
import type { AuditEvent, AuditReport, EngineSnapshot } from "@/types";

const INITIAL_SNAPSHOT: EngineSnapshot = {
  phase: "uninitialized",
  sessionId: null,
  guidance: "Initialising liveness engine…",
  challenge: null,
  completedChallenges: [],
  plannedChallenges: [],
  metrics: null,
  phaseProgress: 0,
  result: null,
  error: null,
  fps: 0,
};

export default function Home() {
  const engineRef = useRef<LivenessEngine | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [snapshot, setSnapshot] = useState<EngineSnapshot>(INITIAL_SNAPSHOT);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [report, setReport] = useState<AuditReport | null>(null);

  // Create, initialise and dispose the engine with the page lifecycle.
  useEffect(() => {
    const engine = new LivenessEngine(
      {},
      {
        onSnapshot: setSnapshot,
        onAuditEvent: (event) => setEvents((prev) => [...prev, event]),
        onReport: setReport,
      },
    );
    engineRef.current = engine;
    void engine.init();
    return () => {
      engine.dispose();
      if (engineRef.current === engine) engineRef.current = null;
    };
  }, []);

  const handleVideoReady = useCallback((video: HTMLVideoElement | null) => {
    videoRef.current = video;
    if (!video) void engineRef.current?.abort("Camera stream ended");
  }, []);

  const handleStart = useCallback(() => {
    const engine = engineRef.current;
    const video = videoRef.current;
    if (!engine?.isReady || !video) return;
    setEvents([]);
    setReport(null);
    void engine.start(video);
  }, []);

  const handleAbort = useCallback(() => {
    void engineRef.current?.abort();
  }, []);

  return (
    <div className="min-h-dvh">
      <Header phase={snapshot.phase} sessionId={snapshot.sessionId} fps={snapshot.fps} />

      <main className="mx-auto grid max-w-7xl gap-6 px-4 py-6 sm:px-6 lg:grid-cols-[minmax(0,1fr)_400px]">
        <div className="flex flex-col gap-4">
          <WebcamCapture
            snapshot={snapshot}
            onVideoReady={handleVideoReady}
            onStart={handleStart}
            onAbort={handleAbort}
          />

          <section className="grid gap-3 text-sm sm:grid-cols-3">
            {[
              {
                title: "1 · Positioning",
                body: "Single face, centred, adequate lighting and frontal pose — the capture-quality gate.",
              },
              {
                title: "2 · Passive PAD",
                body: "Texture, glare, chroma and non-rigid micro-motion screen for print and replay attacks.",
              },
              {
                title: "3 · Active challenges",
                body: "A randomised, nonce-bound sequence with a neutral-pose gate defeats pre-recorded responses.",
              },
            ].map((s) => (
              <div key={s.title} className="rounded-xl border border-white/10 bg-slate-900/40 p-4">
                <h3 className="font-medium text-slate-200">{s.title}</h3>
                <p className="mt-1 text-xs leading-relaxed text-slate-400">{s.body}</p>
              </div>
            ))}
          </section>
        </div>

        <AuditPanel snapshot={snapshot} events={events} report={report} />
      </main>
    </div>
  );
}
