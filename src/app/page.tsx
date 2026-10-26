"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import AuditPanel, { type VerifyState } from "@/components/AuditPanel";
import Header from "@/components/Header";
import WebcamCapture from "@/components/WebcamCapture";
import { LivenessEngine } from "@/lib/livenessEngine";
import type {
  AuditEvent,
  AuditReport,
  EngineSnapshot,
  ReferenceImageMeta,
  SignedSessionPlan,
  VerificationResponse,
} from "@/types";

const INITIAL_SNAPSHOT: EngineSnapshot = {
  phase: "uninitialized",
  sessionId: null,
  guidance: "Initialising liveness engine…",
  challenge: null,
  completedChallenges: [],
  plannedChallenges: [],
  flashColor: null,
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
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [verification, setVerification] = useState<VerificationResponse | null>(null);
  const [verifyState, setVerifyState] = useState<VerifyState>("idle");
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [reference, setReference] = useState<{ url: string; meta: ReferenceImageMeta } | null>(null);

  // Revoke the previous reference image URL whenever it changes or the page unmounts.
  useEffect(() => {
    return () => {
      if (reference) URL.revokeObjectURL(reference.url);
    };
  }, [reference]);

  const submitForVerification = useCallback(async (completed: AuditReport) => {
    if (!completed.result) return; // aborted sessions are logged but not attested
    setVerifyState("verifying");
    setVerifyError(null);
    try {
      const res = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report: completed }),
      });
      const body = (await res.json()) as VerificationResponse | { error: string };
      if ("error" in body) throw new Error(body.error);
      setVerification(body);
      setVerifyState("done");
    } catch (err) {
      setVerifyError(err instanceof Error ? err.message : "Verification request failed");
      setVerifyState("error");
    }
  }, []);

  // Create, initialise and dispose the engine with the page lifecycle.
  useEffect(() => {
    const engine = new LivenessEngine(
      {},
      {
        onSnapshot: setSnapshot,
        onAuditEvent: (event) => setEvents((prev) => [...prev, event]),
        onReport: (r) => {
          setReport(r);
          void submitForVerification(r);
        },
        // In a MOSIP integration, send this image and the attestation to the matcher together.
        onReferenceImage: (blob, meta) => setReference({ url: URL.createObjectURL(blob), meta }),
      },
    );
    engineRef.current = engine;
    void engine.init();
    return () => {
      engine.dispose();
      if (engineRef.current === engine) engineRef.current = null;
    };
  }, [submitForVerification]);

  const handleVideoReady = useCallback((video: HTMLVideoElement | null) => {
    videoRef.current = video;
    if (!video) void engineRef.current?.abort("Camera stream ended");
  }, []);

  const handleStart = useCallback(async () => {
    const engine = engineRef.current;
    const video = videoRef.current;
    if (!engine?.isReady || !video) return;

    setStarting(true);
    setStartError(null);
    setEvents([]);
    setReport(null);
    setVerification(null);
    setVerifyState("idle");
    setVerifyError(null);
    setReference(null);
    try {
      const res = await fetch("/api/session", { method: "POST" });
      if (!res.ok) throw new Error(`Server refused to start a session (${res.status})`);
      const signedPlan = (await res.json()) as SignedSessionPlan;
      await engine.start(video, signedPlan);
    } catch (err) {
      setStartError(err instanceof Error ? err.message : "Could not start a session");
    } finally {
      setStarting(false);
    }
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
            onStart={() => void handleStart()}
            onAbort={handleAbort}
            starting={starting}
            startError={startError}
          />

          <section className="grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4">
            {[
              {
                title: "1 · Passive PAD",
                body: "Micro-motion, blinks, pulse (rPPG), moiré, texture and glare screen for prints, screens and masks.",
              },
              {
                title: "2 · Screen flash",
                body: "A random colour sequence lights the face; replays and injected streams can't reflect it.",
              },
              {
                title: "3 · Challenges + depth",
                body: "Server-chosen actions with at least one head turn, checked for real 3D movement.",
              },
              {
                title: "4 · Server attestation",
                body: "The server re-checks the session, recomputes the decision and signs the result.",
              },
            ].map((s) => (
              <div key={s.title} className="rounded-xl border border-white/10 bg-slate-900/40 p-4">
                <h3 className="font-medium text-slate-200">{s.title}</h3>
                <p className="mt-1 text-xs leading-relaxed text-slate-400">{s.body}</p>
              </div>
            ))}
          </section>
        </div>

        <AuditPanel
          snapshot={snapshot}
          events={events}
          report={report}
          verification={verification}
          verifyState={verifyState}
          verifyError={verifyError}
          reference={reference}
        />
      </main>
    </div>
  );
}
