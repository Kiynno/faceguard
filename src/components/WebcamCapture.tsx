"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ChallengeType, EngineSnapshot, FlashColor } from "@/types";

interface WebcamCaptureProps {
  snapshot: EngineSnapshot;
  onVideoReady: (video: HTMLVideoElement | null) => void;
  onStart: () => void;
  onAbort: () => void;
  /** True while the signed session plan is being fetched from the server. */
  starting: boolean;
  startError: string | null;
}

type CameraState =
  | { status: "idle" }
  | { status: "requesting" }
  | { status: "active" }
  | { status: "error"; message: string };

/** Pure, fully saturated colours give the strongest reflection on skin. */
const FLASH_FILL: Record<FlashColor, string> = {
  RED: "#ff0000",
  GREEN: "#00ff00",
  BLUE: "#0000ff",
};

const CHALLENGE_ICON: Record<ChallengeType, string> = {
  BLINK: "👁",
  TURN_LEFT: "←",
  TURN_RIGHT: "→",
  SMILE: "☺",
  OPEN_MOUTH: "◯",
};

function describeCameraError(err: unknown): string {
  if (err instanceof DOMException) {
    switch (err.name) {
      case "NotAllowedError":
        return "Camera permission was denied. Allow camera access in your browser settings and retry.";
      case "NotFoundError":
        return "No camera was found on this device.";
      case "NotReadableError":
        return "The camera is in use by another application.";
      case "OverconstrainedError":
        return "The camera does not support the requested resolution.";
      case "SecurityError":
        return "Camera access is blocked in this context (HTTPS required).";
    }
  }
  return err instanceof Error ? err.message : "Unable to start the camera.";
}

export default function WebcamCapture({
  snapshot,
  onVideoReady,
  onStart,
  onAbort,
  starting,
  startError,
}: WebcamCaptureProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [camera, setCamera] = useState<CameraState>({ status: "idle" });

  const stopCamera = useCallback(() => {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
    if (videoRef.current) videoRef.current.srcObject = null;
    onVideoReady(null);
  }, [onVideoReady]);

  const startCamera = useCallback(async () => {
    if (!navigator.mediaDevices?.getUserMedia) {
      setCamera({ status: "error", message: "This browser does not support camera capture (HTTPS required)." });
      return;
    }
    setCamera({ status: "requesting" });
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: {
          facingMode: "user",
          width: { ideal: 1280 },
          height: { ideal: 720 },
          frameRate: { ideal: 30, max: 30 },
        },
      });
      streamRef.current = stream;
      const video = videoRef.current;
      if (!video) return;
      video.srcObject = stream;
      await video.play();
      setCamera({ status: "active" });
      onVideoReady(video);
    } catch (err) {
      stopCamera();
      setCamera({ status: "error", message: describeCameraError(err) });
    }
  }, [onVideoReady, stopCamera]);

  useEffect(() => {
    void startCamera();
    return () => stopCamera();
  }, [startCamera, stopCamera]);

  // Overlay: face box + guide oval, drawn in raw camera coordinates and mirrored via CSS.
  useEffect(() => {
    const canvas = canvasRef.current;
    const video = videoRef.current;
    if (!canvas || !video || !video.videoWidth) return;
    if (canvas.width !== video.videoWidth || canvas.height !== video.videoHeight) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
    }
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const { width: w, height: h } = canvas;
    ctx.clearRect(0, 0, w, h);

    const { phase, metrics, result } = snapshot;
    const active = phase === "positioning" || phase === "passive" || phase === "photometric" || phase === "challenge";

    let color = "rgba(148,163,184,0.7)";
    if (phase === "passive") color = "rgba(167,139,250,0.95)";
    if (phase === "photometric") color = "rgba(232,121,249,0.95)";
    if (phase === "challenge") color = "rgba(34,211,238,0.95)";
    if (phase === "positioning" && snapshot.phaseProgress > 0) color = "rgba(56,189,248,0.95)";
    if (phase === "complete" && result) {
      color =
        result.decision === "BONA_FIDE"
          ? "rgba(52,211,153,0.95)"
          : result.decision === "ATTACK"
            ? "rgba(244,63,94,0.95)"
            : "rgba(251,191,36,0.95)";
    }

    // Guide oval with progress arc
    const cx = w / 2;
    const cy = h / 2;
    const rx = h * 0.28;
    const ry = h * 0.38;
    ctx.lineWidth = Math.max(2, h / 220);
    ctx.setLineDash([10, 10]);
    ctx.strokeStyle = "rgba(255,255,255,0.25)";
    ctx.beginPath();
    ctx.ellipse(cx, cy, rx, ry, 0, 0, Math.PI * 2);
    ctx.stroke();
    ctx.setLineDash([]);
    if (active || phase === "complete") {
      ctx.strokeStyle = color;
      ctx.lineWidth = Math.max(3, h / 140);
      ctx.beginPath();
      ctx.ellipse(cx, cy, rx, ry, 0, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * snapshot.phaseProgress);
      ctx.stroke();
    }

    // Face bounding box corners
    const box = metrics?.face?.box;
    if (box && active) {
      const x = box.x * w;
      const y = box.y * h;
      const bw = box.width * w;
      const bh = box.height * h;
      const c = Math.min(bw, bh) * 0.18;
      ctx.strokeStyle = color;
      ctx.lineWidth = Math.max(2, h / 240);
      ctx.beginPath();
      for (const [px, py, dx, dy] of [
        [x, y, 1, 1],
        [x + bw, y, -1, 1],
        [x, y + bh, 1, -1],
        [x + bw, y + bh, -1, -1],
      ] as const) {
        ctx.moveTo(px + dx * c, py);
        ctx.lineTo(px, py);
        ctx.lineTo(px, py + dy * c);
      }
      ctx.stroke();
    }
  }, [snapshot]);

  const { phase, challenge, result, guidance } = snapshot;
  const sessionActive =
    phase === "positioning" || phase === "passive" || phase === "photometric" || phase === "challenge";
  const canStart = camera.status === "active" && !starting && (phase === "ready" || phase === "complete");
  const flash = snapshot.flashColor;

  return (
    <section className="flex flex-col gap-4">
      {/* Screen-flash challenge: the whole screen lights the face in a server-chosen colour. */}
      {flash && (
        <div
          className="fixed inset-0 z-50 flex items-end justify-center pb-16"
          style={{ backgroundColor: FLASH_FILL[flash] }}
          role="alert"
          aria-live="assertive"
        >
          <p className="rounded-full bg-black/70 px-5 py-2 text-sm font-medium text-white">
            Keep looking at the camera — screen check {Math.min(5, Math.floor(snapshot.phaseProgress * 5) + 1)}/5
          </p>
        </div>
      )}

      <div className="relative aspect-video w-full overflow-hidden rounded-2xl border border-white/10 bg-black shadow-2xl shadow-cyan-950/30">
        <video
          ref={videoRef}
          className="absolute inset-0 h-full w-full -scale-x-100 object-cover"
          playsInline
          muted
          autoPlay
          aria-label="Live camera preview"
        />
        <canvas
          ref={canvasRef}
          className="pointer-events-none absolute inset-0 h-full w-full -scale-x-100 object-cover"
          aria-hidden
        />

        {sessionActive && <div className="fg-scanline pointer-events-none absolute inset-x-0 h-24" />}

        {/* Guidance / challenge prompt */}
        {camera.status === "active" && phase !== "uninitialized" && (
          <div className="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/85 via-black/50 to-transparent p-4 sm:p-6">
            {challenge ? (
              <div className="flex items-center gap-4">
                <div
                  className={`grid h-14 w-14 shrink-0 place-items-center rounded-xl border text-2xl ${
                    challenge.armed
                      ? "border-cyan-300/60 bg-cyan-400/15 text-cyan-200"
                      : "border-white/20 bg-white/5 text-slate-300"
                  }`}
                  aria-hidden
                >
                  {challenge.armed ? CHALLENGE_ICON[challenge.type] : "•"}
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-xs uppercase tracking-widest text-cyan-300/80">
                    Challenge {challenge.index + 1} of {challenge.total}
                  </p>
                  <p className="truncate text-lg font-semibold text-white sm:text-xl" aria-live="assertive">
                    {challenge.instruction}
                  </p>
                  <div className="mt-2 h-1 overflow-hidden rounded-full bg-white/15">
                    <div
                      className="h-full bg-cyan-300 transition-[width] duration-100 ease-linear"
                      style={{ width: `${(challenge.remainingMs / challenge.timeoutMs) * 100}%` }}
                    />
                  </div>
                </div>
              </div>
            ) : (
              <p
                className={`text-center text-base font-medium sm:text-lg ${
                  result?.decision === "BONA_FIDE"
                    ? "text-emerald-300"
                    : result?.decision === "ATTACK"
                      ? "text-rose-300"
                      : result?.decision === "INCONCLUSIVE"
                        ? "text-amber-300"
                        : "text-white"
                }`}
                aria-live="polite"
              >
                {guidance}
              </p>
            )}
          </div>
        )}

        {/* Camera states */}
        {camera.status !== "active" && (
          <div className="absolute inset-0 grid place-items-center bg-slate-950/90 p-6 text-center">
            {camera.status === "error" ? (
              <div className="max-w-sm space-y-4">
                <p className="text-sm text-rose-300">{camera.message}</p>
                <button
                  type="button"
                  onClick={() => void startCamera()}
                  className="rounded-lg border border-white/15 bg-white/10 px-4 py-2 text-sm font-medium text-white hover:bg-white/15"
                >
                  Retry camera
                </button>
              </div>
            ) : (
              <p className="animate-pulse text-sm text-slate-400">Requesting camera access…</p>
            )}
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-slate-500">
          Frames are processed on-device. The screen briefly flashes red, green and blue during the check
          (under 2 flashes per second).
        </p>
        {startError && (
          <p className="w-full text-xs text-rose-300" role="alert">
            {startError}
          </p>
        )}
        <div className="flex gap-2">
          {sessionActive ? (
            <button
              type="button"
              onClick={onAbort}
              className="rounded-lg border border-rose-400/40 bg-rose-500/10 px-4 py-2 text-sm font-medium text-rose-200 hover:bg-rose-500/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"
            >
              Abort session
            </button>
          ) : (
            <button
              type="button"
              onClick={onStart}
              disabled={!canStart}
              className="rounded-lg bg-cyan-400 px-5 py-2 text-sm font-semibold text-slate-950 shadow-lg shadow-cyan-500/20 hover:bg-cyan-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-200 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400 disabled:shadow-none"
            >
              {starting
                ? "Requesting session…"
                : phase === "complete"
                  ? "Run again"
                  : phase === "initializing"
                    ? "Loading model…"
                    : "Start liveness check"}
            </button>
          )}
        </div>
      </div>
    </section>
  );
}
