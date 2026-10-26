import { NextResponse } from "next/server";
import { verifyReport } from "@/lib/server/verifyReport";
import type { AuditReport } from "@/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MAX_BODY_BYTES = 512 * 1024;

/** Verifies a client audit report and returns a signed attestation. */
export async function POST(request: Request) {
  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) {
    return NextResponse.json({ error: "Report too large" }, { status: 413 });
  }

  let report: AuditReport;
  try {
    report = (JSON.parse(raw) as { report: AuditReport }).report;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (!report || typeof report !== "object" || !Array.isArray(report.events) || !report.signedPlan) {
    return NextResponse.json({ error: "Body must be { report: AuditReport }" }, { status: 400 });
  }

  try {
    const result = await verifyReport(report);
    return NextResponse.json(result, {
      status: result.verified ? 200 : 422,
      headers: { "Cache-Control": "no-store" },
    });
  } catch (err) {
    console.error("[faceguard] verification error", err);
    return NextResponse.json({ error: "Verification failed" }, { status: 400 });
  }
}
