import { randomBytes, randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { buildSessionPlan } from "@/lib/padCore";
import { keyInfo, publicJwk, signJws } from "@/lib/server/attestation";
import type { SignedSessionPlan } from "@/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const NO_STORE = { "Cache-Control": "no-store" };

/** Issues a signed, single-use session plan (challenges + flash sequence). */
export async function POST(): Promise<NextResponse<SignedSessionPlan>> {
  const plan = buildSessionPlan(randomUUID(), randomBytes(16).toString("hex"));
  return NextResponse.json({ plan, token: signJws(plan) }, { headers: NO_STORE });
}

/** Public key (JWK) that relying parties use to verify FaceGuard attestations. */
export async function GET() {
  return NextResponse.json({ keys: [publicJwk()], ...keyInfo() }, { headers: NO_STORE });
}
