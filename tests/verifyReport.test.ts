/**
 * Integration tests for server-side verification (src/lib/server).
 * Test IDs (TC-xx) match docs/TEST_CASES.md.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { publicJwk, signJws, verifyJws } from "@/lib/server/attestation";
import { verifyReport } from "@/lib/server/verifyReport";
import type { AttestationClaims } from "@/types";
import { buildSignedReport, replayFlashSteps } from "./fixtures";

const failedChecks = (r: Awaited<ReturnType<typeof verifyReport>>) => r.checks.filter((c) => !c.passed).map((c) => c.name);

describe("Server verification", () => {
  test("TC-26 a valid report is verified and receives a signed attestation", async () => {
    const report = await buildSignedReport();
    const r = await verifyReport(report);
    assert.equal(r.verified, true, failedChecks(r).join(", "));
    assert.equal(r.serverResult?.decision, "BONA_FIDE");
    assert.equal(r.clientServerAgree, true);
    const claims = verifyJws<AttestationClaims>(r.attestation ?? "");
    assert.ok(claims);
    assert.equal(claims.sub, report.sessionId);
    assert.equal(claims.referenceImageSha256, report.referenceImage?.sha256);
  });

  test("TC-27 the same report cannot be verified twice", async () => {
    const report = await buildSignedReport();
    assert.equal((await verifyReport(report)).verified, true);
    const again = await verifyReport(report);
    assert.equal(again.verified, false);
    assert.deepEqual(failedChecks(again), ["Single use"]);
  });

  test("TC-28 an edited audit event is rejected", async () => {
    const report = await buildSignedReport();
    report.events[1] = { ...report.events[1], message: "edited" };
    const r = await verifyReport(report);
    assert.equal(r.verified, false);
    assert.ok(failedChecks(r).includes("Audit hash chain"));
  });

  test("TC-29 a forged session plan is rejected", async () => {
    const report = await buildSignedReport();
    report.signedPlan.token = report.signedPlan.token.slice(0, -4) + "AAAA";
    const r = await verifyReport(report);
    assert.equal(r.verified, false);
    assert.deepEqual(failedChecks(r), ["Plan signature"]);
  });

  test("TC-30 challenges chosen by the client are rejected", async () => {
    const report = await buildSignedReport();
    report.plannedChallenges = ["BLINK", "SMILE", "OPEN_MOUTH"];
    const r = await verifyReport(report);
    assert.equal(r.verified, false);
    assert.ok(failedChecks(r).includes("Plan binding"));
  });

  test("TC-31 inconsistent screen-flash data is rejected", async () => {
    const report = await buildSignedReport();
    if (!report.photometric) throw new Error("fixture has no photometric data");
    report.photometric.steps = replayFlashSteps(report.photometric.sequence, 0.03); // keep the client's claimed correlation
    const r = await verifyReport(report);
    assert.equal(r.verified, false);
    assert.ok(failedChecks(r).includes("Screen-flash recomputation"));
  });

  test("TC-32 inhumanly fast responses are rejected", async () => {
    const report = await buildSignedReport();
    report.challenges[0] = { ...report.challenges[0], responseTimeMs: 40 };
    const r = await verifyReport(report);
    assert.equal(r.verified, false);
    assert.ok(failedChecks(r).includes("Human response times"));
  });

  test("TC-33 an expired plan is rejected", async () => {
    const report = await buildSignedReport();
    const later = Date.parse(report.signedPlan.plan.expiresAt) + 60 * 60 * 1000;
    const r = await verifyReport(report, later);
    assert.equal(r.verified, false);
    assert.ok(failedChecks(r).includes("Plan not expired"));
  });

  test("TC-34 the server's decision overrides a client claiming BONA_FIDE", async () => {
    const report = await buildSignedReport();
    // Flat photo: every head turn shows planar motion (a plan may contain both turns).
    report.challenges = report.challenges.map((c) => (c.depthResidual !== null ? { ...c, depthResidual: 0.004 } : c));
    const r = await verifyReport(report);
    assert.equal(report.result?.decision, "BONA_FIDE");
    assert.equal(r.serverResult?.decision, "ATTACK");
    assert.equal(r.claims?.referenceImageSha256 ?? null, null);
  });

  test("TC-35 attestations verify with the published key and reject tampering", () => {
    const token = signJws({ hello: "world" });
    assert.deepEqual(verifyJws(token), { hello: "world" });
    const [h, , s] = token.split(".");
    const forged = `${h}.${Buffer.from(JSON.stringify({ hello: "mallory" })).toString("base64url")}.${s}`;
    assert.equal(verifyJws(forged), null);
    assert.equal(publicJwk().crv, "Ed25519");
  });
});
