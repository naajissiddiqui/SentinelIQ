/**
 * Cross-organization CTI sharing and access control, over HTTP against a real MongoDB.
 * Two genuinely separate organizations with their own users. Run ONLY against a disposable
 * local database:
 *
 *   MONGO_URI=mongodb://127.0.0.1:27999/sentineliq_disposable_test npx tsx src/tests/cti-sharing.db.test.ts
 *
 * Proves: a report is private by default; a recipient sees only what was shared with it; private
 * and unpublished reports never leak; sharing is enforced in the API, not just the UI; and a
 * recipient can verify a shared report's anchor.
 */
import assert from "node:assert";
import { Server } from "node:http";
import mongoose from "mongoose";
import { createApp } from "../app";
import { env } from "../config/env";
import { connectDatabase } from "../config/database";
import { OrganizationModel } from "../models/organization.model";
import { EndpointModel } from "../models/endpoint.model";
import { DetectionModel } from "../models/detection.model";
import { CTIReportModel } from "../models/ctiReport.model";
import { signAccessToken } from "../utils/jwt";

async function runTests() {
  const host = new URL(env.mongoUri.replace(/^mongodb(\+srv)?:/, "http:")).hostname;
  if (!["127.0.0.1", "localhost"].includes(host)) {
    throw new Error(`refusing to run: MONGO_URI host ${host} is not local; use a disposable database`);
  }
  console.log("=== Starting CTI cross-org sharing tests (disposable DB) ===");
  await connectDatabase();
  const server: Server = await new Promise((resolve) => createApp().listen(0, function (this: Server) { resolve(this); }));
  const base = `http://127.0.0.1:${(server.address() as any).port}/api`;

  const orgA = await OrganizationModel.create({ name: `Org A ${Date.now()}` });
  const orgB = await OrganizationModel.create({ name: `Org B ${Date.now()}` });
  const orgC = await OrganizationModel.create({ name: `Org C ${Date.now()}` });
  const adminA = signAccessToken({ userId: new mongoose.Types.ObjectId().toString(), role: "ORG_ADMIN", organizationId: orgA._id.toString() });
  const userB = signAccessToken({ userId: new mongoose.Types.ObjectId().toString(), role: "SECURITY_ANALYST", organizationId: orgB._id.toString() });
  const userC = signAccessToken({ userId: new mongoose.Types.ObjectId().toString(), role: "SECURITY_ANALYST", organizationId: orgC._id.toString() });

  const api = (token: string) => (method: string, path: string, body?: unknown) =>
    fetch(`${base}${path}`, {
      method, headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const A = api(adminA), B = api(userB), C = api(userC);
  const orgIds = { A: orgA._id.toString(), B: orgB._id.toString(), C: orgC._id.toString() };

  try {
    // Org A: a real persisted detection, then a published (anchor-less in this test) CTI report.
    const ep = await EndpointModel.create({ organizationId: orgA._id, name: "WS-A", status: "ONLINE", activationTokenHash: "x", lastCheckInAt: new Date() });
    const det = await DetectionModel.create({
      organizationId: orgA._id, endpointId: ep._id, endpointName: ep.name, attackType: "RANSOMWARE", ruleId: "RANSOMWARE-XGB",
      riskScore: 92, severity: "CRITICAL", indicators: [{ type: "PROCESS_ANOMALY", description: "mass rename", observedAt: new Date() }],
      detectedAt: new Date(), modelVersion: "xgboost-v1.0.0", dataOrigin: "LIVE",
    });
    const draftRes = await A("POST", "/cti", { detectionId: det._id.toString() });
    assert.strictEqual(draftRes.status, 201);
    const report = (await draftRes.json()).report;
    const rid = report._id;
    // Simulate a completed publish without sending a transaction.
    await CTIReportModel.updateOne({ _id: rid }, { $set: { status: "PUBLISHED", publishedAt: new Date(), contentHash: "a".repeat(64) } });

    // Default visibility is PRIVATE, so no other org sees it anywhere.
    assert.strictEqual(report.visibility, "PRIVATE");
    assert.strictEqual((await (await B("GET", "/cti/feed")).json()).reports.length, 0, "private report not in B's feed");
    assert.strictEqual((await B("GET", `/cti/${rid}`)).status, 404, "B cannot read A's private report (not even its existence)");
    console.log("  PASS: reports are private by default; another org sees nothing");

    // A cannot share a report it does not own? (B tries to share A's report.)
    assert.strictEqual((await B("POST", `/cti/${rid}/share`, { visibility: "SHARED_ALL" })).status, 404, "non-owner cannot change sharing");

    // Share with Org B only.
    const shareRes = await A("POST", `/cti/${rid}/share`, { visibility: "SHARED_SELECTED", sharedWithOrgIds: [orgIds.B] });
    assert.strictEqual(shareRes.status, 200);
    assert.strictEqual((await shareRes.json()).report.visibility, "SHARED_SELECTED");

    // B sees it; C does not.
    const feedB = (await (await B("GET", "/cti/feed")).json()).reports;
    assert.strictEqual(feedB.length, 1, "B sees the report shared with it");
    assert.strictEqual(feedB[0]._id, rid);
    const readB = await B("GET", `/cti/${rid}`);
    assert.strictEqual(readB.status, 200);
    const bodyB = await readB.json();
    assert.strictEqual(bodyB.owned, false, "B is not the owner");
    assert.ok(bodyB.report.attackSummary, "B can inspect the shared report's content");
    assert.strictEqual((await (await C("GET", "/cti/feed")).json()).reports.length, 0, "C sees nothing");
    assert.strictEqual((await C("GET", `/cti/${rid}`)).status, 404, "C cannot read a report not shared with it");
    console.log("  PASS: SHARED_SELECTED reaches the chosen org only; a third org is denied at the API");

    // Owner always sees its own published report, in its CTI Reports and in its own feed.
    assert.strictEqual((await A("GET", `/cti/${rid}`)).status, 200);
    const feedA = (await (await A("GET", "/cti/feed")).json()).reports;
    assert.strictEqual(feedA.length, 1, "owner's published report is in its own feed");
    assert.strictEqual(feedA[0]._id, rid);

    // Share with all: C now sees it too.
    assert.strictEqual((await A("POST", `/cti/${rid}/share`, { visibility: "SHARED_ALL" })).status, 200);
    assert.strictEqual((await (await C("GET", "/cti/feed")).json()).reports.length, 1, "SHARED_ALL reaches every org");

    // Revoke back to private: B and C lose access immediately.
    assert.strictEqual((await A("POST", `/cti/${rid}/share`, { visibility: "PRIVATE" })).status, 200);
    assert.strictEqual((await B("GET", `/cti/${rid}`)).status, 404, "revoking sharing removes access");
    assert.strictEqual((await (await C("GET", "/cti/feed")).json()).reports.length, 0);
    console.log("  PASS: SHARED_ALL reaches all; revocation removes access immediately");

    // Validation: cannot share a draft; bad visibility; empty selection; self-share.
    const draft2 = (await (await A("POST", "/cti", { detectionId: det._id.toString() })).json()).report;
    // (generateCTIDraft returns the existing published one's sibling draft only if none open; create a fresh detection)
    const det2 = await DetectionModel.create({ ...det.toObject(), _id: new mongoose.Types.ObjectId(), riskScore: 70, severity: "HIGH" });
    const freshDraft = (await (await A("POST", "/cti", { detectionId: det2._id.toString() })).json()).report;
    assert.strictEqual((await A("POST", `/cti/${freshDraft._id}/share`, { visibility: "SHARED_ALL" })).status, 400, "cannot share an unpublished draft");
    assert.strictEqual((await A("POST", `/cti/${rid}/share`, { visibility: "WORLD" })).status, 400, "invalid visibility rejected");
    assert.strictEqual((await A("POST", `/cti/${rid}/share`, { visibility: "SHARED_SELECTED", sharedWithOrgIds: [] })).status, 400, "selected requires a target");
    assert.strictEqual((await A("POST", `/cti/${rid}/share`, { visibility: "SHARED_SELECTED", sharedWithOrgIds: [orgIds.A] })).status, 400, "cannot share with self");
    assert.strictEqual((await A("POST", `/cti/${rid}/share`, { visibility: "SHARED_SELECTED", sharedWithOrgIds: [new mongoose.Types.ObjectId().toString()] })).status, 400, "unknown org rejected");
    void draft2;
    console.log("  PASS: sharing validation (draft, bad visibility, empty/self/unknown target)");

    // Recipient can verify a shared report's anchor (verification is read access + an on-chain check).
    await A("POST", `/cti/${rid}/share`, { visibility: "SHARED_ALL" });
    const verifyC = await C("POST", `/cti/${rid}/verify`);
    assert.strictEqual(verifyC.status, 200, "a recipient can verify a shared report");
    // (On-chain status is UNAVAILABLE here because no real RPC/anchor exists; the point is access is allowed.)
    assert.strictEqual((await C("POST", `/cti/${freshDraft._id}/verify`)).status, 404, "cannot verify a report not shared with you");

    // Share-targets lists other orgs only, never the caller's own.
    const targets = (await (await A("GET", "/cti/share-targets")).json()).organizations;
    const targetIds = targets.map((o: any) => o.id);
    assert.ok(targetIds.includes(orgIds.B) && targetIds.includes(orgIds.C), "other orgs are listed");
    assert.ok(!targetIds.includes(orgIds.A), "own org is not a share target");
    console.log("  PASS: recipient can verify; share-targets excludes self");

    console.log("=== ALL CTI SHARING TESTS PASSED! ===");
  } finally {
    const ids = [orgA._id, orgB._id, orgC._id];
    await Promise.all([
      CTIReportModel.deleteMany({ organizationId: { $in: ids } }),
      DetectionModel.deleteMany({ organizationId: { $in: ids } }),
      EndpointModel.deleteMany({ organizationId: { $in: ids } }),
      OrganizationModel.deleteMany({ _id: { $in: ids } }),
    ]);
    server.close();
    await mongoose.disconnect();
  }
}

runTests().catch((err) => {
  console.error("TEST FAILED:", err);
  process.exit(1);
});
