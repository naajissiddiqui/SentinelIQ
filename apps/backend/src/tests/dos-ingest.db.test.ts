/**
 * DOS_DDOS end to end over HTTP against a real MongoDB. Run it ONLY against a
 * disposable database, for example:
 *
 *   MONGO_URI=mongodb://127.0.0.1:27999/sentineliq_disposable_test npx tsx src/tests/dos-ingest.db.test.ts
 *
 * It refuses to run against a non-local MONGO_URI. The DoS detection is a TEST
 * FIXTURE: a real alert from the trained XGBoost bundle scoring a held-out
 * CIC-DDoS2019 capture offline (see the fixture's _fixture note).
 */
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { Server } from "node:http";
import mongoose from "mongoose";
import { createApp } from "../app";
import { env } from "../config/env";
import { connectDatabase } from "../config/database";
import { EndpointModel } from "../models/endpoint.model";
import { EndpointActionModel } from "../models/endpointAction.model";
import { DetectionModel } from "../models/detection.model";
import { PolicyModel } from "../models/policy.model";
import { CascadeModel } from "../models/cascade.model";
import { signAccessToken } from "../utils/jwt";

const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "fixtures", "dos-trained-model-alert.fixture.json"), "utf-8")
);

async function runTests() {
  const host = new URL(env.mongoUri.replace(/^mongodb(\+srv)?:/, "http:")).hostname;
  if (!["127.0.0.1", "localhost"].includes(host)) {
    throw new Error(`refusing to run: MONGO_URI host ${host} is not local; use a disposable database`);
  }
  console.log("=== Starting DOS_DDOS ingest tests (disposable DB) ===");
  await connectDatabase();
  const app = createApp();
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const baseUrl = `http://127.0.0.1:${(server.address() as any).port}`;
  const orgId = new mongoose.Types.ObjectId().toString();
  const admin = signAccessToken({ userId: new mongoose.Types.ObjectId().toString(), role: "ORG_ADMIN", organizationId: orgId });

  const ingest = (body: Record<string, unknown>) =>
    fetch(`${baseUrl}/api/detections/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": env.mlServiceApiKey },
      body: JSON.stringify(body),
    });

  try {
    const sensor = await EndpointModel.create({
      organizationId: orgId, name: `TEST-NETWORK-SENSOR-${Date.now()}`, status: "ONLINE",
      activationTokenHash: "dummy_sensor", lastCheckInAt: new Date(),
    });
    const workstation = await EndpointModel.create({
      organizationId: orgId, name: `TEST-WORKSTATION-${Date.now()}`, status: "ONLINE",
      activationTokenHash: "dummy_ws", lastCheckInAt: new Date(),
    });
    // A ransomware-oriented rule that would isolate anything with riskScore > 10.
    const isolatePolicy = await PolicyModel.create({
      organizationId: orgId, name: "TEST ransomware isolate", enabled: true, priority: 50, cooldownPeriodSeconds: 0,
      conditions: [{ field: "riskScore", operator: "GREATER_THAN", value: 10 }],
      actions: [{ type: "ISOLATE_ENDPOINT" }],
    });

    console.log("1. Ingesting the trained-model DoS alert...");
    const res = await ingest({ ...fixture, organizationId: orgId, endpointId: sensor._id.toString() });
    assert.strictEqual(res.status, 201, `expected 201, got ${res.status}: ${await res.clone().text()}`);
    const det = (await res.json()).detection;
    assert.strictEqual(det.attackType, "DOS_DDOS");
    assert.strictEqual(det.dataOrigin, "PCAP_REPLAY");
    assert.strictEqual(det.detectorStatus, "TRAINED");
    assert.strictEqual(det.modelVersion, fixture.modelVersion);
    assert.strictEqual(det.ruleId, "DOS-XGB");
    assert.deepStrictEqual(det.mitre.map((m: any) => m.techniqueId), ["T1498"]);
    assert.ok(det.evidence.some((e: any) => e.id === "dos-prediction" && e.fields.threshold > 0));
    console.log("  PASS: stored with origin, detector status, model version, evidence and T1498");

    // Replaying the same alert episode returns the stored detection instead of a second one.
    const again = await ingest({ ...fixture, organizationId: orgId, endpointId: sensor._id.toString() });
    assert.strictEqual(again.status, 200);
    const againBody = await again.json();
    assert.strictEqual(againBody.duplicate, true);
    assert.strictEqual(againBody.detection._id, det._id);
    assert.strictEqual(await DetectionModel.countDocuments({ organizationId: orgId }), 1);
    const later = await ingest({ ...fixture, organizationId: orgId, endpointId: sensor._id.toString(),
                                 detectedAt: new Date(Date.parse(fixture.detectedAt) + 60_000).toISOString() });
    assert.strictEqual(later.status, 201, "a different episode is a new detection");
    await DetectionModel.deleteOne({ _id: (await later.json()).detection._id });
    assert.strictEqual((await ingest({ ...fixture, organizationId: orgId, endpointId: sensor._id.toString(), detectedAt: "not-a-date" })).status, 400);
    console.log("  PASS: a replayed alert episode is deduplicated (200, same detection); a new episode is stored");

    const sensorAfter = await EndpointModel.findById(sensor._id);
    assert.strictEqual(sensorAfter?.status, "ONLINE", "a DoS alert must not move the endpoint to AT_RISK or ISOLATED");
    assert.strictEqual(await EndpointActionModel.countDocuments({ endpointId: sensor._id }), 0);
    assert.strictEqual((await PolicyModel.findById(isolatePolicy._id))?.triggerCount, 0);
    assert.strictEqual(await CascadeModel.countDocuments({ organizationId: orgId }), 0);
    console.log("  PASS: alert-only (no AT_RISK, no isolation, ransomware policy not triggered, no cascade)");

    console.log("2. Invalid DoS payloads are rejected...");
    const base = { ...fixture, organizationId: orgId, endpointId: sensor._id.toString() };
    for (const [why, body] of [
      ["missing dataOrigin", { ...base, dataOrigin: undefined }],
      ["synthetic detector", { ...base, detectorStatus: "SYNTHETIC_TEST_ONLY" }],
      ["confirmed tier", { ...base, confidenceTier: "confirmed" }],
      ["malformed endpointId", { ...base, endpointId: base.endpointId + "\r" }],
      ["malformed organizationId", { ...base, organizationId: "not-an-id" }],
    ] as const) {
      const r = await ingest(body as Record<string, unknown>);
      assert.strictEqual(r.status, 400, `${why}: expected 400, got ${r.status}`);
    }
    console.log("  PASS: 400 for missing origin, synthetic detector, 'confirmed' and malformed ids");

    console.log("3. CTI draft for the DoS detection is refused...");
    const cti = await fetch(`${baseUrl}/api/cti`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${admin}` },
      body: JSON.stringify({ detectionId: det._id }),
    });
    assert.strictEqual(cti.status, 422, `expected 422, got ${cti.status}`);
    console.log("  PASS: 422 unsupported operation");

    console.log("4. Ransomware regression on the same org and policy...");
    const rres = await ingest({
      organizationId: orgId, endpointId: workstation._id.toString(), riskScore: 95,
      indicators: [{ type: "FILE_ENCRYPTION_BURST", description: "Rapid mass encryption", observedAt: new Date().toISOString() }],
    });
    assert.strictEqual(rres.status, 201);
    const rdet = (await rres.json()).detection;
    assert.strictEqual(rdet.attackType, "RANSOMWARE");
    assert.deepStrictEqual(rdet.mitre.map((m: any) => m.techniqueId), ["T1486"]);
    const wsAfter = await EndpointModel.findById(workstation._id);
    assert.strictEqual(wsAfter?.status, "ISOLATED", "the ransomware policy must still isolate");
    assert.strictEqual((await PolicyModel.findById(isolatePolicy._id))?.triggerCount, 1);
    console.log("  PASS: ransomware detection still isolates via the same policy");

    console.log("=== ALL DOS_DDOS INGEST TESTS PASSED! ===");
  } finally {
    await Promise.all([
      DetectionModel.deleteMany({ organizationId: orgId }),
      EndpointModel.deleteMany({ organizationId: orgId }),
      EndpointActionModel.deleteMany({ organizationId: orgId }),
      PolicyModel.deleteMany({ organizationId: orgId }),
    ]);
    server.close();
    await mongoose.disconnect();
  }
}

runTests().catch((err) => {
  console.error("TEST FAILED:", err);
  process.exit(1);
});
