/**
 * Detection list pagination, filters and the organisation summary, over HTTP against
 * a real MongoDB. Run ONLY against a disposable local database:
 *
 *   MONGO_URI=mongodb://127.0.0.1:27999/sentineliq_disposable_test npx tsx src/tests/detections-api.db.test.ts
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
import { DetectionModel } from "../models/detection.model";
import { CTIReportModel } from "../models/ctiReport.model";
import { signAccessToken } from "../utils/jwt";

// TEST FIXTURES: a real trained-model alert and a heuristic alert from offline PCAP replay.
const trained = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "dos-trained-model-alert.fixture.json"), "utf-8"));
const heuristic = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "dos-pcap-replay-alert.fixture.json"), "utf-8"));

async function runTests() {
  const host = new URL(env.mongoUri.replace(/^mongodb(\+srv)?:/, "http:")).hostname;
  if (!["127.0.0.1", "localhost"].includes(host)) {
    throw new Error(`refusing to run: MONGO_URI host ${host} is not local; use a disposable database`);
  }
  console.log("=== Starting detections API tests (disposable DB) ===");
  await connectDatabase();
  const app = createApp();
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const baseUrl = `http://127.0.0.1:${(server.address() as any).port}`;
  const orgId = new mongoose.Types.ObjectId().toString();
  const token = signAccessToken({ userId: new mongoose.Types.ObjectId().toString(), role: "SECURITY_ANALYST", organizationId: orgId });
  const otherOrgToken = signAccessToken({ userId: new mongoose.Types.ObjectId().toString(), role: "ORG_ADMIN", organizationId: new mongoose.Types.ObjectId().toString() });
  const get = (url: string, t = token) => fetch(`${baseUrl}/api${url}`, { headers: { Authorization: `Bearer ${t}` } });
  const ingest = (body: Record<string, unknown>) =>
    fetch(`${baseUrl}/api/detections/ingest`, {
      method: "POST", headers: { "Content-Type": "application/json", "x-api-key": env.mlServiceApiKey },
      body: JSON.stringify(body),
    });

  try {
    const ep = await EndpointModel.create({
      organizationId: orgId, name: `TEST-SENSOR-${Date.now()}`, status: "ONLINE",
      activationTokenHash: "dummy", lastCheckInAt: new Date(),
    });
    const base = { organizationId: orgId, endpointId: ep._id.toString() };
    const bodies = [
      { ...base, riskScore: 92, indicators: ["Mass file encryption"], attackType: "RANSOMWARE" },
      { ...base, riskScore: 45, indicators: ["vssadmin delete shadows"], attackType: "RANSOMWARE" },
      { ...base, riskScore: 30, indicators: ["Unusual SMB session fan-out"], attackType: "LATERAL_MOVEMENT" },
      { ...trained, ...base, detectedAt: new Date().toISOString() },
      { ...heuristic, ...base, detectedAt: new Date().toISOString() },
      { ...trained, ...base, dataOrigin: "LIVE", detectedAt: new Date().toISOString() },
    ];
    for (const b of bodies) assert.strictEqual((await ingest(b)).status, 201);
    console.log(`1. Ingested ${bodies.length} detections`);

    const p1 = await (await get("/detections?page=1&limit=4")).json();
    assert.strictEqual(p1.total, 6);
    assert.strictEqual(p1.detections.length, 4);
    assert.strictEqual(p1.hasMore, true);
    const p2 = await (await get("/detections?page=2&limit=4")).json();
    assert.strictEqual(p2.detections.length, 2);
    assert.strictEqual(p2.hasMore, false);
    const ids = new Set([...p1.detections, ...p2.detections].map((d: any) => d._id));
    assert.strictEqual(ids.size, 6, "pages must not overlap or skip records");
    console.log("  PASS: pagination reports the true total, pages are disjoint and complete");

    const replay = await (await get("/detections?dataOrigin=PCAP_REPLAY")).json();
    assert.strictEqual(replay.total, 2);
    assert.ok(replay.detections.every((d: any) => d.dataOrigin === "PCAP_REPLAY"));
    const dos = await (await get("/detections?attackType=DOS_DDOS")).json();
    assert.strictEqual(dos.total, 3);
    assert.strictEqual((await get("/detections?page=0")).status, 400);
    assert.strictEqual((await get("/detections?limit=abc")).status, 400);
    assert.strictEqual((await (await get("/detections?limit=100000")).json()).limit, 200);
    console.log("  PASS: origin and type filters, input validation and the 200 page cap");

    const { summary } = await (await get("/detections/summary")).json();
    assert.strictEqual(summary.total, 6);
    assert.strictEqual(summary.active, 6);
    assert.deepStrictEqual(summary.byAttackType, { RANSOMWARE: 2, LATERAL_MOVEMENT: 1, DOS_DDOS: 3 });
    assert.deepStrictEqual(summary.byDataOrigin, { UNSPECIFIED: 3, PCAP_REPLAY: 2, LIVE: 1 });
    assert.deepStrictEqual(summary.byDetectorStatus, { UNSPECIFIED: 3, TRAINED: 2, HEURISTIC: 1 });
    const tech = Object.fromEntries(summary.techniques.map((t: any) => [t.techniqueId, t.count]));
    assert.deepStrictEqual(tech, { T1498: 3, T1486: 2, T1490: 1 });
    assert.strictEqual(summary.unmappedDetections, 1, "LATERAL_MOVEMENT has no evidence-based technique");
    assert.strictEqual(summary.timeline.length, 30);
    assert.strictEqual(summary.timeline.reduce((n: number, d: any) => n + d.count, 0), 6);
    console.log("  PASS: summary counts by type, origin, detector, ATT&CK technique and day");

    const lateral = p1.detections.concat(p2.detections).find((d: any) => d.attackType === "LATERAL_MOVEMENT");
    assert.deepStrictEqual(lateral.mitre, []);
    const ransom = p1.detections.concat(p2.detections).find((d: any) => d.attackType === "RANSOMWARE" && d.riskScore === 45);
    assert.ok(ransom.mitre.every((m: any) => typeof m.mappingReason === "string" && m.mappingReason.length > 0));
    console.log("  PASS: stored MITRE mappings carry reasons; unmapped types stay unmapped");

    // Demo-data safety: seeded records are labelled, and CTI built from them is labelled in its hashed content.
    const admin = signAccessToken({ userId: new mongoose.Types.ObjectId().toString(), role: "ORG_ADMIN", organizationId: orgId });
    const demoRes = await ingest({ ...base, riskScore: 95, attackType: "RANSOMWARE", dataOrigin: "DEMO",
                                   ruleId: "DEMO-SEED-99", indicators: ["Seeded demo indicator"] });
    assert.strictEqual(demoRes.status, 201);
    const demo = (await demoRes.json()).detection;
    assert.strictEqual(demo.dataOrigin, "DEMO");
    assert.ok(demo.mitre.length > 0 && demo.mitre.every((m: any) => m.mappingReason.startsWith("Demonstration data, not an observation")),
      "demo MITRE reasons must not read as observed behaviour");
    assert.ok(ransom.mitre.every((m: any) => !/Demonstration/.test(m.mappingReason)));
    const legacy = await DetectionModel.create({            // seeded before dataOrigin existed
      organizationId: orgId, endpointId: ep._id, endpointName: ep.name, attackType: "RANSOMWARE", ruleId: "DEMO-SEED-16",
      riskScore: 95, severity: "CRITICAL", indicators: [], detectedAt: new Date(), modelVersion: "xgboost-v1.0.0",
    });
    for (const id of [demo._id, legacy._id.toString()]) {
      const draftRes = await fetch(`${baseUrl}/api/cti`, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${admin}` },
        body: JSON.stringify({ detectionId: id }),
      });
      assert.strictEqual(draftRes.status, 201);
      const report = (await draftRes.json()).report;
      assert.match(report.title, /^\[DEMO\] /, "CTI from demo data is titled [DEMO]");
      assert.match(report.attackSummary, /^DEMONSTRATION RECORD - NOT THREAT INTELLIGENCE/);
    }
    const realDraft = await fetch(`${baseUrl}/api/cti`, {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${admin}` },
      body: JSON.stringify({ detectionId: ransom._id }),
    });
    const realReport = (await realDraft.json()).report;
    assert.doesNotMatch(realReport.title, /DEMO/);
    assert.doesNotMatch(realReport.attackSummary, /DEMONSTRATION RECORD/);
    // Draft edits persist every editable list, not only the summary and notes.
    const patch = (body: unknown) => fetch(`${baseUrl}/api/cti/${realReport._id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json", Authorization: `Bearer ${admin}` }, body: JSON.stringify(body),
    });
    const edited = await patch({ indicatorsOfCompromise: ["vssadmin delete shadows /all"], recommendedActions: ["Restore from offline backup"] });
    assert.strictEqual(edited.status, 200);
    const stored = await CTIReportModel.findById(realReport._id);
    assert.deepStrictEqual(stored!.indicatorsOfCompromise, ["vssadmin delete shadows /all"]);
    assert.deepStrictEqual(stored!.recommendedActions, ["Restore from offline backup"]);
    assert.strictEqual((await patch({ indicatorsOfCompromise: "not-a-list" })).status, 400);
    assert.strictEqual((await patch({ recommendedActions: [""] })).status, 400);
    // Ordinary views list incidents only; test records stay stored and are returned on request.
    const sim = await ingest({ ...base, riskScore: 80, attackType: "RANSOMWARE", dataOrigin: "SIMULATED", indicators: ["Simulated encryption burst"] });
    assert.strictEqual(sim.status, 201);
    const s2 = (await (await get("/detections/summary")).json()).summary;
    assert.strictEqual(s2.total, 6, "demo and simulated records are not counted as incidents");
    assert.strictEqual(s2.testRecords, 3);
    assert.strictEqual(s2.scope, "incidents");
    assert.strictEqual(s2.byDataOrigin.DEMO, undefined);
    const listed = await (await get("/detections?limit=200")).json();
    assert.strictEqual(listed.total, 6);
    assert.ok(listed.detections.every((d: any) => !["DEMO", "SIMULATED"].includes(d.dataOrigin) && !/^DEMO-/.test(d.ruleId ?? "")));
    const tests = await (await get("/detections?scope=test")).json();
    assert.strictEqual(tests.total, 3);
    assert.strictEqual((await (await get("/detections?scope=all")).json()).total, 9);
    assert.strictEqual((await (await get("/detections/summary?scope=test")).json()).summary.byDataOrigin.DEMO, 1);
    assert.strictEqual((await get("/detections?scope=everything")).status, 400);
    assert.strictEqual((await get(`/detections/${legacy._id}`)).status, 200, "a test record is still reachable directly");
    // The owner's own CTI Center lists all their reports, including demo ones (the UI labels them).
    const ctiDefault = (await (await get("/cti")).json()).reports;
    assert.ok(ctiDefault.some((r: any) => /^\[DEMO\]/.test(r.title)), "owner sees their own demo reports (labelled) in their CTI Center");
    assert.strictEqual((await (await get("/cti?scope=incidents")).json()).reports.every((r: any) => !/^\[DEMO\]/.test(r.title)), true);
    assert.strictEqual((await (await get("/cti?scope=test")).json()).reports.length, 2);
    // ...but demo reports never reach the cross-organization feed, even when shared-eligible.
    assert.strictEqual((await (await get("/cti/feed")).json()).reports.length, 0);
    console.log("  PASS: test records are excluded from ordinary listings and summaries, available with scope=test");
    await CTIReportModel.deleteMany({ organizationId: orgId });
    console.log("  PASS: demo detections and CTI drafts built from them are labelled; real drafts are not");

    const other = await (await get("/detections/summary", otherOrgToken)).json();
    assert.strictEqual(other.summary.total, 0, "another organization must not see these detections");
    assert.strictEqual((await fetch(`${baseUrl}/api/detections/summary`)).status, 401);
    console.log("  PASS: summary is organization-scoped and requires authentication");

    console.log("=== ALL DETECTIONS API TESTS PASSED! ===");
  } finally {
    await Promise.all([DetectionModel.deleteMany({ organizationId: orgId }), EndpointModel.deleteMany({ organizationId: orgId }),
      CTIReportModel.deleteMany({ organizationId: orgId })]);
    server.close();
    await mongoose.disconnect();
  }
}

runTests().catch((err) => {
  console.error("TEST FAILED:", err);
  process.exit(1);
});
