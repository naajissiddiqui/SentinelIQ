/**
 * DOS_DDOS integration safety tests. No database: Mongoose statics are stubbed
 * with node:test mocks, and bufferCommands is off so any unstubbed query fails
 * immediately instead of waiting for a connection.
 *
 * The detection used end-to-end is a TEST FIXTURE produced by
 * sensor/demo/offline_demo.py (PCAP replay, pps HEURISTIC, not a trained model).
 */
import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import mongoose from "mongoose";

import {
  assertCtiDraftSupported,
  DEMO_CTI_LABEL,
  isDemoDetection,
  isActionAllowed,
  normalizeAttackType,
  policyAppliesToDetection,
  responseProfile,
  validateIngestFields,
  isTestRecord,
  parseRecordScope,
  scopeFilter,
  sourceAlertKey,
} from "../services/detectionProfile";
import { deriveMitreForDetection, getMitreMappingsForRule } from "../utils/mitre";
import { createDetection } from "../services/detection.service";
import { DetectionModel } from "../models/detection.model";
import { EndpointModel } from "../models/endpoint.model";
import { EndpointActionModel } from "../models/endpointAction.model";
import { PolicyModel } from "../models/policy.model";
import { TimelineEventModel } from "../models/timelineEvent.model";
import { CascadeModel } from "../models/cascade.model";
import { threatIntelService } from "../services/cti/threatIntel.service";

mongoose.set("bufferCommands", false);

const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "fixtures", "dos-pcap-replay-alert.fixture.json"), "utf-8")
);
// A real alert from the trained XGBoost bundle on held-out PCAP-replay windows (see the file's _fixture note).
const trainedFixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "fixtures", "dos-trained-model-alert.fixture.json"), "utf-8")
);

function assertAppError(fn: () => unknown, status: number, pattern: RegExp) {
  assert.throws(fn, (err: any) => err.statusCode === status && pattern.test(err.message));
}

describe("DOS_DDOS ingest validation", () => {
  it("accepts the offline-demo fixture and keeps its origin and detector status", () => {
    const out = validateIngestFields(fixture);
    assert.deepStrictEqual(out, { attackType: "DOS_DDOS", dataOrigin: "PCAP_REPLAY", detectorStatus: "HEURISTIC" });
  });

  it("requires dataOrigin and a real detector status, and refuses 'confirmed'", () => {
    assertAppError(() => validateIngestFields({ ...fixture, dataOrigin: undefined }), 400, /dataOrigin/);
    assertAppError(() => validateIngestFields({ ...fixture, dataOrigin: "SYNTHETIC_LIVE" }), 400, /dataOrigin/);
    // SIMULATED is a valid, explicit origin (agent simulator): accepted and kept, never turned into LIVE.
    assert.strictEqual(validateIngestFields({ ...fixture, dataOrigin: "SIMULATED" }).dataOrigin, "SIMULATED");
    assertAppError(() => validateIngestFields({ ...fixture, detectorStatus: "SYNTHETIC_TEST_ONLY" }), 400, /synthetic/);
    assertAppError(() => validateIngestFields({ ...fixture, detectorStatus: undefined }), 400, /detectorStatus/);
    assertAppError(() => validateIngestFields({ ...fixture, confidenceTier: "confirmed" }), 400, /confirmed/);
  });

  it("accepts a trained-model alert with its model version, score and threshold evidence", () => {
    assert.deepStrictEqual(validateIngestFields(trainedFixture),
      { attackType: "DOS_DDOS", dataOrigin: "PCAP_REPLAY", detectorStatus: "TRAINED" });
    assert.strictEqual(trainedFixture.ruleId, "DOS-XGB");
    assert.match(trainedFixture.modelVersion, /^dos-xgb-/);
    const pred = trainedFixture.evidence.find((e: any) => e.id === "dos-prediction").fields;
    assert.ok(pred.score >= pred.threshold);
    assert.strictEqual(pred.detectorStatus, "TRAINED");
    assert.deepStrictEqual(deriveMitreForDetection("DOS_DDOS", "DOS-XGB", [], trainedFixture.evidence).map((m) => m.techniqueId), ["T1498"]);
  });

  it("leaves existing producers alone", () => {
    assert.strictEqual(normalizeAttackType(undefined), "RANSOMWARE");
    assert.deepStrictEqual(validateIngestFields({ attackType: "PRIVILEGE_ESCALATION", confidenceTier: "confirmed" }),
      { attackType: "PRIVILEGE_ESCALATION", dataOrigin: undefined });
    assert.strictEqual(normalizeAttackType("LATERAL_MOVEMENT"), "LATERAL_MOVEMENT"); // seeded/legacy types
    assertAppError(() => normalizeAttackType("dos ddos; drop"), 400, /attackType/);
  });
});

describe("Response profiles and policy guards", () => {
  const isolateOnRisk = { conditions: [{ field: "riskScore", operator: "GREATER_THAN", value: 50 }] };
  const dosPolicy = { conditions: [{ field: "detectionType", operator: "EQUALS", value: "DOS_DDOS" }] };

  it("makes DoS alert-only while ransomware keeps its full response", () => {
    const dos = responseProfile("DOS_DDOS");
    assert.strictEqual(dos.markEndpointAtRisk, false);
    assert.strictEqual(dos.runCascadeCorrelation, false);
    assert.strictEqual(dos.allowIsolation, false);
    assert.strictEqual(dos.ctiDraftSupported, false);
    const ransomware = responseProfile("RANSOMWARE");
    assert.deepStrictEqual(
      [ransomware.markEndpointAtRisk, ransomware.runCascadeCorrelation, ransomware.runPolicies, ransomware.allowIsolation],
      [true, true, true, true]
    );
    assert.deepStrictEqual(responseProfile("LATERAL_MOVEMENT"), ransomware); // unknown types unchanged
    assert.strictEqual(responseProfile("PRIVILEGE_ESCALATION").runPolicies, false);
  });

  it("never lets a ransomware-oriented risk-score rule apply to DoS", () => {
    assert.strictEqual(policyAppliesToDetection(isolateOnRisk, "DOS_DDOS"), false);
    assert.strictEqual(policyAppliesToDetection(dosPolicy, "DOS_DDOS"), true);
    assert.strictEqual(policyAppliesToDetection(isolateOnRisk, "RANSOMWARE"), true);
    assert.strictEqual(
      policyAppliesToDetection({ conditions: [{ field: "detectionType", operator: "NOT_EQUALS", value: "DOS_DDOS" }] }, "DOS_DDOS"),
      false
    );
  });

  it("blocks isolation for DoS whatever the policy says", () => {
    assert.strictEqual(isActionAllowed("ISOLATE_ENDPOINT", "DOS_DDOS"), false);
    assert.strictEqual(isActionAllowed("MARK_HIGH_RISK", "DOS_DDOS"), true);
    assert.strictEqual(isActionAllowed("ISOLATE_ENDPOINT", "RANSOMWARE"), true);
  });
});

describe("MITRE and CTI for DOS_DDOS", () => {
  it("maps DoS to T1498 and never to ransomware T1486", () => {
    for (const ruleId of ["DOS-XGB", "DOS-PPS-HEURISTIC", undefined]) {
      const ids = deriveMitreForDetection("DOS_DDOS", ruleId, [], []).map((m) => m.techniqueId);
      assert.deepStrictEqual(ids, ["T1498"], String(ruleId));
    }
    assert.deepStrictEqual(getMitreMappingsForRule("RANSOMWARE-XGB").map((m) => m.techniqueId), ["T1486"]);
    assert.deepStrictEqual(deriveMitreForDetection("RANSOMWARE", undefined, [], []).map((m) => m.techniqueId), ["T1486"]);
  });

  it("gives every assigned technique a reason, and no technique without an evidence basis", () => {
    const cases: Array<[string | undefined, string | undefined, any[], string[]]> = [
      ["DOS_DDOS", undefined, [], ["T1498"]],
      ["RANSOMWARE", undefined, [], ["T1486"]],
      [undefined, undefined, [], ["T1486"]],
      ["RANSOMWARE", undefined, [{ type: "PROCESS", description: "vssadmin delete shadows /all" }], ["T1486", "T1490"]],
      ["PRIVILEGE_ESCALATION", "PE-04-SERVICE", [], ["T1543.003"]],
    ];
    for (const [type, rule, indicators, expected] of cases) {
      const mappings = deriveMitreForDetection(type, rule, indicators, []);
      assert.deepStrictEqual(mappings.map((m) => m.techniqueId), expected, `${type}/${rule}`);
      for (const m of mappings) assert.ok(m.mappingReason && m.mappingReason.length > 10, `${m.techniqueId} has no reason`);
    }
    assert.match(deriveMitreForDetection("DOS_DDOS", undefined, [], [])[0].mappingReason!, /No sub-technique/);
    // Types without an evidence-based mapping are left unmapped instead of borrowing ransomware's T1486.
    for (const type of ["LATERAL_MOVEMENT", "DATA_EXFILTRATION", "CREDENTIAL_ACCESS"]) {
      assert.deepStrictEqual(deriveMitreForDetection(type, undefined, [{ type: "X", description: "shadow copies" }], []), [], type);
    }
  });

  it("recognises demo data, including seeded records that predate dataOrigin", () => {
    assert.strictEqual(isDemoDetection({ dataOrigin: "DEMO" }), true);
    assert.strictEqual(isDemoDetection({ ruleId: "DEMO-SEED-16" }), true);
    assert.strictEqual(isDemoDetection({ modelVersion: "DEMO-seed-xgboost-v1.0.0" }), true);
    assert.strictEqual(isDemoDetection({ ruleId: "RANSOMWARE-XGB", dataOrigin: "LIVE" }), false);
    assert.strictEqual(isDemoDetection(fixture), false);
    assert.strictEqual(validateIngestFields({ attackType: "RANSOMWARE", dataOrigin: "DEMO" }).dataOrigin, "DEMO");
    assert.match(DEMO_CTI_LABEL, /^DEMONSTRATION RECORD - NOT THREAT INTELLIGENCE/);
  });

  it("refuses CTI drafts for DoS and allows them for ransomware", () => {
    assertAppError(() => assertCtiDraftSupported("DOS_DDOS"), 422, /not supported/);
    assert.doesNotThrow(() => assertCtiDraftSupported("RANSOMWARE"));
    assert.doesNotThrow(() => assertCtiDraftSupported("LATERAL_MOVEMENT"));
  });
});

describe("createDetection end to end (stubbed models)", () => {
  const orgId = new mongoose.Types.ObjectId().toString();
  const endpointId = new mongoose.Types.ObjectId();
  let calls: Record<string, number>;
  let endpoint: any;
  let triggered: string[];

  const policies = () => [
    {
      _id: new mongoose.Types.ObjectId(), name: "Ransomware: isolate on high risk", logicalOperator: "AND",
      cooldownPeriodSeconds: 0, triggerCount: 0,
      conditions: [{ field: "riskScore", operator: "GREATER_THAN", value: 50 }],
      actions: [{ type: "ISOLATE_ENDPOINT" }],
      save: async function () { triggered.push(this.name); },
    },
    {
      _id: new mongoose.Types.ObjectId(), name: "DoS: escalate (misconfigured with isolation)", logicalOperator: "AND",
      cooldownPeriodSeconds: 0, triggerCount: 0,
      conditions: [{ field: "detectionType", operator: "EQUALS", value: "DOS_DDOS" }],
      actions: [{ type: "ISOLATE_ENDPOINT" }, { type: "MARK_HIGH_RISK" }],
      save: async function () { triggered.push(this.name); },
    },
  ];

  beforeEach(() => {
    calls = { endpointSave: 0, cascadeQueries: 0, isolationActions: 0, markHighRisk: 0, timeline: 0 };
    triggered = [];
    endpoint = {
      _id: endpointId, organizationId: new mongoose.Types.ObjectId(orgId), name: "network-sensor-pcap-replay",
      status: "ONLINE", save: async () => { calls.endpointSave += 1; },
    };
    mock.method(EndpointModel, "findOne", async () => endpoint);
    mock.method(threatIntelService, "correlateDetection", async () => ({ matched: false }));
    mock.method(DetectionModel, "create", async (doc: any) => ({ ...doc, _id: new mongoose.Types.ObjectId() }));
    mock.method(DetectionModel, "countDocuments", async () => 1);
    mock.method(DetectionModel, "find", () => { calls.cascadeQueries += 1; return { sort: async () => [] }; });
    mock.method(DetectionModel, "updateOne", async () => { calls.markHighRisk += 1; return {}; });
    mock.method(CascadeModel, "findOne", async () => { calls.cascadeQueries += 1; return null; });
    mock.method(EndpointActionModel, "create", async () => { calls.isolationActions += 1; return { _id: new mongoose.Types.ObjectId() }; });
    mock.method(TimelineEventModel, "create", async (doc: any) => { calls.timeline += 1; return doc; });
    mock.method(PolicyModel, "find", () => ({ sort: async () => policies() }));
  });

  afterEach(() => mock.restoreAll());

  function input(overrides: Record<string, unknown> = {}) {
    const checked = validateIngestFields({ ...fixture, ...overrides });
    return {
      organizationId: orgId, endpointId: endpointId.toString(), riskScore: fixture.riskScore,
      indicators: fixture.indicators, modelVersion: fixture.modelVersion, detectedAt: new Date(fixture.detectedAt),
      ruleId: fixture.ruleId, confidenceTier: fixture.confidenceTier, evidence: fixture.evidence,
      ...checked,
    };
  }

  it("DoS: no AT_RISK, no cascade, no isolation, no ransomware policy; T1498 and origin stored", async () => {
    const detection: any = await createDetection(input());
    assert.strictEqual(endpoint.status, "ONLINE");
    assert.strictEqual(calls.endpointSave, 0);
    assert.strictEqual(calls.cascadeQueries, 0);
    assert.strictEqual(calls.isolationActions, 0);
    assert.deepStrictEqual(triggered, ["DoS: escalate (misconfigured with isolation)"]);
    assert.strictEqual(calls.markHighRisk, 1); // the allowed action of the explicit DoS policy ran
    assert.deepStrictEqual(detection.mitre.map((m: any) => m.techniqueId), ["T1498"]);
    assert.strictEqual(detection.attackType, "DOS_DDOS");
    assert.strictEqual(detection.dataOrigin, "PCAP_REPLAY");
    assert.strictEqual(detection.detectorStatus, "HEURISTIC");
  });

  it("trained-model DoS alert stays alert-only through the real service path", async () => {
    const checked = validateIngestFields(trainedFixture);
    const detection: any = await createDetection({
      organizationId: orgId, endpointId: endpointId.toString(), riskScore: trainedFixture.riskScore,
      indicators: trainedFixture.indicators, modelVersion: trainedFixture.modelVersion, ruleId: trainedFixture.ruleId,
      confidenceTier: trainedFixture.confidenceTier, evidence: trainedFixture.evidence,
      detectedAt: new Date(trainedFixture.detectedAt), ...checked,
    });
    assert.strictEqual(endpoint.status, "ONLINE");
    assert.strictEqual(calls.cascadeQueries, 0);
    assert.strictEqual(calls.isolationActions, 0);
    assert.strictEqual(detection.detectorStatus, "TRAINED");
    assert.strictEqual(detection.modelVersion, trainedFixture.modelVersion);
    assert.deepStrictEqual(detection.mitre.map((m: any) => m.techniqueId), ["T1498"]);
  });

  it("ransomware regression: AT_RISK, cascade lookup and isolation still happen", async () => {
    const detection: any = await createDetection({
      organizationId: orgId, endpointId: endpointId.toString(), riskScore: 92,
      indicators: ["Mass file encryption pattern"], attackType: "RANSOMWARE",
    });
    assert.strictEqual(calls.endpointSave >= 1, true);
    assert.strictEqual(calls.cascadeQueries >= 1, true);
    assert.strictEqual(calls.isolationActions, 1);
    assert.deepStrictEqual(triggered, ["Ransomware: isolate on high risk"]);
    assert.deepStrictEqual(detection.mitre.map((m: any) => m.techniqueId), ["T1486"]);
  });
});

describe("test-record scoping and alert-episode identity", () => {
  it("treats demo and simulated records as test records, everything else as incidents", () => {
    assert.strictEqual(isTestRecord({ dataOrigin: "SIMULATED" }), true);
    assert.strictEqual(isTestRecord({ ruleId: "DEMO-SEED-3" }), true);
    assert.strictEqual(isTestRecord({ dataOrigin: "PCAP_REPLAY", ruleId: "DOS-XGB" }), false);
    assert.strictEqual(isTestRecord({ dataOrigin: "LIVE" }), false);
    assert.strictEqual(parseRecordScope(undefined), "incidents");
    assert.strictEqual(parseRecordScope("all"), "all");
    assert.throws(() => parseRecordScope("everything"));
    assert.deepStrictEqual(scopeFilter("all"), {});
    assert.ok("$nor" in scopeFilter("incidents"));
  });

  it("gives one key per sensor alert episode, and none to payloads without their own time or rule", () => {
    const base = { endpointId: "e1", attackType: "DOS_DDOS", ruleId: "DOS-XGB", modelVersion: "m1", dataOrigin: "PCAP_REPLAY",
                   detectedAt: new Date("2018-11-03T14:01:45Z"), evidence: [{ fields: { target: "192.168.50.4" } }] };
    const k = sourceAlertKey(base);
    assert.match(k!, /^[0-9a-f]{64}$/);
    assert.strictEqual(sourceAlertKey({ ...base }), k);
    assert.notStrictEqual(sourceAlertKey({ ...base, detectedAt: new Date("2018-11-03T14:01:50Z") }), k);
    assert.notStrictEqual(sourceAlertKey({ ...base, evidence: [{ fields: { target: "172.16.0.5" } }] }), k);
    assert.notStrictEqual(sourceAlertKey({ ...base, endpointId: "e2" }), k);
    assert.notStrictEqual(sourceAlertKey({ ...base, dataOrigin: "LIVE" }), k);
    assert.strictEqual(sourceAlertKey({ ...base, detectedAt: undefined }), undefined);
    assert.strictEqual(sourceAlertKey({ ...base, ruleId: undefined }), undefined);
  });
});
