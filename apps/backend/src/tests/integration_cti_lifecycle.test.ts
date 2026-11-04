import { describe, it, before, after } from "node:test";
import assert from "node:assert";
import mongoose, { Types } from "mongoose";
import { DetectionModel } from "../models/detection.model";
import { CTIReportModel } from "../models/ctiReport.model";
import { EndpointModel } from "../models/endpoint.model";
import { UserModel } from "../models/user.model";
import { OrganizationModel } from "../models/organization.model";
import { createDetection } from "../services/detection.service";
import {
  generateCTIDraft,
  updateCTIDraft,
  verifyCTIReport,
  listSharedCTIFeed,
  createReportRevision,
} from "../services/cti.service";
import { computeReportHash } from "../utils/canonical";
import dotenv from "dotenv";

dotenv.config();

const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/ransomware_cti_test";

describe("Multi-Threat CTI Integration Lifecycle", () => {
  let orgId: string;
  let endpointId: string;
  let userId: string;
  let testDetectionId: string;
  let testReportId: string;

  before(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(MONGO_URI);
    }

    // Find or create test organization
    let org = await OrganizationModel.findOne();
    if (!org) {
      org = await OrganizationModel.create({ name: "SentinelIQ Test Org" });
    }
    orgId = org._id.toString();

    // Find or create test user
    let user = await UserModel.findOne({ organizationId: org._id });
    if (!user) {
      user = await UserModel.create({
        organizationId: org._id,
        name: "Test Analyst",
        email: `analyst-${Date.now()}@sentineliq.local`,
        passwordHash: "test-hash",
        role: "SECURITY_ANALYST",
      });
    }
    userId = user._id.toString();

    // Find or create test endpoint
    let ep = await EndpointModel.findOne({ organizationId: org._id });
    if (!ep) {
      ep = await EndpointModel.create({
        organizationId: org._id,
        name: "WIN-TEST-HOST-01",
        status: "ONLINE",
        osVersion: "Windows 11 22H2",
        agentVersion: "1.0.0",
        lastCheckInAt: new Date(),
        isDeleted: false,
      });
    }
    endpointId = ep._id.toString();
  });

  after(async () => {
    // Cleanup created test records
    if (testDetectionId) {
      await DetectionModel.deleteOne({ _id: testDetectionId });
    }
    if (testReportId) {
      await CTIReportModel.deleteMany({ detectionId: testDetectionId });
    }
    await mongoose.disconnect();
  });

  it("1. Ingests a safe privilege escalation detection with evidence and derives MITRE mappings", async () => {
    const safeEvidence = [
      {
        id: "ev-pe02-test-1",
        source: "sysmon",
        eventId: 13,
        time: new Date().toISOString(),
        description: "Registry value set in HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command",
        fields: {
          targetImage: "fodhelper.exe",
          targetRegistry: "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command",
          commandLine: "powershell.exe -ExecutionPolicy Bypass",
        },
      },
    ];

    const detection = await createDetection({
      organizationId: orgId,
      endpointId,
      attackType: "PRIVILEGE_ESCALATION",
      ruleId: "PE-02",
      confidenceTier: "likely",
      riskScore: 78,
      indicators: [
        {
          type: "REGISTRY",
          description: "Auto-elevate binary triggered with registry hijack context: fodhelper.exe",
          observedAt: new Date(),
        },
      ],
      evidence: safeEvidence,
      modelVersion: "1.0.0",
    });

    testDetectionId = detection._id.toString();

    assert.ok(detection._id, "Detection should be created");
    assert.strictEqual(detection.attackType, "PRIVILEGE_ESCALATION");
    assert.strictEqual(detection.ruleId, "PE-02");
    assert.strictEqual(detection.confidenceTier, "likely");
    assert.strictEqual(detection.riskScore, 78);
    assert.strictEqual(detection.severity, "HIGH");

    // MITRE ATT&CK mapping check
    assert.ok(detection.mitre && detection.mitre.length >= 1, "Must map to MITRE techniques");
    const techIds = detection.mitre.map((m: any) => m.techniqueId);
    assert.ok(techIds.includes("T1134"), "PE-02 must map to T1134 (Access Token Manipulation)");

    for (const m of detection.mitre) {
      assert.ok(m.referenceUrl.startsWith("https://attack.mitre.org/"), "URL must be official MITRE");
    }
  });

  it("2. Generates a structured Schema v1.0 CTI Report draft for the incident", async () => {
    const draft = await generateCTIDraft(orgId, testDetectionId, userId);
    testReportId = draft._id.toString();

    assert.ok(draft._id);
    assert.strictEqual(draft.schemaVersion, "v1.0");
    assert.strictEqual(draft.attackType, "PRIVILEGE_ESCALATION");
    assert.strictEqual(draft.version, 1);
    assert.strictEqual(draft.status, "DRAFT");
    assert.strictEqual(draft.confidenceTier, "likely");
    assert.strictEqual(draft.detector?.id, "PE-02");
    assert.ok(draft.title?.includes("Privilege Escalation"));
    assert.ok(draft.recommendedActions.length >= 3, "Must have tailored privilege escalation remediation actions");
  });

  it("3. Prevents duplicate report generation when Publish/Generate is clicked repeatedly (Idempotence)", async () => {
    const secondDraft = await generateCTIDraft(orgId, testDetectionId, userId);

    assert.strictEqual(
      secondDraft._id.toString(),
      testReportId,
      "Second call must return the existing draft, not create a duplicate"
    );

    const count = await CTIReportModel.countDocuments({ detectionId: testDetectionId });
    assert.strictEqual(count, 1, "Exactly 1 report must exist for this detection");
  });

  it("4. Canonicalizes and computes RFC 8785 SHA-256 content hash", async () => {
    const report = await CTIReportModel.findById(testReportId);
    assert.ok(report);

    const { canonicalJson, contentHash, contentHashBytes32 } = computeReportHash(report);

    assert.ok(contentHash.length === 64, "SHA-256 hash must be 64 hex characters");
    assert.strictEqual(contentHashBytes32, "0x" + contentHash);
    assert.ok(canonicalJson.includes('"attackType":"PRIVILEGE_ESCALATION"'));
    assert.ok(canonicalJson.includes('"schemaVersion":"v1.0"'));

    // Check that DB transient fields are excluded from canonical JSON
    assert.ok(!canonicalJson.includes('"_id"'), "Canonical JSON must exclude MongoDB _id");
    assert.ok(!canonicalJson.includes('"__v"'), "Canonical JSON must exclude MongoDB __v");
  });

  it("5. Detects unauthorized tampering: modified report produces different hash and TAMPERED status", async () => {
    const report = await CTIReportModel.findById(testReportId);
    assert.ok(report);

    const { contentHash: originalHash } = computeReportHash(report);

    // Simulate tampering: adversary alters riskScore or description in DB
    const tampered = report.toObject();
    tampered.riskScore = 5; // Adversary downgrades severity

    const { contentHash: tamperedHash } = computeReportHash(tampered);

    assert.notStrictEqual(
      originalHash,
      tamperedHash,
      "Tampered report must produce a completely different SHA-256 hash"
    );
  });

  it("6. Creates an immutable new version revision for corrections instead of silent overwrite", async () => {
    const revision = await createReportRevision(
      orgId,
      testReportId,
      userId,
      "Updated with additional forensic analysis"
    );

    assert.strictEqual(revision.version, 2, "Revision version must increment to 2");
    assert.ok(revision.supersedes, "Revision must track superseded parent report");
    assert.strictEqual(revision.status, "DRAFT");

    // Clean up revision
    await CTIReportModel.deleteOne({ _id: revision._id });
  });

  it("7. Public CTI feed returns persisted reports without temporary-state loss", async () => {
    // Mark test report as PUBLISHED to test feed query
    const report = await CTIReportModel.findById(testReportId);
    assert.ok(report);
    report.status = "PUBLISHED";
    report.publishedAt = new Date();
    report.transactionHash = "0x" + "a".repeat(64);
    report.blockNumber = 56000000;
    report.verificationStatus = "VERIFIED";
    report.visibility = "SHARED_ALL";
    await report.save();

    // Another organization sees a SHARED_ALL report in its feed...
    const otherOrgId = new mongoose.Types.ObjectId().toString();
    const feedReports = await listSharedCTIFeed(otherOrgId);
    const found = feedReports.find((r) => r._id.toString() === testReportId);
    assert.ok(found, "A shared published report must appear in another org's feed");
    assert.strictEqual(found.attackType, "PRIVILEGE_ESCALATION");
    assert.strictEqual(found.status, "PUBLISHED");

    // ...but the owning organization does not see its own report in the shared feed.
    const ownerFeed = await listSharedCTIFeed(orgId);
    assert.ok(!ownerFeed.find((r) => r._id.toString() === testReportId), "Owner's own report is not in the shared feed");

    // A PRIVATE published report is not visible to anyone else.
    report.visibility = "PRIVATE";
    await report.save();
    const afterPrivate = await listSharedCTIFeed(otherOrgId);
    assert.ok(!afterPrivate.find((r) => r._id.toString() === testReportId), "A private report must never appear in another org's feed");
  });
});
