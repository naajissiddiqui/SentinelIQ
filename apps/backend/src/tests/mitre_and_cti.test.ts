import { describe, it } from "node:test";
import assert from "node:assert";
import {
  MITRE_TECHNIQUE_CATALOG,
  RULE_MITRE_MAP,
  getMitreMappingsForRule,
  deriveMitreForDetection,
} from "../utils/mitre";
import {
  canonicalizeJson,
  computeReportHash,
  extractCanonicalReportPayload,
} from "../utils/canonical";

describe("MITRE ATT&CK Mapping Module", () => {
  it("includes all required Enterprise ATT&CK techniques with official URLs", () => {
    const requiredTechniques = [
      "T1486",      // Data Encrypted for Impact
      "T1490",      // Inhibit System Recovery
      "T1083",      // File and Directory Discovery
      "T1068",      // Exploitation for Privilege Escalation
      "T1548.002",  // Abuse Elevation Control Mechanism: Bypass UAC
      "T1543.003",  // Create or Modify System Process: Windows Service
      "T1053.005",  // Scheduled Task/Job: Scheduled Task
      "T1098",      // Account Manipulation
      "T1136.001",  // Create Account: Local Account
      "T1003.001",  // OS Credential Dumping: LSASS Memory
      "T1546.012",  // Event Triggered Execution: IFEO Injection
      "T1112",      // Modify Registry
    ];

    for (const tid of requiredTechniques) {
      const entry = MITRE_TECHNIQUE_CATALOG[tid];
      assert.ok(entry, `Technique ${tid} should exist in catalog`);
      assert.ok(entry.referenceUrl.startsWith("https://attack.mitre.org/"), `Reference URL for ${tid} must be official MITRE`);
      assert.ok(entry.tacticId.startsWith("TA"), `Tactic ID for ${tid} must start with TA`);
      assert.ok(entry.techniqueName.length > 0, `Technique ${tid} must have a name`);
    }
  });

  it("maps PE-05-UAC-REG (UAC Bypass) precisely to T1548.002 and T1112 with evidence link", () => {
    const evIds = ["ev-mock-001"];
    const mappings = getMitreMappingsForRule("PE-05-UAC-REG", evIds);
    assert.strictEqual(mappings.length, 2);

    const techIds = mappings.map((m) => m.techniqueId);
    assert.ok(techIds.includes("T1548.002"));
    assert.ok(techIds.includes("T1112"));

    for (const m of mappings) {
      assert.deepStrictEqual(m.evidenceRef, evIds);
      assert.strictEqual(m.attackVersion, "v14.1");
    }
  });

  it("maps PE-04-SERVICE precisely to T1543.003 and PE-04-TASK to T1053.005", () => {
    const svcMappings = getMitreMappingsForRule("PE-04-SERVICE");
    assert.strictEqual(svcMappings.length, 1);
    assert.strictEqual(svcMappings[0].techniqueId, "T1543.003");

    const taskMappings = getMitreMappingsForRule("PE-04-TASK");
    assert.strictEqual(taskMappings.length, 1);
    assert.strictEqual(taskMappings[0].techniqueId, "T1053.005");
  });

  it("does not map arbitrary techniques for unknown rules (Negative Test)", () => {
    const mappings = getMitreMappingsForRule("BENIGN_EXPLORER_EVENT");
    assert.strictEqual(mappings.length, 0, "Unknown rule should yield 0 mappings");
  });

  it("derives ransomware indicators to T1486, T1490, and T1083 only when justified", () => {
    const indicatorsWithVss = [
      { type: "PROCESS", description: "vssadmin.exe delete shadows /all /quiet" },
      { type: "FS", description: "mass traversal enumeration" },
    ];
    const mappings = deriveMitreForDetection("RANSOMWARE", undefined, indicatorsWithVss, []);
    const techIds = mappings.map((m) => m.techniqueId);

    assert.ok(techIds.includes("T1486"), "Must include T1486 for ransomware");
    assert.ok(techIds.includes("T1490"), "Must include T1490 when vssadmin is observed");
    assert.ok(techIds.includes("T1083"), "Must include T1083 when traversal is observed");
  });
});

describe("RFC 8785 JSON Canonicalization & SHA-256 Hashing", () => {
  it("produces identical JSON string regardless of key insertion order", () => {
    const objA = { z: 1, a: "hello", m: [3, 2, 1] };
    const objB = { a: "hello", m: [3, 2, 1], z: 1 };

    const canonA = canonicalizeJson(objA);
    const canonB = canonicalizeJson(objB);

    assert.strictEqual(canonA, canonB);
    assert.strictEqual(canonA, '{"a":"hello","m":[3,2,1],"z":1}');
  });

  it("computes deterministic SHA-256 content hash for structured CTI reports", () => {
    const mockReport = {
      reportId: "cti-test-001",
      schemaVersion: "v1.0",
      attackType: "PRIVILEGE_ESCALATION",
      title: "Privilege Escalation PE-02 on WIN-TEST",
      detectedAt: "2026-10-13T00:00:00.000Z",
      severity: "HIGH",
      riskScore: 78,
      confidenceTier: "likely",
      attackSummary: "UAC bypass observed via fodhelper registry hijack.",
      indicatorsOfCompromise: ["PROCESS: fodhelper.exe", "REGISTRY: ms-settings\\shell\\open\\command"],
      recommendedActions: ["Terminate process", "Revoke credentials"],
      detector: { type: "rule", id: "PE-02", version: "1.0.0" },
      evidence: [
        {
          id: "ev-01",
          source: "sysmon",
          eventId: 13,
          time: "2026-10-13T00:00:00.000Z",
          description: "Registry value set",
          fields: { targetRegistry: "ms-settings" },
        },
      ],
      mitre: [
        {
          tacticId: "TA0004",
          tacticName: "Privilege Escalation",
          techniqueId: "T1548.002",
          techniqueName: "Abuse Elevation Control Mechanism: Bypass User Account Control",
          attackVersion: "v14.1",
          referenceUrl: "https://attack.mitre.org/techniques/T1548/002/",
          evidenceRef: ["ev-01"],
        },
      ],
      version: 1,
    };

    const hashResult1 = computeReportHash(mockReport);
    const hashResult2 = computeReportHash(mockReport);

    assert.strictEqual(hashResult1.contentHash, hashResult2.contentHash);
    assert.strictEqual(hashResult1.contentHashBytes32, "0x" + hashResult1.contentHash);
    assert.strictEqual(hashResult1.contentHash.length, 64);
  });

  it("detects tampering when any critical report field is altered (Tamper Test)", () => {
    const originalReport = {
      reportId: "cti-test-002",
      schemaVersion: "v1.0",
      attackType: "PRIVILEGE_ESCALATION",
      title: "Privilege Escalation PE-05 on HOST-01",
      detectedAt: "2026-10-13T00:00:00.000Z",
      severity: "CRITICAL",
      riskScore: 92,
      confidenceTier: "confirmed",
      attackSummary: "LSASS memory read detected",
      indicatorsOfCompromise: ["PROCESS: lsass.exe"],
      recommendedActions: ["Isolate host"],
      detector: { type: "rule", id: "PE-05", version: "1.0.0" },
      evidence: [],
      mitre: [],
      version: 1,
    };

    const originalHash = computeReportHash(originalReport).contentHash;

    // Tamper with riskScore (e.g. adversary lowers score)
    const tamperedReport = { ...originalReport, riskScore: 10 };
    const tamperedHash = computeReportHash(tamperedReport).contentHash;

    assert.notStrictEqual(originalHash, tamperedHash, "Tampered report must produce different hash");
  });
});
