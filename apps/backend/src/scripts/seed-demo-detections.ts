import dns from "dns";
import mongoose from "mongoose";
import { env } from "../config/env";
import { OrganizationModel } from "../models/organization.model";
import { EndpointModel } from "../models/endpoint.model";
import { DetectionModel, severityFromRiskScore, DetectionSeverity, DetectionStatus } from "../models/detection.model";
import { deriveMitreForDetection } from "../utils/mitre";

// DNS workaround for Windows / ISP SRV lookup failures
try {
  dns.setServers(["8.8.8.8", "1.1.1.1"]);
} catch {
  // Use system default if setting custom servers fails
}

interface DemoDetectionSpec {
  ruleId: string;
  daysAgo: number;
  timeOffsetMs: number; // Offset from midnight UTC
  riskScore: number;
  status: DetectionStatus;
  attackType: string;
  confidenceTier: "suspicious" | "likely" | "confirmed";
  endpointIndex: number;
  indicators: Array<{ type: string; description: string }>;
  ctiMatch?: {
    matched: boolean;
    indicator: string;
    type: string;
    isMalicious: boolean;
    confidence: number;
    threatCategory: string;
    tags: string[];
    source: string;
  };
}

/**
 * 17 realistic detection records distributed across the past 7 days (Days 0 to 6).
 * Distribution pattern:
 * - Day 6 (6 days ago): 1 detection  (Quiet probe)
 * - Day 5 (5 days ago): 2 detections (Early reconnaissance)
 * - Day 4 (4 days ago): 1 detection  (Low activity / false alarm)
 * - Day 3 (3 days ago): 3 detections (Activity rising)
 * - Day 2 (2 days ago): 5 detections (Campaign peak / ransomware burst spike!)
 * - Day 1 (1 day ago):  3 detections (Containment & follow-up)
 * - Day 0 (Today):      2 detections (Active threats for SOC review!)
 *
 * Daily totals: [1, 2, 1, 3, 5, 3, 2] = 17 detections.
 */
const DEMO_DETECTIONS: DemoDetectionSpec[] = [
  // ── Day -6 (6 days ago) ──────────────────────────────────────────────────
  {
    ruleId: "DEMO-SEED-01",
    daysAgo: 6,
    timeOffsetMs: 11 * 3600000 + 23 * 60000, // 11:23 UTC
    riskScore: 35,
    status: "RESOLVED",
    attackType: "DEFENSE_EVASION",
    confidenceTier: "suspicious",
    endpointIndex: 0,
    indicators: [
      {
        type: "SUSPICIOUS_PATH",
        description: "Unsigned updater payload staged in temp directory: %TEMP%\\update_patch_88.tmp",
      },
    ],
  },

  // ── Day -5 (5 days ago) ──────────────────────────────────────────────────
  {
    ruleId: "DEMO-SEED-02",
    daysAgo: 5,
    timeOffsetMs: 9 * 3600000 + 41 * 60000, // 09:41 UTC
    riskScore: 42,
    status: "RESOLVED",
    attackType: "CREDENTIAL_ACCESS",
    confidenceTier: "suspicious",
    endpointIndex: 1,
    indicators: [
      {
        type: "PROCESS_ACCESS",
        description: "OpenProcess token query targeting lsass.exe from unverified parent process",
      },
    ],
  },
  {
    ruleId: "DEMO-SEED-03",
    daysAgo: 5,
    timeOffsetMs: 15 * 3600000 + 18 * 60000, // 15:18 UTC
    riskScore: 28,
    status: "FALSE_POSITIVE",
    attackType: "SUSPICIOUS_EXECUTION",
    confidenceTier: "suspicious",
    endpointIndex: 0,
    indicators: [
      {
        type: "SCRIPT_HOST",
        description: "Base64-encoded command string detected in routine administrative maintenance script",
      },
    ],
  },

  // ── Day -4 (4 days ago) ──────────────────────────────────────────────────
  {
    ruleId: "DEMO-SEED-04",
    daysAgo: 4,
    timeOffsetMs: 14 * 3600000 + 5 * 60000, // 14:05 UTC
    riskScore: 38,
    status: "RESOLVED",
    attackType: "PERSISTENCE",
    confidenceTier: "suspicious",
    endpointIndex: 1,
    indicators: [
      {
        type: "REGISTRY_MODIFICATION",
        description: "Run key persistence entry added to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      },
    ],
  },

  // ── Day -3 (3 days ago) ──────────────────────────────────────────────────
  {
    ruleId: "DEMO-SEED-05",
    daysAgo: 3,
    timeOffsetMs: 8 * 3600000 + 12 * 60000, // 08:12 UTC
    riskScore: 65,
    status: "RESOLVED",
    attackType: "LATERAL_MOVEMENT",
    confidenceTier: "likely",
    endpointIndex: 0,
    indicators: [
      {
        type: "REMOTE_SMB_SHARE",
        description: "High-frequency enumeration of IPC$ and C$ admin network shares across adjacent subnet",
      },
    ],
  },
  {
    ruleId: "DEMO-SEED-06",
    daysAgo: 3,
    timeOffsetMs: 13 * 3600000 + 40 * 60000, // 13:40 UTC
    riskScore: 72,
    status: "RESOLVED",
    attackType: "DEFENSE_EVASION",
    confidenceTier: "likely",
    endpointIndex: 1,
    indicators: [
      {
        type: "SHADOW_COPY_TAMPER",
        description: "vssadmin.exe delete shadows /all /quiet executed to inhibit recovery",
      },
      {
        type: "SECURITY_TOOL_DISABLE",
        description: "Attempted service state modification for Windows Defender Antivirus service",
      },
    ],
  },
  {
    ruleId: "DEMO-SEED-07",
    daysAgo: 3,
    timeOffsetMs: 19 * 3600000 + 55 * 60000, // 19:55 UTC
    riskScore: 58,
    status: "RESOLVED",
    attackType: "DATA_EXFILTRATION",
    confidenceTier: "likely",
    endpointIndex: 0,
    indicators: [
      {
        type: "HIGH_OUTBOUND_TRAFFIC",
        description: "Encrypted 420MB staging archive transmitted via curl.exe to external destination",
      },
    ],
  },

  // ── Day -2 (2 days ago) — SPIKE / CAMPAIGN PEAK (5 detections) ──────────
  {
    ruleId: "DEMO-SEED-08",
    daysAgo: 2,
    timeOffsetMs: 2 * 3600000 + 15 * 60000, // 02:15 UTC
    riskScore: 94,
    status: "RESOLVED",
    attackType: "RANSOMWARE",
    confidenceTier: "confirmed",
    endpointIndex: 0,
    ctiMatch: {
      matched: true,
      indicator: "lockbit3_encryptor.exe",
      type: "FILE_HASH",
      isMalicious: true,
      confidence: 96,
      threatCategory: "Ransomware",
      tags: ["lockbit", "ransomware", "encryption"],
      source: "SentinelIQ Global Threat Feed",
    },
    indicators: [
      {
        type: "MASS_FILE_RENAME",
        description: "384 user document files renamed with .lockbit extension within 11 seconds",
      },
      {
        type: "RANSOM_NOTE_DROP",
        description: "Restore instructions file 'Restore-My-Files.txt' written to 32 directory trees",
      },
    ],
  },
  {
    ruleId: "DEMO-SEED-09",
    daysAgo: 2,
    timeOffsetMs: 3 * 3600000 + 2 * 60000, // 03:02 UTC
    riskScore: 91,
    status: "RESOLVED",
    attackType: "RANSOMWARE",
    confidenceTier: "confirmed",
    endpointIndex: 1,
    indicators: [
      {
        type: "HIGH_ENTROPY_WRITE",
        description: "Burst write activity with Shannon entropy > 7.98 detected on system drive",
      },
      {
        type: "SYSTEM_RESTORE_DISABLE",
        description: "bcdedit.exe /set {default} recoveryenabled No command sequence detected",
      },
    ],
  },
  {
    ruleId: "DEMO-SEED-10",
    daysAgo: 2,
    timeOffsetMs: 6 * 3600000 + 45 * 60000, // 06:45 UTC
    riskScore: 84,
    status: "RESOLVED",
    attackType: "LATERAL_MOVEMENT",
    confidenceTier: "likely",
    endpointIndex: 0,
    indicators: [
      {
        type: "WMI_REMOTE_EXEC",
        description: "Remote process creation via wmic.exe /node attempting network propagation",
      },
    ],
  },
  {
    ruleId: "DEMO-SEED-11",
    daysAgo: 2,
    timeOffsetMs: 11 * 3600000 + 30 * 60000, // 11:30 UTC
    riskScore: 78,
    status: "RESOLVED",
    attackType: "RANSOMWARE",
    confidenceTier: "likely",
    endpointIndex: 1,
    indicators: [
      {
        type: "RANSOM_NOTE_DROP",
        description: "HTML ransom note dropped in shared company repository folder",
      },
    ],
  },
  {
    ruleId: "DEMO-SEED-12",
    daysAgo: 2,
    timeOffsetMs: 17 * 3600000 + 10 * 60000, // 17:10 UTC
    riskScore: 52,
    status: "RESOLVED",
    attackType: "SUSPICIOUS_NETWORK",
    confidenceTier: "suspicious",
    endpointIndex: 0,
    indicators: [
      {
        type: "C2_BEACON",
        description: "Periodic beaconing to known dynamic DNS host every 60 seconds",
      },
    ],
  },

  // ── Day -1 (1 day ago) ──────────────────────────────────────────────────
  {
    ruleId: "DEMO-SEED-13",
    daysAgo: 1,
    timeOffsetMs: 7 * 3600000 + 20 * 60000, // 07:20 UTC
    riskScore: 86,
    status: "RESOLVED",
    attackType: "PERSISTENCE",
    confidenceTier: "likely",
    endpointIndex: 1,
    ctiMatch: {
      matched: true,
      indicator: "185.220.101.5",
      type: "IPV4",
      isMalicious: true,
      confidence: 89,
      threatCategory: "C2 Server",
      tags: ["lockbit-c2", "cobalt-strike", "malicious-ip"],
      source: "SentinelIQ Global Threat Feed",
    },
    indicators: [
      {
        type: "SCHEDULED_TASK_CREATE",
        description: "Hidden scheduled task 'SystemTelemetrySync' created under NT AUTHORITY\\SYSTEM",
      },
    ],
  },
  {
    ruleId: "DEMO-SEED-14",
    daysAgo: 1,
    timeOffsetMs: 12 * 3600000 + 5 * 60000, // 12:05 UTC
    riskScore: 62,
    status: "RESOLVED",
    attackType: "DEFENSE_EVASION",
    confidenceTier: "likely",
    endpointIndex: 0,
    indicators: [
      {
        type: "EVENT_LOG_CLEAR",
        description: "Windows Security log clearing event (Event ID 1102) detected via wevtutil",
      },
    ],
  },
  {
    ruleId: "DEMO-SEED-15",
    daysAgo: 1,
    timeOffsetMs: 18 * 3600000 + 44 * 60000, // 18:44 UTC
    riskScore: 32,
    status: "RESOLVED",
    attackType: "SUSPICIOUS_PATH",
    confidenceTier: "suspicious",
    endpointIndex: 1,
    indicators: [
      {
        type: "RECOVERY_PROBE",
        description: "Unsigned execution artifact detected in Recycle Bin folder path",
      },
    ],
  },

  // ── Day 0 (Today) — ACTIVE INCIDENTS ─────────────────────────────────────
  {
    ruleId: "DEMO-SEED-16",
    daysAgo: 0,
    timeOffsetMs: 1 * 3600000 + 15 * 60000, // 01:15 UTC
    riskScore: 95,
    status: "NEW", // Active detection requiring review!
    attackType: "RANSOMWARE",
    confidenceTier: "confirmed",
    endpointIndex: 0,
    ctiMatch: {
      matched: true,
      indicator: "darkside_locker.bin",
      type: "FILE_HASH",
      isMalicious: true,
      confidence: 98,
      threatCategory: "Ransomware",
      tags: ["darkside", "double-extortion", "crypto"],
      source: "SentinelIQ Global Threat Feed",
    },
    indicators: [
      {
        type: "MASS_FILE_RENAME",
        description: "512 files modified with .cryptoid extension in 15 seconds",
      },
      {
        type: "PROCESS_INJECTION",
        description: "Memory injection detected into explorer.exe from unverified process",
      },
    ],
  },
  {
    ruleId: "DEMO-SEED-17",
    daysAgo: 0,
    timeOffsetMs: 2 * 3600000 + 30 * 60000, // 02:30 UTC
    riskScore: 75,
    status: "INVESTIGATING", // Active detection requiring review!
    attackType: "LATERAL_MOVEMENT",
    confidenceTier: "likely",
    endpointIndex: 1,
    indicators: [
      {
        type: "PS_EXEC_REMOTE",
        description: "PsExec lateral execution attempt over port 445 SMB transport",
      },
    ],
  },
];

async function seedOrgDetections(org: any) {
  const endpoints = await EndpointModel.find({
    organizationId: org._id,
    isDeleted: { $ne: true },
  });

  if (!endpoints || endpoints.length === 0) {
    console.log(`[seed-detections] Skipping ${org.name}: No active endpoints found.`);
    return 0;
  }

  console.log(`[seed-detections] Seeding ${DEMO_DETECTIONS.length} detections for "${org.name}" across ${endpoints.length} endpoints: ${endpoints.map(e => e.name).join(", ")}`);

  // Idempotent: Remove only previously seeded demo detections for this organization
  const deleted = await DetectionModel.deleteMany({
    organizationId: org._id,
    ruleId: { $regex: /^DEMO-SEED-/ },
  });
  if (deleted.deletedCount > 0) {
    console.log(`[seed-detections] Cleaned up ${deleted.deletedCount} previous demo records for "${org.name}".`);
  }

  // Base date: Midnight UTC today
  const now = new Date();
  const todayMidnightUtc = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())).getTime();

  const toInsert = DEMO_DETECTIONS.map((spec) => {
    const endpoint = endpoints[spec.endpointIndex % endpoints.length];
    const detectedAt = new Date(todayMidnightUtc - spec.daysAgo * 86400000 + spec.timeOffsetMs);

    const formattedIndicators = spec.indicators.map((ind) => ({
      type: ind.type,
      description: ind.description,
      observedAt: detectedAt,
    }));

    const mitre = deriveMitreForDetection(spec.attackType, spec.ruleId, formattedIndicators, []);

    return {
      organizationId: org._id,
      endpointId: endpoint._id,
      endpointName: endpoint.name,
      attackType: spec.attackType,
      ruleId: spec.ruleId,
      confidenceTier: spec.confidenceTier,
      riskScore: spec.riskScore,
      severity: severityFromRiskScore(spec.riskScore),
      status: spec.status,
      indicators: formattedIndicators,
      // Demonstration records: labelled as such so the UI and CTI never present them as real incidents.
      dataOrigin: "DEMO",
      evidence: [
        {
          id: `ev-${spec.ruleId.toLowerCase()}`,
          source: "demo-seed (synthetic, not Sysmon)",
          eventId: 1,
          time: detectedAt.toISOString(),
          description: spec.indicators[0]?.description || "Behavioral anomaly detected",
        },
      ],
      mitre,
      modelVersion: "DEMO-seed-xgboost-v1.0.0",
      detectedAt,
      resolvedAt: spec.status === "RESOLVED" || spec.status === "FALSE_POSITIVE" ? new Date(detectedAt.getTime() + 4 * 3600000) : undefined,
      ctiMatch: spec.ctiMatch ? { ...spec.ctiMatch, matchedAt: detectedAt } : undefined,
    };
  });

  await DetectionModel.insertMany(toInsert);
  console.log(`[seed-detections] Successfully inserted ${toInsert.length} demo detection records for "${org.name}".`);
  return toInsert.length;
}

async function main() {
  console.log("=========================================================");
  console.log("  SentinelIQ: 7-Day Demo Detections Seeder");
  console.log("=========================================================");

  await mongoose.connect(env.mongoUri);
  console.log("[seed-detections] Connected to MongoDB Atlas.");

  const orgs = await OrganizationModel.find({});
  if (!orgs || orgs.length === 0) {
    console.error("[seed-detections] No organizations found in database.");
    await mongoose.disconnect();
    process.exit(1);
  }

  let totalInserted = 0;
  for (const org of orgs) {
    const inserted = await seedOrgDetections(org);
    totalInserted += inserted;
  }

  // Verification & Reporting
  console.log("\n=================== VERIFICATION SUMMARY ===================");
  const now = new Date();
  for (const org of orgs) {
    const orgDetections = await DetectionModel.find({ organizationId: org._id }).sort({ detectedAt: -1 });
    if (orgDetections.length === 0) continue;

    console.log(`\nOrganization: ${org.name} (Total Detections: ${orgDetections.length})`);
    console.log("Daily Distribution Over Past 7 Days (UTC):");

    for (let dayOffset = 6; dayOffset >= 0; dayOffset--) {
      const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - dayOffset));
      const dateStr = d.toISOString().slice(0, 10);
      const count = orgDetections.filter(
        (det) => det.detectedAt && new Date(det.detectedAt).toISOString().slice(0, 10) === dateStr
      ).length;

      const bar = "█".repeat(count * 3);
      const label = dayOffset === 0 ? "Today" : `${dayOffset} days ago`;
      console.log(`  ${dateStr} (${label.padEnd(11)}): ${count.toString().padStart(2)} records  ${bar}`);
    }

    const activeCount = orgDetections.filter(d => d.status === "NEW" || d.status === "INVESTIGATING").length;
    const resolvedCount = orgDetections.filter(d => d.status === "RESOLVED" || d.status === "FALSE_POSITIVE").length;
    const ctiMatches = orgDetections.filter(d => d.ctiMatch?.matched).length;

    console.log(`  Status Breakdown: ${activeCount} Active, ${resolvedCount} Resolved/False Positive`);
    console.log(`  CTI IOC Matches : ${ctiMatches}`);
  }

  console.log("\n[seed-detections] Seeding completed successfully.");
  await mongoose.disconnect();
}

main().catch((err) => {
  console.error("[seed-detections] Fatal error:", err);
  process.exit(1);
});
