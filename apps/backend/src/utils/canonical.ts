import crypto from "crypto";

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) serializer.
 * Produces a deterministic JSON string with sorted keys and no insignificant whitespace.
 */
export function canonicalizeJson(value: any): string {
  if (value === null || typeof value !== "object") {
    // Numbers, booleans, strings, null
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const elements = value.map((item) => canonicalizeJson(item ?? null));
    return `[${elements.join(",")}]`;
  }

  // Object: sort keys in lexicographical Unicode code unit order
  const keys = Object.keys(value).filter((k) => value[k] !== undefined);
  keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  const entries = keys.map((key) => {
    return `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`;
  });

  return `{${entries.join(",")}}`;
}

/**
 * Extracts and standardizes canonical fields for CTI Report hashing.
 * Excludes transient DB fields (_id, __v, transactionHash, blockNumber, status,
 * verificationStatus, canonicalJson, contentHash, publishedAt, updatedAt).
 */
export function extractCanonicalReportPayload(report: any): any {
  return {
    reportId: String(report.reportId || report._id || ""),
    schemaVersion: String(report.schemaVersion || "v1.0"),
    attackType: String(report.attackType || "RANSOMWARE"),
    title: String(report.title || "CTI Incident Report"),
    detectedAt: report.detectedAt
      ? new Date(report.detectedAt).toISOString()
      : report.createdAt
      ? new Date(report.createdAt).toISOString()
      : "1970-01-01T00:00:00.000Z",
    severity: String(report.severity || "MEDIUM"),
    riskScore: Number(report.riskScore ?? 0),
    confidenceTier: String(report.confidenceTier || "suspicious"),
    attackSummary: String(report.attackSummary || ""),
    indicatorsOfCompromise: (report.indicatorsOfCompromise || []).map(String).sort(),
    recommendedActions: (report.recommendedActions || []).map(String),
    detector: {
      type: String(report.detector?.type || "rule"),
      id: String(report.detector?.id || "PE-01"),
      version: String(report.detector?.version || "1.0.0"),
    },
    evidence: (report.evidence || []).map((e: any) => ({
      id: String(e.id || ""),
      source: String(e.source || "sysmon"),
      eventId: e.eventId !== undefined ? Number(e.eventId) : undefined,
      time: e.time ? new Date(e.time).toISOString() : "",
      description: String(e.description || ""),
      fields: e.fields ? canonicalizeFields(e.fields) : {},
    })),
    mitre: (report.mitre || []).map((m: any) => ({
      tacticId: String(m.tacticId || ""),
      tacticName: String(m.tacticName || ""),
      techniqueId: String(m.techniqueId || ""),
      techniqueName: String(m.techniqueName || ""),
      attackVersion: String(m.attackVersion || "v14.1"),
      referenceUrl: String(m.referenceUrl || ""),
      evidenceRef: (m.evidenceRef || []).map(String).sort(),
    })),
    version: Number(report.version || 1),
  };
}

function canonicalizeFields(fields: Record<string, any>): Record<string, any> {
  const result: Record<string, any> = {};
  for (const k of Object.keys(fields).sort()) {
    if (fields[k] !== undefined) {
      result[k] = fields[k];
    }
  }
  return result;
}

/**
 * Computes deterministic RFC 8785 canonical JSON and SHA-256 hash.
 */
export function computeReportHash(report: any): {
  canonicalJson: string;
  contentHash: string;
  contentHashBytes32: string;
} {
  const payload = extractCanonicalReportPayload(report);
  const canonicalJson = canonicalizeJson(payload);
  const contentHash = crypto.createHash("sha256").update(canonicalJson, "utf8").digest("hex");
  const contentHashBytes32 = "0x" + contentHash;
  return { canonicalJson, contentHash, contentHashBytes32 };
}
