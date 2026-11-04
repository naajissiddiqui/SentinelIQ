import { MitreMapping } from "@ransomware-cti/shared-types";

export const ATTACK_VERSION = "v14.1";

export interface MitreTechniqueCatalogEntry {
  tacticId: string;
  tacticName: string;
  techniqueId: string;
  techniqueName: string;
  referenceUrl: string;
}

export const MITRE_TECHNIQUE_CATALOG: Record<string, MitreTechniqueCatalogEntry> = {
  // Ransomware / Impact
  T1486: {
    tacticId: "TA0040",
    tacticName: "Impact",
    techniqueId: "T1486",
    techniqueName: "Data Encrypted for Impact",
    referenceUrl: "https://attack.mitre.org/techniques/T1486/",
  },
  T1490: {
    tacticId: "TA0040",
    tacticName: "Impact",
    techniqueId: "T1490",
    techniqueName: "Inhibit System Recovery",
    referenceUrl: "https://attack.mitre.org/techniques/T1490/",
  },
  T1083: {
    tacticId: "TA0007",
    tacticName: "Discovery",
    techniqueId: "T1083",
    techniqueName: "File and Directory Discovery",
    referenceUrl: "https://attack.mitre.org/techniques/T1083/",
  },

  // Privilege Escalation / Persistence / Evasion / Credential Access
  T1068: {
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    techniqueId: "T1068",
    techniqueName: "Exploitation for Privilege Escalation",
    referenceUrl: "https://attack.mitre.org/techniques/T1068/",
  },
  "T1548.002": {
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    techniqueId: "T1548.002",
    techniqueName: "Abuse Elevation Control Mechanism: Bypass User Account Control",
    referenceUrl: "https://attack.mitre.org/techniques/T1548/002/",
  },
  "T1543.003": {
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    techniqueId: "T1543.003",
    techniqueName: "Create or Modify System Process: Windows Service",
    referenceUrl: "https://attack.mitre.org/techniques/T1543/003/",
  },
  "T1053.005": {
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    techniqueId: "T1053.005",
    techniqueName: "Scheduled Task/Job: Scheduled Task",
    referenceUrl: "https://attack.mitre.org/techniques/T1053/005/",
  },
  T1098: {
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    techniqueId: "T1098",
    techniqueName: "Account Manipulation",
    referenceUrl: "https://attack.mitre.org/techniques/T1098/",
  },
  "T1136.001": {
    tacticId: "TA0003",
    tacticName: "Persistence",
    techniqueId: "T1136.001",
    techniqueName: "Create Account: Local Account",
    referenceUrl: "https://attack.mitre.org/techniques/T1136/001/",
  },
  "T1003.001": {
    tacticId: "TA0006",
    tacticName: "Credential Access",
    techniqueId: "T1003.001",
    techniqueName: "OS Credential Dumping: LSASS Memory",
    referenceUrl: "https://attack.mitre.org/techniques/T1003/001/",
  },
  "T1546.012": {
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    techniqueId: "T1546.012",
    techniqueName: "Event Triggered Execution: Image File Execution Options Injection",
    referenceUrl: "https://attack.mitre.org/techniques/T1546/012/",
  },
  T1112: {
    tacticId: "TA0005",
    tacticName: "Defense Evasion",
    techniqueId: "T1112",
    techniqueName: "Modify Registry",
    referenceUrl: "https://attack.mitre.org/techniques/T1112/",
  },
  "T1134": {
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    techniqueId: "T1134",
    techniqueName: "Access Token Manipulation",
    referenceUrl: "https://attack.mitre.org/techniques/T1134/",
  },
  "T1134.001": {
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    techniqueId: "T1134.001",
    techniqueName: "Access Token Manipulation: Token Impersonation/Theft",
    referenceUrl: "https://attack.mitre.org/techniques/T1134/001/",
  },
  "T1546.008": {
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    techniqueId: "T1546.008",
    techniqueName: "Event Triggered Execution: Accessibility Features",
    referenceUrl: "https://attack.mitre.org/techniques/T1546/008/",
  },
  "T1547.002": {
    tacticId: "TA0003",
    tacticName: "Persistence",
    techniqueId: "T1547.002",
    techniqueName: "Boot or Logon Autostart Execution: Authentication Package",
    referenceUrl: "https://attack.mitre.org/techniques/T1547/002/",
  },
  "T1547.004": {
    tacticId: "TA0003",
    tacticName: "Persistence",
    techniqueId: "T1547.004",
    techniqueName: "Boot or Logon Autostart Execution: Winlogon Helper DLL",
    referenceUrl: "https://attack.mitre.org/techniques/T1547/004/",
  },
  "T1547.005": {
    tacticId: "TA0003",
    tacticName: "Persistence",
    techniqueId: "T1547.005",
    techniqueName: "Boot or Logon Autostart Execution: Security Support Provider",
    referenceUrl: "https://attack.mitre.org/techniques/T1547/005/",
  },
  "T1562.001": {
    tacticId: "TA0005",
    tacticName: "Defense Evasion",
    techniqueId: "T1562.001",
    techniqueName: "Impair Defenses: Disable or Modify Tools",
    referenceUrl: "https://attack.mitre.org/techniques/T1562/001/",
  },
  // Network denial of service. The parent technique only: sub-techniques
  // (T1498.001 direct flood, T1498.002 reflection amplification) would need
  // evidence the window model does not see, so none is inferred.
  T1498: {
    tacticId: "TA0040",
    tacticName: "Impact",
    techniqueId: "T1498",
    techniqueName: "Network Denial of Service",
    referenceUrl: "https://attack.mitre.org/techniques/T1498/",
  },
};

export const RULE_MITRE_MAP: Record<string, string[]> = {
  "RANSOMWARE-XGB": ["T1486"],
  "RANSOMWARE-HEURISTIC": ["T1486"],
  "VSS-SHADOW-DELETE": ["T1490"],
  "MASS-FILE-ENUM": ["T1083"],
  "PE-01": ["T1068"],
  "PE-02": ["T1134"],
  "PE-03": ["T1098"],
  "PE-03-USER": ["T1136.001"],
  "PE-03-GROUP": ["T1098"],
  "PE-04": ["T1543.003", "T1053.005"],
  "PE-04-SERVICE": ["T1543.003"],
  "PE-04-TASK": ["T1053.005"],
  "PE-05": ["T1548.002"],
  "PE-05-UAC-REG": ["T1548.002", "T1112"],
  "PE-05-UAC-EXEC": ["T1548.002"],
  "PE-05-TOOL": ["T1134"],
  "PE-06": ["T1112"],
  "DOS-XGB": ["T1498"],
  "DOS-PPS-HEURISTIC": ["T1498"],
};

export function getMitreMappingsForRule(
  ruleId: string,
  evidenceIds: string[] = [],
  extraTechniques: string[] = []
): MitreMapping[] {
  const techniqueIds = [...(RULE_MITRE_MAP[ruleId] || [])];
  for (const tid of extraTechniques) {
    if (!techniqueIds.includes(tid)) {
      techniqueIds.push(tid);
    }
  }

  const results: MitreMapping[] = [];
  for (const tid of techniqueIds) {
    const entry = MITRE_TECHNIQUE_CATALOG[tid];
    if (entry) {
      results.push({
        tacticId: entry.tacticId,
        tacticName: entry.tacticName,
        techniqueId: entry.techniqueId,
        techniqueName: entry.techniqueName,
        attackVersion: ATTACK_VERSION,
        referenceUrl: entry.referenceUrl,
        evidenceRef: evidenceIds,
      });
    }
  }
  return results;
}

function withReasons(mappings: MitreMapping[], reasonFor: (techniqueId: string) => string): MitreMapping[] {
  return mappings.map((m) => ({ ...m, mappingReason: reasonFor(m.techniqueId) }));
}

/**
 * ATT&CK techniques for a detection, each with the reason it was assigned.
 * A technique is only assigned from evidence the detector actually has: a
 * rule-specific mapping, the detection type's documented behaviour, or an
 * indicator naming the behaviour. A type without such a basis gets NO
 * technique (an empty list), never a borrowed ransomware mapping.
 */
export function deriveMitreForDetection(
  attackType?: string,
  ruleId?: string,
  indicators?: any[],
  evidence?: any[]
): MitreMapping[] {
  const evIds = (evidence || []).map((e: any) => e.id).filter(Boolean);
  if (ruleId && RULE_MITRE_MAP[ruleId]) {
    const dosRule = ruleId === "DOS-XGB" || ruleId === "DOS-PPS-HEURISTIC";
    return withReasons(getMitreMappingsForRule(ruleId, evIds), (t) => dosRule
      ? `The network detector observed a sustained inbound flood against the target across consecutive 5-second windows (network denial of service). ` +
        "No sub-technique: direct vs reflection flooding is not established by the window features."
      : `Rule ${ruleId} is mapped to ${t}.`);
  }
  if (attackType === "PRIVILEGE_ESCALATION") {
    return withReasons(getMitreMappingsForRule("PE-01", evIds), () =>
      "Privilege-escalation detection without a rule-specific mapping: generic T1068.");
  }
  if (attackType === "DOS_DDOS") {
    return withReasons(getMitreMappingsForRule("DOS-XGB", evIds), () =>
      "DoS/DDoS window detector: sustained inbound flood against the target (network denial of service). " +
      "No sub-technique: direct vs reflection flooding is not established by the window features.");
  }
  if (attackType && attackType !== "RANSOMWARE") {
    return []; // no evidence-based mapping for this detection type
  }
  const extra: string[] = [];
  const indText = JSON.stringify(indicators || "").toLowerCase();
  if (indText.includes("vssadmin") || indText.includes("shadow")) {
    extra.push("T1490");
  }
  if (indText.includes("enumeration") || indText.includes("traversal")) {
    extra.push("T1083");
  }
  return withReasons(getMitreMappingsForRule("RANSOMWARE-XGB", evIds, extra), (t) =>
    t === "T1486" ? "Ransomware detection: file-encryption behaviour (encryption model)." :
    t === "T1490" ? "An indicator mentions shadow-copy deletion (vssadmin / shadow copies)." :
    t === "T1083" ? "An indicator mentions mass file enumeration / directory traversal." :
    `Mapped from ransomware indicators to ${t}.`);
}
