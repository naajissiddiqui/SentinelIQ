"""
mitre_mapper.py
===============
Reusable MITRE ATT&CK mapping module for SentinelIQ.
Maps observed detection rules and telemetry evidence to official MITRE Enterprise ATT&CK matrix tactics and techniques.
All technique IDs, tactic names, and reference URLs conform to attack.mitre.org (Enterprise v14.1).
"""

from typing import List, Dict, Any, Optional

ATTACK_VERSION = "v14.1"

# Authoritative catalog of MITRE ATT&CK techniques used in SentinelIQ
MITRE_TECHNIQUE_CATALOG: Dict[str, Dict[str, Any]] = {
    # --- Impact & Discovery (Ransomware) ---
    "T1486": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "reference_url": "https://attack.mitre.org/techniques/T1486/",
    },
    "T1490": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1490",
        "technique_name": "Inhibit System Recovery",
        "reference_url": "https://attack.mitre.org/techniques/T1490/",
    },
    "T1083": {
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "reference_url": "https://attack.mitre.org/techniques/T1083/",
    },

    # --- Privilege Escalation, Persistence, Defense Evasion, Credential Access ---
    "T1068": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "reference_url": "https://attack.mitre.org/techniques/T1068/",
    },
    "T1548.002": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1548.002",
        "technique_name": "Abuse Elevation Control Mechanism: Bypass User Account Control",
        "reference_url": "https://attack.mitre.org/techniques/T1548/002/",
    },
    "T1543.003": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1543.003",
        "technique_name": "Create or Modify System Process: Windows Service",
        "reference_url": "https://attack.mitre.org/techniques/T1543/003/",
    },
    "T1053.005": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "reference_url": "https://attack.mitre.org/techniques/T1053/005/",
    },
    "T1098": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "reference_url": "https://attack.mitre.org/techniques/T1098/",
    },
    "T1136.001": {
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "technique_id": "T1136.001",
        "technique_name": "Create Account: Local Account",
        "reference_url": "https://attack.mitre.org/techniques/T1136/001/",
    },
    "T1003.001": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "reference_url": "https://attack.mitre.org/techniques/T1003/001/",
    },
    "T1546.012": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1546.012",
        "technique_name": "Event Triggered Execution: Image File Execution Options Injection",
        "reference_url": "https://attack.mitre.org/techniques/T1546/012/",
    },
    "T1112": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1112",
        "technique_name": "Modify Registry",
        "reference_url": "https://attack.mitre.org/techniques/T1112/",
    },
    "T1134": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1134",
        "technique_name": "Access Token Manipulation",
        "reference_url": "https://attack.mitre.org/techniques/T1134/",
    },
    "T1134.001": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1134.001",
        "technique_name": "Access Token Manipulation: Token Impersonation/Theft",
        "reference_url": "https://attack.mitre.org/techniques/T1134/001/",
    },
    "T1546.008": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1546.008",
        "technique_name": "Event Triggered Execution: Accessibility Features",
        "reference_url": "https://attack.mitre.org/techniques/T1546/008/",
    },
    "T1547.002": {
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "technique_id": "T1547.002",
        "technique_name": "Boot or Logon Autostart Execution: Authentication Package",
        "reference_url": "https://attack.mitre.org/techniques/T1547/002/",
    },
    "T1547.004": {
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "technique_id": "T1547.004",
        "technique_name": "Boot or Logon Autostart Execution: Winlogon Helper DLL",
        "reference_url": "https://attack.mitre.org/techniques/T1547/004/",
    },
    "T1547.005": {
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "technique_id": "T1547.005",
        "technique_name": "Boot or Logon Autostart Execution: Security Support Provider",
        "reference_url": "https://attack.mitre.org/techniques/T1547/005/",
    },
    "T1562.001": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1562.001",
        "technique_name": "Impair Defenses: Disable or Modify Tools",
        "reference_url": "https://attack.mitre.org/techniques/T1562/001/",
    },
}

# Rule-to-Technique default mapping table
RULE_MITRE_MAP: Dict[str, List[str]] = {
    # Ransomware
    "RANSOMWARE-XGB": ["T1486"],
    "RANSOMWARE-HEURISTIC": ["T1486"],
    "VSS-SHADOW-DELETE": ["T1490"],
    "MASS-FILE-ENUM": ["T1083"],

    # Privilege Escalation (base rule IDs + evidence-specific variants)
    "PE-01": ["T1068"],                       # Unexpected privileged process execution
    "PE-02": ["T1134"],                       # Suspicious elevated parent-child chain
    "PE-03": ["T1098"],                       # Account / privileged-group manipulation
    "PE-03-USER": ["T1136.001"],
    "PE-03-GROUP": ["T1098"],
    "PE-04": ["T1543.003", "T1053.005"],      # Elevated service / scheduled task creation
    "PE-04-SERVICE": ["T1543.003"],
    "PE-04-TASK": ["T1053.005"],
    "PE-05": ["T1548.002"],                   # Known PE / UAC-bypass indicators
    "PE-05-UAC-REG": ["T1548.002", "T1112"],
    "PE-05-UAC-EXEC": ["T1548.002"],
    "PE-05-TOOL": ["T1134"],
    "PE-06": ["T1112"],                       # Security-relevant registry modification
}


def map_mitre_techniques(rule_id: str, evidence_ids: Optional[List[str]] = None, extra_technique_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Returns a list of structured MITRE mapping objects for a given rule_id and supporting evidence.
    Techniques are only attached when justified by the triggering rule and evidence.
    """
    technique_ids = list(RULE_MITRE_MAP.get(rule_id, []))
    if extra_technique_ids:
        for tid in extra_technique_ids:
            if tid not in technique_ids:
                technique_ids.append(tid)

    results = []
    for tid in technique_ids:
        if tid in MITRE_TECHNIQUE_CATALOG:
            cat = MITRE_TECHNIQUE_CATALOG[tid]
            results.append({
                "tacticId": cat["tactic_id"],
                "tacticName": cat["tactic_name"],
                "techniqueId": cat["technique_id"],
                "techniqueName": cat["technique_name"],
                "attackVersion": ATTACK_VERSION,
                "referenceUrl": cat["reference_url"],
                "evidenceRef": list(evidence_ids) if evidence_ids else [],
            })

    return results
