export enum UserRole {
  ORG_ADMIN = "ORG_ADMIN",
  SECURITY_ANALYST = "SECURITY_ANALYST",
  SUPER_ADMIN = "SUPER_ADMIN",
}

export enum EndpointStatus {
  ONLINE = "ONLINE",
  OFFLINE = "OFFLINE",
  AT_RISK = "AT_RISK",
}

export enum DetectionStatus {
  NEW = "NEW",
  INVESTIGATING = "INVESTIGATING",
  RESOLVED = "RESOLVED",
  FALSE_POSITIVE = "FALSE_POSITIVE",
}

export enum DetectionSeverity {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL",
}

export enum AttackType {
  RANSOMWARE = "RANSOMWARE",
  PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION",
  DATA_EXFILTRATION = "DATA_EXFILTRATION",
  DOS_DDOS = "DOS_DDOS",
}

/** Where a detection's data came from. PCAP replay must never be presented as live traffic. */
export enum DataOrigin {
  LIVE = "LIVE",
  PCAP_REPLAY = "PCAP_REPLAY",
  SIMULATED = "SIMULATED",
  DEMO = "DEMO",
}

/** What produced a DoS/DDoS detection. */
export enum DetectorStatus {
  TRAINED = "TRAINED",
  HEURISTIC = "HEURISTIC",
}

export enum ConfidenceTier {
  SUSPICIOUS = "suspicious",
  LIKELY = "likely",
  CONFIRMED = "confirmed",
}

export enum CTIStatus {
  DRAFT = "DRAFT",
  PENDING_APPROVAL = "PENDING_APPROVAL",
  PUBLISHING = "PUBLISHING",
  PUBLISHED = "PUBLISHED",
  FAILED = "FAILED",
}

export enum BlockchainVerificationStatus {
  VERIFIED = "VERIFIED",
  PENDING = "PENDING",
  FAILED = "FAILED",
  TAMPERED = "TAMPERED",
  UNANCHORED = "UNANCHORED",
  UNTRUSTED_PUBLISHER = "UNTRUSTED_PUBLISHER",
}

export enum AlertStatus {
  ACTIVE = "ACTIVE",
  ACKNOWLEDGED = "ACKNOWLEDGED",
}