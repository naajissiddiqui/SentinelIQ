import { CTIStatus, BlockchainVerificationStatus, AttackType, ConfidenceTier } from "./enums";
import { MitreMapping, EvidenceItem } from "./detection";

export type IOCType = "IP" | "DOMAIN" | "HASH" | "URL";

export interface ThreatIntelIOC {
  indicator: string;
  type: IOCType;
  isMalicious: boolean;
  confidence: number; // 0 - 100
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  threatCategory: string; // e.g. "Ransomware C2", "Malware Payload", "Data Exfiltration"
  tags: string[];
  source: string;
  firstSeen: string;
  lastSeen: string;
  description?: string;
}

export interface CTIMatchResult {
  matched: boolean;
  indicator?: string;
  type?: IOCType;
  isMalicious?: boolean;
  confidence?: number;
  severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  threatCategory?: string;
  tags?: string[];
  source?: string;
  matchedAt?: string;
}

export interface CTIReport {
  _id: string;
  reportId?: string;
  schemaVersion?: string;
  organizationId: string;
  detectionId: string;
  attackType?: AttackType | string;
  title?: string;
  detectedAt?: string;
  firstSeen?: string;
  lastSeen?: string;
  severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  riskScore?: number;
  confidenceTier?: ConfidenceTier | string;
  attackSummary: string;
  indicatorsOfCompromise: string[];
  recommendedActions: string[];
  analystNotes?: string;
  detector?: {
    type: "rule" | "xgboost";
    id: string;
    version: string;
  };
  evidence?: EvidenceItem[];
  mitre?: MitreMapping[];
  hostRef?: string;
  status: CTIStatus | string;
  version?: number;
  supersedes?: string | null;
  createdByUserId?: string;
  transactionHash?: string | null;
  blockNumber?: number | null;
  publisherAddress?: string | null;
  contractAddress?: string | null;
  chainId?: number | null;
  network?: string | null;
  anchorKey?: string | null;
  anchorError?: string | null;
  verificationStatus?: BlockchainVerificationStatus | string;
  contentHash?: string;
  canonicalJson?: string;
  publishedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CTIVerificationResult {
  reportId: string;
  /** UNAVAILABLE = the chain could not be queried; integrity is NOT confirmed. */
  status: "VERIFIED" | "TAMPERED" | "UNANCHORED" | "UNTRUSTED_PUBLISHER" | "UNAVAILABLE";
  matches: boolean;
  recomputedHash: string;
  persistedHash: string | null;
  onChainHash: string | null;
  publisher: string | null;
  isAuthorizedPublisher: boolean | null;
  blockNumber: number | null;
  transactionHash: string | null;
  transactionConfirmed: boolean | null;
  timestamp: string | null;
  contractAddress: string;
  chainId: number;
  network: string;
  error?: string;
}