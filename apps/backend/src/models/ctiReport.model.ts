import { Schema, model, Document, Types } from "mongoose";

export type CTIStatus = "DRAFT" | "PENDING_APPROVAL" | "PUBLISHING" | "PUBLISHED" | "ANCHORED" | "FAILED";
export type BlockchainVerificationStatus = "VERIFIED" | "PENDING" | "FAILED" | "TAMPERED" | "UNANCHORED" | "UNTRUSTED_PUBLISHER";

export interface CTIReportDocument extends Document {
  reportId?: string;
  schemaVersion?: string;
  organizationId: Types.ObjectId;
  detectionId: Types.ObjectId;
  attackType?: string;
  title?: string;
  detectedAt?: Date;
  severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  riskScore?: number;
  confidenceTier?: string;
  attackSummary: string;
  indicatorsOfCompromise: string[];
  recommendedActions: string[];
  analystNotes?: string;
  detector?: {
    type: string;
    id: string;
    version: string;
  };
  evidence?: any[];
  mitre?: any[];
  hostRef?: string;
  // Data provenance for display (LIVE / PCAP_REPLAY / SIMULATED / DEMO). Not part of the on-chain
  // hash; the hashed attackSummary already states provenance in words.
  dataOrigin?: string;
  version?: number;
  supersedes?: string | null;
  // Who may read this report besides its owner organization. PRIVATE: owner only.
  // SHARED_SELECTED: owner plus sharedWithOrgIds. SHARED_ALL: every organization.
  // Sharing controls READ ACCESS to the stored report content; it is independent of
  // the on-chain anchor, which only ever holds the hash, never the content.
  visibility?: "PRIVATE" | "SHARED_SELECTED" | "SHARED_ALL";
  sharedWithOrgIds?: Types.ObjectId[];
  status: CTIStatus;
  createdByUserId: Types.ObjectId;
  transactionHash?: string | null;
  blockNumber?: number | null;
  publisherAddress?: string | null;
  contentHash?: string;
  canonicalJson?: string;
  verificationStatus?: BlockchainVerificationStatus;
  lastVerifiedAt?: Date | null;
  // On-chain anchor metadata. transactionHash is only ever a hash returned by
  // the RPC provider for a submitted publishCTI transaction.
  anchorKey?: string | null;
  contractAddress?: string | null;
  chainId?: number | null;
  network?: string | null;
  anchorError?: string | null;
  failedTransactionHashes?: string[];
  publishLockedUntil?: Date | null;
  invalidatedAnchor?: Record<string, unknown> | null;
  publishedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const ctiReportSchema = new Schema<CTIReportDocument>(
  {
    reportId: { type: String, index: true },
    schemaVersion: { type: String, default: "v1.0" },
    organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    detectionId: { type: Schema.Types.ObjectId, ref: "Detection", required: true, index: true },
    attackType: { type: String, default: "RANSOMWARE", index: true },
    title: { type: String },
    detectedAt: { type: Date },
    severity: { type: String, enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
    riskScore: { type: Number },
    confidenceTier: { type: String },
    attackSummary: { type: String, required: true },
    indicatorsOfCompromise: { type: [String], default: [] },
    recommendedActions: { type: [String], default: [] },
    analystNotes: { type: String },
    detector: {
      type: {
        type: String,
        enum: ["rule", "xgboost"],
      },
      id: { type: String },
      version: { type: String },
    },
    evidence: { type: [Schema.Types.Mixed], default: [] },
    mitre: { type: [Schema.Types.Mixed], default: [] },
    hostRef: { type: String },
    dataOrigin: { type: String },
    version: { type: Number, default: 1 },
    supersedes: { type: String, default: null },
    visibility: {
      type: String,
      enum: ["PRIVATE", "SHARED_SELECTED", "SHARED_ALL"],
      default: "PRIVATE",
      index: true,
    },
    sharedWithOrgIds: { type: [Schema.Types.ObjectId], ref: "Organization", default: [], index: true },
    status: {
      type: String,
      enum: ["DRAFT", "PENDING_APPROVAL", "PUBLISHING", "PUBLISHED", "ANCHORED", "FAILED"],
      default: "DRAFT",
    },
    createdByUserId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    transactionHash: { type: String },
    blockNumber: { type: Number },
    publisherAddress: { type: String },
    contentHash: { type: String },
    canonicalJson: { type: String },
    verificationStatus: {
      type: String,
      enum: ["VERIFIED", "PENDING", "FAILED", "TAMPERED", "UNANCHORED", "UNTRUSTED_PUBLISHER"],
    },
    lastVerifiedAt: { type: Date },
    anchorKey: { type: String },
    contractAddress: { type: String },
    chainId: { type: Number },
    network: { type: String },
    anchorError: { type: String },
    failedTransactionHashes: { type: [String], default: [] },
    publishLockedUntil: { type: Date },
    // Fake/unverifiable anchor metadata moved aside by the invalidation script.
    invalidatedAnchor: { type: Schema.Types.Mixed },
    publishedAt: { type: Date },
  },
  { timestamps: true }
);

ctiReportSchema.index({ organizationId: 1, createdAt: -1 });
ctiReportSchema.index({ status: 1, publishedAt: -1 });

export const CTIReportModel = model<CTIReportDocument>("CTIReport", ctiReportSchema);