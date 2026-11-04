import { Types } from "mongoose";
import { CTIReportModel, CTIReportDocument } from "../models/ctiReport.model";
import { DetectionModel } from "../models/detection.model";
import { OrganizationModel } from "../models/organization.model";
import { AppError } from "../middleware/error.middleware";
import { AnchorError, AnchorErrorKind, getRegistryGateway } from "./blockchain.service";
import { anchorReport, verifyReportAnchor } from "./ctiAnchor.service";
import { env } from "../config/env";
import { deriveMitreForDetection } from "../utils/mitre";
import { emitToOrganization } from "../websocket/socket";
import { assertCtiDraftSupported, DEMO_CTI_LABEL, isDemoDetection, isTestRecord, RecordScope, reportScopeFilter, SIMULATED_CTI_LABEL } from "./detectionProfile";

/**
 * Indicators of compromise, built ONLY from what was actually observed on the detection. Nothing
 * is invented: no IP reputation, no malware family, no attack tool is added here. Network, file,
 * process, registry and hash indicators are extracted from the detection's own evidence fields.
 */
function buildIndicatorsOfCompromise(
  indicators: { type: string; description: string }[],
  evidence: any[]
): string[] {
  const iocs = new Set<string>();
  for (const i of indicators || []) {
    iocs.add(`${i.type}: ${i.description}`);
  }
  for (const ev of evidence || []) {
    const f = ev.fields || {};
    if (f.targetImage || f.Image || f.ProcessName) iocs.add(`PROCESS: ${f.targetImage || f.Image || f.ProcessName}`);
    if (f.targetRegistry || f.TargetObject) iocs.add(`REGISTRY: ${f.targetRegistry || f.TargetObject}`);
    if (f.commandLine || f.CommandLine) iocs.add(`COMMAND: ${f.commandLine || f.CommandLine}`);
    if (f.targetFilename || f.TargetFilename) iocs.add(`FILE: ${f.targetFilename || f.TargetFilename}`);
    if (f.hashes || f.Hashes) iocs.add(`HASH: ${f.hashes || f.Hashes}`);
    // Network indicators observed by the sensor (source/destination host and port).
    const target = f.target || f.DestinationIp || f.destinationIp;
    if (target) iocs.add(`NETWORK: destination ${target}${f.DestinationPort ? `:${f.DestinationPort}` : ""}`);
    if (f.SourceIp || f.sourceIp) iocs.add(`NETWORK: source ${f.SourceIp || f.sourceIp}${f.SourcePort ? `:${f.SourcePort}` : ""}`);
  }
  return Array.from(iocs);
}

/**
 * A fixed, honest attribution statement. SentinelIQ observes behaviour; it does not identify the
 * threat actor, malware family or attack tool, and the blockchain anchor establishes integrity and
 * publication provenance, never attribution. This goes into the hashed report content so a
 * recipient cannot be misled by an altered copy.
 */
function attributionStatement(): string {
  return (
    " Attribution: the threat actor, malware family and attack tool are NOT established by " +
    "SentinelIQ's telemetry and are reported as UNVERIFIED. Indicators above are observations from " +
    "this endpoint's own events, not externally confirmed threat intelligence."
  );
}

/** A provenance sentence (data source and the detector that produced the score), for the hashed summary. */
function provenanceStatement(detection: { dataOrigin?: string; detectorStatus?: string; modelVersion?: string; ruleId?: string }): string {
  const source =
    detection.dataOrigin === "PCAP_REPLAY" ? "recorded network traffic (offline analysis)"
    : detection.dataOrigin === "SIMULATED" ? "simulated endpoint telemetry"
    : detection.dataOrigin === "DEMO" ? "seeded demonstration data"
    : detection.dataOrigin === "LIVE" ? "live endpoint telemetry"
    : "an unspecified source";
  const detector = detection.detectorStatus === "HEURISTIC" ? "a rate-threshold rule"
    : /-XGB$/i.test(detection.ruleId || "") ? "a machine-learning behavioural detector"
    : "a rule-based detector";
  return ` Provenance: derived from ${source} by ${detector} (${detection.modelVersion || detection.ruleId || "unversioned"}).`;
}

function buildRecommendedActions(attackType: string, severity: string): string[] {
  if (attackType === "PRIVILEGE_ESCALATION") {
    return [
      "Terminate suspicious process hierarchy and revoke compromised privileges immediately.",
      "Audit local administrators and unauthorized privileged group memberships.",
      "Inspect scheduled tasks and services for persistence mechanisms.",
      "Review authentication and security event logs around the detection window.",
      "Isolate the endpoint if lateral movement or credential harvesting is suspected.",
    ];
  }

  const base = [
    "Isolate the affected endpoint from the network immediately.",
    "Rotate credentials for any accounts active on the affected machine.",
    "Review backup integrity before restoring any files.",
  ];
  if (severity === "CRITICAL" || severity === "HIGH") {
    base.unshift("Disconnect affected endpoint's shared drives to prevent lateral encryption.");
  }
  return base;
}

export async function generateCTIDraft(
  organizationId: string,
  detectionId: string,
  userId: string
) {
  const detection = await DetectionModel.findOne({ _id: detectionId, organizationId });
  if (!detection) {
    throw new AppError("Detection not found", 404);
  }
  // DoS/DDoS has no CTI template yet: refuse rather than produce a ransomware-style draft.
  assertCtiDraftSupported(detection.attackType);

  // Return existing draft if one is already open
  const existingDraft = await CTIReportModel.findOne({
    detectionId,
    status: { $in: ["DRAFT", "PENDING_APPROVAL"] },
  });
  if (existingDraft) {
    return existingDraft;
  }

  const attackType = detection.attackType || "RANSOMWARE";
  const ruleId = detection.ruleId || (attackType === "PRIVILEGE_ESCALATION" ? "PE-01" : "RANSOMWARE-XGB");
  const confidenceTier =
    detection.confidenceTier ||
    (detection.riskScore >= 80 ? "confirmed" : detection.riskScore >= 50 ? "likely" : "suspicious");

  // Test records (demo or simulated) are labelled in the title and in the hashed summary, so a
  // draft or a published anchor built from one can never pass for a real incident.
  const demo = isTestRecord(detection);
  const title =
    (demo ? "[DEMO] " : "") +
    (attackType === "PRIVILEGE_ESCALATION"
      ? `Privilege Escalation (${ruleId}) on ${detection.endpointName}`
      : `Ransomware Incident on ${detection.endpointName}`);

  const attackSummary =
    (demo ? (isDemoDetection(detection) ? DEMO_CTI_LABEL : SIMULATED_CTI_LABEL) : "") +
    (attackType === "PRIVILEGE_ESCALATION"
      ? `Privilege escalation activity detected on endpoint "${detection.endpointName}" via rule [${ruleId}] with confidence level "${confidenceTier}" and risk score ${detection.riskScore}/100. Observed behavior indicates unauthorized privilege elevation.`
      : `Ransomware-pattern behaviour detected on endpoint "${detection.endpointName}" with risk score ${detection.riskScore}/100 (severity: ${detection.severity}). ${detection.indicators.length} behavioural indicator(s) were observed.`) +
    provenanceStatement(detection) +
    attributionStatement();

  const evidence = detection.evidence || [];
  const mitre =
    detection.mitre && detection.mitre.length > 0
      ? detection.mitre
      : deriveMitreForDetection(attackType, ruleId, detection.indicators, evidence);

  const reportId = `cti-${detection._id.toString().slice(-6)}-${Date.now().toString(36)}`;

  const report = await CTIReportModel.create({
    reportId,
    schemaVersion: "v1.0",
    organizationId,
    detectionId,
    attackType,
    title,
    detectedAt: detection.detectedAt,
    severity: detection.severity,
    riskScore: detection.riskScore,
    confidenceTier,
    attackSummary,
    indicatorsOfCompromise: buildIndicatorsOfCompromise(detection.indicators, evidence),
    recommendedActions: buildRecommendedActions(attackType, detection.severity),
    detector: {
      type: attackType === "PRIVILEGE_ESCALATION" ? "rule" : "xgboost",
      id: ruleId,
      version: detection.modelVersion || "1.0.0",
    },
    evidence,
    mitre,
    hostRef: detection.endpointName,
    dataOrigin: detection.dataOrigin,
    status: "DRAFT",
    version: 1,
    visibility: "PRIVATE",
    createdByUserId: userId,
  });

  return report;
}

export async function updateCTIDraft(
  organizationId: string,
  reportId: string,
  updates: { analystNotes?: string; attackSummary?: string; recommendedActions?: string[]; indicatorsOfCompromise?: string[] }
) {
  const report = await CTIReportModel.findOne({
    $or: [{ _id: Types.ObjectId.isValid(reportId) ? reportId : undefined }, { reportId }],
    organizationId,
  });

  if (!report) {
    throw new AppError("CTI report not found", 404);
  }
  if (report.status !== "DRAFT" && report.status !== "PENDING_APPROVAL") {
    throw new AppError("Only draft reports can be edited", 400);
  }

  if (updates.analystNotes !== undefined) report.analystNotes = updates.analystNotes;
  if (updates.attackSummary !== undefined) report.attackSummary = updates.attackSummary;
  if (updates.recommendedActions !== undefined) report.recommendedActions = updates.recommendedActions;
  if (updates.indicatorsOfCompromise !== undefined) report.indicatorsOfCompromise = updates.indicatorsOfCompromise;

  await report.save();
  return report;
}

export async function createReportRevision(
  organizationId: string,
  parentReportId: string,
  userId: string,
  notes?: string
) {
  const parent = await CTIReportModel.findOne({
    $or: [{ _id: Types.ObjectId.isValid(parentReportId) ? parentReportId : undefined }, { reportId: parentReportId }],
    organizationId,
  });
  if (!parent) {
    throw new AppError("Parent report not found", 404);
  }

  const nextVersion = (parent.version || 1) + 1;
  const newReportId = `cti-${parent.detectionId.toString().slice(-6)}-v${nextVersion}-${Date.now().toString(36)}`;

  const revision = await CTIReportModel.create({
    reportId: newReportId,
    schemaVersion: "v1.0",
    organizationId,
    detectionId: parent.detectionId,
    attackType: parent.attackType,
    title: `${parent.title} (v${nextVersion})`,
    detectedAt: parent.detectedAt,
    severity: parent.severity,
    riskScore: parent.riskScore,
    confidenceTier: parent.confidenceTier,
    attackSummary: parent.attackSummary,
    indicatorsOfCompromise: parent.indicatorsOfCompromise,
    recommendedActions: parent.recommendedActions,
    analystNotes: notes || `Revision based on ${parent.reportId || parent._id}`,
    detector: parent.detector,
    evidence: parent.evidence,
    mitre: parent.mitre,
    hostRef: parent.hostRef,
    dataOrigin: parent.dataOrigin,
    version: nextVersion,
    supersedes: parent.reportId || parent._id.toString(),
    status: "DRAFT",
    // A revision starts private; the owner re-shares it deliberately. It never inherits the
    // parent's audience automatically.
    visibility: "PRIVATE",
    createdByUserId: userId,
  });

  return revision;
}

export type PublishResult =
  | { state: "ANCHORED"; report: CTIReportDocument; alreadyAnchored: boolean }
  | { state: "PENDING"; report: CTIReportDocument; message: string };

const ANCHOR_ERROR_STATUS: Record<AnchorErrorKind, number> = {
  CONFIG: 503,
  UNAVAILABLE: 503,
  FUNDS: 503,
  REVERT: 502,
};

export async function publishCTIReport(organizationId: string, reportId: string): Promise<PublishResult> {
  const report = await CTIReportModel.findOne({
    $or: [{ _id: Types.ObjectId.isValid(reportId) ? reportId : undefined }, { reportId }],
    organizationId,
  });

  if (!report) {
    throw new AppError("CTI report not found", 404);
  }
  // Idempotent: a repeated click on an anchored report is not an error.
  if (report.status === "PUBLISHED" || report.status === "ANCHORED") {
    return { state: "ANCHORED", report, alreadyAnchored: true };
  }

  // Atomically claim the report so concurrent clicks can't both submit.
  // A PUBLISHING report is reclaimable once its lock expires (or immediately
  // when it holds a pending tx), in which case anchorReport reconciles the
  // existing transaction instead of sending a new one.
  const now = new Date();
  const lockMs = env.blockchain.receiptTimeoutMs + 60_000;
  const claimed = await CTIReportModel.findOneAndUpdate(
    {
      _id: report._id,
      $or: [
        { status: { $in: ["DRAFT", "PENDING_APPROVAL", "FAILED"] } },
        {
          status: "PUBLISHING",
          $or: [{ publishLockedUntil: null }, { publishLockedUntil: { $lte: now } }],
        },
      ],
    },
    { $set: { status: "PUBLISHING", publishLockedUntil: new Date(now.getTime() + lockMs) } },
    { new: true }
  );
  if (!claimed) {
    throw new AppError("Publication is already in progress for this report. Please wait for confirmation.", 409);
  }

  try {
    const outcome = await anchorReport(claimed, getRegistryGateway(), {
      receiptTimeoutMs: env.blockchain.receiptTimeoutMs,
    });
    if (outcome.state === "ANCHORED") {
      emitToOrganization(organizationId, "cti:published", outcome.report);
    }
    return outcome;
  } catch (e: any) {
    if (e instanceof AnchorError) {
      throw new AppError(e.message, ANCHOR_ERROR_STATUS[e.kind]);
    }
    throw e;
  }
}

export async function verifyCTIReport(organizationId: string, reportId: string) {
  // A viewer may verify any report they can read: their own, or one shared with them. This is the
  // point of anchoring — a recipient independently confirms the report they received is intact.
  const { report } = await getAccessibleReport(organizationId, reportId);
  return verifyReportAnchor(report, getRegistryGateway());
}

export async function discardCTIDraft(organizationId: string, reportId: string) {
  const report = await CTIReportModel.findOne({
    $or: [{ _id: Types.ObjectId.isValid(reportId) ? reportId : undefined }, { reportId }],
    organizationId,
  });

  if (!report) {
    throw new AppError("CTI report not found", 404);
  }
  if (report.status !== "DRAFT" && report.status !== "PENDING_APPROVAL" && report.status !== "FAILED") {
    throw new AppError("Only unpublished reports can be discarded", 400);
  }
  await report.deleteOne();
}

export async function listCTIReports(organizationId: string, scope: RecordScope = "incidents") {
  return CTIReportModel.find({ organizationId, ...reportScopeFilter(scope) }).sort({ createdAt: -1 });
}

export type ReportVisibility = "PRIVATE" | "SHARED_SELECTED" | "SHARED_ALL";
const VISIBILITIES: ReportVisibility[] = ["PRIVATE", "SHARED_SELECTED", "SHARED_ALL"];

/**
 * Mongo filter for reports a viewer organization is allowed to READ but does NOT own:
 * published/anchored reports shared with everyone, or shared with this org specifically.
 * Private or unpublished reports never match. The viewer's own reports are excluded here;
 * they are read through the owner-scoped functions instead.
 */
export function sharedWithOrgFilter(viewerOrgId: string): Record<string, unknown> {
  const orgId = new Types.ObjectId(viewerOrgId);
  return {
    organizationId: { $ne: orgId },
    status: { $in: ["PUBLISHED", "ANCHORED"] },
    $or: [{ visibility: "SHARED_ALL" }, { visibility: "SHARED_SELECTED", sharedWithOrgIds: orgId }],
  };
}

/**
 * Sets a report's sharing policy. Owner organization only; a non-owner gets 404 (the report is
 * not disclosed to exist). Only published reports can be shared with all participating
 * organizations, so draft content is never exposed. SHARED_SELECTED requires at least one target.
 */
export async function setReportSharing(
  organizationId: string,
  reportId: string,
  visibility: ReportVisibility,
  sharedWithOrgIds: string[] | undefined
) {
  if (!VISIBILITIES.includes(visibility)) {
    throw new AppError(`visibility must be one of ${VISIBILITIES.join(", ")}`, 400);
  }
  const report = await CTIReportModel.findOne({
    $or: [{ _id: Types.ObjectId.isValid(reportId) ? reportId : undefined }, { reportId }],
    organizationId,
  });
  if (!report) {
    throw new AppError("CTI report not found", 404);
  }

  let targets: Types.ObjectId[] = [];
  if (visibility === "SHARED_SELECTED") {
    const ids = Array.from(new Set(sharedWithOrgIds ?? []));
    if (ids.length === 0) {
      throw new AppError("SHARED_SELECTED requires at least one organization in sharedWithOrgIds", 400);
    }
    for (const id of ids) {
      if (!Types.ObjectId.isValid(id)) throw new AppError(`invalid organization id ${id}`, 400);
      if (id === organizationId) throw new AppError("cannot share a report with its own organization", 400);
    }
    const found = await OrganizationModel.countDocuments({ _id: { $in: ids } });
    if (found !== ids.length) throw new AppError("one or more target organizations do not exist", 400);
    targets = ids.map((id) => new Types.ObjectId(id));
  }

  if (visibility !== "PRIVATE" && report.status !== "PUBLISHED" && report.status !== "ANCHORED") {
    throw new AppError("Only a published report can be shared with other organizations", 400);
  }

  report.visibility = visibility;
  report.sharedWithOrgIds = targets;
  await report.save();
  emitToOrganization(organizationId, "cti:updated", report);
  return report;
}

/**
 * Reads one report for a viewer organization, enforcing access control at the data layer:
 * the owner sees it in full; another organization sees it only if it is published and shared
 * with them. Returns the report plus whether the viewer owns it. Otherwise 404 (never disclosing
 * existence of a report the viewer may not read).
 */
export async function getAccessibleReport(viewerOrgId: string, reportId: string) {
  const byId = {
    $or: [{ _id: Types.ObjectId.isValid(reportId) ? reportId : undefined }, { reportId }],
  };
  const owned = await CTIReportModel.findOne({ ...byId, organizationId: viewerOrgId });
  if (owned) return { report: owned, owned: true };

  const shared = await CTIReportModel.findOne({ $and: [byId, sharedWithOrgFilter(viewerOrgId)] });
  if (shared) return { report: shared, owned: false };

  throw new AppError("CTI report not found", 404);
}

export async function getCTIReportById(organizationId: string, reportId: string) {
  const report = await CTIReportModel.findOne({
    $or: [{ _id: Types.ObjectId.isValid(reportId) ? reportId : undefined }, { reportId }],
    organizationId,
  });

  if (!report) {
    throw new AppError("CTI report not found", 404);
  }
  return report;
}

/**
 * The cross-organization intelligence feed FOR a viewer organization: published reports that
 * other organizations have shared with everyone or with this organization specifically. It never
 * includes the viewer's own reports (those are in their CTI Center) and never includes private or
 * unpublished reports. Access control lives in the query, not the UI.
 */
export async function listSharedCTIFeed(viewerOrgId: string, scope: RecordScope = "incidents") {
  return CTIReportModel.find({ ...sharedWithOrgFilter(viewerOrgId), ...reportScopeFilter(scope) })
    .sort({ publishedAt: -1 })
    .limit(100);
}

/**
 * The CTI feed a viewer organization sees: its own published/anchored reports plus every report
 * other organizations shared with it (sharedWithOrgFilter). Drafts and other organizations'
 * private reports never match, so access control still lives in the query.
 */
export async function listCTIFeed(viewerOrgId: string, scope: RecordScope = "incidents") {
  const ownPublished = {
    organizationId: new Types.ObjectId(viewerOrgId),
    status: { $in: ["PUBLISHED", "ANCHORED"] },
  };
  return CTIReportModel.find({ $and: [{ $or: [ownPublished, sharedWithOrgFilter(viewerOrgId)] }, reportScopeFilter(scope)] })
    .sort({ publishedAt: -1 })
    .limit(100);
}
