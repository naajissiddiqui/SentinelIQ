import { Types } from "mongoose";
import { DetectionModel, severityFromRiskScore, BehaviourIndicator } from "../models/detection.model";
import { EndpointModel } from "../models/endpoint.model";
import { UserModel } from "../models/user.model";
import { AppError } from "../middleware/error.middleware";
import { emitToOrganization } from "../websocket/socket";
import { recordTimelineEvent } from "./timeline.service";
import { TimelineActorType } from "../models/timelineEvent.model";
import { threatIntelService } from "./cti/threatIntel.service";
import { correlateCascade } from "./cascade.service";
import { evaluatePolicies } from "./policy.service";
import { deriveMitreForDetection } from "../utils/mitre";
import { isDemoDetection, normalizeAttackType, responseProfile, RecordScope, scopeFilter, TEST_RECORD_FILTER } from "./detectionProfile";

interface CreateDetectionInput {
  organizationId: string;
  endpointId: string;
  riskScore: number;
  indicators: (BehaviourIndicator | string)[];
  modelVersion?: string;
  detectedAt?: Date;
  attackType?: string;
  ruleId?: string;
  confidenceTier?: string;
  evidence?: any[];
  mitre?: any[];
  dataOrigin?: string;
  detectorStatus?: string;
  sourceAlertKey?: string;
}

/** The detection already stored for this sensor alert episode, if any (ingest deduplication). */
export async function findDetectionBySourceAlertKey(organizationId: string, key: string) {
  return DetectionModel.findOne({ organizationId, sourceAlertKey: key });
}

export async function createDetection(input: CreateDetectionInput) {
  const endpoint = await EndpointModel.findOne({
    _id: input.endpointId,
    organizationId: input.organizationId,
    isDeleted: false,
  });

  if (!endpoint) {
    throw new AppError("Endpoint not found for this organization", 404);
  }

  // Normalize indicators whether they are strings or structured objects
  const formattedIndicators = (input.indicators || []).map((ind: any) => {
    if (typeof ind === "string") {
      return {
        type: "BEHAVIOUR_PATTERN",
        description: ind,
        observedAt: new Date(),
      };
    }
    return {
      type: ind.type || "BEHAVIOUR_PATTERN",
      description: ind.description || String(ind),
      observedAt: ind.observedAt ? new Date(ind.observedAt) : new Date(),
    };
  });

  // 1. CTI Threat Intelligence Correlation
  const ctiResult = await threatIntelService.correlateDetection(formattedIndicators);
  const ctiMatchData = ctiResult.matched
    ? {
        matched: true,
        indicator: ctiResult.indicator,
        type: ctiResult.type,
        isMalicious: ctiResult.isMalicious,
        confidence: ctiResult.confidence,
        severity: ctiResult.severity,
        threatCategory: ctiResult.threatCategory,
        tags: ctiResult.tags,
        source: ctiResult.source,
        matchedAt: new Date(),
      }
    : undefined;

  const attackType = normalizeAttackType(input.attackType);
  const profile = responseProfile(attackType);
  const evidence = input.evidence || [];
  // Producer-supplied mappings (e.g. the endpoint agent's own mapper) are kept as sent,
  // and labelled as such when they carry no reason of their own.
  const mapped = (input.mitre && input.mitre.length > 0)
    ? input.mitre.map((m: any) => (m && !m.mappingReason
        ? { ...m, mappingReason: `Supplied by the reporting producer${input.ruleId ? ` for rule ${input.ruleId}` : ""}.` }
        : m))
    : deriveMitreForDetection(attackType, input.ruleId, formattedIndicators, evidence);
  // Demonstration records describe no observed behaviour, so their mapping reasons say so.
  const mitre = isDemoDetection({ dataOrigin: input.dataOrigin, ruleId: input.ruleId, modelVersion: input.modelVersion })
    ? mapped.map((m: any) => ({ ...m, mappingReason: `Demonstration data, not an observation: ${m.mappingReason ?? ""}`.trim() }))
    : mapped;

  const detection = await DetectionModel.create({
    organizationId: input.organizationId,
    endpointId: endpoint._id,
    endpointName: endpoint.name,
    attackType,
    ruleId: input.ruleId,
    confidenceTier: input.confidenceTier,
    riskScore: input.riskScore,
    severity: severityFromRiskScore(input.riskScore),
    indicators: formattedIndicators,
    evidence,
    mitre,
    modelVersion: input.modelVersion,
    detectedAt: input.detectedAt ?? new Date(),
    ctiMatch: ctiMatchData,
    dataOrigin: input.dataOrigin,
    detectorStatus: input.detectorStatus,
    sourceAlertKey: input.sourceAlertKey,
  });

  const prevStatus = endpoint.status;

  // Endpoint moves to AT_RISK the moment a new detection lands on it —
  // matches the Dashboard's donut chart and Endpoint Management status column.
  // DoS/DDoS alerts are alert-only and leave the endpoint status alone.
  if (profile.markEndpointAtRisk) {
    endpoint.status = "AT_RISK";
    await endpoint.save();
    emitToOrganization(input.organizationId, "endpoint:updated", endpoint);
  }
  emitToOrganization(input.organizationId, "detection:new", detection);

  // Automatically record forensic timeline events
  const threatLabel = profile.threatLabel;
  await recordTimelineEvent({
    organizationId: input.organizationId,
    endpointId: endpoint._id,
    endpointName: endpoint.name,
    detectionId: detection._id,
    eventType: "DETECTION_CREATED",
    actorType: "AGENT",
    actorName: endpoint.name,
    message: `${threatLabel} detection recorded on ${endpoint.name} — Risk score: ${input.riskScore}/100 (${detection.severity})`,
    metadata: {
      attackType,
      ruleId: input.ruleId,
      confidenceTier: input.confidenceTier,
      riskScore: input.riskScore,
      severity: detection.severity,
      indicators: formattedIndicators,
      evidence,
      mitre,
      modelVersion: input.modelVersion,
      ctiMatched: Boolean(ctiMatchData?.matched),
      dataOrigin: input.dataOrigin,
      detectorStatus: input.detectorStatus,
    },
    timestamp: detection.detectedAt,
  });

  if (profile.markEndpointAtRisk && prevStatus !== "AT_RISK") {
    await recordTimelineEvent({
      organizationId: input.organizationId,
      endpointId: endpoint._id,
      endpointName: endpoint.name,
      detectionId: detection._id,
      eventType: "ENDPOINT_STATUS_CHANGED",
      actorType: "SYSTEM",
      message: `Endpoint status changed: ${prevStatus} → AT_RISK`,
      metadata: {
        from: prevStatus,
        to: "AT_RISK",
        reason: profile.atRiskReason,
      },
      timestamp: detection.detectedAt,
    });
  }

  // Record CTI Match timeline event & emit Socket.IO
  if (ctiMatchData?.matched) {
    emitToOrganization(input.organizationId, "cti:match", {
      detectionId: detection._id.toString(),
      endpointId: endpoint._id.toString(),
      endpointName: endpoint.name,
      ctiMatch: ctiMatchData,
    });

    await recordTimelineEvent({
      organizationId: input.organizationId,
      endpointId: endpoint._id,
      endpointName: endpoint.name,
      detectionId: detection._id,
      eventType: "CTI_MATCHED",
      actorType: "SYSTEM",
      message: `Threat Intel matched IOC "${ctiMatchData.indicator}" (${ctiMatchData.threatCategory}) — Confidence: ${ctiMatchData.confidence}%`,
      metadata: {
        indicator: ctiMatchData.indicator,
        type: ctiMatchData.type,
        threatCategory: ctiMatchData.threatCategory,
        confidence: ctiMatchData.confidence,
        severity: ctiMatchData.severity,
        source: ctiMatchData.source,
      },
      timestamp: new Date(),
    });
  }

  // Privilege escalation detections are alert-only: skip cascade correlation
  // (its types/containment are ransomware/C2-specific) and automated response
  // actions (isolation, process kill, severity escalation).
  if (!profile.runPolicies) {
    return detection;
  }

  // 2. Cross-Endpoint Attack / Cascade Correlation (ransomware-oriented; DoS skips it)
  const cascade = profile.runCascadeCorrelation ? await correlateCascade(detection) : null;

  // 3. Automated Response Policy Evaluation
  const consecutiveDetectionsCount = await DetectionModel.countDocuments({
    organizationId: input.organizationId,
    endpointId: endpoint._id,
    status: { $in: ["NEW", "INVESTIGATING"] },
  });

  await evaluatePolicies({
    organizationId: input.organizationId,
    endpointId: endpoint._id.toString(),
    endpointName: endpoint.name,
    endpointStatus: endpoint.status,
    detectionId: detection._id.toString(),
    riskScore: detection.riskScore,
    severity: detection.severity,
    detectionType: attackType,
    consecutiveDetections: consecutiveDetectionsCount,
    ctiMatch: Boolean(ctiMatchData?.matched),
    ctiConfidence: ctiMatchData?.confidence,
    maliciousIocMatch: Boolean(ctiMatchData?.isMalicious),
    iocValue: ctiMatchData?.indicator,
    iocType: ctiMatchData?.type,
    affectedEndpointCount: cascade ? cascade.affectedEndpointIds.length : 1,
    crossEndpointAttack: Boolean(cascade),
    cascadeId: cascade?.cascadeId,
    cascadeSeverity: cascade?.severity,
  });

  return detection;
}

interface ListDetectionsInput {
  organizationId: string;
  status?: string;
  severity?: string;
  attackType?: string;
  dataOrigin?: string;
  endpointId?: string;
  from?: string;
  to?: string;
  page?: number;
  limit?: number;
  /** Incidents only (default), test records only, or both. */
  scope?: RecordScope;
}

export const MAX_DETECTION_PAGE_SIZE = 200;

function detectionQuery(input: ListDetectionsInput): Record<string, any> {
  const query: Record<string, any> = { organizationId: input.organizationId, ...scopeFilter(input.scope ?? "incidents") };
  if (input.status) query.status = input.status;
  if (input.severity) query.severity = input.severity;
  if (input.attackType) query.attackType = input.attackType;
  if (input.dataOrigin) query.dataOrigin = input.dataOrigin;
  if (input.endpointId) query.endpointId = input.endpointId;
  if (input.from || input.to) {
    query.detectedAt = {};
    if (input.from) query.detectedAt.$gte = new Date(input.from);
    if (input.to) query.detectedAt.$lte = new Date(input.to);
  }
  return query;
}

/**
 * One page of detections, newest first, with the total that matches the
 * filters, so clients never mistake a truncated page for the whole set.
 */
export async function listDetections(input: ListDetectionsInput) {
  const limit = Math.min(Math.max(Math.trunc(input.limit ?? MAX_DETECTION_PAGE_SIZE), 1), MAX_DETECTION_PAGE_SIZE);
  const page = Math.max(Math.trunc(input.page ?? 1), 1);
  const query = detectionQuery(input);
  const [detections, total] = await Promise.all([
    DetectionModel.find(query).sort({ detectedAt: -1, _id: -1 }).skip((page - 1) * limit).limit(limit),
    DetectionModel.countDocuments(query),
  ]);
  return { detections, total, page, limit, hasMore: page * limit < total };
}

/** Organisation-wide counts computed in MongoDB: not limited by any page size. */
export async function summarizeDetections(organizationId: string, days = 30, scope: RecordScope = "incidents") {
  const orgId = new Types.ObjectId(organizationId);
  const now = new Date();
  const since = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - (days - 1)));
  const group = (field: string) => [{ $group: { _id: `$${field}`, count: { $sum: 1 } } }];
  const [facet] = await DetectionModel.aggregate([
    { $match: { organizationId: orgId, ...scopeFilter(scope) } },
    {
      $facet: {
        total: [{ $count: "n" }],
        byStatus: group("status"),
        bySeverity: group("severity"),
        byAttackType: group("attackType"),
        byDataOrigin: group("dataOrigin"),
        byDetectorStatus: group("detectorStatus"),
        daily: [
          { $match: { detectedAt: { $gte: since } } },
          { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$detectedAt", timezone: "UTC" } }, count: { $sum: 1 } } },
        ],
        techniques: [
          { $unwind: "$mitre" },
          { $group: { _id: { id: "$mitre.techniqueId", name: "$mitre.techniqueName", tactic: "$mitre.tacticName" }, count: { $sum: 1 } } },
          { $sort: { count: -1 } },
        ],
        unmapped: [{ $match: { $or: [{ mitre: { $exists: false } }, { mitre: { $size: 0 } }] } }, { $count: "n" }],
        ctiMatched: [{ $match: { "ctiMatch.matched": true } }, { $count: "n" }],
      },
    },
  ]);
  // Test records (demonstration or simulated) held for this organisation, whatever the scope.
  const testRecords = await DetectionModel.countDocuments({ organizationId: orgId, ...TEST_RECORD_FILTER });
  const toMap = (rows: Array<{ _id: string | null; count: number }>) =>
    Object.fromEntries(rows.map((r) => [r._id ?? "UNSPECIFIED", r.count]));
  const daily = Object.fromEntries(facet.daily.map((r: any) => [r._id, r.count]));
  const timeline = Array.from({ length: days }, (_, i) => {
    const d = new Date(since.getTime() + i * 86_400_000).toISOString().slice(0, 10);
    return { date: d, count: daily[d] ?? 0 };
  });
  const byStatus = toMap(facet.byStatus);
  return {
    total: facet.total[0]?.n ?? 0,
    active: (byStatus.NEW ?? 0) + (byStatus.INVESTIGATING ?? 0),
    byStatus,
    bySeverity: toMap(facet.bySeverity),
    byAttackType: toMap(facet.byAttackType),
    byDataOrigin: toMap(facet.byDataOrigin),
    byDetectorStatus: toMap(facet.byDetectorStatus),
    timeline,
    techniques: facet.techniques.map((t: any) => ({ techniqueId: t._id.id, techniqueName: t._id.name, tacticName: t._id.tactic, count: t.count })),
    unmappedDetections: facet.unmapped[0]?.n ?? 0,
    ctiMatched: facet.ctiMatched[0]?.n ?? 0,
    scope,
    testRecords,
    generatedAt: now.toISOString(),
  };
}

export async function getDetectionById(organizationId: string, detectionId: string) {
  if (!Types.ObjectId.isValid(detectionId)) {
    throw new AppError("Invalid detection ID", 400);
  }

  const detection = await DetectionModel.findOne({
    _id: detectionId,
    organizationId,
  });

  if (!detection) {
    throw new AppError("Detection not found", 404);
  }

  return detection;
}

export async function resolveDetection(
  organizationId: string,
  detectionId: string,
  userId: string,
  outcome: "RESOLVED" | "FALSE_POSITIVE" = "RESOLVED"
) {
  const detection = await getDetectionById(organizationId, detectionId);

  detection.status = outcome;
  detection.resolvedAt = new Date();
  detection.resolvedByUserId = new Types.ObjectId(userId);
  await detection.save();

  // Determine user identity and role for timeline actor attribution
  let actorName = "Security Analyst";
  let actorType: TimelineActorType = "SECURITY_ANALYST";
  if (userId && Types.ObjectId.isValid(userId)) {
    const user = await UserModel.findById(userId).select("name email role");
    if (user) {
      actorName = user.name || user.email;
      actorType = user.role === "ORG_ADMIN" ? "ORG_ADMIN" : "SECURITY_ANALYST";
    }
  }

  // Record resolution timeline event
  await recordTimelineEvent({
    organizationId,
    endpointId: detection.endpointId,
    endpointName: detection.endpointName,
    detectionId: detection._id,
    eventType: outcome === "FALSE_POSITIVE" ? "DETECTION_FALSE_POSITIVE" : "DETECTION_RESOLVED",
    actorType,
    actorId: userId,
    actorName,
    message: `Detection marked as ${outcome === "RESOLVED" ? "Resolved" : "False Positive"}`,
    metadata: {
      outcome,
      riskScore: detection.riskScore,
      severity: detection.severity,
    },
    timestamp: detection.resolvedAt,
  });

  // If no other active detections remain on this endpoint, bring it back
  // to ONLINE — avoids the endpoint staying "AT_RISK" forever after cleanup.
  const stillAtRisk = await DetectionModel.exists({
    organizationId,
    endpointId: detection.endpointId,
    status: { $in: ["NEW", "INVESTIGATING"] },
  });

  if (!stillAtRisk) {
    const currentEp = await EndpointModel.findById(detection.endpointId);
    if (currentEp && currentEp.status === "AT_RISK") {
      currentEp.status = "ONLINE";
      await currentEp.save();
      emitToOrganization(organizationId, "endpoint:updated", currentEp);

      await recordTimelineEvent({
        organizationId,
        endpointId: currentEp._id,
        endpointName: currentEp.name,
        detectionId: detection._id,
        eventType: "ENDPOINT_STATUS_CHANGED",
        actorType: "SYSTEM",
        message: `Endpoint status changed: AT_RISK → ONLINE (all active threats resolved)`,
        metadata: {
          from: "AT_RISK",
          to: "ONLINE",
          reason: "All active detections resolved",
        },
      });
    }
  }

  emitToOrganization(organizationId, "detection:resolved", detection);

  return detection;
}