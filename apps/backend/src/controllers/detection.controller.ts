import { Response } from "express";
import { Types } from "mongoose";
import { Request } from "express";
import { AuthenticatedRequest } from "../middleware/auth.middleware";
import {
  createDetection,
  findDetectionBySourceAlertKey,
  listDetections,
  summarizeDetections,
  getDetectionById,
  resolveDetection,
} from "../services/detection.service";
import { AppError } from "../middleware/error.middleware";
import { parseRecordScope, sourceAlertKey, validateIngestFields } from "../services/detectionProfile";

// Called by the ML service or Agent (service-API-key auth, not a logged-in user).
export async function ingestDetection(req: Request, res: Response) {
  const {
    organizationId,
    endpointId,
    riskScore,
    indicators,
    modelVersion,
    detectedAt,
    attackType,
    ruleId,
    confidenceTier,
    evidence,
    mitre,
    dataOrigin,
    detectorStatus,
  } = req.body;

  if (!organizationId || !endpointId || typeof riskScore !== "number") {
    throw new AppError("organizationId, endpointId, and riskScore are required", 400);
  }
  // A malformed id is a client error (400), not an unhandled cast failure (500).
  if (!Types.ObjectId.isValid(String(organizationId)) || !Types.ObjectId.isValid(String(endpointId))) {
    throw new AppError("organizationId and endpointId must be valid ids", 400);
  }
  const checked = validateIngestFields({ attackType, confidenceTier, dataOrigin, detectorStatus });
  const when = detectedAt ? new Date(detectedAt) : undefined;
  if (when && Number.isNaN(when.getTime())) throw new AppError("detectedAt must be a valid date", 400);

  // A sensor alert episode is stored once: re-sending it returns the existing detection.
  const key = sourceAlertKey({ endpointId: String(endpointId), attackType: checked.attackType, ruleId, modelVersion, dataOrigin: checked.dataOrigin,
                               detectedAt: when, evidence: Array.isArray(evidence) ? evidence : undefined });
  if (key) {
    const existing = await findDetectionBySourceAlertKey(String(organizationId), key);
    if (existing) {
      res.status(200).json({ message: "Alert already recorded", duplicate: true, detection: existing });
      return;
    }
  }

  const detection = await createDetection({
    organizationId,
    endpointId,
    riskScore,
    indicators: indicators ?? [],
    modelVersion,
    detectedAt: when,
    attackType: checked.attackType,
    ruleId,
    confidenceTier,
    evidence,
    mitre,
    dataOrigin: checked.dataOrigin,
    detectorStatus: checked.detectorStatus,
    sourceAlertKey: key,
  });

  res.status(201).json({ message: "Detection recorded", detection });
}

export async function getDetections(req: AuthenticatedRequest, res: Response) {
  const organizationId = req.user!.organizationId;
  const { status, severity, attackType, dataOrigin, endpointId, from, to, page, limit, scope } = req.query;
  const str = (v: unknown) => (typeof v === "string" && v !== "" ? v : undefined);
  const int = (v: unknown) => {
    if (v === undefined) return undefined;
    const n = Number(v);
    if (!Number.isInteger(n) || n < 1) throw new AppError("page and limit must be positive integers", 400);
    return n;
  };

  const result = await listDetections({
    organizationId,
    status: str(status),
    severity: str(severity),
    attackType: str(attackType),
    dataOrigin: str(dataOrigin),
    endpointId: str(endpointId),
    from: str(from),
    to: str(to),
    page: int(page),
    limit: int(limit),
    scope: parseRecordScope(scope),
  });

  res.status(200).json(result);
}

export async function getDetectionSummary(req: AuthenticatedRequest, res: Response) {
  res.status(200).json({ summary: await summarizeDetections(req.user!.organizationId, 30, parseRecordScope(req.query.scope)) });
}

export async function getDetection(req: AuthenticatedRequest, res: Response) {
  const organizationId = req.user!.organizationId;
  const detection = await getDetectionById(organizationId, req.params.id);
  res.status(200).json({ detection });
}

export async function markResolved(req: AuthenticatedRequest, res: Response) {
  const organizationId = req.user!.organizationId;
  const userId = req.user!.userId;
  const { outcome = "RESOLVED" } = (req.body || {}) as { outcome?: "RESOLVED" | "FALSE_POSITIVE" };

  if (outcome !== "RESOLVED" && outcome !== "FALSE_POSITIVE") {
    throw new AppError('outcome must be "RESOLVED" or "FALSE_POSITIVE"', 400);
  }

  const detection = await resolveDetection(organizationId, req.params.id, userId, outcome);
  res.status(200).json({
    message: `Detection marked as ${outcome === "RESOLVED" ? "resolved" : "false positive"}`,
    detection,
  });
}