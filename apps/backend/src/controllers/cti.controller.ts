import { parseRecordScope } from "../services/detectionProfile";
import { Response } from "express";
import { AuthenticatedRequest } from "../middleware/auth.middleware";
import {
  generateCTIDraft,
  updateCTIDraft,
  publishCTIReport,
  discardCTIDraft,
  listCTIReports,
  getAccessibleReport,
  listCTIFeed,
  setReportSharing,
  verifyCTIReport,
  createReportRevision,
} from "../services/cti.service";
import { OrganizationModel } from "../models/organization.model";
import { AppError } from "../middleware/error.middleware";
import { validateBlockchainConfig } from "../config/blockchain";

export async function createDraft(req: AuthenticatedRequest, res: Response) {
  const { detectionId } = req.body;
  if (!detectionId) {
    throw new AppError("detectionId is required", 400);
  }

  const report = await generateCTIDraft(
    req.user!.organizationId,
    detectionId,
    req.user!.userId
  );

  res.status(201).json({
    message: "CTI report generated. Please review before publishing.",
    report,
  });
}

/** An optional list of non-empty strings from a request body (draft IOCs and actions). */
function stringList(value: unknown, field: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 200 || !value.every((v) => typeof v === "string" && v.trim() && v.length <= 2000)) {
    throw new AppError(`${field} must be a list of up to 200 non-empty strings`, 400);
  }
  return value.map((v) => v.trim());
}

export async function editDraft(req: AuthenticatedRequest, res: Response) {
  const report = await updateCTIDraft(req.user!.organizationId, req.params.id, {
    analystNotes: req.body.analystNotes,
    attackSummary: req.body.attackSummary,
    recommendedActions: stringList(req.body.recommendedActions, "recommendedActions"),
    indicatorsOfCompromise: stringList(req.body.indicatorsOfCompromise, "indicatorsOfCompromise"),
  });
  res.status(200).json({ message: "Draft updated", report });
}

export async function publish(req: AuthenticatedRequest, res: Response) {
  const result = await publishCTIReport(req.user!.organizationId, req.params.id);
  if (result.state === "PENDING") {
    res.status(202).json({ message: result.message, pending: true, report: result.report });
    return;
  }
  res.status(200).json({
    message: result.alreadyAnchored
      ? "Report was already anchored on Polygon Amoy."
      : `Report hash anchored on Polygon Amoy in block ${result.report.blockNumber}.`,
    pending: false,
    alreadyAnchored: result.alreadyAnchored,
    report: result.report,
  });
}

export async function blockchainStatus(_req: AuthenticatedRequest, res: Response) {
  const status = await validateBlockchainConfig();
  res.status(200).json({ blockchain: status });
}

export async function discard(req: AuthenticatedRequest, res: Response) {
  await discardCTIDraft(req.user!.organizationId, req.params.id);
  res.status(200).json({ message: "Draft discarded" });
}

export async function getReports(req: AuthenticatedRequest, res: Response) {
  // An organization's OWN CTI Center is a private management view: it shows every report they own,
  // including demonstration/simulated ones (the UI labels those). Demo records are only hidden from
  // the cross-organization feed and the dashboard, not from the owner's own list. A scope can still
  // be passed explicitly to narrow it.
  const scope = req.query.scope ? parseRecordScope(req.query.scope) : "all";
  const reports = await listCTIReports(req.user!.organizationId, scope);
  res.status(200).json({ reports });
}

export async function getReport(req: AuthenticatedRequest, res: Response) {
  // A viewer may read their own report, or one another organization shared with them.
  const { report, owned } = await getAccessibleReport(req.user!.organizationId, req.params.id);
  res.status(200).json({ report, owned });
}

export async function getPublicFeed(req: AuthenticatedRequest, res: Response) {
  const reports = await listCTIFeed(req.user!.organizationId, parseRecordScope(req.query.scope));
  res.status(200).json({ reports });
}

export async function shareReport(req: AuthenticatedRequest, res: Response) {
  const { visibility, sharedWithOrgIds } = req.body ?? {};
  const report = await setReportSharing(req.user!.organizationId, req.params.id, visibility, sharedWithOrgIds);
  res.status(200).json({ message: "Sharing policy updated", report });
}

export async function getShareTargets(req: AuthenticatedRequest, res: Response) {
  // Other organizations this org can share a report with (id and name only; no internal data).
  const orgs = await OrganizationModel.find({ _id: { $ne: req.user!.organizationId } })
    .select("name")
    .sort({ name: 1 });
  res.status(200).json({ organizations: orgs.map((o) => ({ id: o._id, name: o.name })) });
}

export async function verifyReport(req: AuthenticatedRequest, res: Response) {
  const result = await verifyCTIReport(req.user!.organizationId, req.params.id);
  res.status(200).json({ message: "Verification completed", verification: result });
}

export async function reviseReport(req: AuthenticatedRequest, res: Response) {
  const revision = await createReportRevision(
    req.user!.organizationId,
    req.params.id,
    req.user!.userId,
    req.body.analystNotes
  );
  res.status(201).json({ message: "Revision draft created", report: revision });
}