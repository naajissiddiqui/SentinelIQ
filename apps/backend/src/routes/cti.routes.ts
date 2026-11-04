import { Router } from "express";
import { requireAuth } from "../middleware/auth.middleware";
import { asyncHandler } from "../utils/asyncHandler";
import { auditLog } from "../middleware/auditLog.middleware";
import {
  createDraft,
  editDraft,
  publish,
  discard,
  getReports,
  getReport,
  getPublicFeed,
  getShareTargets,
  shareReport,
  verifyReport,
  reviseReport,
  blockchainStatus,
} from "../controllers/cti.controller";
import { requireRole } from "../middleware/auth.middleware";

const router = Router();

router.use(requireAuth);

router.get("/", asyncHandler(getReports));
router.get("/feed", asyncHandler(getPublicFeed)); // must come before /:id
router.get("/share-targets", asyncHandler(getShareTargets)); // must come before /:id
router.get("/blockchain/status", asyncHandler(blockchainStatus));
router.get("/:id", asyncHandler(getReport));
router.get("/:id/verify", asyncHandler(verifyReport));
router.post("/:id/verify", asyncHandler(verifyReport));

router.post("/", auditLog("CTI_DRAFT_GENERATED"), asyncHandler(createDraft));
router.patch("/:id", asyncHandler(editDraft));
router.post("/:id/publish", auditLog("CTI_PUBLISHED"), asyncHandler(publish));
router.post("/:id/revise", auditLog("CTI_REVISION_CREATED"), asyncHandler(reviseReport));
router.post("/:id/share", requireRole("ORG_ADMIN", "SECURITY_ANALYST"), auditLog("CTI_SHARING_UPDATED"), asyncHandler(shareReport));
router.delete("/:id", asyncHandler(discard));

export default router;