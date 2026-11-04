import { Router } from "express";
import { register, join, login, refresh, logout, changeOwnPassword } from "../controllers/auth.controller";
import { requireAuth } from "../middleware/auth.middleware";
import { asyncHandler } from "../utils/asyncHandler";
import { auditLog } from "../middleware/auditLog.middleware";

const router = Router();

router.post("/register", auditLog("ORGANIZATION_REGISTERED"), asyncHandler(register));
router.post("/join", auditLog("USER_JOINED_ORGANIZATION"), asyncHandler(join));
router.post("/login", auditLog("USER_LOGIN"), asyncHandler(login));
router.post("/refresh-token", asyncHandler(refresh)); // too frequent/low-signal to log
router.post("/logout", auditLog("USER_LOGOUT"), asyncHandler(logout));
router.post("/change-password", requireAuth, auditLog("PASSWORD_CHANGED"), asyncHandler(changeOwnPassword));

export default router;