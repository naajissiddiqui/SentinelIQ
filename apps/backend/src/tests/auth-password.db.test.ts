/**
 * Self-service password change over HTTP against a real MongoDB. Run ONLY against a disposable
 * local database:
 *
 *   MONGO_URI=mongodb://127.0.0.1:27999/sentineliq_disposable_test npx tsx src/tests/auth-password.db.test.ts
 */
import assert from "node:assert";
import { Server } from "node:http";
import mongoose from "mongoose";
import { createApp } from "../app";
import { env } from "../config/env";
import { connectDatabase } from "../config/database";
import { OrganizationModel } from "../models/organization.model";
import { UserModel } from "../models/user.model";
import { SessionModel } from "../models/session.model";

async function runTests() {
  const host = new URL(env.mongoUri.replace(/^mongodb(\+srv)?:/, "http:")).hostname;
  if (!["127.0.0.1", "localhost"].includes(host)) {
    throw new Error(`refusing to run: MONGO_URI host ${host} is not local; use a disposable database`);
  }
  console.log("=== Starting password change tests (disposable DB) ===");
  await connectDatabase();
  const server: Server = await new Promise((resolve) => {
    const s = createApp().listen(0, () => resolve(s));
  });
  const api = `http://127.0.0.1:${(server.address() as any).port}/api`;
  const email = `pw-test-${Date.now()}@sentineliq.test`;
  const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    fetch(`${api}${path}`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
  let orgId: string | undefined;

  try {
    const reg = await post("/auth/register", { organizationName: "PW Test Org", adminName: "PW Admin", email, password: "Original-pass-1" });
    assert.strictEqual(reg.status, 201);
    orgId = (await reg.json()).organizationId;
    const login = async (password: string) => post("/auth/login", { email, password });
    const first = await login("Original-pass-1");
    const second = await login("Original-pass-1");     // a second session, e.g. another browser
    assert.strictEqual(first.status, 200);
    const token = (await first.json()).accessToken;
    const keepCookie = (first.headers.get("set-cookie") || "").split(";")[0];
    assert.strictEqual(second.status, 200);
    const userId = (await UserModel.findOne({ email }))!._id;
    assert.strictEqual(await SessionModel.countDocuments({ userId }), 2);
    const auth = { Authorization: `Bearer ${token}`, Cookie: keepCookie };

    assert.strictEqual((await post("/auth/change-password", { currentPassword: "x", newPassword: "New-pass-2026" })).status, 401);
    assert.strictEqual((await post("/auth/change-password", { currentPassword: "wrong-one", newPassword: "New-pass-2026" }, auth)).status, 400);
    assert.strictEqual((await post("/auth/change-password", { currentPassword: "Original-pass-1", newPassword: "short" }, auth)).status, 400);
    assert.strictEqual((await post("/auth/change-password", { currentPassword: "Original-pass-1", newPassword: "Original-pass-1" }, auth)).status, 400);
    console.log("  PASS: refused without auth, with a wrong current password, a short or unchanged new password");

    const ok = await post("/auth/change-password", { currentPassword: "Original-pass-1", newPassword: "New-pass-2026" }, auth);
    assert.strictEqual(ok.status, 200);
    assert.strictEqual((await login("Original-pass-1")).status, 401);
    assert.strictEqual(await SessionModel.countDocuments({ userId }), 1, "other sessions are revoked, the caller's is kept");
    assert.strictEqual((await login("New-pass-2026")).status, 200);
    console.log("  PASS: password changed; the old one no longer works; other sessions revoked");
    console.log("=== ALL PASSWORD CHANGE TESTS PASSED! ===");
  } finally {
    if (orgId) {
      const users = await UserModel.find({ organizationId: orgId });
      await SessionModel.deleteMany({ userId: { $in: users.map((u) => u._id) } });
      await UserModel.deleteMany({ organizationId: orgId });
      await OrganizationModel.deleteOne({ _id: orgId });
    }
    server.close();
    await mongoose.disconnect();
  }
}

runTests().catch((err) => {
  console.error("TEST FAILED:", err);
  process.exit(1);
});
