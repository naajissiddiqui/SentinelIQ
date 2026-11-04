#!/usr/bin/env node
/**
 * Release readiness check - builds, type-checks and runs every automated suite:
 *
 *   MONGOD_BIN=C:\path\to\mongod.exe npm run release:check [-- --skip-db] [-- --skip-chain] [-- --skip-web-build]
 *
 * Database suites run ONLY against a disposable mongod started here in a temporary directory
 * (never the MONGO_URI in apps/backend/.env). Local-chain suites start their own Hardhat node.
 * No testnet transaction is sent. Exit code is non-zero if any step fails.
 */
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = new Set(process.argv.slice(2));
const MONGO_PORT = Number(process.env.RELEASE_MONGO_PORT || 27998);
const results = [];

function run(label, cmd, cwd, env = {}) {
  process.stdout.write(`\n=== ${label} ===\n$ ${cmd}\n`);
  const t0 = Date.now();
  const r = spawnSync(cmd, { cwd: path.join(ROOT, cwd), env: { ...process.env, ...env }, shell: true, stdio: "inherit" });
  const ok = r.status === 0;
  results.push({ label, ok, seconds: ((Date.now() - t0) / 1000).toFixed(1) });
  return ok;
}

function py(dir) {
  const p = path.join(ROOT, dir, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
  return fs.existsSync(p) ? `"${p}"` : null;
}

// --- builds and type checks
run("shared-types build", "npx tsc -p packages/shared-types", ".");
run("backend typecheck", "npx tsc --noEmit -p .", "apps/backend");
run("web typecheck", "npx tsc --noEmit -p .", "apps/web");
run("web unit tests", "npm test", "apps/web");
// Production build of the web app. Stop `npm run dev:web` first: both use apps/web/.next.
if (!args.has("--skip-web-build")) run("web production build", "npx next build", "apps/web");

// --- backend suites that need neither a database nor a chain
const tests = fs.readdirSync(path.join(ROOT, "apps/backend/src/tests")).filter((f) => f.endsWith(".test.ts"));
const source = (f) => fs.readFileSync(path.join(ROOT, "apps/backend/src/tests", f), "utf-8");
const needsDb = (f) => /connectDatabase|mongoose\.connect/.test(source(f));
const needsChain = (f) => /localchain/.test(f);
const tsx = (f) => (/from "node:test"/.test(source(f)) ? `npx tsx --test src/tests/${f}` : `npx tsx src/tests/${f}`);
for (const f of tests.filter((f) => !needsDb(f) && !needsChain(f))) run(`backend ${f}`, tsx(f), "apps/backend");
if (!args.has("--skip-chain")) {
  for (const f of tests.filter((f) => needsChain(f) && !needsDb(f))) run(`backend ${f}`, tsx(f), "apps/backend");
}

// --- backend suites against a disposable local MongoDB
if (!args.has("--skip-db")) {
  const mongod = process.env.MONGOD_BIN || "mongod";
  if (spawnSync(mongod, ["--version"], { stdio: "ignore" }).status !== 0) {
    results.push({ label: "backend DB suites", ok: false, seconds: "0", note: "no mongod: set MONGOD_BIN (or pass --skip-db)" });
  } else {
    const dbPath = fs.mkdtempSync(path.join(os.tmpdir(), "sentineliq-release-db-"));
    const db = spawn(mongod, ["--dbpath", dbPath, "--port", String(MONGO_PORT), "--bind_ip", "127.0.0.1", "--quiet", "--wiredTigerCacheSizeGB", "0.25"], { stdio: "ignore" });
    await new Promise((r) => setTimeout(r, 3000));
    const dbEnv = {
      MONGO_URI: `mongodb://127.0.0.1:${MONGO_PORT}/sentineliq_disposable_test`,
      POLYGON_AMOY_RPC_URL: "http://127.0.0.1:9",      // unreachable: nothing can reach a real network
      BLOCKCHAIN_PRIVATE_KEY: "0x" + "1".repeat(64),   // dummy, never funded
    };
    try {
      for (const f of tests.filter((f) => needsDb(f) && (!needsChain(f) || !args.has("--skip-chain")))) {
        run(`backend ${f} (disposable DB)`, tsx(f), "apps/backend", dbEnv);
      }
    } finally {
      if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(db.pid), "/T", "/F"], { stdio: "ignore" });
      else db.kill();
      await new Promise((r) => setTimeout(r, 1000));
      fs.rmSync(dbPath, { recursive: true, force: true });
    }
  }
}

// --- Python suites
const mlPy = py("apps/ml-service");          // has numpy/xgboost, so the sensor's ML tests run too
const sensorPy = mlPy || py("sensor");
if (sensorPy) run("sensor tests", `${sensorPy} -B -m unittest discover -s tests -t .`, "sensor");
else results.push({ label: "sensor tests", ok: false, seconds: "0", note: "no Python venv found" });
const agentPy = py("agent");
if (agentPy) run("agent tests", `${agentPy} -B -m unittest discover -s tests -p "test_*.py"`, "agent");
else results.push({ label: "agent tests", ok: false, seconds: "0", note: "no agent venv found" });

console.log("\n=== Release check summary ===");
for (const r of results) console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.label.padEnd(58)} ${r.seconds}s ${r.note ?? ""}`);
const failed = results.filter((r) => !r.ok).length;
console.log(failed ? `\n${failed} step(s) FAILED` : `\nall ${results.length} steps passed`);
process.exit(failed ? 1 : 0);
