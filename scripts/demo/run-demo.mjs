#!/usr/bin/env node
/**
 * SentinelIQ rehearsal environment - one command, fully isolated from your real data:
 *
 *   MONGOD_BIN=C:\path\to\mongod.exe npm run demo [-- --verify-amoy] [-- --no-web]
 *
 * This is NOT the real application setup (that is `npm run dev:backend` + `npm run dev:web`, with
 * `npm run replay:recorded` to send recorded detections). It starts a DISPOSABLE local MongoDB
 * (temporary data directory), the same backend and web app, then:
 *   1. registers a rehearsal organisation and a network-sensor endpoint through the real API;
 *   2. forwards the recorded-traffic DoS alerts (data/recorded-traffic/*.jsonl, produced offline
 *      from CIC-DDoS2019 captures) through the sensor's `ingest-alerts` forwarder.
 * Optional --verify-amoy reads the already published Polygon Amoy transaction (read-only; no
 * transaction is ever sent by this script).
 *
 * Safety: never connects to the MongoDB in apps/backend/.env; CTI publishing is disabled (the
 * backend is given an unreachable RPC, so it truthfully reports publishing as unavailable); nothing
 * here claims to be live telemetry. Ctrl+C stops everything this script started.
 */
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const args = new Set(process.argv.slice(2));
const PORTS = { mongo: Number(process.env.DEMO_MONGO_PORT || 27999), api: Number(process.env.DEMO_API_PORT || 4123), web: Number(process.env.DEMO_WEB_PORT || 3005) };
const API = `http://127.0.0.1:${PORTS.api}/api`;
const DEMO_KEY = "sentineliq-local-demo-key";       // local demo only; never a production key
const ADMIN = { organizationName: "SentinelIQ Rehearsal (local)", adminName: "Rehearsal Analyst", email: "rehearsal-analyst@sentineliq.local", password: "Rehearsal-local-2026" };
const children = [];
const log = (m) => console.log(`[demo] ${m}`);

function fail(msg) {
  console.error(`[demo] ERROR: ${msg}`);
  shutdown(1);
}

function shutdown(code = 0) {
  for (const c of children.reverse()) {
    if (!c.pid || c.exitCode !== null) continue;
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(c.pid), "/T", "/F"], { stdio: "ignore" });
    else try { process.kill(-c.pid); } catch { c.kill(); }
  }
  process.exit(code);
}
process.on("SIGINT", () => { log("stopping..."); shutdown(0); });

function start(name, cmd, cmdArgs, opts) {
  const logFile = path.join(opts.logDir, `${name}.log`);
  const out = fs.openSync(logFile, "w");
  const useShell = process.platform === "win32" && opts.shell !== false;   // npx is a .cmd shim on Windows
  // Arguments here are fixed strings and port numbers from this script, never user input.
  const child = useShell
    ? spawn([cmd, ...cmdArgs].join(" "), { ...opts, stdio: ["ignore", out, out], shell: true })
    : spawn(cmd, cmdArgs, { ...opts, stdio: ["ignore", out, out], shell: false, detached: process.platform !== "win32" });
  children.push(child);
  child.on("exit", (code) => { if (code && !child.killed) log(`${name} exited with code ${code}; see ${logFile}`); });
  return child;
}

async function waitFor(url, label, ms = 180_000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { const r = await fetch(url); if (r.status < 500) return; } catch {}
    await new Promise((r) => setTimeout(r, 1000));
  }
  fail(`${label} did not start in time`);
}

async function portFree(port) {
  try { await fetch(`http://127.0.0.1:${port}`); return false; } catch (e) { return e?.cause?.code === "ECONNREFUSED"; }
}

async function api(method, url, body, token, extra = {}) {
  const res = await fetch(`${API}${url}`, {
    method, headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}), ...extra },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

function findPython() {
  for (const p of [path.join(ROOT, "sensor", ".venv", "Scripts", "python.exe"), path.join(ROOT, "sensor", ".venv", "bin", "python")]) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

async function verifyAmoy() {
  // Read-only check of the published demo report's transaction (no signing, no transaction sent).
  const env = fs.readFileSync(path.join(ROOT, "apps", "backend", ".env"), "utf-8");
  const rpc = /^POLYGON_AMOY_RPC_URL=(.*)$/m.exec(env)?.[1]?.trim();
  if (!rpc) { log("--verify-amoy: no POLYGON_AMOY_RPC_URL in apps/backend/.env; skipped"); return; }
  const { createRequire } = await import("node:module");
  const req = createRequire(path.join(ROOT, "apps", "backend", "package.json"));
  const { ethers } = req("ethers");
  const abi = req("./src/abi/CTIRegistry.json");
  const TX = "0x9721610b9eb21715c69ee14b246c7ae455ae08909d0aa770330db9ea4d30886c";
  const KEY = "0x105df89364d0eb58b8068c375418fe3e097c4c0082b717300967d55470a0c977";
  const EXPECTED = "0xb67bb2d0738070bfdc192ffbb6e6c982c54703a995b27f4d2826a91d55ada321";
  const provider = new ethers.JsonRpcProvider(rpc, 80002, { staticNetwork: true });
  const receipt = await provider.getTransactionReceipt(TX);
  const head = await provider.getBlockNumber();
  const rec = await new ethers.Contract("0xAAc39CC2A0B2A37F85bD56421483475c36295beb", abi.abi || abi, provider).getCTI(KEY);
  const onChain = rec.contentHash ?? rec[0];
  log(`Amoy demo report cti-e551e4-mv646myn: tx status ${receipt?.status}, block ${receipt?.blockNumber}, ` +
      `${head - receipt.blockNumber + 1} confirmations, on-chain hash ${onChain === EXPECTED ? "MATCHES" : "DIFFERS"} (read-only)`);
  provider.destroy();
}

async function main() {
  const mongod = process.env.MONGOD_BIN || "mongod";
  if (spawnSync(mongod, ["--version"], { stdio: "ignore", shell: false }).status !== 0) {
    fail("no MongoDB server binary: set MONGOD_BIN to a local mongod executable (the demo never uses the Atlas URI)");
  }
  for (const [name, port] of Object.entries(PORTS)) {
    if (name === "web" && args.has("--no-web")) continue;
    if (!(await portFree(port))) fail(`port ${port} (${name}) is in use; set DEMO_${name.toUpperCase()}_PORT`);
  }
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "sentineliq-demo-"));
  const logDir = path.join(work, "logs");
  fs.mkdirSync(path.join(work, "db"), { recursive: true });
  fs.mkdirSync(logDir);
  log(`working directory (disposable): ${work}`);

  start("mongod", mongod, ["--dbpath", path.join(work, "db"), "--port", String(PORTS.mongo), "--bind_ip", "127.0.0.1", "--quiet"], { logDir, shell: false });
  await new Promise((r) => setTimeout(r, 2500));

  const backendEnv = {
    ...process.env, PORT: String(PORTS.api), NODE_ENV: "development",
    MONGO_URI: `mongodb://127.0.0.1:${PORTS.mongo}/sentineliq_demo`,
    ML_SERVICE_API_KEY: DEMO_KEY,
    POLYGON_AMOY_RPC_URL: "http://127.0.0.1:9",   // unreachable on purpose: publishing is disabled in the demo
    BLOCKCHAIN_PRIVATE_KEY: "0x" + "1".repeat(64), // never a funded key; publishing cannot succeed
    CORS_ORIGIN: `http://localhost:${PORTS.web}`,
  };
  start("backend", "npx", ["tsx", "src/server.ts"], { cwd: path.join(ROOT, "apps", "backend"), env: backendEnv, logDir });
  await waitFor(`${API}/health`, "backend");
  log(`backend up on ${API} (local disposable database; CTI publishing disabled)`);

  if (!args.has("--no-web")) {
    start("web", "npx", ["next", "dev", "-p", String(PORTS.web)], {
      cwd: path.join(ROOT, "apps", "web"), env: { ...process.env, BACKEND_URL: `http://127.0.0.1:${PORTS.api}` }, logDir,
    });
  }

  // 1. organisation, analyst, network-sensor endpoint
  let reg = await api("POST", "/auth/register", ADMIN);
  if (reg.status !== 201 && reg.status !== 409) fail(`register failed: ${reg.status} ${JSON.stringify(reg.body)}`);
  const login = await api("POST", "/auth/login", { email: ADMIN.email, password: ADMIN.password });
  if (login.status !== 200) fail(`login failed: ${login.status}`);
  const token = login.body.accessToken;
  const ep = await api("POST", "/endpoints", { name: "Network Sensor (recorded traffic)" }, token);
  if (ep.status !== 201) fail(`endpoint registration failed: ${ep.status}`);
  const orgId = ep.body.endpoint.organizationId;
  const endpointId = ep.body.endpoint._id;

  // 2. real PCAP-replay alerts through the sensor forwarder
  const python = findPython();
  for (const file of ["pcap-replay-trained-model-alerts.jsonl", "pcap-replay-heuristic-alerts.jsonl"]) {
    const src = path.join(ROOT, "data", "recorded-traffic", file);
    const dir = path.join(work, path.basename(file, ".jsonl"));
    fs.mkdirSync(dir);
    fs.copyFileSync(src, path.join(dir, "alerts.jsonl"));
    if (python) {
      const r = spawnSync(python, ["-B", "-m", "netsensor", "ingest-alerts", "--alerts", path.join(dir, "alerts.jsonl"), "--api", API,
                                   "--organization-id", orgId, "--endpoint-id", endpointId],
                          { cwd: path.join(ROOT, "sensor"), env: { ...process.env, ML_SERVICE_API_KEY: DEMO_KEY }, encoding: "utf-8" });
      if (r.status !== 0) fail(`ingest-alerts failed for ${file}: ${r.stderr || r.stdout}`);
      log(`forwarded ${file} with netsensor ingest-alerts: ${r.stdout.trim()}`);
    } else {
      for (const line of fs.readFileSync(src, "utf-8").split("\n").filter(Boolean)) {
        const p = JSON.parse(line);
        delete p._fixture;
        const r = await api("POST", "/detections/ingest", { ...p, organizationId: orgId, endpointId }, null, { "x-api-key": DEMO_KEY });
        if (r.status !== 201) fail(`ingest failed: ${r.status} ${JSON.stringify(r.body)}`);
      }
      log(`forwarded ${file} directly (sensor venv not found)`);
    }
  }

  const summary = (await api("GET", "/detections/summary", undefined, token)).body.summary;
  log(`detections stored: ${summary.total} (sources ${JSON.stringify(summary.byDataOrigin)}); ` +
      `ATT&CK: ${summary.techniques.map((t) => `${t.techniqueId}x${t.count}`).join(", ")}`);
  const listed = (await api("GET", "/detections?limit=50", undefined, token)).body.detections ?? [];
  const trainedDos = listed.find((d) => d.attackType === "DOS_DDOS" && d.detectorStatus === "TRAINED");
  log(`open a machine-learning network detection: /detections/${trainedDos?._id}`);
  if (args.has("--verify-amoy")) await verifyAmoy().catch((e) => log(`--verify-amoy failed: ${e.message}`));

  if (!args.has("--no-web")) await waitFor(`http://localhost:${PORTS.web}/login`, "web app");
  console.log(`
  SentinelIQ rehearsal environment is running (recorded traffic only; nothing here is live telemetry)
    Web:       ${args.has("--no-web") ? "(disabled)" : `http://localhost:${PORTS.web}`}
    API:       ${API}
    Sign in:   ${ADMIN.email} / ${ADMIN.password}
    Logs:      ${logDir}
  Try: Dashboard -> Detection Sources; Detections -> source "Recorded traffic"; open a detection.
  Press Ctrl+C to stop everything.`);
  if (args.has("--exit")) shutdown(0);
}

main().catch((e) => fail(e?.stack || String(e)));
