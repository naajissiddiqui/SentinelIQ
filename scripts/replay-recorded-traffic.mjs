#!/usr/bin/env node
/**
 * Send previously computed network detections (recorded CIC-DDoS2019 traffic, scored offline by
 * the SentinelIQ network sensor) into the RUNNING SentinelIQ backend, through the real APIs:
 *
 *   npm run replay:recorded -- --email you@example.com [--alerts PATH] [--api URL] [--web URL]
 *
 * 1. Signs in with your account (POST /auth/login). The password is read from SENTINELIQ_PASSWORD
 *    or asked for interactively; it is never printed or stored.
 * 2. Finds your organisation's "Network Sensor (recorded traffic)" endpoint, or registers it
 *    through POST /endpoints (organisation admins only).
 * 3. Forwards the alerts with the sensor's own forwarder (`python -m netsensor ingest-alerts`),
 *    authenticated with the backend's service API key (ML_SERVICE_API_KEY from the environment or
 *    apps/backend/.env, never printed).
 *
 * Re-running is safe: the backend stores each alert episode once and answers a repeat with the
 * existing detection. Nothing here is live traffic; every detection is stored with
 * dataOrigin PCAP_REPLAY and its original capture time and provenance.
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SENSOR_ENDPOINT_NAME = "Network Sensor (recorded traffic)";

function option(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}
const API = option("api", "http://127.0.0.1:4000/api").replace(/\/$/, "");
const WEB = option("web", "http://localhost:3000").replace(/\/$/, "");
const ALERTS = path.resolve(option("alerts", path.join(ROOT, "data", "recorded-traffic", "pcap-replay-trained-model-alerts.jsonl")));
const EMAIL = option("email", process.env.SENTINELIQ_EMAIL);

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

function askHidden(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(prompt)) rl.output.write(s); };   // echo the prompt, not the password
    rl.question(prompt, (answer) => { rl.close(); process.stdout.write("\n"); resolve(answer); });
  });
}

function serviceKey() {
  if (process.env.ML_SERVICE_API_KEY) return process.env.ML_SERVICE_API_KEY;
  const envFile = path.join(ROOT, "apps", "backend", ".env");
  const line = fs.existsSync(envFile) && fs.readFileSync(envFile, "utf-8").split(/\r?\n/).find((l) => l.startsWith("ML_SERVICE_API_KEY="));
  if (!line) fail("ML_SERVICE_API_KEY is not set and not found in apps/backend/.env");
  return line.slice("ML_SERVICE_API_KEY=".length).trim().replace(/^["']|["']$/g, "");
}

function python() {
  for (const p of [path.join(ROOT, "sensor", ".venv", "Scripts", "python.exe"), path.join(ROOT, "sensor", ".venv", "bin", "python")]) {
    if (fs.existsSync(p)) return p;
  }
  return process.platform === "win32" ? "python" : "python3";
}

async function call(method, url, token, body) {
  let res;
  try {
    res = await fetch(`${API}${url}`, {
      method,
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    fail(`the backend is not reachable at ${API}. Start it first: npm run dev:backend`);
  }
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function main() {
  if (!EMAIL) fail("pass --email <your SentinelIQ sign-in email>");
  if (!fs.existsSync(ALERTS)) fail(`alerts file not found: ${ALERTS}`);
  const password = process.env.SENTINELIQ_PASSWORD || (await askHidden(`Password for ${EMAIL}: `));

  const login = await call("POST", "/auth/login", null, { email: EMAIL, password });
  if (login.status !== 200) fail(`sign-in failed (${login.status}): ${login.body.error || login.body.message || "check the email and password"}`);
  const { accessToken: token, user } = login.body;
  console.log(`Signed in as ${user.email} (${user.role}).`);

  const listed = await call("GET", "/endpoints", token);
  if (listed.status !== 200) fail(`could not list endpoints (${listed.status})`);
  let sensor = (listed.body.endpoints || []).find((e) => e.name === SENSOR_ENDPOINT_NAME);
  if (!sensor) {
    if (user.role !== "ORG_ADMIN") fail(`no "${SENSOR_ENDPOINT_NAME}" endpoint yet, and only an organisation admin can register one`);
    const created = await call("POST", "/endpoints", token, { name: SENSOR_ENDPOINT_NAME });
    if (created.status !== 201) fail(`could not register the sensor endpoint (${created.status}): ${created.body.error || ""}`);
    sensor = created.body.endpoint;
    console.log(`Registered endpoint "${SENSOR_ENDPOINT_NAME}".`);
  } else {
    console.log(`Using endpoint "${SENSOR_ENDPOINT_NAME}".`);
  }

  // A fresh log per run, outside the repository data folder; the backend handles repeats.
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const log = path.join(ROOT, "sensor", "ingest-runs", `${path.basename(ALERTS, ".jsonl")}-${stamp}.jsonl`);
  const run = spawnSync(python(), ["-B", "-m", "netsensor", "ingest-alerts", "--alerts", ALERTS, "--api", API,
                                   "--organization-id", String(user.organizationId), "--endpoint-id", String(sensor._id), "--log", log],
                        { cwd: path.join(ROOT, "sensor"), env: { ...process.env, ML_SERVICE_API_KEY: serviceKey() }, encoding: "utf-8" });
  if (run.status !== 0 && run.status !== 3) fail(`the sensor forwarder failed: ${(run.stderr || run.stdout).trim()}`);   // 3: some alerts rejected
  const result = JSON.parse(run.stdout.trim().split(/\r?\n/).pop());

  console.log(`\nRecorded traffic: ${result.alerts} alert episode(s) sent through ${result.url}`);
  console.log(`  newly recorded: ${result.created}   already recorded (deduplicated): ${result.already_recorded}   failed: ${result.failed}`);
  for (const id of result.detection_ids) console.log(`  ${WEB}/detections/${id}`);
  console.log(`  log: ${result.log}`);
  if (result.failed) process.exit(1);
}

main().catch((e) => fail(e?.message || String(e)));
