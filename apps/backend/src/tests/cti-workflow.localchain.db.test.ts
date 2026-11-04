/**
 * The CTI workflow end to end over HTTP: eligible detection -> structured CTI draft
 * (MongoDB) -> publish -> report hash anchored by a REAL transaction on a local Hardhat
 * node running the compiled CTIRegistry -> confirmed receipt -> on-chain verification ->
 * public CTI feed. Plus the refusal and failure paths.
 *
 * Local only: a disposable MongoDB and a local Hardhat node with its dev accounts (no
 * testnet, no real key, no real RPC). The app's configured Amoy gateway is replaced by an
 * ethers gateway for the local chain; the backend's Amoy chain-ID guard is untouched.
 *
 *   MONGO_URI=mongodb://127.0.0.1:27999/sentineliq_disposable_test \
 *     npx tsx --test src/tests/cti-workflow.localchain.db.test.ts
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, ChildProcess } from "child_process";
import fs from "fs";
import path from "path";
import { Server } from "node:http";
import { ethers } from "ethers";
import mongoose from "mongoose";
import { createApp } from "../app";
import { env } from "../config/env";
import { AnchorError, EthersRegistryGateway, setRegistryGateway } from "../services/blockchain.service";
import { isTransactionHash } from "../config/blockchain.constants";
import { EndpointModel } from "../models/endpoint.model";
import { DetectionModel } from "../models/detection.model";
import { CTIReportModel } from "../models/ctiReport.model";
import { signAccessToken } from "../utils/jwt";

const blockchainDir = path.resolve(__dirname, "../../../../blockchain");
const artifact = JSON.parse(
  fs.readFileSync(path.join(blockchainDir, "artifacts/contracts/CTIRegistry.sol/CTIRegistry.json"), "utf8")
);
// TEST FIXTURE: a real trained-model DoS alert (offline PCAP replay).
const dosFixture = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "dos-trained-model-alert.fixture.json"), "utf-8"));
const PORT = 19545 + Math.floor(Math.random() * 1000);
const RPC = `http://127.0.0.1:${PORT}`;

let node: ChildProcess;
let provider: ethers.JsonRpcProvider;
let owner: ethers.Signer;
let stranger: ethers.Signer;
let contractAddress: string;
let server: Server;
let baseUrl: string;
const orgId = new mongoose.Types.ObjectId().toString();
const admin = signAccessToken({ userId: new mongoose.Types.ObjectId().toString(), role: "ORG_ADMIN", organizationId: orgId });

function gateway(signer: ethers.Signer | null, checkReady: (s: boolean) => Promise<void> = async () => {}) {
  return new EthersRegistryGateway({
    provider, signer, contractAddress, chainId: 31337, networkName: "hardhat-local", deployBlock: 0, checkReady,
  });
}

async function api(method: string, url: string, body?: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(`${baseUrl}/api${url}`, {
    method,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${admin}`, ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as any };
}

async function ingest(body: Record<string, unknown>) {
  const r = await api("POST", "/detections/ingest", body, { "x-api-key": env.mlServiceApiKey, Authorization: "" });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  return r.body.detection;
}

async function waitForRpc(timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const p = new ethers.JsonRpcProvider(RPC, 31337, { staticNetwork: true });
      await p.getBlockNumber();
      p.destroy();
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  throw new Error("hardhat node did not start");
}

describe("CTI workflow over HTTP with a local CTIRegistry", { timeout: 240_000 }, () => {
  let endpointId: string;

  before(async () => {
    const host = new URL(env.mongoUri.replace(/^mongodb(\+srv)?:/, "http:")).hostname;
    if (!["127.0.0.1", "localhost"].includes(host)) throw new Error(`refusing to run: MONGO_URI host ${host} is not local`);
    node = spawn("npx", ["hardhat", "node", "--port", String(PORT)], { cwd: blockchainDir, shell: true, stdio: "ignore" });
    await waitForRpc(90_000);
    provider = new ethers.JsonRpcProvider(RPC, 31337, { staticNetwork: true, cacheTimeout: -1 });
    owner = await provider.getSigner(0);      // local dev account, never used on a real network
    stranger = await provider.getSigner(1);
    const c = await new ethers.ContractFactory(artifact.abi, artifact.bytecode, owner).deploy(await owner.getAddress());
    await c.waitForDeployment();
    contractAddress = await c.getAddress();
    setRegistryGateway(gateway(owner));

    await mongoose.connect(env.mongoUri);
    const app = createApp();
    server = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
    baseUrl = `http://127.0.0.1:${(server.address() as any).port}`;
    const ep = await EndpointModel.create({
      organizationId: orgId, name: `TEST-WS-${Date.now()}`, status: "ONLINE", activationTokenHash: "x", lastCheckInAt: new Date(),
    });
    endpointId = ep._id.toString();
  });

  after(async () => {
    setRegistryGateway(null);
    await Promise.all([
      DetectionModel.deleteMany({ organizationId: orgId }),
      EndpointModel.deleteMany({ organizationId: orgId }),
      CTIReportModel.deleteMany({ organizationId: orgId }),
    ]);
    server?.close();
    await mongoose.disconnect();
    provider?.destroy();
    if (node?.pid) {
      if (process.platform === "win32") spawn("taskkill", ["/pid", String(node.pid), "/T", "/F"]);
      else node.kill();
    }
  });

  it("refuses a CTI draft for a DoS detection before anything is written", async () => {
    const dos = await ingest({ ...dosFixture, organizationId: orgId, endpointId });
    const r = await api("POST", "/cti", { detectionId: dos._id });
    assert.equal(r.status, 422);
    assert.equal(await CTIReportModel.countDocuments({ detectionId: dos._id }), 0);
  });

  it("drafts, anchors with a confirmed transaction, verifies on-chain and lists in the feed", async () => {
    const det = await ingest({ organizationId: orgId, endpointId, riskScore: 91, attackType: "RANSOMWARE",
                               indicators: ["Mass file encryption in shared folders", "vssadmin delete shadows /all"] });
    const draft = await api("POST", "/cti", { detectionId: det._id });
    assert.equal(draft.status, 201, JSON.stringify(draft.body));
    const report = draft.body.report;
    assert.equal(report.status, "DRAFT");
    assert.equal(report.transactionHash ?? null, null);
    assert.ok((await api("GET", "/cti")).body.reports.some((r: any) => r._id === report._id));
    assert.ok(!(await api("GET", "/cti/feed")).body.reports.some((r: any) => r._id === report._id), "drafts are not in the feed");

    const pub = await api("POST", `/cti/${report._id}/publish`);
    assert.equal(pub.status, 200, JSON.stringify(pub.body));
    const published = pub.body.report;
    assert.equal(published.status, "PUBLISHED");
    assert.ok(isTransactionHash(published.transactionHash));
    const receipt = await provider.getTransactionReceipt(published.transactionHash);
    assert.equal(receipt?.status, 1, "the transaction exists on the chain and succeeded");
    assert.equal(published.blockNumber, receipt!.blockNumber);
    assert.equal(published.verificationStatus, "VERIFIED");

    const registry = new ethers.Contract(contractAddress, artifact.abi, provider);
    const onChain = await registry.getCTI(published.anchorKey);
    const onChainHash = (onChain.contentHash ?? onChain[0]) as string;
    assert.equal(onChainHash.toLowerCase(), ("0x" + published.contentHash.replace(/^0x/, "")).toLowerCase(),
                 "only the report hash is on-chain, and it matches");
    const stored = await CTIReportModel.findById(report._id);
    assert.ok(stored?.canonicalJson && stored.canonicalJson.length > 100, "the full report stays off-chain in MongoDB");

    const ver = await api("GET", `/cti/${report._id}/verify`);
    assert.equal(ver.status, 200);
    assert.equal(ver.body.verification.status, "VERIFIED");
    assert.equal(ver.body.verification.transactionConfirmed, true);
    // The owner's published report appears in its own feed. Cross-org visibility on sharing is
    // covered by cti-sharing.db.test.ts.
    const feed = (await api("GET", "/cti/feed")).body.reports;
    assert.ok(feed.some((r: any) => r._id === report._id), "owner's published report is in its own feed");

    const again = await api("POST", `/cti/${report._id}/publish`);
    assert.equal(again.status, 200);
    assert.equal(again.body.report.transactionHash, published.transactionHash, "no second transaction");
  });

  it("an unreachable chain leaves the report FAILED with no transaction hash", async () => {
    const det = await ingest({ organizationId: orgId, endpointId, riskScore: 88, attackType: "RANSOMWARE", indicators: ["Encryption burst"] });
    const report = (await api("POST", "/cti", { detectionId: det._id })).body.report;
    setRegistryGateway(gateway(owner, async () => { throw new AnchorError("UNAVAILABLE", "RPC unreachable (test)"); }));
    try {
      const pub = await api("POST", `/cti/${report._id}/publish`);
      assert.equal(pub.status, 503);
      const fresh = (await api("GET", `/cti/${report._id}`)).body.report;
      assert.equal(fresh.status, "FAILED");
      assert.equal(fresh.transactionHash ?? null, null, "no transaction hash is ever invented");
      assert.match(fresh.anchorError, /unreachable/);
      assert.ok(!(await api("GET", "/cti/feed")).body.reports.some((r: any) => r._id === report._id));
    } finally {
      setRegistryGateway(gateway(owner));
    }
    const retry = await api("POST", `/cti/${report._id}/publish`);  // FAILED reports can be retried
    assert.equal(retry.status, 200);
    assert.equal(retry.body.report.status, "PUBLISHED");
  });

  it("a non-owner signer is a contract revert: FAILED, no transaction stored", async () => {
    const det = await ingest({ organizationId: orgId, endpointId, riskScore: 80, attackType: "RANSOMWARE", indicators: ["Encryption burst"] });
    const report = (await api("POST", "/cti", { detectionId: det._id })).body.report;
    setRegistryGateway(gateway(stranger));
    try {
      const pub = await api("POST", `/cti/${report._id}/publish`);
      assert.equal(pub.status, 502);
      const fresh = (await api("GET", `/cti/${report._id}`)).body.report;
      assert.equal(fresh.status, "FAILED");
      assert.equal(fresh.transactionHash ?? null, null);
    } finally {
      setRegistryGateway(gateway(owner));
    }
  });
});
