/**
 * End-to-end test of the real ethers RegistryGateway against a local Hardhat
 * node running the compiled CTIRegistry artifact: real transaction
 * submission, receipt + CTIPublished event validation, getCTI reads,
 * duplicate protection, owner-only enforcement and tamper detection.
 *
 * Starts `hardhat node` on a free port; no testnet funds involved.
 * Run: npx tsx --test src/tests/cti_anchor.localchain.test.ts
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, ChildProcess } from "child_process";
import fs from "fs";
import path from "path";
import { ethers } from "ethers";
import { EthersRegistryGateway, AnchorError } from "../services/blockchain.service";
import { anchorReport, verifyReportAnchor } from "../services/ctiAnchor.service";
import { isTransactionHash } from "../config/blockchain.constants";

const blockchainDir = path.resolve(__dirname, "../../../../blockchain");
const artifact = JSON.parse(
  fs.readFileSync(path.join(blockchainDir, "artifacts/contracts/CTIRegistry.sol/CTIRegistry.json"), "utf8")
);
const PORT = 18545 + Math.floor(Math.random() * 1000);
const RPC = `http://127.0.0.1:${PORT}`;

let node: ChildProcess;
let provider: ethers.JsonRpcProvider;
let owner: ethers.Signer;
let stranger: ethers.Signer;
let contractAddress: string;

function makeGateway(signer: ethers.Signer | null) {
  return new EthersRegistryGateway({
    provider,
    signer,
    contractAddress,
    chainId: 31337,
    networkName: "hardhat-local",
    deployBlock: 0,
    checkReady: async () => {},
  });
}

function makeReport(reportId: string, overrides: Record<string, unknown> = {}) {
  return {
    _id: "000000000000000000000001",
    reportId,
    attackType: "PRIVILEGE_ESCALATION",
    title: "Privilege Escalation (PE-01) on WS-07",
    detectedAt: new Date("2026-10-02T08:00:00Z"),
    severity: "HIGH",
    riskScore: 77,
    confidenceTier: "likely",
    attackSummary: "Token manipulation observed.",
    indicatorsOfCompromise: ["PROCESS: whoami.exe /priv"],
    recommendedActions: ["Revoke privileges"],
    detector: { type: "rule", id: "PE-01", version: "1.0.0" },
    evidence: [],
    mitre: [],
    version: 1,
    status: "PUBLISHING",
    failedTransactionHashes: [] as string[],
    ...overrides,
    async save() {},
  } as any;
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

describe("CTIRegistry gateway on a local Hardhat node", { timeout: 180_000 }, () => {
  before(async () => {
    node = spawn("npx", ["hardhat", "node", "--port", String(PORT)], {
      cwd: blockchainDir,
      shell: true,
      stdio: "ignore",
    });
    await waitForRpc(90_000);
    provider = new ethers.JsonRpcProvider(RPC, 31337, { staticNetwork: true, cacheTimeout: -1 });
    // Local-only dev accounts (never used on a real network).
    owner = await provider.getSigner(0);
    stranger = await provider.getSigner(1);
    const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, owner);
    const c = await factory.deploy(await owner.getAddress());
    await c.waitForDeployment();
    contractAddress = await c.getAddress();
    assert.notEqual(await provider.getCode(contractAddress), "0x");
  });

  after(() => {
    provider?.destroy();
    if (node?.pid) {
      if (process.platform === "win32") spawn("taskkill", ["/pid", String(node.pid), "/T", "/F"]);
      else node.kill();
    }
  });

  it("anchors a report with a real tx, valid receipt and on-chain record, then verifies it", async () => {
    const gw = makeGateway(owner);
    const report = makeReport(`cti-local-${Date.now()}`);
    const out = await anchorReport(report, gw, { receiptTimeoutMs: 30_000 });

    assert.equal(out.state, "ANCHORED");
    assert.ok(isTransactionHash(report.transactionHash));
    const receipt = await provider.getTransactionReceipt(report.transactionHash);
    assert.equal(receipt?.status, 1);
    assert.equal(receipt?.to?.toLowerCase(), contractAddress.toLowerCase());
    assert.equal(report.blockNumber, receipt?.blockNumber);
    assert.equal(report.verificationStatus, "VERIFIED");

    const v = await verifyReportAnchor(report, gw);
    assert.equal(v.status, "VERIFIED");
    assert.equal(v.transactionConfirmed, true);
    assert.equal(v.onChainHash, `0x${report.contentHash}`);
  });

  it("does not submit a second transaction for an already anchored report", async () => {
    const gw = makeGateway(owner);
    const id = `cti-local-dup-${Date.now()}`;
    const first = makeReport(id);
    await anchorReport(first, gw, { receiptTimeoutMs: 30_000 });
    const nonceBefore = await provider.getTransactionCount(await owner.getAddress());

    const second = makeReport(id); // same report, DB lost the tx hash
    const out = await anchorReport(second, gw, { receiptTimeoutMs: 30_000 });
    assert.equal(out.state === "ANCHORED" && out.alreadyAnchored, true);
    assert.equal(second.transactionHash, first.transactionHash);
    assert.equal(await provider.getTransactionCount(await owner.getAddress()), nonceBefore);
  });

  it("detects tampering of a stored report against the on-chain hash", async () => {
    const gw = makeGateway(owner);
    const report = makeReport(`cti-local-tamper-${Date.now()}`);
    await anchorReport(report, gw, { receiptTimeoutMs: 30_000 });
    report.riskScore = 10;
    const v = await verifyReportAnchor(report, gw);
    assert.equal(v.status, "TAMPERED");
  });

  it("reports UNANCHORED for a report never published", async () => {
    const v = await verifyReportAnchor(makeReport(`cti-local-none-${Date.now()}`), makeGateway(null));
    assert.equal(v.status, "UNANCHORED");
  });

  it("surfaces a non-owner signer as a contract revert without sending a tx", async () => {
    const gw = makeGateway(stranger);
    const report = makeReport(`cti-local-stranger-${Date.now()}`);
    await assert.rejects(
      anchorReport(report, gw, { receiptTimeoutMs: 30_000 }),
      (e: any) => e instanceof AnchorError && e.kind === "REVERT" && /OwnableUnauthorizedAccount/.test(e.message)
    );
    assert.equal(report.status, "FAILED");
    assert.ok(!report.transactionHash);
  });
});
