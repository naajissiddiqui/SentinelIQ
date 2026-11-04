/**
 * Unit tests for CTI anchoring/verification against a fake CTIRegistry.
 * No MongoDB and no network access.
 *
 * Run: npx tsx --test src/tests/cti_anchor.unit.test.ts
 */
import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { canonicalizeJson, computeReportHash } from "../utils/canonical";
import {
  AnchorError,
  AnchorReceipt,
  OnChainRecord,
  RegistryGateway,
  reportKeyFor,
  toBytes32,
} from "../services/blockchain.service";
import { anchorReport, verifyReportAnchor } from "../services/ctiAnchor.service";
import {
  explorerTxUrl,
  isPublicDevAddress,
  isTransactionHash,
} from "../config/blockchain.constants";

const CONTRACT = "0x1111111111111111111111111111111111111111";
const OWNER = "0x2222222222222222222222222222222222222222";

function randomTxHash() {
  return "0x" + crypto.randomBytes(32).toString("hex");
}

/** In-memory CTIRegistry + mempool. */
class FakeGateway implements RegistryGateway {
  contractAddress = CONTRACT;
  chainId = 80002;
  networkName = "Polygon Amoy Testnet";
  records = new Map<string, OnChainRecord>();
  txs = new Map<string, { receipt: AnchorReceipt | null }>();
  submits = 0;
  // knobs
  mineOnSubmit = true;
  revertOnSubmit = false;
  rpcDown = false;
  owner = OWNER;
  saveLog: Array<{ transactionHash: unknown; status: unknown }> = [];

  private check() {
    if (this.rpcDown) throw new AnchorError("UNAVAILABLE", "RPC down");
  }
  async ensureWritable() {
    this.check();
  }
  async ensureReadable() {
    this.check();
  }
  async getRecord(key: string) {
    this.check();
    return this.records.get(key) ?? null;
  }
  async getOwner() {
    this.check();
    return this.owner;
  }
  async submitPublish(key: string, hash: string, _attackType: string) {
    this.check();
    if (this.records.has(key)) throw new AnchorError("REVERT", "CTIRegistry: report already published");
    this.submits++;
    const txHash = randomTxHash();
    this.txs.set(txHash, { receipt: null });
    if (this.mineOnSubmit) this.mine(txHash, key, hash);
    return txHash;
  }
  mine(txHash: string, key: string, hash: string) {
    const status = this.revertOnSubmit ? 0 : 1;
    if (status === 1) this.records.set(key, { contentHash: hash, publisher: this.owner, timestamp: 1_700_000_000 });
    this.txs.set(txHash, {
      receipt: {
        hash: txHash,
        status,
        blockNumber: 1234,
        from: this.owner,
        to: CONTRACT,
        event: status === 1 ? { reportKey: key, contentHash: hash, publisher: this.owner } : null,
      },
    });
  }
  async waitForReceipt(txHash: string) {
    this.check();
    return this.txs.get(txHash)?.receipt ?? null;
  }
  async getReceipt(txHash: string) {
    this.check();
    return this.txs.get(txHash)?.receipt ?? null;
  }
  async isTransactionKnown(txHash: string) {
    this.check();
    return this.txs.has(txHash);
  }
  async findPublishEvent(key: string) {
    for (const [hash, t] of this.txs) {
      if (t.receipt?.status === 1 && t.receipt.event?.reportKey === key) {
        return { transactionHash: hash, blockNumber: t.receipt.blockNumber };
      }
    }
    return null;
  }
}

function makeReport(gw: FakeGateway, overrides: Record<string, unknown> = {}) {
  const report: any = {
    _id: "6acd2375c095f663cd99ade3",
    reportId: `cti-test-${crypto.randomBytes(4).toString("hex")}`,
    schemaVersion: "v1.0",
    attackType: "RANSOMWARE",
    title: "Ransomware Incident on WS-01",
    detectedAt: new Date("2026-10-01T10:00:00Z"),
    severity: "HIGH",
    riskScore: 88,
    confidenceTier: "confirmed",
    attackSummary: "Mass file encryption observed.",
    indicatorsOfCompromise: ["PROCESS: evil.exe", "FILE: *.locked"],
    recommendedActions: ["Isolate endpoint", "Rotate credentials"],
    detector: { type: "xgboost", id: "RANSOMWARE-XGB", version: "1.0.0" },
    evidence: [],
    mitre: [],
    version: 1,
    status: "PUBLISHING",
    failedTransactionHashes: [],
    ...overrides,
    async save() {
      gw.saveLog.push({ transactionHash: this.transactionHash, status: this.status });
    },
  };
  return report;
}

const opts = { receiptTimeoutMs: 1000 };

describe("hashing and canonicalization", () => {
  it("canonicalizes with sorted keys and no whitespace (RFC 8785 style)", () => {
    assert.equal(canonicalizeJson({ b: 1, a: [true, null, "x"], c: { z: 1, y: 2 } }), '{"a":[true,null,"x"],"b":1,"c":{"y":2,"z":1}}');
  });

  it("produces the SHA-256 of the canonical JSON, independent of key order", () => {
    const gw = new FakeGateway();
    const r1 = makeReport(gw);
    const r2 = makeReport(gw, { reportId: r1.reportId });
    const reordered = Object.fromEntries(Object.entries(r2).reverse());
    const h1 = computeReportHash(r1);
    const h2 = computeReportHash(reordered);
    assert.equal(h1.contentHash, h2.contentHash);
    assert.equal(h1.contentHash, crypto.createHash("sha256").update(h1.canonicalJson, "utf8").digest("hex"));
    assert.match(h1.contentHash, /^[0-9a-f]{64}$/);
  });

  it("changes the hash when any reported field changes", () => {
    const gw = new FakeGateway();
    const r = makeReport(gw);
    const before = computeReportHash(r).contentHash;
    r.attackSummary += " (edited)";
    assert.notEqual(computeReportHash(r).contentHash, before);
  });

  it("derives a bytes32 report key distinct from the content hash", () => {
    const key = reportKeyFor("cti-abc");
    assert.match(key, /^0x[0-9a-f]{64}$/);
    assert.throws(() => toBytes32("not-a-hash"));
  });
});

describe("configuration guards", () => {
  it("flags the public Hardhat accounts", () => {
    assert.equal(isPublicDevAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), true);
    assert.equal(isPublicDevAddress(OWNER), false);
  });

  it("only builds explorer links for 32-byte transaction hashes", () => {
    assert.equal(isTransactionHash("6acd2375c095f663cd99ade3"), false); // ObjectId
    assert.equal(explorerTxUrl("6acd2375c095f663cd99ade3"), null);
    const tx = randomTxHash();
    assert.equal(explorerTxUrl(tx), `https://amoy.polygonscan.com/tx/${tx}`);
  });

  it("hardhat config has no hardcoded fallback private key", () => {
    const cfg = fs.readFileSync(path.resolve(__dirname, "../../../../blockchain/hardhat.config.ts"), "utf8");
    assert.doesNotMatch(cfg, /0x[0-9a-fA-F]{64}/);
    assert.match(cfg, /chainId: 80002/);
  });

  it("backend ABI matches the compiled CTIRegistry artifact and exposes publish/read", () => {
    const compiled = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../../../blockchain/artifacts/contracts/CTIRegistry.sol/CTIRegistry.json"), "utf8")
    );
    const backend = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../abi/CTIRegistry.json"), "utf8"));
    assert.deepEqual(backend.abi, compiled.abi);
    const names = compiled.abi.map((x: any) => x.name);
    for (const n of ["publishCTI", "getCTI", "verifyCTI", "owner", "CTIPublished"]) assert.ok(names.includes(n), n);
  });
});

describe("anchorReport", () => {
  let gw: FakeGateway;
  beforeEach(() => {
    gw = new FakeGateway();
  });

  it("submits once, persists the provider tx hash before the receipt, and verifies on-chain", async () => {
    const report = makeReport(gw);
    const out = await anchorReport(report, gw, opts);

    assert.equal(out.state, "ANCHORED");
    assert.equal(gw.submits, 1);
    assert.equal(report.status, "PUBLISHED");
    assert.ok(isTransactionHash(report.transactionHash));
    assert.ok(gw.txs.has(report.transactionHash), "tx hash must come from the provider");
    assert.notEqual(report.transactionHash, "0x" + report.contentHash);
    assert.equal(report.blockNumber, 1234);
    assert.equal(report.contractAddress, CONTRACT);
    assert.equal(report.chainId, 80002);
    assert.equal(report.publisherAddress, OWNER);
    assert.equal(report.verificationStatus, "VERIFIED");
    assert.equal(report.contentHash, computeReportHash(report).contentHash);
    // first persisted save with a tx hash happened while still PUBLISHING
    const firstWithTx = gw.saveLog.find((s) => s.transactionHash);
    assert.equal(firstWithTx?.status, "PUBLISHING");
  });

  it("returns PENDING on receipt timeout, then reconciles without resubmitting", async () => {
    gw.mineOnSubmit = false;
    const report = makeReport(gw);
    const first = await anchorReport(report, gw, opts);
    assert.equal(first.state, "PENDING");
    assert.equal(report.status, "PUBLISHING");
    assert.equal(report.verificationStatus, "PENDING");
    const txHash = report.transactionHash;
    assert.ok(isTransactionHash(txHash));

    // retry while still pending: no new submission
    const again = await anchorReport(report, gw, opts);
    assert.equal(again.state, "PENDING");
    assert.equal(gw.submits, 1);

    // mined later
    gw.mine(txHash, reportKeyFor(report.reportId), toBytes32(report.contentHash));
    const done = await anchorReport(report, gw, opts);
    assert.equal(done.state, "ANCHORED");
    assert.equal(report.transactionHash, txHash);
    assert.equal(gw.submits, 1);
  });

  it("marks a reverted receipt FAILED and never shows it as the anchor tx", async () => {
    gw.revertOnSubmit = true;
    const report = makeReport(gw);
    await assert.rejects(anchorReport(report, gw, opts), (e: any) => e.kind === "REVERT");
    assert.equal(report.status, "FAILED");
    assert.equal(report.transactionHash, null);
    assert.equal(report.failedTransactionHashes.length, 1);
    assert.equal(report.verificationStatus, "UNANCHORED");
  });

  it("marks RPC failure before submission FAILED/UNAVAILABLE without a tx hash", async () => {
    gw.rpcDown = true;
    const report = makeReport(gw);
    await assert.rejects(anchorReport(report, gw, opts), (e: any) => e.kind === "UNAVAILABLE");
    assert.equal(report.status, "FAILED");
    assert.ok(!report.transactionHash);
    assert.match(report.anchorError, /RPC down/);
  });

  it("keeps a submitted tx PUBLISHING (not FAILED) if the RPC dies while waiting", async () => {
    gw.mineOnSubmit = false;
    const report = makeReport(gw);
    const origWait = gw.waitForReceipt.bind(gw);
    gw.waitForReceipt = async () => {
      throw new AnchorError("UNAVAILABLE", "RPC down");
    };
    await assert.rejects(anchorReport(report, gw, opts));
    assert.equal(report.status, "PUBLISHING");
    assert.ok(isTransactionHash(report.transactionHash));
    gw.waitForReceipt = origWait;
  });

  it("does not duplicate an anchor that already exists on-chain (crash after submit)", async () => {
    const report = makeReport(gw);
    await anchorReport(report, gw, opts);
    const original = report.transactionHash;
    // simulate DB losing the tx hash
    const reloaded = makeReport(gw, { reportId: report.reportId });
    const out = await anchorReport(reloaded, gw, opts);
    assert.equal(out.state, "ANCHORED");
    assert.equal(out.state === "ANCHORED" && out.alreadyAnchored, true);
    assert.equal(gw.submits, 1);
    assert.equal(reloaded.transactionHash, original);
  });

  it("refuses to publish when the chain already holds a different hash", async () => {
    const report = makeReport(gw);
    await anchorReport(report, gw, opts);
    const edited = makeReport(gw, { reportId: report.reportId, attackSummary: "changed" });
    await assert.rejects(anchorReport(edited, gw, opts), /different hash/);
    assert.equal(edited.verificationStatus, "TAMPERED");
    assert.equal(gw.submits, 1);
  });

  it("rejects a successful receipt that lacks the matching CTIPublished event", async () => {
    gw.mineOnSubmit = false;
    const report = makeReport(gw);
    await anchorReport(report, gw, opts);
    gw.txs.set(report.transactionHash, {
      receipt: { hash: report.transactionHash, status: 1, blockNumber: 9, from: OWNER, to: CONTRACT, event: null },
    });
    await assert.rejects(anchorReport(report, gw, opts), /no CTIPublished event/);
    assert.notEqual(report.status, "PUBLISHED");
  });

  it("drops a non-hash value from the transactionHash field", async () => {
    const report = makeReport(gw, { transactionHash: "6acd2375c095f663cd99ade3" });
    await anchorReport(report, gw, opts);
    assert.ok(isTransactionHash(report.transactionHash));
    assert.ok(report.failedTransactionHashes.includes("invalid:6acd2375c095f663cd99ade3"));
  });
});

describe("verifyReportAnchor", () => {
  let gw: FakeGateway;
  beforeEach(() => {
    gw = new FakeGateway();
  });

  it("VERIFIED when recomputed, persisted and on-chain hashes agree", async () => {
    const report = makeReport(gw);
    await anchorReport(report, gw, opts);
    const v = await verifyReportAnchor(report, gw);
    assert.equal(v.status, "VERIFIED");
    assert.equal(v.matches, true);
    assert.equal(v.onChainHash, v.recomputedHash);
    assert.equal(v.transactionConfirmed, true);
  });

  it("TAMPERED when stored report content is changed after anchoring", async () => {
    const report = makeReport(gw);
    await anchorReport(report, gw, opts);
    report.indicatorsOfCompromise = ["PROCESS: harmless.exe"];
    const v = await verifyReportAnchor(report, gw);
    assert.equal(v.status, "TAMPERED");
    assert.equal(v.checks.onChainHashMatchesRecomputed, false);
    assert.equal(report.verificationStatus, "TAMPERED");
  });

  it("TAMPERED when content and stored hash are both rewritten consistently", async () => {
    const report = makeReport(gw);
    await anchorReport(report, gw, opts);
    report.attackSummary = "rewritten";
    const h = computeReportHash(report);
    report.contentHash = h.contentHash;
    report.canonicalJson = h.canonicalJson;
    const v = await verifyReportAnchor(report, gw);
    assert.equal(v.status, "TAMPERED");
    assert.equal(v.checks.persistedHashMatchesRecomputed, true);
    assert.equal(v.checks.onChainHashMatchesRecomputed, false);
  });

  it("UNANCHORED when the report was never published, even with a local hash", async () => {
    const report = makeReport(gw, { status: "PUBLISHED" });
    report.contentHash = computeReportHash(report).contentHash;
    const v = await verifyReportAnchor(report, gw);
    assert.equal(v.status, "UNANCHORED");
    assert.match(v.error ?? "", /no record/);
  });

  it("UNAVAILABLE on RPC failure, without overwriting the stored status", async () => {
    const report = makeReport(gw);
    await anchorReport(report, gw, opts);
    gw.rpcDown = true;
    const v = await verifyReportAnchor(report, gw);
    assert.equal(v.status, "UNAVAILABLE");
    assert.equal(report.verificationStatus, "VERIFIED");
  });

  it("UNTRUSTED_PUBLISHER when the record's publisher is not the contract owner", async () => {
    const report = makeReport(gw);
    await anchorReport(report, gw, opts);
    gw.owner = "0x3333333333333333333333333333333333333333";
    const v = await verifyReportAnchor(report, gw);
    assert.equal(v.status, "UNTRUSTED_PUBLISHER");
  });
});
