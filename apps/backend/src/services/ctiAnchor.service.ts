import { computeReportHash } from "../utils/canonical";
import { isTransactionHash } from "../config/blockchain.constants";
import {
  AnchorError,
  AnchorReceipt,
  RegistryGateway,
  reportKeyFor,
  toBytes32,
} from "./blockchain.service";

/**
 * Publication and verification of CTI report hashes against CTIRegistry.
 *
 * Works on any mongoose-like report document (needs `save()`) and a
 * RegistryGateway, so the whole state machine is unit-testable with a fake
 * chain. Invariants:
 *  - transactionHash is only ever a hash returned by the provider for a
 *    publishCTI transaction (or recovered from a CTIPublished event log).
 *  - A report is PUBLISHED only after a receipt with status 1 containing the
 *    matching CTIPublished(reportKey, contentHash) event.
 *  - A submitted tx hash is persisted before waiting for its receipt, so a
 *    timeout/crash is reconciled on retry rather than re-submitted.
 *  - The contract itself rejects a second publish for the same reportKey,
 *    and we check getCTI() before submitting, so retries never duplicate.
 */

export type AnchorableReport = {
  _id: any;
  reportId?: string;
  attackType?: string;
  status: string;
  contentHash?: string;
  canonicalJson?: string;
  anchorKey?: string | null;
  transactionHash?: string | null;
  blockNumber?: number | null;
  publisherAddress?: string | null;
  contractAddress?: string | null;
  chainId?: number | null;
  network?: string | null;
  anchorError?: string | null;
  failedTransactionHashes?: string[];
  publishLockedUntil?: Date | null;
  verificationStatus?: string;
  lastVerifiedAt?: Date | null;
  publishedAt?: Date;
  save(): Promise<unknown>;
  [key: string]: any;
};

export type PublishOutcome<T extends AnchorableReport> =
  | { state: "ANCHORED"; report: T; alreadyAnchored: boolean }
  | { state: "PENDING"; report: T; message: string };

export function targetReportId(report: AnchorableReport): string {
  return report.reportId || String(report._id);
}

function recordFailedTx(report: AnchorableReport, txHash: string) {
  const list = report.failedTransactionHashes ?? [];
  if (!list.includes(txHash)) list.push(txHash);
  report.failedTransactionHashes = list;
}

function assertAnchorReceipt(
  receipt: AnchorReceipt,
  gw: RegistryGateway,
  reportKey: string,
  hashBytes32: string
) {
  if (receipt.status !== 1) {
    throw new AnchorError("REVERT", `Transaction ${receipt.hash} reverted (status ${receipt.status}).`);
  }
  if (!receipt.to || receipt.to.toLowerCase() !== gw.contractAddress.toLowerCase()) {
    throw new AnchorError("REVERT", `Transaction ${receipt.hash} was not sent to CTIRegistry ${gw.contractAddress}.`);
  }
  if (
    !receipt.event ||
    receipt.event.reportKey.toLowerCase() !== reportKey.toLowerCase() ||
    receipt.event.contentHash.toLowerCase() !== hashBytes32
  ) {
    throw new AnchorError("REVERT", `Transaction ${receipt.hash} has no CTIPublished event for this report hash.`);
  }
}

async function finalize<T extends AnchorableReport>(
  report: T,
  receipt: AnchorReceipt,
  gw: RegistryGateway,
  reportKey: string,
  hashBytes32: string,
  alreadyAnchored: boolean
): Promise<PublishOutcome<T>> {
  assertAnchorReceipt(receipt, gw, reportKey, hashBytes32);

  report.status = "PUBLISHED";
  report.transactionHash = receipt.hash;
  report.blockNumber = receipt.blockNumber;
  report.publisherAddress = receipt.event!.publisher;
  report.publishedAt = report.publishedAt ?? new Date();
  report.publishLockedUntil = null;
  report.anchorError = null;

  // Independent read-back of contract state. A lagging RPC node may not see
  // the new block yet; that leaves verification PENDING, never VERIFIED.
  try {
    const record = await gw.getRecord(reportKey);
    report.verificationStatus = record && record.contentHash === hashBytes32 ? "VERIFIED" : "PENDING";
  } catch {
    report.verificationStatus = "PENDING";
  }
  report.lastVerifiedAt = report.verificationStatus === "VERIFIED" ? new Date() : null;

  await report.save();
  return { state: "ANCHORED", report, alreadyAnchored };
}

async function markPending<T extends AnchorableReport>(report: T): Promise<PublishOutcome<T>> {
  report.status = "PUBLISHING";
  report.verificationStatus = "PENDING";
  report.publishLockedUntil = new Date(); // reclaimable at once for reconciliation
  report.anchorError = null;
  await report.save();
  return {
    state: "PENDING",
    report,
    message: `Transaction ${report.transactionHash} submitted; waiting for a confirmation receipt. Publish again to re-check.`,
  };
}

/**
 * Anchors (or reconciles the anchoring of) a report the caller has already
 * claimed by setting status PUBLISHING.
 */
export async function anchorReport<T extends AnchorableReport>(
  report: T,
  gw: RegistryGateway,
  opts: { receiptTimeoutMs: number }
): Promise<PublishOutcome<T>> {
  const { canonicalJson, contentHash } = computeReportHash(report);
  const hashBytes32 = toBytes32(contentHash);
  const reportKey = reportKeyFor(targetReportId(report));

  report.contentHash = contentHash;
  report.canonicalJson = canonicalJson;
  report.anchorKey = reportKey;
  report.contractAddress = gw.contractAddress;
  report.chainId = gw.chainId;
  report.network = gw.networkName;
  if (report.transactionHash && !isTransactionHash(report.transactionHash)) {
    // Never keep something that isn't a real tx hash in the tx field.
    recordFailedTx(report, `invalid:${report.transactionHash}`);
    report.transactionHash = null;
  }

  try {
    await gw.ensureWritable();

    // 1. Reconcile a transaction submitted by an earlier attempt.
    if (report.transactionHash) {
      const prior = await gw.getReceipt(report.transactionHash);
      if (prior && prior.status === 1) {
        return await finalize(report, prior, gw, reportKey, hashBytes32, false);
      }
      if (!prior && (await gw.isTransactionKnown(report.transactionHash))) {
        return await markPending(report);
      }
      // Reverted, or dropped from the mempool: remember it, fall through.
      recordFailedTx(report, report.transactionHash);
      report.transactionHash = null;
      report.blockNumber = null;
    }

    // 2. Already anchored on-chain (e.g. crash after submit)? Never resubmit.
    const existing = await gw.getRecord(reportKey);
    if (existing) {
      if (existing.contentHash !== hashBytes32) {
        report.verificationStatus = "TAMPERED";
        throw new AnchorError(
          "REVERT",
          `CTIRegistry already holds a different hash (${existing.contentHash}) for report ${targetReportId(report)}; ` +
            `current content hashes to ${hashBytes32}. Create a revision instead.`
        );
      }
      const event = await gw.findPublishEvent(reportKey);
      const receipt = event ? await gw.getReceipt(event.transactionHash) : null;
      if (!receipt) {
        throw new AnchorError(
          "UNAVAILABLE",
          "Report hash is on-chain but its CTIPublished transaction could not be located yet (event log query). Retry shortly."
        );
      }
      return await finalize(report, receipt, gw, reportKey, hashBytes32, true);
    }

    // 3. Submit. Persist the hash before waiting so it survives a timeout.
    const txHash = await gw.submitPublish(reportKey, hashBytes32, report.attackType || "RANSOMWARE");
    if (!isTransactionHash(txHash)) {
      throw new AnchorError("UNAVAILABLE", `Provider returned an invalid transaction hash: ${txHash}`);
    }
    report.transactionHash = txHash;
    report.blockNumber = null;
    await report.save();

    const receipt = await gw.waitForReceipt(txHash, opts.receiptTimeoutMs);
    if (!receipt) {
      return await markPending(report);
    }
    if (receipt.status !== 1) {
      recordFailedTx(report, txHash);
      report.transactionHash = null;
      throw new AnchorError("REVERT", `Transaction ${txHash} was mined in block ${receipt.blockNumber} but reverted.`);
    }
    return await finalize(report, receipt, gw, reportKey, hashBytes32, false);
  } catch (e: any) {
    const err = e instanceof AnchorError ? e : new AnchorError("UNAVAILABLE", e?.message || String(e));
    report.anchorError = err.message;
    if (report.transactionHash) {
      // Submitted but outcome unknown: keep PUBLISHING so a retry reconciles it.
      report.status = "PUBLISHING";
      report.verificationStatus = "PENDING";
      report.publishLockedUntil = new Date();
    } else {
      report.status = "FAILED";
      report.publishLockedUntil = null;
      if (report.verificationStatus !== "TAMPERED") report.verificationStatus = "UNANCHORED";
    }
    await report.save();
    throw err;
  }
}

export type VerificationOutcome = "VERIFIED" | "TAMPERED" | "UNANCHORED" | "UNTRUSTED_PUBLISHER" | "UNAVAILABLE";

export interface ReportVerification {
  reportId: string;
  status: VerificationOutcome;
  matches: boolean;
  recomputedHash: string;
  persistedHash: string | null;
  onChainHash: string | null;
  publisher: string | null;
  isAuthorizedPublisher: boolean | null;
  timestamp: string | null;
  transactionHash: string | null;
  transactionConfirmed: boolean | null;
  blockNumber: number | null;
  contractAddress: string;
  chainId: number;
  network: string;
  checks: {
    persistedHashMatchesRecomputed: boolean | null;
    persistedCanonicalJsonMatches: boolean | null;
    onChainHashMatchesRecomputed: boolean | null;
  };
  error?: string;
}

/**
 * Recomputes the report hash from its stored fields and compares it to both
 * the persisted hash and the CTIRegistry record. Persists only definitive
 * results; UNAVAILABLE (RPC/config failure) leaves the stored status alone.
 */
export async function verifyReportAnchor(
  report: AnchorableReport,
  gw: RegistryGateway
): Promise<ReportVerification> {
  const { canonicalJson, contentHash } = computeReportHash(report);
  const recomputed = toBytes32(contentHash);
  const reportKey = reportKeyFor(targetReportId(report));
  const persisted = report.contentHash ? toBytes32(report.contentHash) : null;

  const result: ReportVerification = {
    reportId: targetReportId(report),
    status: "UNAVAILABLE",
    matches: false,
    recomputedHash: recomputed,
    persistedHash: persisted,
    onChainHash: null,
    publisher: null,
    isAuthorizedPublisher: null,
    timestamp: null,
    transactionHash: isTransactionHash(report.transactionHash) ? report.transactionHash : null,
    transactionConfirmed: null,
    blockNumber: report.blockNumber ?? null,
    contractAddress: gw.contractAddress,
    chainId: gw.chainId,
    network: gw.networkName,
    checks: {
      persistedHashMatchesRecomputed: persisted ? persisted === recomputed : null,
      persistedCanonicalJsonMatches: report.canonicalJson ? report.canonicalJson === canonicalJson : null,
      onChainHashMatchesRecomputed: null,
    },
  };

  try {
    await gw.ensureReadable();
    const record = await gw.getRecord(reportKey);

    if (!record) {
      result.status = "UNANCHORED";
      if (report.status === "PUBLISHED" || result.transactionHash) {
        result.error = "The database claims this report was published, but CTIRegistry has no record for it.";
      }
    } else {
      result.onChainHash = record.contentHash;
      result.publisher = record.publisher;
      result.timestamp = new Date(record.timestamp * 1000).toISOString();
      const owner = await gw.getOwner();
      result.isAuthorizedPublisher = owner.toLowerCase() === record.publisher.toLowerCase();
      result.checks.onChainHashMatchesRecomputed = record.contentHash === recomputed;

      if (result.transactionHash) {
        const receipt = await gw.getReceipt(result.transactionHash);
        result.transactionConfirmed =
          !!receipt &&
          receipt.status === 1 &&
          receipt.to?.toLowerCase() === gw.contractAddress.toLowerCase() &&
          receipt.event?.reportKey.toLowerCase() === reportKey.toLowerCase() &&
          receipt.event?.contentHash === record.contentHash;
      }

      if (!result.isAuthorizedPublisher) {
        result.status = "UNTRUSTED_PUBLISHER";
      } else if (
        result.checks.onChainHashMatchesRecomputed &&
        result.checks.persistedHashMatchesRecomputed !== false &&
        result.checks.persistedCanonicalJsonMatches !== false
      ) {
        result.status = "VERIFIED";
        result.matches = true;
      } else {
        result.status = "TAMPERED";
      }
    }
  } catch (e: any) {
    result.status = "UNAVAILABLE";
    result.error = e instanceof AnchorError ? e.message : `Verification unavailable: ${e?.message || e}`;
    return result;
  }

  report.verificationStatus = result.status;
  report.lastVerifiedAt = new Date();
  await report.save();
  return result;
}
