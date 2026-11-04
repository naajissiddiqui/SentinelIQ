/**
 * Invalidates misleading blockchain metadata on CTI reports WITHOUT deleting
 * any report or its content.
 *
 * A report marked PUBLISHED/ANCHORED/PUBLISHING is kept as anchored only if
 * its transactionHash is a real Polygon Amoy transaction to the configured
 * CTIRegistry with a successful receipt and a CTIPublished event for this
 * report. Otherwise the old metadata is moved into `invalidatedAnchor`, the
 * tx fields are cleared, and the report returns to PENDING_APPROVAL /
 * UNANCHORED so it can be published for real.
 *
 * Dry run by default. Usage (from apps/backend):
 *   npx tsx src/scripts/invalidate-unanchored-reports.ts           # report only
 *   npx tsx src/scripts/invalidate-unanchored-reports.ts --apply   # write changes
 */
import mongoose from "mongoose";
import { env } from "../config/env";
import { CTIReportModel } from "../models/ctiReport.model";
import { isContractConfigured, isTransactionHash } from "../config/blockchain";
import { getRegistryGateway, reportKeyFor } from "../services/blockchain.service";
import { targetReportId } from "../services/ctiAnchor.service";

const apply = process.argv.includes("--apply");

async function realAnchorProblem(report: any): Promise<string | null> {
  if (!report.transactionHash) return "no transaction hash";
  if (!isTransactionHash(report.transactionHash)) return `not a transaction hash: ${report.transactionHash}`;
  if (!isContractConfigured()) return "no CTIRegistry deployed/configured, so this cannot be a real anchor";
  const gw = getRegistryGateway();
  const receipt = await gw.getReceipt(report.transactionHash); // throws if RPC is down: we then change nothing
  if (!receipt) return "transaction not found on Polygon Amoy";
  if (receipt.status !== 1) return "transaction reverted";
  if (receipt.to?.toLowerCase() !== gw.contractAddress.toLowerCase()) return `transaction was sent to ${receipt.to}, not CTIRegistry`;
  if (receipt.event?.reportKey.toLowerCase() !== reportKeyFor(targetReportId(report)).toLowerCase()) {
    return "transaction has no CTIPublished event for this report";
  }
  return null;
}

async function main() {
  await mongoose.connect(env.mongoUri);
  const candidates = await CTIReportModel.find({ status: { $in: ["PUBLISHED", "ANCHORED", "PUBLISHING"] } });
  console.log(`${candidates.length} report(s) claim to be published/publishing. Mode: ${apply ? "APPLY" : "DRY RUN"}`);

  let invalidated = 0;
  for (const report of candidates) {
    const problem = await realAnchorProblem(report);
    const id = targetReportId(report as any);
    if (!problem) {
      console.log(`  keep  ${id}: real anchor tx ${report.transactionHash}`);
      continue;
    }
    if (report.status === "PUBLISHING" && isTransactionHash(report.transactionHash) && problem === "transaction not found on Polygon Amoy") {
      console.log(`  skip  ${id}: pending tx ${report.transactionHash} (publish again to reconcile)`);
      continue;
    }
    console.log(`  fix   ${id} [${report.status}/${report.verificationStatus ?? "-"}]: ${problem}`);
    invalidated++;
    if (!apply) continue;

    report.invalidatedAnchor = {
      reason: problem,
      invalidatedAt: new Date().toISOString(),
      previous: {
        status: report.status,
        verificationStatus: report.verificationStatus ?? null,
        transactionHash: report.transactionHash ?? null,
        blockNumber: report.blockNumber ?? null,
        publisherAddress: report.publisherAddress ?? null,
        publishedAt: report.publishedAt ?? null,
      },
    };
    report.status = "PENDING_APPROVAL";
    report.verificationStatus = "UNANCHORED";
    report.transactionHash = null;
    report.blockNumber = null;
    report.publisherAddress = null;
    report.publishedAt = undefined;
    report.publishLockedUntil = null;
    await report.save();
  }

  console.log(apply ? `Invalidated ${invalidated} report(s).` : `${invalidated} report(s) would be invalidated. Re-run with --apply.`);
  await mongoose.disconnect();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
