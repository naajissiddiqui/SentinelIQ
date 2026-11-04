import {
  ethers,
  provider,
  wallet,
  ctiRegistryAbi,
  getBlockchainStatus,
  validateBlockchainConfig,
  POLYGON_AMOY_CHAIN_ID,
  POLYGON_AMOY_NETWORK_NAME,
} from "../config/blockchain";
import { env } from "../config/env";

/**
 * Why a chain operation could not complete:
 *  - CONFIG:      signer/contract/network misconfigured (operator must fix)
 *  - UNAVAILABLE: RPC unreachable / timed out (retry later)
 *  - FUNDS:       signer cannot pay for gas
 *  - REVERT:      the contract rejected the call
 */
export type AnchorErrorKind = "CONFIG" | "UNAVAILABLE" | "FUNDS" | "REVERT";

export class AnchorError extends Error {
  constructor(public kind: AnchorErrorKind, message: string) {
    super(message);
    this.name = "AnchorError";
  }
}

export interface OnChainRecord {
  contentHash: string; // 0x-prefixed lowercase bytes32
  publisher: string;
  timestamp: number; // unix seconds
}

export interface AnchorReceipt {
  hash: string;
  status: number;
  blockNumber: number;
  from: string;
  to: string | null;
  /** The CTIPublished event in this receipt, if any. */
  event: { reportKey: string; contentHash: string; publisher: string } | null;
}

/** Everything the CTI service needs from the chain; faked in unit tests. */
export interface RegistryGateway {
  readonly contractAddress: string;
  readonly chainId: number;
  readonly networkName: string;
  ensureWritable(): Promise<void>;
  ensureReadable(): Promise<void>;
  getRecord(reportKey: string): Promise<OnChainRecord | null>;
  getOwner(): Promise<string>;
  submitPublish(reportKey: string, contentHashBytes32: string, attackType: string): Promise<string>;
  waitForReceipt(txHash: string, timeoutMs: number): Promise<AnchorReceipt | null>;
  getReceipt(txHash: string): Promise<AnchorReceipt | null>;
  isTransactionKnown(txHash: string): Promise<boolean>;
  findPublishEvent(reportKey: string): Promise<{ transactionHash: string; blockNumber: number } | null>;
}

/** On-chain mapping key: keccak256 of the human-readable report ID. */
export function reportKeyFor(reportId: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(reportId));
}

export function toBytes32(contentHashHex: string): string {
  const hex = contentHashHex.replace(/^0x/, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(`Not a SHA-256 hex digest: ${contentHashHex}`);
  }
  return `0x${hex}`;
}

const NETWORK_ERROR_CODES = new Set(["NETWORK_ERROR", "SERVER_ERROR", "TIMEOUT", "UNKNOWN_ERROR", "BAD_DATA"]);

const registryInterface = new ethers.Interface(ctiRegistryAbi);

function revertReason(e: any): string | null {
  if (e?.reason) return e.reason;
  // estimateGas paths can leave custom errors undecoded; decode with our ABI.
  if (typeof e?.data === "string" && e.data.length >= 10) {
    try {
      const parsed = registryInterface.parseError(e.data);
      if (parsed) return `${parsed.name}(${parsed.args.join(", ")})`;
    } catch {
      /* fall through */
    }
  }
  // Custom errors (e.g. OwnableUnauthorizedAccount) only come back decoded.
  if (e?.revert) return `${e.revert.name}(${(e.revert.args || []).join(", ")})`;
  return null;
}

function classify(e: any, context: string): AnchorError {
  if (e instanceof AnchorError) return e;
  const msg = e?.shortMessage || e?.message || String(e);
  if (e?.code === "INSUFFICIENT_FUNDS" || /insufficient funds/i.test(msg)) {
    return new AnchorError("FUNDS", `${context}: signer has insufficient POL for gas (${msg})`);
  }
  if (e?.code === "CALL_EXCEPTION" && (revertReason(e) || (typeof e?.data === "string" && e.data !== "0x"))) {
    return new AnchorError("REVERT", `${context}: contract reverted: ${revertReason(e) ?? e.data}`);
  }
  if (NETWORK_ERROR_CODES.has(e?.code) || /ECONNREFUSED|ENOTFOUND|ETIMEDOUT|fetch failed|socket hang up/i.test(msg)) {
    return new AnchorError("UNAVAILABLE", `${context}: Polygon Amoy RPC unavailable (${msg})`);
  }
  return new AnchorError("UNAVAILABLE", `${context}: ${msg}`);
}

export interface EthersGatewayOptions {
  provider: ethers.JsonRpcProvider;
  signer: ethers.Signer | null;
  contractAddress: string;
  chainId: number;
  networkName: string;
  deployBlock: number | null;
  /** Readiness check; defaults to the startup validator's status. */
  checkReady?: (requireSigner: boolean) => Promise<void>;
}

async function checkConfiguredReady(requireSigner: boolean) {
  let status = getBlockchainStatus();
  if (!status.ready) status = await validateBlockchainConfig(); // RPC may have recovered
  if (status.ready) return;
  if (!status.rpcReachable) {
    throw new AnchorError("UNAVAILABLE", status.errors.join(" "));
  }
  const readable = status.contractHasBytecode && status.chainId === POLYGON_AMOY_CHAIN_ID;
  if (!requireSigner && readable) return;
  throw new AnchorError("CONFIG", status.errors.join(" "));
}

export class EthersRegistryGateway implements RegistryGateway {
  readonly contractAddress: string;
  readonly chainId: number;
  readonly networkName: string;
  private readonly provider: ethers.JsonRpcProvider;
  private readonly signer: ethers.Signer | null;
  private readonly deployBlock: number | null;
  private readonly checkReady: (requireSigner: boolean) => Promise<void>;
  private readonly iface = registryInterface;
  private readonly reader: ethers.Contract | null;
  private readonly writer: ethers.Contract | null;

  constructor(opts: EthersGatewayOptions) {
    this.provider = opts.provider;
    this.signer = opts.signer;
    this.contractAddress = opts.contractAddress;
    this.chainId = opts.chainId;
    this.networkName = opts.networkName;
    this.deployBlock = opts.deployBlock;
    this.checkReady = opts.checkReady ?? checkConfiguredReady;
    const valid = ethers.isAddress(opts.contractAddress) && opts.contractAddress !== ethers.ZeroAddress;
    this.reader = valid ? new ethers.Contract(opts.contractAddress, ctiRegistryAbi, opts.provider) : null;
    this.writer = valid && opts.signer ? new ethers.Contract(opts.contractAddress, ctiRegistryAbi, opts.signer) : null;
  }

  private ensure(requireSigner: boolean) {
    return this.checkReady(requireSigner);
  }

  ensureWritable() {
    return this.ensure(true);
  }

  ensureReadable() {
    return this.ensure(false);
  }

  async getRecord(reportKey: string): Promise<OnChainRecord | null> {
    if (!this.reader) throw new AnchorError("CONFIG", "CTI_REGISTRY_CONTRACT_ADDRESS is not configured.");
    try {
      const r = await this.reader.getCTI(reportKey);
      return {
        contentHash: String(r.contentHash).toLowerCase(),
        publisher: String(r.publisher),
        timestamp: Number(r.timestamp),
      };
    } catch (e: any) {
      if (e?.code === "CALL_EXCEPTION" && /report not found/.test(String(revertReason(e)))) {
        return null;
      }
      throw classify(e, "getCTI");
    }
  }

  async getOwner(): Promise<string> {
    if (!this.reader) throw new AnchorError("CONFIG", "CTI_REGISTRY_CONTRACT_ADDRESS is not configured.");
    try {
      return await this.reader.owner();
    } catch (e) {
      throw classify(e, "owner");
    }
  }

  async submitPublish(reportKey: string, contentHashBytes32: string, attackType: string): Promise<string> {
    if (!this.writer || !this.signer) throw new AnchorError("CONFIG", "Signer or contract is not configured.");
    try {
      // estimateGas simulates the call: an owner/duplicate revert surfaces here
      // without spending gas.
      const gas = await this.writer.publishCTI.estimateGas(reportKey, contentHashBytes32, attackType);
      const gasLimit = (gas * 130n) / 100n;
      const feeData = await this.provider.getFeeData();
      const block = await this.provider.getBlock("latest");
      const minTip = ethers.parseUnits("25", "gwei"); // Amoy Bor minimum tip
      const maxPriorityFeePerGas =
        feeData.maxPriorityFeePerGas && feeData.maxPriorityFeePerGas > minTip ? feeData.maxPriorityFeePerGas : minTip;
      const maxFeePerGas = (block?.baseFeePerGas ?? 0n) * 2n + maxPriorityFeePerGas;

      const signerAddress = await this.signer.getAddress();
      const balance = await this.provider.getBalance(signerAddress);
      const maxCost = gasLimit * maxFeePerGas;
      if (balance < maxCost) {
        throw new AnchorError(
          "FUNDS",
          `Signer ${signerAddress} has ${ethers.formatEther(balance)} POL; publishing needs up to ${ethers.formatEther(maxCost)} POL.`
        );
      }

      const tx = await this.writer.publishCTI(reportKey, contentHashBytes32, attackType, {
        gasLimit,
        maxFeePerGas,
        maxPriorityFeePerGas,
      });
      return tx.hash;
    } catch (e) {
      throw classify(e, "publishCTI");
    }
  }

  private toAnchorReceipt(receipt: ethers.TransactionReceipt): AnchorReceipt {
    let event: AnchorReceipt["event"] = null;
    for (const log of receipt.logs) {
      if (log.address.toLowerCase() !== this.contractAddress.toLowerCase()) continue;
      const parsed = this.iface.parseLog(log);
      if (parsed?.name === "CTIPublished") {
        event = {
          reportKey: String(parsed.args.reportKey).toLowerCase(),
          contentHash: String(parsed.args.contentHash).toLowerCase(),
          publisher: String(parsed.args.publisher),
        };
      }
    }
    return {
      hash: receipt.hash,
      status: receipt.status ?? 0,
      blockNumber: receipt.blockNumber,
      from: receipt.from,
      to: receipt.to,
      event,
    };
  }

  async waitForReceipt(txHash: string, timeoutMs: number): Promise<AnchorReceipt | null> {
    try {
      const receipt = await this.provider.waitForTransaction(txHash, 1, timeoutMs);
      return receipt ? this.toAnchorReceipt(receipt) : null;
    } catch (e: any) {
      if (e?.code === "TIMEOUT") return null;
      throw classify(e, "waitForTransaction");
    }
  }

  async getReceipt(txHash: string): Promise<AnchorReceipt | null> {
    try {
      const receipt = await this.provider.getTransactionReceipt(txHash);
      return receipt ? this.toAnchorReceipt(receipt) : null;
    } catch (e) {
      throw classify(e, "getTransactionReceipt");
    }
  }

  async isTransactionKnown(txHash: string): Promise<boolean> {
    try {
      return (await this.provider.getTransaction(txHash)) !== null;
    } catch (e) {
      throw classify(e, "getTransaction");
    }
  }

  async findPublishEvent(reportKey: string) {
    if (!this.reader) return null;
    const CHUNK = 9_000; // stay under public RPC eth_getLogs range limits
    try {
      const latest = await this.provider.getBlockNumber();
      const from = this.deployBlock ?? Math.max(0, latest - 50_000);
      const filter = this.reader.filters.CTIPublished(reportKey);
      for (let start = from; start <= latest; start += CHUNK + 1) {
        const events = await this.reader.queryFilter(filter, start, Math.min(start + CHUNK, latest));
        if (events.length > 0) {
          return { transactionHash: events[0].transactionHash, blockNumber: events[0].blockNumber };
        }
      }
      return null;
    } catch (e) {
      throw classify(e, "queryFilter(CTIPublished)");
    }
  }
}

let gateway: RegistryGateway | null = null;

export function getRegistryGateway(): RegistryGateway {
  if (!gateway) {
    gateway = new EthersRegistryGateway({
      provider,
      signer: wallet,
      contractAddress: env.blockchain.contractAddress,
      chainId: POLYGON_AMOY_CHAIN_ID,
      networkName: POLYGON_AMOY_NETWORK_NAME,
      deployBlock: env.blockchain.deployBlock,
    });
  }
  return gateway;
}

/** Test hook: swap in a fake chain. Pass null to restore the real one. */
export function setRegistryGateway(next: RegistryGateway | null) {
  gateway = next;
}
