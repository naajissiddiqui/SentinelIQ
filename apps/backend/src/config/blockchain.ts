import { ethers } from "ethers";
import { env } from "./env";
import ctiRegistryArtifact from "../abi/CTIRegistry.json";
import {
  POLYGON_AMOY_CHAIN_ID,
  POLYGON_AMOY_NETWORK_NAME,
  ZERO_ADDRESS,
  isPublicDevAddress,
} from "./blockchain.constants";

export * from "./blockchain.constants";

export const ctiRegistryAbi = ctiRegistryArtifact.abi;

// A single shared provider configured for Polygon Amoy
const provider = new ethers.JsonRpcProvider(env.blockchain.rpcUrl, POLYGON_AMOY_CHAIN_ID, {
  staticNetwork: true,
});

function buildWallet(): ethers.Wallet | null {
  try {
    return new ethers.Wallet(env.blockchain.privateKey, provider);
  } catch {
    return null; // reported by validateBlockchainConfig()
  }
}

const wallet = buildWallet();

export function isContractConfigured(): boolean {
  const addr = env.blockchain.contractAddress;
  return Boolean(addr && addr !== ZERO_ADDRESS && ethers.isAddress(addr));
}

export const ctiRegistryContract: ethers.Contract | null =
  isContractConfigured() && wallet
    ? new ethers.Contract(env.blockchain.contractAddress, ctiRegistryAbi, wallet)
    : null;

export interface BlockchainStatus {
  ready: boolean;
  checkedAt: string | null;
  network: string;
  expectedChainId: number;
  chainId: number | null;
  rpcReachable: boolean;
  latestBlock: number | null;
  signerAddress: string | null;
  signerBalancePol: string | null;
  contractAddress: string;
  contractHasBytecode: boolean;
  contractOwner: string | null;
  signerIsOwner: boolean;
  deployBlock: number | null;
  errors: string[];
}

let status: BlockchainStatus = {
  ready: false,
  checkedAt: null,
  network: POLYGON_AMOY_NETWORK_NAME,
  expectedChainId: POLYGON_AMOY_CHAIN_ID,
  chainId: null,
  rpcReachable: false,
  latestBlock: null,
  signerAddress: wallet?.address ?? null,
  signerBalancePol: null,
  contractAddress: env.blockchain.contractAddress,
  contractHasBytecode: false,
  contractOwner: null,
  signerIsOwner: false,
  deployBlock: env.blockchain.deployBlock,
  errors: [],
};

export function getBlockchainStatus(): BlockchainStatus {
  return status;
}

/**
 * Validates the signer, RPC/network, contract address, deployed bytecode and
 * contract ownership. Never throws: the rest of the platform keeps working
 * and publishing is refused with the recorded errors until this passes.
 */
export async function validateBlockchainConfig(): Promise<BlockchainStatus> {
  const errors: string[] = [];
  const next: BlockchainStatus = {
    ...status,
    ready: false,
    checkedAt: new Date().toISOString(),
    chainId: null,
    rpcReachable: false,
    latestBlock: null,
    signerBalancePol: null,
    contractHasBytecode: false,
    contractOwner: null,
    signerIsOwner: false,
    errors,
  };

  if (!wallet) {
    errors.push("BLOCKCHAIN_PRIVATE_KEY is not a valid 32-byte hex private key.");
  } else if (isPublicDevAddress(wallet.address)) {
    errors.push(
      `BLOCKCHAIN_PRIVATE_KEY derives ${wallet.address}, a public Hardhat development account. ` +
        "Its key is published; generate a private key (npx tsx src/scripts/generate-signer-key.ts)."
    );
  }

  if (!isContractConfigured()) {
    errors.push(
      `CTI_REGISTRY_CONTRACT_ADDRESS (${env.blockchain.contractAddress}) is missing, invalid or the zero address. ` +
        "Deploy CTIRegistry (blockchain: npm run deploy:amoy)."
    );
  }

  try {
    // Ask the RPC directly: staticNetwork would otherwise just echo 80002 back.
    next.chainId = Number(await provider.send("eth_chainId", []));
    next.latestBlock = await provider.getBlockNumber();
    next.rpcReachable = true;
    if (next.chainId !== POLYGON_AMOY_CHAIN_ID) {
      errors.push(`RPC reports chain ID ${next.chainId}; expected Polygon Amoy (${POLYGON_AMOY_CHAIN_ID}).`);
    }
  } catch (e: any) {
    errors.push(`Polygon Amoy RPC (${env.blockchain.rpcUrl}) is unreachable: ${e?.shortMessage || e?.message}`);
  }

  if (next.rpcReachable && wallet) {
    try {
      next.signerBalancePol = ethers.formatEther(await provider.getBalance(wallet.address));
    } catch {
      /* non-fatal */
    }
  }

  if (next.rpcReachable && next.chainId === POLYGON_AMOY_CHAIN_ID && isContractConfigured()) {
    try {
      const code = await provider.getCode(env.blockchain.contractAddress);
      next.contractHasBytecode = code !== "0x";
      if (!next.contractHasBytecode) {
        errors.push(`No contract bytecode at ${env.blockchain.contractAddress} on Polygon Amoy.`);
      } else {
        const reader = new ethers.Contract(env.blockchain.contractAddress, ctiRegistryAbi, provider);
        next.contractOwner = await reader.owner();
        next.signerIsOwner =
          !!wallet && next.contractOwner!.toLowerCase() === wallet.address.toLowerCase();
        if (!next.signerIsOwner) {
          errors.push(`Signer ${wallet?.address} is not the CTIRegistry owner (${next.contractOwner}); publishCTI would revert.`);
        }
      }
    } catch (e: any) {
      errors.push(`Could not read CTIRegistry at ${env.blockchain.contractAddress}: ${e?.shortMessage || e?.message}`);
    }
  }

  next.ready = errors.length === 0;
  status = next;
  return next;
}

export { ethers, provider, wallet };
