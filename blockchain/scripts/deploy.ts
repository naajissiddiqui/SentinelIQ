/**
 * Deploys CTIRegistry to Polygon Amoy using the compiled Hardhat artifact.
 *
 *   npx hardhat run scripts/deploy.ts --network amoy               # deploy
 *   DRY_RUN=1 npx hardhat run scripts/deploy.ts --network amoy     # checks + gas estimate only
 *   FORCE_REDEPLOY=1 ...                                           # deploy even if a valid one exists
 *
 * Credentials come from apps/backend/.env (see hardhat.config.ts). The private
 * key is never printed. On success the script records the deployment in
 * deployments/amoy.json and updates CTI_REGISTRY_CONTRACT_ADDRESS /
 * CTI_REGISTRY_DEPLOY_BLOCK in apps/backend/.env.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { network } from "hardhat";

const AMOY_CHAIN_ID = 80002n;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
// Hardhat/Anvil default accounts: their private keys are public, so any funds
// or contract ownership given to them can be taken by anyone.
const PUBLIC_DEV_ADDRESSES = new Set(
  [
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
  ].map((a) => a.toLowerCase())
);

const here = path.dirname(fileURLToPath(import.meta.url));
const backendEnvPath = path.resolve(here, "../../apps/backend/.env");
const deploymentRecordPath = path.resolve(here, "../deployments/amoy.json");

function fail(message: string): never {
  throw new Error(message);
}

function setEnvLine(content: string, key: string, value: string): string {
  const line = `${key}=${value}`;
  const re = new RegExp(`^${key}=.*$`, "m");
  return re.test(content) ? content.replace(re, line) : `${content.replace(/\s*$/, "")}\n${line}\n`;
}

async function main() {
  const dryRun = process.env.DRY_RUN === "1";
  const force = process.env.FORCE_REDEPLOY === "1";

  const { ethers } = await network.create();
  const provider = ethers.provider;

  // 1. Network
  const { chainId } = await provider.getNetwork();
  if (chainId !== AMOY_CHAIN_ID) fail(`Connected to chain ${chainId}; expected Polygon Amoy (80002). Use --network amoy.`);
  console.log(`Network: Polygon Amoy (chain ${chainId}), latest block ${await provider.getBlockNumber()}`);

  // 2. Signer
  const signers = await ethers.getSigners();
  if (signers.length === 0) fail("No signer configured. Set BLOCKCHAIN_PRIVATE_KEY in apps/backend/.env.");
  const deployer = signers[0];
  const deployerAddress = await deployer.getAddress();
  console.log(`Deployer: ${deployerAddress}`);
  if (PUBLIC_DEV_ADDRESSES.has(deployerAddress.toLowerCase())) {
    fail(
      `Deployer ${deployerAddress} is a public Hardhat development account whose private key is published. ` +
        "Configure a private, newly generated key in BLOCKCHAIN_PRIVATE_KEY."
    );
  }

  // 3. Existing deployment
  const backendEnv = fs.existsSync(backendEnvPath) ? fs.readFileSync(backendEnvPath, "utf8") : "";
  const configured = /^CTI_REGISTRY_CONTRACT_ADDRESS=(.*)$/m.exec(backendEnv)?.[1]?.trim();
  if (configured && configured !== ZERO_ADDRESS && ethers.isAddress(configured)) {
    const code = await provider.getCode(configured);
    if (code !== "0x" && !force) {
      fail(`A contract already exists at the configured address ${configured}. Not redeploying (set FORCE_REDEPLOY=1 to override).`);
    }
  }
  if (fs.existsSync(deploymentRecordPath) && !force) {
    const record = JSON.parse(fs.readFileSync(deploymentRecordPath, "utf8"));
    if (record.address && (await provider.getCode(record.address)) !== "0x") {
      fail(`deployments/amoy.json records a live deployment at ${record.address}. Not redeploying (set FORCE_REDEPLOY=1 to override).`);
    }
  }

  // 4. Gas estimate from the compiled artifact vs balance
  const factory = await ethers.getContractFactory("CTIRegistry", deployer);
  const deployTx = await factory.getDeployTransaction(deployerAddress);
  const gas = await provider.estimateGas({ ...deployTx, from: deployerAddress });
  const feeData = await provider.getFeeData();
  const latest = await provider.getBlock("latest");
  const minTip = ethers.parseUnits("25", "gwei");
  const tip = feeData.maxPriorityFeePerGas && feeData.maxPriorityFeePerGas > minTip ? feeData.maxPriorityFeePerGas : minTip;
  const maxFeePerGas = (latest?.baseFeePerGas ?? 0n) * 2n + tip;
  const gasLimit = (gas * 120n) / 100n;
  const worstCase = gasLimit * maxFeePerGas;
  const balance = await provider.getBalance(deployerAddress);
  console.log(`Estimated deployment gas: ${gas} (limit ${gasLimit})`);
  console.log(`Max cost: ${ethers.formatEther(worstCase)} POL; balance: ${ethers.formatEther(balance)} POL`);
  if (balance < worstCase) {
    fail(`Insufficient balance: need ~${ethers.formatEther(worstCase)} POL, have ${ethers.formatEther(balance)} POL at ${deployerAddress}.`);
  }
  if (dryRun) {
    console.log("DRY_RUN=1: all pre-flight checks passed; not deploying.");
    return;
  }

  // 5. Deploy and verify
  const contract = await factory.deploy(deployerAddress, { gasLimit, maxFeePerGas, maxPriorityFeePerGas: tip });
  const tx = contract.deploymentTransaction();
  if (!tx) fail("No deployment transaction returned by provider.");
  console.log(`Deployment tx submitted: ${tx.hash}`);
  const receipt = await tx.wait(2, 300_000);
  if (!receipt || receipt.status !== 1) fail(`Deployment transaction ${tx.hash} failed (status ${receipt?.status}).`);
  const address = receipt.contractAddress ?? (await contract.getAddress());
  const code = await provider.getCode(address);
  if (code === "0x") fail(`No bytecode at ${address} after deployment.`);
  const owner = await (contract as any).owner();
  if (owner.toLowerCase() !== deployerAddress.toLowerCase()) fail(`Owner mismatch: ${owner}`);

  const record = {
    contract: "CTIRegistry",
    network: "polygon-amoy",
    chainId: Number(chainId),
    address,
    transactionHash: receipt.hash,
    blockNumber: receipt.blockNumber,
    deployer: deployerAddress,
    owner,
    gasUsed: receipt.gasUsed.toString(),
    deployedBytecodeKeccak256: ethers.keccak256(code),
    deployedAt: new Date().toISOString(),
    explorer: `https://amoy.polygonscan.com/tx/${receipt.hash}`,
  };
  fs.mkdirSync(path.dirname(deploymentRecordPath), { recursive: true });
  fs.writeFileSync(deploymentRecordPath, JSON.stringify(record, null, 2) + "\n");

  if (fs.existsSync(backendEnvPath)) {
    let updated = setEnvLine(backendEnv, "CTI_REGISTRY_CONTRACT_ADDRESS", address);
    updated = setEnvLine(updated, "CTI_REGISTRY_DEPLOY_BLOCK", String(receipt.blockNumber));
    fs.writeFileSync(backendEnvPath, updated);
  }

  console.log(`CTIRegistry deployed at ${address} (block ${receipt.blockNumber}, gas used ${receipt.gasUsed})`);
  console.log(`Explorer: ${record.explorer}`);
  console.log("Recorded in blockchain/deployments/amoy.json and apps/backend/.env");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
