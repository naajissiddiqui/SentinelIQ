import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

// Single source of truth for blockchain credentials: the backend's .env.
// (blockchain/.env is also honoured if present, but never required.)
const here = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(here, "../apps/backend/.env") });
dotenv.config({ path: path.resolve(here, ".env") });

// No fallback key. A deploy without BLOCKCHAIN_PRIVATE_KEY must fail loudly
// rather than silently using a publicly known development key.
const amoyAccounts = process.env.BLOCKCHAIN_PRIVATE_KEY
  ? [process.env.BLOCKCHAIN_PRIVATE_KEY]
  : [];

export default defineConfig({
  plugins: [hardhatToolboxMochaEthers],
  solidity: {
    version: "0.8.28",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    amoy: {
      type: "http",
      url: process.env.POLYGON_AMOY_RPC_URL || "https://polygon-amoy-bor-rpc.publicnode.com",
      chainId: 80002,
      accounts: amoyAccounts,
    },
  },
});
