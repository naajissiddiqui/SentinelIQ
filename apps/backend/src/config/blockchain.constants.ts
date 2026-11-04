// Side-effect-free blockchain constants and validators (no env access), so
// they can be shared by scripts and unit tests.

export const POLYGON_AMOY_CHAIN_ID = 80002;
export const POLYGON_AMOY_NETWORK_NAME = "Polygon Amoy Testnet";
export const AMOY_EXPLORER_TX_BASE = "https://amoy.polygonscan.com/tx/";
export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

// Hardhat/Anvil default accounts. Their private keys are published, so they
// must never sign real anchors: anyone could front-run or impersonate them.
const PUBLIC_DEV_ADDRESSES = new Set(
  [
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
  ].map((a) => a.toLowerCase())
);

export function isPublicDevAddress(address: string): boolean {
  return PUBLIC_DEV_ADDRESSES.has(address.toLowerCase());
}

/** A real transaction hash is exactly 32 bytes of hex. */
export function isTransactionHash(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

export function explorerTxUrl(txHash: string): string | null {
  return isTransactionHash(txHash) ? `${AMOY_EXPLORER_TX_BASE}${txHash}` : null;
}
