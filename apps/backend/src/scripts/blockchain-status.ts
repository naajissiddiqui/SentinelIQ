/**
 * Prints the same blockchain readiness check the server runs at startup:
 * signer address (never the key), Amoy chain ID, RPC reachability, balance,
 * contract bytecode and ownership. Exit code 1 if publishing is not ready.
 *
 * Usage (from apps/backend): npm run blockchain:status
 */
import { validateBlockchainConfig } from "../config/blockchain";

validateBlockchainConfig().then((status) => {
  console.log(JSON.stringify(status, null, 2));
  process.exit(status.ready ? 0 : 1);
});
