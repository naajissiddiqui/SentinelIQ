import http from "http";
import { createApp } from "./app";
import { connectDatabase } from "./config/database";
import { env } from "./config/env";
import { initializeSocketServer } from "./websocket/socket";
import { validateBlockchainConfig } from "./config/blockchain";

async function start() {
  await connectDatabase();

  // Validate signer, Amoy RPC/chain ID, contract address, bytecode and
  // ownership. Failures disable publishing (with the reason) but keep the
  // rest of the platform running.
  const chain = await validateBlockchainConfig();
  if (chain.ready) {
    console.log(
      `[blockchain] Ready: Polygon Amoy (chain ${chain.chainId}), CTIRegistry ${chain.contractAddress}, ` +
        `signer ${chain.signerAddress} (${chain.signerBalancePol} POL)`
    );
  } else {
    console.error("[blockchain] CTI publishing DISABLED:");
    for (const err of chain.errors) console.error(`  - ${err}`);
  }
  const app = createApp();

  // Wrapping Express in a plain http.Server lets Socket.IO attach to the
  // exact same port - no separate WebSocket port to manage or expose.
  const httpServer = http.createServer(app);
  initializeSocketServer(httpServer);

  httpServer.listen(env.port, () => {
    console.log(`[server] Listening on http://localhost:${env.port}`);
    console.log(`[server] WebSocket server ready on the same port`);
  });
}

start();