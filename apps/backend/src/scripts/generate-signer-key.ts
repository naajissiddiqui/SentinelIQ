/**
 * Generates a new random Polygon Amoy signer key and writes it to
 * apps/backend/.env as BLOCKCHAIN_PRIVATE_KEY. Only the derived public
 * address is printed; the key and mnemonic are never echoed.
 *
 * Safety:
 *  - aborts unless .env (and the backup name) are git-ignored and untracked
 *  - backs up .env to .env.backup-<timestamp> (also git-ignored) first
 *  - preserves every other line of .env
 *  - reads the file back and verifies the saved key derives the new address
 *  - refuses to replace an existing private (non-public-dev) key unless
 *    --rotate is passed, so repeated runs never silently rotate a wallet
 *
 * Usage (from apps/backend): npx tsx src/scripts/generate-signer-key.ts [--rotate]
 */
import fs from "fs";
import path from "path";
import { execFileSync } from "child_process";
import { ethers } from "ethers";
import { isPublicDevAddress } from "../config/blockchain.constants";

const envPath = path.resolve(__dirname, "../../.env");
const rotate = process.argv.includes("--rotate") || process.argv.includes("--force");
const KEY_LINE = /^BLOCKCHAIN_PRIVATE_KEY=.*$/m;

function fail(message: string): never {
  console.error(`FAILED: ${message}`);
  process.exit(1);
}

function gitIgnored(file: string): boolean {
  try {
    execFileSync("git", ["check-ignore", "-q", file], { cwd: path.dirname(envPath), stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function gitTracked(file: string): boolean {
  try {
    const out = execFileSync("git", ["ls-files", "--", file], { cwd: path.dirname(envPath) }).toString().trim();
    return out.length > 0;
  } catch {
    return false;
  }
}

function addressFromEnv(content: string): string | null {
  const key = /^BLOCKCHAIN_PRIVATE_KEY=(.*)$/m.exec(content)?.[1]?.trim();
  if (!key) return null;
  try {
    return new ethers.Wallet(key).address;
  } catch {
    return null;
  }
}

function main() {
  if (!fs.existsSync(envPath)) fail(`${envPath} not found.`);

  const backupPath = `${envPath}.backup-${new Date().toISOString().replace(/[:.]/g, "-")}`;
  if (!gitIgnored(envPath) || gitTracked(envPath)) fail(".env is not git-ignored (or is tracked). Not writing a key.");
  if (!gitIgnored(backupPath)) fail("The .env backup filename would not be git-ignored. Not writing a key.");

  const content = fs.readFileSync(envPath, "utf8");
  const currentAddress = addressFromEnv(content);
  if (currentAddress && !isPublicDevAddress(currentAddress) && !rotate) {
    console.log(`No change: BLOCKCHAIN_PRIVATE_KEY already holds a private key for ${currentAddress}.`);
    console.log("Pass --rotate to replace it.");
    return;
  }

  // Backup first (owner read/write only where the OS supports it).
  fs.copyFileSync(envPath, backupPath, fs.constants.COPYFILE_EXCL);
  try {
    fs.chmodSync(backupPath, 0o600);
  } catch {
    /* best effort on Windows */
  }

  const wallet = ethers.Wallet.createRandom(); // CSPRNG-backed
  const expected = wallet.address;
  if (isPublicDevAddress(expected)) fail("Generated a public dev address (should be impossible). Aborting.");

  const line = `BLOCKCHAIN_PRIVATE_KEY=${wallet.privateKey}`;
  const updated = KEY_LINE.test(content)
    ? content.replace(KEY_LINE, () => line)
    : `${content.replace(/\s*$/, "")}\n${line}\n`;

  // Every other line must be untouched.
  const otherLines = (s: string) => s.split(/\r?\n/).filter((l) => !l.startsWith("BLOCKCHAIN_PRIVATE_KEY="));
  if (JSON.stringify(otherLines(updated)) !== JSON.stringify(otherLines(content).concat(KEY_LINE.test(content) ? [] : []))) {
    if (KEY_LINE.test(content)) fail("Refusing to write: other .env lines would change. .env left untouched.");
  }

  fs.writeFileSync(envPath, updated);

  // Read back and verify.
  const saved = addressFromEnv(fs.readFileSync(envPath, "utf8"));
  if (saved !== expected) {
    fs.copyFileSync(backupPath, envPath);
    fail("Saved key did not derive the expected address. Restored .env from backup.");
  }
  if (isPublicDevAddress(saved)) {
    fs.copyFileSync(backupPath, envPath);
    fail("Saved key is a public dev key. Restored .env from backup.");
  }

  console.log("SUCCESS: new signer key saved to apps/backend/.env (backup created, both git-ignored).");
  console.log(`New wallet address: ${saved}`);
}

main();
