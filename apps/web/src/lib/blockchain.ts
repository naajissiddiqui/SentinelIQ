// Polygon Amoy explorer helpers. A transaction link is only ever built from a
// well-formed 32-byte transaction hash; report IDs, MongoDB ObjectIds and
// SHA-256 content hashes are never turned into explorer links.

export const AMOY_CHAIN_ID = 80002
export const AMOY_EXPLORER = 'https://amoy.polygonscan.com'

export function isTxHash(value: unknown): value is string {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value)
}

export function isAddress(value: unknown): value is string {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value) && !/^0x0{40}$/.test(value)
}

export function txExplorerUrl(txHash: unknown): string | null {
  return isTxHash(txHash) ? `${AMOY_EXPLORER}/tx/${txHash}` : null
}

export function addressExplorerUrl(address: unknown): string | null {
  return isAddress(address) ? `${AMOY_EXPLORER}/address/${address}` : null
}

/** A report counts as anchored only with a confirmed, well-formed tx hash. */
export function isAnchored(r: { status?: string; transactionHash?: string | null; blockNumber?: number | null }): boolean {
  return r.status === 'PUBLISHED' && isTxHash(r.transactionHash) && typeof r.blockNumber === 'number'
}

export function shortHash(h: string, head = 10, tail = 8): string {
  return h.length > head + tail + 1 ? `${h.slice(0, head)}…${h.slice(-tail)}` : h
}
