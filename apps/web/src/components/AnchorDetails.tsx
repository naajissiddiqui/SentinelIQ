'use client'

import { ExternalLink, AlertTriangle } from 'lucide-react'
import { MUTED, TEXT } from '@/components/ui'
import type { CTIReport, CTIVerificationResult } from '@/lib/types'
import { addressExplorerUrl, isAnchored, txExplorerUrl } from '@/lib/blockchain'

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="py-1.5 border-b border-slate-100 last:border-0">
      <span className="block text-[11px] mb-0.5" style={{ color: MUTED }}>{label}</span>
      <div className="text-xs" style={{ color: TEXT }}>{children}</div>
    </div>
  )
}

function Mono({ children }: { children: React.ReactNode }) {
  return <code className="font-mono text-[11px] break-all select-all">{children}</code>
}

function NotAvailable({ children }: { children: React.ReactNode }) {
  return <span className="italic text-slate-400">{children}</span>
}

/**
 * Keeps the four identifiers visibly distinct:
 *   Report ID / SHA-256 content hash / transaction hash / contract address.
 * Only a well-formed transaction hash on a PUBLISHED report is linked to the
 * explorer; nothing is ever derived from the report ID or content hash.
 */
export default function AnchorDetails({
  report,
  verification,
}: {
  report: CTIReport
  verification?: CTIVerificationResult | null
}) {
  const anchored = isAnchored(report)
  const txUrl = anchored ? txExplorerUrl(report.transactionHash) : null
  const contractUrl = addressExplorerUrl(report.contractAddress)
  const pendingTx = report.status === 'PUBLISHING' ? txExplorerUrl(report.transactionHash) : null

  return (
    <div className="space-y-0.5">
      <Row label="Report ID">
        <Mono>{report.reportId || report._id}</Mono>
      </Row>

      <Row label="SHA-256 content hash (RFC 8785 canonical JSON)">
        {report.contentHash ? <Mono>{report.contentHash}</Mono> : <NotAvailable>Computed when the report is published</NotAvailable>}
      </Row>

      <Row label="Blockchain transaction hash">
        {txUrl ? (
          <div className="flex flex-wrap items-center gap-2">
            <Mono>{report.transactionHash}</Mono>
            <a
              href={txUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-[11px] font-semibold text-purple-700 hover:underline"
            >
              <ExternalLink className="w-3 h-3" /> View on PolygonScan
            </a>
          </div>
        ) : pendingTx ? (
          <div className="flex flex-wrap items-center gap-2">
            <Mono>{report.transactionHash}</Mono>
            <span className="text-[11px] font-semibold text-amber-700">awaiting confirmation</span>
            <a href={pendingTx} target="_blank" rel="noopener noreferrer" className="text-[11px] text-purple-700 hover:underline">
              track
            </a>
          </div>
        ) : (
          <NotAvailable>Not anchored on-chain</NotAvailable>
        )}
      </Row>

      <Row label="Contract address">
        {contractUrl ? (
          <a href={contractUrl} target="_blank" rel="noopener noreferrer" className="font-mono text-[11px] break-all text-purple-700 hover:underline">
            {report.contractAddress}
          </a>
        ) : (
          <NotAvailable>—</NotAvailable>
        )}
      </Row>

      <Row label="Network">
        {report.network ? `${report.network}${report.chainId ? ` (chain ${report.chainId})` : ''}` : <NotAvailable>—</NotAvailable>}
      </Row>

      <Row label="Block number">
        {anchored ? <Mono>#{report.blockNumber!.toLocaleString()}</Mono> : <NotAvailable>—</NotAvailable>}
      </Row>

      {anchored && report.publisherAddress && (
        <Row label="Publisher (contract owner)">
          <Mono>{report.publisherAddress}</Mono>
        </Row>
      )}

      {verification && (
        <Row label="On-chain hash (from CTIRegistry.getCTI)">
          {verification.onChainHash ? <Mono>{verification.onChainHash}</Mono> : <NotAvailable>No on-chain record</NotAvailable>}
        </Row>
      )}

      {(verification?.error || report.anchorError) && (
        <div className="mt-2 p-2 rounded bg-amber-50 border border-amber-200 text-[11px] text-amber-800 flex gap-1.5">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
          <span>{verification?.error || report.anchorError}</span>
        </div>
      )}
    </div>
  )
}
