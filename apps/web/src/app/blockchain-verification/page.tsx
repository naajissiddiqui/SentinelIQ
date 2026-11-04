'use client'

import { useState } from 'react'
import { Zap, CheckCircle2, XCircle, Search, Loader2, Fingerprint, AlertTriangle } from 'lucide-react'
import AnchorDetails from '@/components/AnchorDetails'
import { useApp } from '@/lib/context'
import { Button, Input, Card, CTIStatusBadge, VerificationBadge } from '@/components/ui'
import type { CTIReport, CTIVerificationResult } from '@/lib/types'


export default function BlockchainVerificationPage() {
  const { ctiReports, globalFeed, verifyCTI } = useApp()
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [verifyStatus, setVerifyStatus] = useState<CTIVerificationResult['status'] | 'NOT_FOUND' | null>(null)
  const [foundReport, setFoundReport] = useState<CTIReport | null>(null)
  const [verificationData, setVerificationData] = useState<CTIVerificationResult | null>(null)

  const allReports = [...ctiReports, ...globalFeed]
    .filter((r, i, list) => list.findIndex(o => o._id === r._id) === i)

  const handleVerify = async (value: string = query) => {
    if (!value.trim()) return
    setLoading(true)
    setVerifyStatus(null)
    setFoundReport(null)
    setVerificationData(null)

    const trimmed = value.trim().toLowerCase()
    const match = allReports.find(r =>
      (r.reportId && r.reportId.toLowerCase() === trimmed) ||
      (r._id && r._id.toLowerCase() === trimmed) ||
      (r.transactionHash && r.transactionHash.toLowerCase() === trimmed) ||
      (r.contentHash && r.contentHash.toLowerCase() === trimmed)
    )

    if (match) {
      setFoundReport(match)
      try {
        const targetId = match.reportId || match._id
        const res = await verifyCTI(targetId)
        setVerificationData(res)
        setVerifyStatus(res.status)
      } catch {
        // Never fall back to a stored status: without a live on-chain check
        // the result is simply unavailable.
        setVerifyStatus('UNAVAILABLE')
      }
    } else {
      setVerifyStatus('NOT_FOUND')
    }
    setLoading(false)
  }

  return (
    <div className="p-6 max-w-3xl space-y-6 mx-auto">
      {/* Intro */}
      <Card className="p-5">
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 bg-navy-900 rounded-xl flex items-center justify-center flex-shrink-0">
            <Zap size={18} className="text-white" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-navy-900 mb-1">Blockchain Verification Tool</h2>
            <p className="text-sm text-slate-600 leading-relaxed">
              Verify the authenticity and tamper-proof integrity of any CTI report anchored to the Polygon Amoy blockchain.
              Enter a Report ID, Canonical Content Hash, or Polygon Transaction Hash.
            </p>
          </div>
        </div>
      </Card>

      {/* Input */}
      <Card className="p-5">
        <div className="space-y-3">
          <Input
            label="Report ID, Content Hash, or Transaction Hash"
            placeholder="Report ID (cti-…) or transaction hash (0x…)"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleVerify()}
            icon={<Search size={15} />}
          />
          <Button onClick={() => handleVerify()} loading={loading} className="w-full">
            {loading ? 'Verifying on Polygon Amoy…' : 'Verify Report Integrity'}
          </Button>
          {loading && (
            <div className="flex items-center gap-2 text-xs text-slate-500 justify-center">
              <Loader2 size={12} className="animate-spin" />
              Recomputing canonical SHA-256 hash and querying smart contract on Polygon Amoy…
            </div>
          )}
        </div>
      </Card>

      {/* Quick access */}
      {allReports.length > 0 && (
        <div>
          <p className="text-xs font-medium text-slate-500 mb-2">Quick verify: click a report ID to check it on-chain now.</p>
          <div className="flex flex-wrap gap-2">
            {allReports.slice(0, 8).map(r => (
              <button
                key={r._id}
                onClick={() => {
                  const id = r.reportId || r._id
                  setQuery(id)
                  handleVerify(id)
                }}
                className="text-xs font-mono bg-slate-100 hover:bg-slate-200 text-slate-700 px-2 py-1 rounded-lg transition-colors cursor-pointer"
              >
                {r.reportId || r._id}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Result Cards */}
      {verifyStatus === 'VERIFIED' && foundReport && (
        <Card className="overflow-hidden border-emerald-300">
          <div className="h-1 bg-emerald-500" />
          <div className="p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-emerald-50 border border-emerald-200 rounded-xl flex items-center justify-center flex-shrink-0">
                  <CheckCircle2 size={20} className="text-emerald-600" />
                </div>
                <div>
                  <p className="text-sm font-bold text-emerald-700">Cryptographically Verified on Blockchain</p>
                  <p className="text-xs text-slate-500">
                    On-chain content hash matches recomputed RFC 8785 canonical hash perfectly
                  </p>
                </div>
              </div>
              <VerificationBadge status="VERIFIED" />
            </div>

            <div className="bg-slate-50 rounded-xl p-4">
              <AnchorDetails report={foundReport} verification={verificationData} />
            </div>

            <div>
              <p className="text-xs font-medium text-slate-500 mb-1">Threat Incident Summary</p>
              <p className="text-sm text-slate-700 leading-relaxed bg-white p-3 rounded-lg border border-slate-200">
                {foundReport.attackSummary}
              </p>
            </div>
          </div>
        </Card>
      )}

      {verifyStatus === 'TAMPERED' && foundReport && (
        <Card className="overflow-hidden border-red-300">
          <div className="h-1 bg-red-500" />
          <div className="p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-red-50 border border-red-200 rounded-xl flex items-center justify-center flex-shrink-0">
                  <XCircle size={20} className="text-red-600" />
                </div>
                <div>
                  <p className="text-sm font-bold text-red-700">Tamper Alert: Hash Mismatch Detected!</p>
                  <p className="text-xs text-slate-500">
                    The report contents have been modified since being published to the blockchain
                  </p>
                </div>
              </div>
              <VerificationBadge status="TAMPERED" />
            </div>

            <div className="bg-red-50/50 rounded-xl p-4 space-y-2 text-xs border border-red-100">
              <div>
                <span className="text-red-700 font-semibold block mb-0.5">Recomputed Content Hash:</span>
                <code className="font-mono text-[11px] break-all bg-white p-1.5 rounded border border-red-200 block text-red-900">
                  {verificationData?.recomputedHash}
                </code>
              </div>
              <div>
                <span className="text-red-700 font-semibold block mb-0.5">On-Chain Registered Hash:</span>
                <code className="font-mono text-[11px] break-all bg-white p-1.5 rounded border border-red-200 block text-red-900">
                  {verificationData?.onChainHash || 'None found'}
                </code>
              </div>
            </div>
          </div>
        </Card>
      )}

      {verifyStatus === 'UNANCHORED' && foundReport && (
        <Card className="overflow-hidden border-amber-300">
          <div className="h-1 bg-amber-500" />
          <div className="p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-amber-50 border border-amber-200 rounded-xl flex items-center justify-center flex-shrink-0">
                  <Fingerprint size={20} className="text-amber-600" />
                </div>
                <div>
                  <p className="text-sm font-bold text-amber-800">Report Not Anchored On-Chain</p>
                  <p className="text-xs text-slate-500">
                    {verificationData?.error || 'CTIRegistry has no record for this report. A locally computed hash is not proof of publication.'}
                  </p>
                </div>
              </div>
              <VerificationBadge status="UNANCHORED" />
            </div>

            <div className="bg-slate-50 rounded-xl p-3 text-xs space-y-1.5">
              <div className="flex justify-between">
                <span className="text-slate-500">Report ID:</span>
                <span className="font-mono font-bold text-slate-800">{foundReport.reportId || foundReport._id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Publication Status:</span>
                <CTIStatusBadge status={foundReport.status} />
              </div>
              <div>
                <span className="text-slate-500 block mb-0.5">Recomputed Canonical SHA-256 Hash:</span>
                <code className="font-mono text-[11px] break-all bg-white p-1.5 rounded border border-slate-200 block text-slate-800">
                  {foundReport.contentHash || verificationData?.recomputedHash || 'Not recorded for this report'}
                </code>
              </div>
            </div>
          </div>
        </Card>
      )}

      {(verifyStatus === 'UNAVAILABLE' || verifyStatus === 'UNTRUSTED_PUBLISHER') && foundReport && (
        <Card className="overflow-hidden border-amber-300">
          <div className="h-1 bg-amber-500" />
          <div className="p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-amber-50 border border-amber-200 rounded-xl flex items-center justify-center flex-shrink-0">
                  <AlertTriangle size={20} className="text-amber-600" />
                </div>
                <div>
                  <p className="text-sm font-bold text-amber-800">
                    {verifyStatus === 'UNAVAILABLE' ? 'Verification Unavailable' : 'Untrusted Publisher'}
                  </p>
                  <p className="text-xs text-slate-500">
                    {verifyStatus === 'UNAVAILABLE'
                      ? 'The on-chain record could not be queried, so integrity is NOT confirmed. Try again later.'
                      : 'The on-chain record was not written by the CTIRegistry owner.'}
                  </p>
                </div>
              </div>
              <VerificationBadge status={verifyStatus} />
            </div>
            <div className="bg-slate-50 rounded-xl p-4">
              <AnchorDetails report={foundReport} verification={verificationData} />
            </div>
          </div>
        </Card>
      )}

      {verifyStatus === 'NOT_FOUND' && (
        <Card className="overflow-hidden border-slate-200">
          <div className="h-1 bg-slate-300" />
          <div className="p-5 flex items-start gap-4">
            <div className="w-10 h-10 bg-slate-100 border border-slate-200 rounded-xl flex items-center justify-center flex-shrink-0">
              <XCircle size={20} className="text-slate-500" />
            </div>
            <div>
              <p className="text-sm font-bold text-slate-800">Report Not Found</p>
              <p className="text-sm text-slate-600 mt-1 leading-relaxed">
                No matching CTI report was found for the provided identifier. Please ensure you entered a valid Report ID, Content Hash, or Transaction Hash.
              </p>
            </div>
          </div>
        </Card>
      )}
    </div>
  )
}
