'use client'

import { useState } from 'react'
import Layout from '@/components/Layout'
import { Check, ChevronRight, Lock, Loader2, ExternalLink, CheckCircle2, AlertCircle, Fingerprint } from 'lucide-react'
import {
  P, STORM, BG, TEXT, MUTED, BORDER, RED, GREEN, CTIStatusBadge, VerificationBadge
} from '@/components/ui'
import { useApp } from '@/lib/context'
import { ReportSharingControl } from '@/components/ReportSharingControl'
import type { CTIReport } from '@/lib/types'
import AnchorDetails from '@/components/AnchorDetails'
import { isAnchored } from '@/lib/blockchain'


function dataSourceLabel(origin?: string): string {
  switch (origin) {
    case 'LIVE': return 'Live endpoint telemetry'
    case 'PCAP_REPLAY': return 'Recorded network traffic'
    case 'SIMULATED': return 'Simulated telemetry'
    case 'DEMO': return 'Demonstration data'
    default: return 'Not recorded'
  }
}

function CTICenterContent() {
  const { ctiReports, publishCTI, navigate, showToast } = useApp()
  const [step, setStep] = useState<1 | 2 | 3>(1)
  const [publishing, setPublishing] = useState(false)
  const [publishError, setPublishError] = useState<string | null>(null)
  const [selectedReportId, setSelectedReportId] = useState<string>('')
  const [publishedResult, setPublishedResult] = useState<CTIReport | null>(null)

  // Find currently available draft reports or pick first draft / report
  const draftReports = ctiReports.filter(r => r.status === 'DRAFT' || r.status === 'PENDING_APPROVAL' || r.status === 'FAILED' || r.status === 'PUBLISHING')
  const activeReport = ctiReports.find(r => (r.reportId || r._id) === selectedReportId) || draftReports[0] || ctiReports[0] || null

  const stepLabels = ['Review Draft', 'Publish', 'Verify']

  const doPublish = async () => {
    if (!activeReport) return
    setPublishing(true)
    setPublishError(null)
    const targetId = activeReport.reportId || activeReport._id
    try {
      const res = await publishCTI(targetId)
      setPublishedResult(res)
      setStep(3)
    } catch (err: any) {
      setPublishError(err?.message || 'Failed to publish to Polygon blockchain')
    } finally {
      setPublishing(false)
    }
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: TEXT }}>CTI Center</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Cryptographic Threat Intelligence Publishing Workflow & Integrity Verification
          </p>
        </div>

        {/* Report Selector if multiple exist */}
        {ctiReports.length > 1 && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 font-medium">Select Incident:</span>
            <select
              value={activeReport ? (activeReport.reportId || activeReport._id) : ''}
              onChange={(e) => {
                setSelectedReportId(e.target.value)
                setStep(1)
                setPublishError(null)
              }}
              className="border border-slate-300 rounded-lg text-xs px-3 py-1.5 bg-white font-mono"
            >
              {ctiReports.map(r => (
                <option key={r._id} value={r.reportId || r._id}>
                  {r.reportId || r._id} [{r.status}] {(r.attackType || 'RANSOMWARE').replace(/_/g, ' ')}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Step indicator */}
      <div className="flex items-start justify-center gap-0 mb-8">
        {stepLabels.map((label, i) => {
          const n = (i + 1) as 1 | 2 | 3
          const done = n < step
          const active = n === step
          return (
            <div key={n} className="flex items-start">
              <div className="flex flex-col items-center gap-2 w-28">
                <div
                  className="w-8 h-8 rounded-full flex items-center justify-center text-[13px] font-bold border-2 transition-all"
                  style={{
                    backgroundColor: done ? GREEN : active ? P : 'white',
                    borderColor: done ? GREEN : active ? P : BORDER,
                    color: done || active ? 'white' : MUTED,
                  }}
                >
                  {done ? <Check className="w-4 h-4" /> : n}
                </div>
                <span className="text-[12px] font-medium text-center" style={{ color: active ? TEXT : MUTED }}>{label}</span>
              </div>
              {i < 2 && (
                <div className="w-24 h-px mt-4" style={{ backgroundColor: done ? GREEN : BORDER }} />
              )}
            </div>
          )
        })}
      </div>

      {!activeReport ? (
        <div className="text-center py-12 border rounded-xl bg-white" style={{ borderColor: BORDER }}>
          <p className="text-sm text-slate-500 mb-3">No threat-intelligence reports have been generated for your organization yet.</p>
          <button
            onClick={() => navigate('detections')}
            className="px-4 py-2 rounded-lg text-xs font-semibold text-white cursor-pointer"
            style={{ backgroundColor: P }}
          >
            Go to Detections to Generate Report
          </button>
        </div>
      ) : (
        <>
          {/* Stage 1 */}
          {step === 1 && (
            <>
              <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
                <div className="lg:col-span-3 flex flex-col gap-4">
                  <div className="border rounded-[10px] overflow-hidden bg-white" style={{ borderColor: BORDER }}>
                    <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: BORDER, backgroundColor: BG }}>
                      <p className="text-[11px] font-bold uppercase tracking-wide" style={{ color: MUTED }}>Attack Summary</p>
                      <div className="flex items-center gap-1.5">
                        <CTIStatusBadge status={activeReport.status} />
                        <span className="text-xs font-mono text-slate-400">ID: {activeReport.reportId || activeReport._id}</span>
                      </div>
                    </div>
                    <p className="p-4 text-[13px] leading-relaxed" style={{ color: TEXT }}>
                      {activeReport.attackSummary}
                    </p>
                  </div>

                  <div className="border rounded-[10px] overflow-hidden bg-white" style={{ borderColor: BORDER }}>
                    <div className="px-4 py-3 border-b" style={{ borderColor: BORDER, backgroundColor: BG }}>
                      <p className="text-[11px] font-bold uppercase tracking-wide" style={{ color: MUTED }}>Indicators of Compromise</p>
                    </div>
                    <div className="p-4 flex flex-wrap gap-2">
                      {(activeReport.indicatorsOfCompromise || []).map(ioc => (
                        <span key={ioc} className="px-2.5 py-1 rounded border text-[11px]"
                          style={{ borderColor: BORDER, backgroundColor: BG, color: TEXT, fontFamily: 'var(--font-mono, monospace)' }}>
                          {ioc}
                        </span>
                      ))}
                      {(!activeReport.indicatorsOfCompromise || activeReport.indicatorsOfCompromise.length === 0) && (
                        <span className="text-xs text-slate-400 italic">No indicators added</span>
                      )}
                    </div>
                  </div>

                  <div className="border rounded-[10px] overflow-hidden bg-white" style={{ borderColor: BORDER }}>
                    <div className="px-4 py-3 border-b" style={{ borderColor: BORDER, backgroundColor: BG }}>
                      <p className="text-[11px] font-bold uppercase tracking-wide" style={{ color: MUTED }}>Recommended Actions</p>
                    </div>
                    <ul className="p-4 flex flex-col gap-2.5">
                      {(activeReport.recommendedActions || []).map((a, i) => (
                        <li key={i} className="flex items-start gap-2.5 text-[13px]" style={{ color: TEXT }}>
                          <span className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0" style={{ backgroundColor: P }} />
                          {a}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Sidebar */}
                <div className="lg:col-span-2">
                  <div className="sticky top-4 border rounded-[10px] overflow-hidden bg-white" style={{ borderColor: BORDER }}>
                    <div className="px-4 py-3 border-b" style={{ borderColor: BORDER, backgroundColor: BG }}>
                      <p className="text-[11px] font-bold uppercase tracking-wide" style={{ color: MUTED }}>Report Telemetry</p>
                    </div>
                    <div className="p-4 flex flex-col gap-2.5 border-b" style={{ borderColor: BORDER }}>
                      {[
                        ['Threat Type', (activeReport.attackType || 'Not stated').replace(/_/g, ' ')],
                        ['Severity', activeReport.severity || 'Not stated'],
                        ['Risk Score', `${activeReport.riskScore ?? 0} / 100 (severity, not a probability)`],
                        ['Data source', dataSourceLabel(activeReport.dataOrigin)],
                        ['Status', activeReport.status],
                      ].map(([k, v]) => (
                        <div key={k} className="flex justify-between">
                          <span className="text-[12px]" style={{ color: MUTED }}>{k}</span>
                          <span className="text-[12px] font-semibold" style={{ color: TEXT }}>{v}</span>
                        </div>
                      ))}
                    </div>
                    <div className="px-4 py-3 border-b" style={{ borderColor: BORDER, backgroundColor: BG }}>
                      <p className="text-[11px] font-bold uppercase tracking-wide" style={{ color: MUTED }}>Analyst Notes</p>
                    </div>
                    <div className="p-4">
                      <p className="text-[12px] text-slate-700 italic">
                        {activeReport.analystNotes || 'No analyst notes attached.'}
                      </p>
                    </div>
                  </div>

                  <ReportSharingControl report={activeReport} />
                </div>
              </div>

              <div className="flex justify-between items-center mt-6 pt-5 border-t" style={{ borderColor: BORDER }}>
                <button
                  onClick={() => navigate('cti-feed')}
                  className="text-[13px] hover:opacity-70 transition-opacity cursor-pointer font-medium text-slate-500"
                >
                  View Global Feed
                </button>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => navigate('cti-draft-editor', { id: activeReport.reportId || activeReport._id })}
                    className="h-10 px-4 rounded-[10px] text-[13px] font-semibold border hover:bg-slate-50 transition-colors cursor-pointer"
                    style={{ borderColor: BORDER, color: TEXT }}
                  >
                    Edit Draft in Full Editor
                  </button>
                  <button
                    onClick={() => setStep(2)}
                    disabled={activeReport.status === 'PUBLISHED' || activeReport.status === 'ANCHORED'}
                    className="h-10 px-6 rounded-[10px] text-[13px] font-semibold text-white flex items-center gap-2 cursor-pointer disabled:opacity-50"
                    style={{ backgroundColor: P }}
                  >
                    {activeReport.status === 'PUBLISHED' ? 'Already Anchored' : activeReport.status === 'PUBLISHING' ? 'Re-check Pending Transaction' : 'Publish to Blockchain'}
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </>
          )}

          {/* Stage 2 */}
          {step === 2 && (
            <div className="flex justify-center">
              <div className="w-full max-w-[560px] bg-white border rounded-2xl p-7 shadow-sm" style={{ borderColor: BORDER }}>
                <h2 className="text-[18px] font-bold mb-1" style={{ color: TEXT }}>{"You're about to publish this CTI report."}</h2>
                <p className="text-[13px] mb-5" style={{ color: MUTED }}>
                  This action anchors the canonical RFC 8785 SHA-256 report hash on Polygon Amoy testnet.
                </p>

                {publishError && (
                  <div className="p-3 mb-4 rounded-lg bg-red-50 border border-red-200 flex items-start gap-2 text-xs text-red-700">
                    <AlertCircle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="font-semibold">Publication Error</p>
                      <p className="mt-0.5">{publishError}</p>
                    </div>
                  </div>
                )}

                <div className="p-4 rounded-[10px] border mb-5" style={{ borderColor: BORDER, backgroundColor: BG }}>
                  <p className="text-[11px] font-bold uppercase tracking-wide mb-3" style={{ color: MUTED }}>What will be published on-chain</p>
                  {[
                    ['Report ID', activeReport.reportId || activeReport._id],
                    ['Attack type', activeReport.attackType || 'RANSOMWARE'],
                    ['Content Hash (SHA-256)', activeReport.contentHash ? `${activeReport.contentHash.slice(0, 16)}…` : 'Computed on submit'],
                    ['Target Blockchain', 'Polygon Amoy (Chain 80002)'],
                    ['Endpoint Evidence', 'Excluded from on-chain payload'],
                  ].map(([k, v]) => (
                    <div key={k} className="flex justify-between py-1.5 text-xs">
                      <span style={{ color: MUTED }}>{k}</span>
                      <span className="font-semibold font-mono" style={{ color: TEXT }}>{v}</span>
                    </div>
                  ))}
                  <div className="mt-3 flex items-center gap-1.5 text-[11px]" style={{ color: GREEN }}>
                    <Lock className="w-3 h-3" /> No sensitive raw endpoint files or PII stored on-chain
                  </div>
                </div>

                <div className="flex flex-col gap-1 mb-6">
                  <p className="text-[12px] font-semibold" style={{ color: MUTED }}>Visibility</p>
                  <p className="text-[12px]" style={{ color: TEXT }}>
                    Published reports are shared in the CTI Feed with every SentinelIQ organisation, and their content
                    hash is anchored on Polygon Amoy. Organisation-only publishing is not available.
                  </p>
                </div>

                {publishing ? (
                  <div className="flex flex-col items-center py-5 gap-3">
                    <Loader2 className="w-6 h-6 animate-spin" style={{ color: STORM }} />
                    <p className="text-[13px] font-medium" style={{ color: TEXT }}>Submitting transaction to Polygon Amoy…</p>
                    <p className="text-[11px] text-slate-400">Waiting for transaction confirmation (1 block)…</p>
                  </div>
                ) : (
                  <div className="flex gap-3">
                    <button
                      onClick={() => setStep(1)}
                      className="flex-1 h-10 rounded-[10px] text-[13px] font-medium border hover:bg-gray-50 transition-colors cursor-pointer"
                      style={{ borderColor: BORDER, color: TEXT }}
                    >
                      Cancel
                    </button>
                    <button
                      onClick={doPublish}
                      className="flex-1 h-10 rounded-[10px] text-[13px] font-semibold text-white cursor-pointer"
                      style={{ backgroundColor: P }}
                    >
                      Confirm & Publish
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Stage 3 */}
          {step === 3 && publishedResult && (
            <div className="flex flex-col items-center gap-5">
              {isAnchored(publishedResult) ? (
                <div
                  className="w-full max-w-[620px] px-5 py-3 rounded-xl flex items-center gap-2 text-[13px] font-medium"
                  style={{ backgroundColor: 'rgba(22,163,74,0.08)', color: GREEN }}
                >
                  <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                  Report hash anchored on Polygon Amoy in block #{publishedResult.blockNumber}. Receipt status: success.
                </div>
              ) : (
                <div className="w-full max-w-[620px] px-5 py-3 rounded-xl flex items-center gap-2 text-[13px] font-medium bg-amber-50 text-amber-800 border border-amber-200">
                  <Loader2 className="w-4 h-4 flex-shrink-0 animate-spin" />
                  Transaction submitted and awaiting confirmation. Click Publish again later to re-check its receipt.
                </div>
              )}

              <div className="w-full max-w-[620px] bg-white border rounded-2xl p-7 shadow-sm space-y-4" style={{ borderColor: BORDER }}>
                <div className="flex items-center justify-between pb-3 border-b border-slate-200">
                  <h2 className="text-[16px] font-bold" style={{ color: TEXT }}>Blockchain Anchor Details</h2>
                  <div className="flex items-center gap-2">
                    <CTIStatusBadge status={publishedResult.status} />
                    <VerificationBadge status={publishedResult.verificationStatus} />
                  </div>
                </div>

                <AnchorDetails report={publishedResult} />
                <div className="mt-5 flex items-center justify-between pt-3">
                  <button
                    className="text-[13px] hover:opacity-70 cursor-pointer font-medium text-slate-600"
                    onClick={() => { setStep(1); setPublishedResult(null); }}
                  >
                    Publish another report
                  </button>

                  <button
                    onClick={() => navigate('cti-feed')}
                    className="flex items-center gap-1.5 h-9 px-4 rounded-lg text-[13px] font-semibold text-white transition-colors cursor-pointer"
                    style={{ backgroundColor: P }}
                  >
                    Go to Live CTI Feed <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default function CTICenterPage() {
  return (
    <Layout>
      <CTICenterContent />
    </Layout>
  )
}
