'use client'

import { useState, useMemo } from 'react'
import Layout from '@/components/Layout'
import {
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  Clock,
  RefreshCw,
  Search,
  Fingerprint,
  Layers,
  Terminal,
  Activity,
  X,
  FileCode,
  Check,
} from 'lucide-react'
import { useApp } from '@/lib/context'
import { supersededBy } from '@/lib/demoData'
import type { CTIReport, CTIVerificationResult, MitreMapping, EvidenceItem } from '@/lib/types'
import AnchorDetails from '@/components/AnchorDetails'
import { isAnchored as isAnchoredReport, shortHash, txExplorerUrl } from '@/lib/blockchain'
import {
  P,
  BG,
  TEXT,
  MUTED,
  BORDER,
  RED,
  AMBER,
  GREEN,
  CTIStatusBadge,
  VerificationBadge,
  SeverityBadge,
} from '@/components/ui'


export default function CTIFeedPage() {
  const { globalFeed, feedLoading, feedError, refetchFeed, verifyCTI, showToast } = useApp()
  const source = globalFeed || []
  const sourceLoading = feedLoading
  const sourceError = feedError
  const [selectedReport, setSelectedReport] = useState<CTIReport | null>(null)
  const [activeTypeFilter, setActiveTypeFilter] = useState('ALL')
  const [searchQuery, setSearchQuery] = useState('')
  const [verifyingId, setVerifyingId] = useState<string | null>(null)
  const [verification, setVerification] = useState<CTIVerificationResult | null>(null)

  const replacedBy = useMemo(() => supersededBy(source), [source])

  const filteredReports = useMemo(() => {
    return source.filter((report) => {
      const matchesType =
        activeTypeFilter === 'ALL' ||
        (report.attackType || 'RANSOMWARE').toUpperCase() === activeTypeFilter.toUpperCase()

      const query = searchQuery.trim().toLowerCase()
      if (!query) return matchesType

      const text = [
        report.reportId || report._id,
        report.title || '',
        report.attackType || '',
        report.attackSummary || '',
        ...(report.indicatorsOfCompromise || []),
        ...(report.mitre?.map((m) => `${m.techniqueId} ${m.techniqueName}`) || []),
      ]
        .join(' ')
        .toLowerCase()

      return matchesType && text.includes(query)
    })
  }, [source, activeTypeFilter, searchQuery])

  const handleVerify = async (report: CTIReport, e?: React.MouseEvent) => {
    if (e) e.stopPropagation()
    const targetId = report.reportId || report._id
    setVerifyingId(targetId)
    try {
      const res = await verifyCTI(targetId)
      setVerification(res)
      if (res.status !== 'UNAVAILABLE' && selectedReport && (selectedReport._id === report._id || selectedReport.reportId === report.reportId)) {
        setSelectedReport((prev) => (prev ? { ...prev, verificationStatus: res.status } : null))
      }
    } catch {
      // toast is handled in AppProvider
    } finally {
      setVerifyingId(null)
    }
  }

  const attackTypeColor = (type?: string) => {
    switch ((type || '').toUpperCase()) {
      case 'PRIVILEGE_ESCALATION':
        return { text: '#854D0E', bg: 'rgba(234,179,8,0.12)', border: '#FDE047', label: 'Privilege Escalation' }
      case 'DEFENSE_EVASION':
        return { text: '#4338CA', bg: 'rgba(99,102,241,0.12)', border: '#C7D2FE', label: 'Defense Evasion' }
      case 'CREDENTIAL_ACCESS':
        return { text: '#9333EA', bg: 'rgba(168,85,247,0.12)', border: '#E9D5FF', label: 'Credential Access' }
      default:
        return { text: RED, bg: 'rgba(220,38,38,0.08)', border: '#FECACA', label: 'Ransomware' }
    }
  }

  return (
    <Layout>
      <div className="p-6 max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-2xl font-bold tracking-tight" style={{ color: TEXT }}>
                CTI Blockchain Feed
              </h1>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-mono font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                Polygon Amoy Testnet
              </span>
            </div>
            <p className="text-sm mt-1" style={{ color: MUTED }}>
              Published threat intelligence from your organization and reports other organizations have shared with you. Each report's integrity hash is anchored on-chain, so you can independently verify the report you received has not been altered.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => refetchFeed()}
              disabled={sourceLoading}
              className="flex items-center gap-1.5 px-3.5 h-9 rounded-lg text-xs font-semibold border transition-all cursor-pointer hover:bg-slate-50"
              style={{ borderColor: BORDER, color: TEXT }}
              title="Refresh CTI Feed from Database"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${sourceLoading ? 'animate-spin' : ''}`} />
              Refresh Feed
            </button>
          </div>
        </div>

        {/* Filter & Search Bar */}
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 bg-white p-3.5 rounded-xl border" style={{ borderColor: BORDER }}>
          {/* Attack Type Badges */}
          <div className="flex flex-wrap items-center gap-1.5">
            {[
              { id: 'ALL', label: 'All Threats' },
              { id: 'PRIVILEGE_ESCALATION', label: 'Privilege Escalation' },
              { id: 'RANSOMWARE', label: 'Ransomware' },
              { id: 'DEFENSE_EVASION', label: 'Defense Evasion' },
              { id: 'CREDENTIAL_ACCESS', label: 'Credential Access' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTypeFilter(tab.id)}
                className="px-3 h-8 rounded-lg text-xs font-medium border transition-colors cursor-pointer"
                style={{
                  borderColor: activeTypeFilter === tab.id ? P : BORDER,
                  backgroundColor: activeTypeFilter === tab.id ? 'rgba(23,49,62,0.08)' : 'white',
                  color: activeTypeFilter === tab.id ? P : MUTED,
                  fontWeight: activeTypeFilter === tab.id ? 600 : 500,
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Search box */}
          <div className="relative min-w-[240px]">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by ID, MITRE, indicator..."
              className="w-full h-8 pl-9 pr-3 rounded-lg text-xs border focus:outline-none focus:ring-1 focus:ring-slate-400"
              style={{ borderColor: BORDER }}
            />
          </div>
        </div>

        {sourceError && (
          <div role="alert" className="flex items-center justify-between gap-3 px-4 py-3 rounded-xl border border-red-200 bg-red-50 text-xs text-red-800">
            <span>Could not load the CTI feed: {sourceError}</span>
            <button onClick={() => refetchFeed()}
              className="px-3 h-8 rounded-lg border border-red-300 bg-white font-medium cursor-pointer">Retry</button>
          </div>
        )}

        {/* Feed List */}
        {sourceLoading && filteredReports.length === 0 ? (
          <div className="bg-white border rounded-xl p-12 text-center text-xs text-slate-500" style={{ borderColor: BORDER }}>
            Loading the CTI feed…
          </div>
        ) : filteredReports.length === 0 ? (
          <div className="bg-white border rounded-xl p-12 text-center" style={{ borderColor: BORDER }}>
            <Fingerprint className="w-10 h-10 mx-auto text-slate-300 mb-3" />
            <h3 className="text-sm font-semibold text-slate-800">
              No published reports yet
            </h3>
            <p className="text-xs text-slate-500 max-w-md mx-auto mt-1">
              {searchQuery || activeTypeFilter !== 'ALL'
                ? 'No published reports match the current filters.'
                : 'Reports appear here once your organization publishes a CTI report, or another organization shares one with yours.'}
            </p>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {filteredReports.map((report) => {
              const typeCfg = attackTypeColor(report.attackType)
              const reportId = report.reportId || report._id
              const isVerifying = verifyingId === reportId
              const isAnchored = isAnchoredReport(report)

              return (
                <div
                  key={report._id}
                  onClick={() => setSelectedReport(report)}
                  className="bg-white border rounded-xl p-5 cursor-pointer transition-all hover:shadow-md hover:border-slate-300 flex flex-col md:flex-row md:items-center justify-between gap-4"
                  style={{ borderColor: BORDER }}
                >
                  <div className="flex items-start gap-4 flex-1 min-w-0">
                    {/* Attack Type Icon */}
                    <div
                      className="w-10 h-10 rounded-xl flex-shrink-0 flex items-center justify-center mt-0.5"
                      style={{ backgroundColor: typeCfg.bg }}
                    >
                      <AlertTriangle className="w-5 h-5" style={{ color: typeCfg.text }} />
                    </div>

                    {/* Report Information */}
                    <div className="flex-1 min-w-0 space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className="px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider border"
                          style={{
                            backgroundColor: typeCfg.bg,
                            color: typeCfg.text,
                            borderColor: typeCfg.border,
                          }}
                        >
                          {typeCfg.label}
                        </span>

                        <span className="text-xs font-mono font-medium text-slate-400">
                          {report.reportId || report._id}
                        </span>

                        {report.severity && <SeverityBadge severity={report.severity} />}

                        {report.riskScore !== undefined && (
                          <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
                            Risk {report.riskScore}/100
                          </span>
                        )}

                        <span className="text-xs text-slate-400 flex items-center gap-1 ml-auto md:ml-0">
                          <Clock className="w-3 h-3" />
                          {report.detectedAt || report.createdAt
                            ? new Date(report.detectedAt || report.createdAt).toLocaleString()
                            : 'Recent'}
                        </span>
                      </div>

                      <h3 className="text-sm font-semibold text-slate-900 truncate">
                        {report.title || `Threat Detection Report (${reportId})`}
                      </h3>
                      {report.reportId && replacedBy.has(report.reportId) && (
                        <p className="text-[11px] font-semibold text-amber-700">
                          Superseded by revision {replacedBy.get(report.reportId)}. The original stays on-chain unchanged.
                        </p>
                      )}

                      <p className="text-xs text-slate-600 line-clamp-2">
                        {report.attackSummary}
                      </p>

                      {/* MITRE ATT&CK Badges */}
                      {report.mitre && report.mitre.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5 pt-1">
                          <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                            MITRE ATT&CK:
                          </span>
                          {report.mitre.map((m: MitreMapping, idx: number) => (
                            <a
                              key={idx}
                              href={m.referenceUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              className="inline-flex items-center gap-1 text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200 transition-colors"
                              title={`${m.techniqueName} (${m.tacticName})`}
                            >
                              <span>{m.techniqueId}</span>
                              <ExternalLink className="w-2.5 h-2.5 text-blue-500" />
                            </a>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Blockchain & Verification Actions */}
                  <div className="flex md:flex-col items-center md:items-end justify-between gap-2.5 flex-shrink-0 pt-2 md:pt-0 border-t md:border-t-0 border-slate-100">
                    <div className="flex items-center gap-2">
                      <CTIStatusBadge status={report.status} />
                      <VerificationBadge status={report.verificationStatus} />
                    </div>

                    {txExplorerUrl(report.transactionHash) && isAnchoredReport(report) && (
                      <a
                        href={txExplorerUrl(report.transactionHash)!}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="inline-flex items-center gap-1 text-[11px] font-mono text-purple-700 hover:text-purple-900 hover:underline"
                        title="View Polygon Transaction on Amoy Explorer"
                      >
                        <span>tx: {shortHash(report.transactionHash!)}</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    )}

                    <div className="flex items-center gap-2">
                      <button
                        onClick={(e) => handleVerify(report, e)}
                        disabled={isVerifying || !isAnchored}
                        className="inline-flex items-center gap-1 px-3 py-1 rounded-lg text-xs font-semibold border transition-all cursor-pointer hover:bg-slate-50 disabled:opacity-50"
                        style={{ borderColor: BORDER, color: P }}
                      >
                        <RefreshCw className={`w-3 h-3 ${isVerifying ? 'animate-spin' : ''}`} />
                        {isVerifying ? 'Verifying...' : 'Verify Hash'}
                      </button>

                      <button
                        onClick={() => setSelectedReport(report)}
                        className="px-3 py-1 rounded-lg text-xs font-semibold text-white transition-opacity hover:opacity-90 cursor-pointer"
                        style={{ backgroundColor: P }}
                      >
                        Inspect
                      </button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {/* Detailed Report Inspection Drawer / Modal */}
        {selectedReport && (
          <div className="fixed inset-0 z-50 flex justify-end">
            <div className="absolute inset-0 bg-black/30 backdrop-blur-xs" onClick={() => setSelectedReport(null)} />
            <div className="relative w-full max-w-2xl bg-white h-full shadow-2xl flex flex-col overflow-y-auto z-10">
              {/* Header */}
              <div className="flex items-start justify-between px-6 py-5 border-b sticky top-0 bg-white z-10" style={{ borderColor: BORDER }}>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className="px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider"
                      style={{
                        backgroundColor: attackTypeColor(selectedReport.attackType).bg,
                        color: attackTypeColor(selectedReport.attackType).text,
                      }}
                    >
                      {attackTypeColor(selectedReport.attackType).label}
                    </span>
                    <CTIStatusBadge status={selectedReport.status} />
                    <VerificationBadge status={selectedReport.verificationStatus} />
                  </div>
                  <h2 className="text-lg font-bold text-slate-900">
                    {selectedReport.title || 'Structured CTI Incident Report'}
                  </h2>
                  {selectedReport.reportId && replacedBy.has(selectedReport.reportId) && (
                    <p className="text-xs font-semibold text-amber-700 mt-0.5">
                      Superseded by revision {replacedBy.get(selectedReport.reportId)}. The original stays on-chain unchanged.
                    </p>
                  )}
                  {selectedReport.supersedes && (
                    <p className="text-xs text-slate-500 mt-0.5">Revision of {selectedReport.supersedes}</p>
                  )}
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Report ID: {selectedReport.reportId || selectedReport._id} · Schema: {selectedReport.schemaVersion || 'v1.0'} · Version: {selectedReport.version || 1}
                  </p>
                </div>

                <button
                  onClick={() => setSelectedReport(null)}
                  className="p-1.5 rounded-lg hover:bg-slate-100 text-slate-400 hover:text-slate-700 transition-colors cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Drawer Body */}
              <div className="p-6 space-y-6">
                {/* On-Chain Anchoring & Integrity Section */}
                <div className="bg-slate-50 border rounded-xl p-4 space-y-3" style={{ borderColor: BORDER }}>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                      <Fingerprint className="w-4 h-4 text-slate-700" />
                      Cryptographic Anchoring (Polygon Amoy)
                    </span>
                    <button
                      onClick={() => handleVerify(selectedReport)}
                      disabled={verifyingId === (selectedReport.reportId || selectedReport._id)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-semibold bg-white border border-slate-300 text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
                    >
                      <RefreshCw className={`w-3 h-3 ${verifyingId === (selectedReport.reportId || selectedReport._id) ? 'animate-spin' : ''}`} />
                      Re-verify Hash
                    </button>
                  </div>

                  <AnchorDetails
                    report={selectedReport}
                    verification={verification && verification.reportId === (selectedReport.reportId || selectedReport._id) ? verification : null}
                  />
                </div>

                {/* Attack Summary */}
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                    Executive Threat Summary
                  </h4>
                  <p className="text-sm text-slate-800 leading-relaxed bg-white p-3.5 rounded-xl border border-slate-200">
                    {selectedReport.attackSummary}
                  </p>
                </div>

                {/* MITRE ATT&CK Matrix Mapping */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                      MITRE ATT&CK Enterprise Mapping
                    </h4>
                    <span className="text-[11px] font-mono text-slate-400">
                      Version: {selectedReport.mitre?.[0]?.attackVersion || 'v14.1'}
                    </span>
                  </div>

                  {selectedReport.mitre && selectedReport.mitre.length > 0 ? (
                    <div className="grid grid-cols-1 gap-2.5">
                      {selectedReport.mitre.map((m: MitreMapping, idx: number) => (
                        <div
                          key={idx}
                          className="bg-slate-50 border border-slate-200 rounded-lg p-3 flex items-start justify-between gap-3"
                        >
                          <div className="space-y-0.5">
                            <div className="flex items-center gap-2">
                              <span className="font-mono font-bold text-xs text-blue-800 bg-blue-100 px-2 py-0.5 rounded">
                                {m.techniqueId}
                              </span>
                              <span className="text-xs font-semibold text-slate-800">
                                {m.techniqueName}
                              </span>
                            </div>
                            <p className="text-xs text-slate-500">
                              Tactic: <strong className="text-slate-700">{m.tacticName}</strong> ({m.tacticId})
                            </p>
                            {m.evidenceRef && m.evidenceRef.length > 0 && (
                              <p className="text-[11px] text-slate-400 font-mono">
                                Associated Evidence: {m.evidenceRef.join(', ')}
                              </p>
                            )}
                          </div>

                          <a
                            href={m.referenceUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-800 hover:underline flex-shrink-0"
                          >
                            <span>Official ATT&CK</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-slate-400 italic">No MITRE mappings recorded.</p>
                  )}
                </div>

                {/* Forensic Telemetry & Evidence */}
                {selectedReport.evidence && selectedReport.evidence.length > 0 && (
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                      Forensic Telemetry & Supporting Evidence
                    </h4>
                    <div className="space-y-2">
                      {selectedReport.evidence.map((ev: EvidenceItem, idx: number) => (
                        <div key={idx} className="bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="font-mono font-bold text-slate-700">
                              [{ev.id}] {ev.source.toUpperCase()} {ev.eventId ? `(Event ID ${ev.eventId})` : ''}
                            </span>
                            <span className="text-slate-400 font-mono text-[11px]">
                              {ev.time ? new Date(ev.time).toLocaleTimeString() : ''}
                            </span>
                          </div>
                          <p className="text-slate-700">{ev.description}</p>
                          {ev.fields && Object.keys(ev.fields).length > 0 && (
                            <div className="bg-white p-2 rounded border border-slate-200 font-mono text-[11px] space-y-0.5">
                              {Object.entries(ev.fields).map(([k, v]) => (
                                <div key={k} className="truncate">
                                  <span className="text-slate-400">{k}:</span>{' '}
                                  <span className="text-slate-800">{String(v)}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Indicators of Compromise */}
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                    Indicators of Compromise
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedReport.indicatorsOfCompromise?.map((ioc, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 rounded text-xs font-mono bg-slate-50 border border-slate-200 text-slate-800"
                      >
                        {ioc}
                      </span>
                    ))}
                    {(!selectedReport.indicatorsOfCompromise || selectedReport.indicatorsOfCompromise.length === 0) && (
                      <p className="text-xs text-slate-400 italic">No indicators recorded.</p>
                    )}
                  </div>
                </div>

                {/* Recommended Remediation Actions */}
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                    Recommended Actions
                  </h4>
                  <div className="space-y-2">
                    {selectedReport.recommendedActions?.map((act, idx) => (
                      <div key={idx} className="flex items-start gap-2.5 text-xs text-slate-800">
                        <Check className="w-4 h-4 text-emerald-600 flex-shrink-0 mt-0.5" />
                        <span>{act}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Detector & Model Metadata */}
                {selectedReport.detector && (
                  <div className="border-t pt-4 text-xs text-slate-400 flex items-center justify-between font-mono">
                    <span>
                      Detector: {selectedReport.detector.type.toUpperCase()} ({selectedReport.detector.id})
                    </span>
                    <span>Version: {selectedReport.detector.version}</span>
                  </div>
                )}
              </div>

              {/* Drawer Footer */}
              <div className="sticky bottom-0 px-6 py-4 border-t bg-white flex items-center justify-between" style={{ borderColor: BORDER }}>
                <button
                  onClick={() => setSelectedReport(null)}
                  className="px-4 h-9 rounded-lg text-xs font-semibold border border-slate-300 text-slate-700 hover:bg-slate-50 transition-colors cursor-pointer"
                >
                  Close
                </button>

                {isAnchoredReport(selectedReport) && txExplorerUrl(selectedReport.transactionHash) && (
                  <a
                    href={txExplorerUrl(selectedReport.transactionHash)!}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 px-4 h-9 rounded-lg text-xs font-semibold text-white transition-opacity hover:opacity-90 cursor-pointer"
                    style={{ backgroundColor: P }}
                  >
                    <span>View on Polygon Amoy Explorer</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  )
}
