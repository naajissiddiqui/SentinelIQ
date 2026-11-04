'use client'

import { useState, useEffect, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import {
  ChevronLeft,
  Plus,
  Trash2,
  Loader2,
  Globe,
  ExternalLink,
  ShieldCheck,
  Database,
  CheckCircle2,
  Fingerprint,
  RefreshCw,
  Copy,
} from 'lucide-react'
import { useApp } from '@/lib/context'
import {
  Button,
  Textarea,
  ConfirmModal,
  CTIStatusBadge,
  VerificationBadge,
  Card,
  SeverityBadge,
} from '@/components/ui'
import { apiGet } from '@/lib/api'
import type { CTIReport, CTIVerificationResult, MitreMapping, EvidenceItem } from '@/lib/types'
import AnchorDetails from '@/components/AnchorDetails'


function CTIDraftEditorContent() {
  const { ctiReports, updateCTIDraft, publishCTI, verifyCTI, discardCTI, navigate, pageParams, showToast } = useApp()
  const router = useRouter()
  const searchParams = useSearchParams()
  const reportId = searchParams.get('id') || pageParams.id

  const fromContext = ctiReports.find((r) => r._id === reportId || r.reportId === reportId)
  const [report, setReport] = useState<CTIReport | null>(fromContext || null)
  const [verification, setVerification] = useState<CTIVerificationResult | null>(null)
  const [fetching, setFetching] = useState(!fromContext && !!reportId)
  const [loadError, setLoadError] = useState<string | null>(null)

  const [attackSummary, setAttackSummary] = useState(report?.attackSummary ?? '')
  const [analystNotes, setAnalystNotes] = useState(report?.analystNotes ?? '')
  const [iocs, setIocs] = useState<string[]>(report?.indicatorsOfCompromise ?? [])
  const [actions, setActions] = useState<string[]>(report?.recommendedActions ?? [])
  const [saving, setSaving] = useState(false)
  const [publishing, setPublishing] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [showDiscard, setShowDiscard] = useState(false)
  const [discarding, setDiscarding] = useState(false)
  const [newIoc, setNewIoc] = useState('')
  const [newAction, setNewAction] = useState('')

  useEffect(() => {
    if (fromContext) {
      setReport(fromContext)
      setAttackSummary(fromContext.attackSummary || '')
      setAnalystNotes(fromContext.analystNotes || '')
      setIocs(fromContext.indicatorsOfCompromise || [])
      setActions(fromContext.recommendedActions || [])
      return
    }

    if (reportId) {
      setFetching(true)
      apiGet<{ report: CTIReport }>(`/cti/${reportId}`)
        .then((res) => {
          if (res.report) {
            setReport(res.report)
            setAttackSummary(res.report.attackSummary || '')
            setAnalystNotes(res.report.analystNotes || '')
            setIocs(res.report.indicatorsOfCompromise || [])
            setActions(res.report.recommendedActions || [])
          }
        })
        .catch((err) => setLoadError(err instanceof Error ? err.message : 'The report could not be loaded'))
        .finally(() => setFetching(false))
    }
  }, [reportId, fromContext])

  const goBack = () => {
    navigate('cti-feed')
    router.push('/cti-feed')
  }

  if (fetching) {
    return (
      <div className="p-8 max-w-4xl mx-auto flex items-center justify-center space-y-3">
        <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
        <span className="text-sm text-slate-500 ml-2">Loading structured CTI report...</span>
      </div>
    )
  }

  if (!report) {
    return (
      <div className="p-6 max-w-4xl mx-auto">
        <p className="text-slate-500 text-sm">
          {loadError ? `The CTI report could not be loaded: ${loadError}` : reportId ? 'CTI report not found.' : 'No CTI report was selected.'}
        </p>
        <button onClick={goBack} className="text-xs text-blue-600 mt-2 hover:underline cursor-pointer">
          ← Return to CTI Feed
        </button>
      </div>
    )
  }

  const isDraft = report.status === 'DRAFT' || report.status === 'PENDING_APPROVAL'

  /** Saves the draft; false when the save failed (the provider has already shown why). */
  const handleSave = async (): Promise<boolean> => {
    setSaving(true)
    const targetId = report.reportId || report._id
    try {
      await updateCTIDraft(targetId, {
        attackSummary,
        analystNotes,
        indicatorsOfCompromise: iocs,
        recommendedActions: actions,
      })
      return true
    } catch {
      return false
    } finally {
      setSaving(false)
    }
  }

  const handlePublish = async () => {
    // Never anchor content that differs from what is stored: publish only after a successful save.
    if (!(await handleSave())) return
    setPublishing(true)
    const targetId = report.reportId || report._id
    try {
      const published = await publishCTI(targetId)
      if (published) {
        setReport(published)
      }
    } catch {
      // Toast displayed by AppProvider
    } finally {
      setPublishing(false)
    }
  }

  const handleVerifyReport = async () => {
    if (!report) return
    setVerifying(true)
    const targetId = report.reportId || report._id
    try {
      const result = await verifyCTI(targetId)
      setVerification(result)
      if (result.status !== 'UNAVAILABLE') {
        setReport((prev) => (prev ? { ...prev, verificationStatus: result.status } : null))
      }
    } catch {
      // Toast handled by AppProvider
    } finally {
      setVerifying(false)
    }
  }

  const handleDiscard = async () => {
    setDiscarding(true)
    const targetId = report.reportId || report._id
    try {
      await discardCTI(targetId)
      goBack()
    } catch {
      // the provider has already shown the server's error; the draft still exists
    } finally {
      setDiscarding(false)
    }
  }

  const addIoc = () => {
    if (newIoc.trim()) {
      setIocs((prev) => [...prev, newIoc.trim()])
      setNewIoc('')
    }
  }

  const addAction = () => {
    if (newAction.trim()) {
      setActions((prev) => [...prev, newAction.trim()])
      setNewAction('')
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      {/* Navigation */}
      <button
        onClick={goBack}
        className="flex items-center gap-1.5 text-xs font-semibold text-slate-500 hover:text-slate-900 transition-colors cursor-pointer"
      >
        <ChevronLeft size={16} /> Back to CTI Feed
      </button>

      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-200">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded border ${
                (report.attackType || '').toUpperCase() === 'PRIVILEGE_ESCALATION'
                  ? 'bg-amber-50 text-amber-800 border-amber-300'
                  : 'bg-red-50 text-red-800 border-red-200'
              }`}
            >
              {(report.attackType || 'Not stated').replace(/_/g, ' ')}
            </span>
            <CTIStatusBadge status={report.status} />
            {report.status === 'PUBLISHED' && <VerificationBadge status={report.verificationStatus} />}
            <span className="text-xs font-mono text-slate-400">
              ID: {report.reportId || report._id}
            </span>
          </div>
          <h1 className="text-xl font-bold text-slate-900">
            {report.title || 'Structured Threat Intelligence Report'}
          </h1>
          <p className="text-xs text-slate-400 font-mono">
            Schema: {report.schemaVersion || 'not stated'} · Version: {report.version ?? 'not stated'} · Host reference: {report.hostRef || 'not recorded'}
          </p>
        </div>

        {publishing && (
          <div className="flex items-center gap-2 text-xs font-medium text-slate-600 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2">
            <Loader2 size={14} className="animate-spin text-blue-600" />
            Anchoring hash to Polygon Amoy…
          </div>
        )}
      </div>

      {/* Incident Metadata & Severity Card */}
      <Card className="p-5 bg-slate-50/50">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
          <div>
            <span className="text-slate-400 font-medium block">Detector / Rule</span>
            <span className="font-mono font-bold text-slate-800">
              {report.detector?.id || 'Not recorded'}
            </span>
          </div>
          <div>
            <span className="text-slate-400 font-medium block">Confidence Level</span>
            <span className="font-bold text-slate-800 uppercase">
              {report.confidenceTier || 'Not stated'}
            </span>
          </div>
          <div>
            <span className="text-slate-400 font-medium block">Severity & Risk</span>
            <div className="flex items-center gap-1.5 mt-0.5">
              {report.severity && <SeverityBadge severity={report.severity} />}
              {report.riskScore !== undefined && (
                <span className="font-mono font-bold text-slate-800">{report.riskScore}/100</span>
              )}
            </div>
          </div>
          <div>
            <span className="text-slate-400 font-medium block">Detection Timestamp</span>
            <span className="font-medium text-slate-700">
              {report.detectedAt ? new Date(report.detectedAt).toLocaleString() : 'Not recorded'}
            </span>
          </div>
        </div>
      </Card>

      {/* On-Chain Cryptographic Anchoring & Blockchain Verification Card */}
      {(report.status === 'PUBLISHED' || report.status === 'ANCHORED' || report.transactionHash || report.contentHash) && (
        <Card className="p-5 border-purple-200 bg-purple-50/20">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-purple-100">
            <div className="flex items-center gap-2">
              <Fingerprint className="w-5 h-5 text-purple-700" />
              <div>
                <h3 className="text-sm font-bold text-slate-900">
                  Cryptographic Blockchain Anchoring (Polygon Amoy)
                </h3>
                <p className="text-xs text-slate-500">
                  Smart contract-verified Cyber Threat Intelligence immutable record
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <VerificationBadge status={report.verificationStatus} />
              <button
                onClick={handleVerifyReport}
                disabled={verifying}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 transition-colors shadow-xs cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
                {verifying ? 'Verifying on-chain…' : 'Re-verify Hash'}
              </button>
            </div>
          </div>

          <div className="pt-3 flex items-center gap-2 text-xs">
            <span className="text-slate-400 font-medium">Publication Status:</span>
            <CTIStatusBadge status={report.status} />
          </div>
          <div className="pt-2">
            <AnchorDetails
              report={report}
              verification={verification && verification.reportId === (report.reportId || report._id) ? verification : null}
            />
          </div>
        </Card>
      )}

      {/* MITRE ATT&CK Mapping Card */}
      {report.mitre && report.mitre.length > 0 && (
        <Card className="p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Globe size={16} className="text-blue-600" />
              MITRE ATT&CK Enterprise Mapping
            </h3>
            <span className="text-xs font-mono text-slate-400">
              {report.mitre[0]?.attackVersion ? `ATT&CK ${report.mitre[0].attackVersion}` : ''}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {report.mitre.map((m: MitreMapping, idx: number) => (
              <div
                key={idx}
                className="bg-slate-50 border border-slate-200 rounded-lg p-3 flex items-start justify-between gap-3 text-xs"
              >
                <div>
                  <div className="flex items-center gap-1.5 mb-1">
                    <span className="font-mono font-bold text-blue-700 bg-blue-100 px-2 py-0.5 rounded">
                      {m.techniqueId}
                    </span>
                    <span className="font-semibold text-slate-900">{m.techniqueName}</span>
                  </div>
                  <p className="text-slate-500">Tactic: {m.tacticName} ({m.tacticId})</p>
                </div>
                <a
                  href={m.referenceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 hover:underline flex-shrink-0 font-medium"
                >
                  <span>ATT&CK</span>
                  <ExternalLink size={12} />
                </a>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Forensic Telemetry & Evidence */}
      {report.evidence && report.evidence.length > 0 && (
        <Card className="p-5">
          <h3 className="text-sm font-semibold text-slate-900 mb-3 flex items-center gap-2">
            <Database size={16} className="text-slate-700" />
            Forensic Telemetry & Evidence Artifacts
          </h3>
          <div className="space-y-2">
            {report.evidence.map((ev: EvidenceItem, idx: number) => (
              <div key={idx} className="bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs space-y-1">
                <div className="flex items-center justify-between font-mono">
                  <span className="font-bold text-slate-800">
                    [{ev.id}] {ev.source.toUpperCase()} {ev.eventId ? `(Sysmon ${ev.eventId})` : ''}
                  </span>
                  <span className="text-slate-400 text-[11px]">
                    {ev.time ? new Date(ev.time).toLocaleTimeString() : ''}
                  </span>
                </div>
                <p className="text-slate-700">{ev.description}</p>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Attack Summary */}
      <Card className="p-5">
        <Textarea
          label="Attack Summary (Included in Canonical Hash)"
          value={attackSummary}
          onChange={(e) => setAttackSummary(e.target.value)}
          rows={4}
          placeholder="Describe the observed threat behavior..."
          disabled={!isDraft}
          className={isDraft ? '' : 'bg-slate-50 cursor-default'}
        />
      </Card>

      {/* IOCs */}
      <Card className="p-5">
        <h3 className="text-sm font-semibold text-slate-900 mb-3">Indicators of Compromise</h3>
        <div className="space-y-2 mb-3">
          {iocs.map((ioc, i) => (
            <div key={i} className="flex items-start gap-2 bg-slate-50 rounded-lg px-3 py-2 group">
              <span className="text-xs font-mono text-slate-700 flex-1">{ioc}</span>
              {isDraft && (
                <button
                  onClick={() => setIocs((prev) => prev.filter((_, j) => j !== i))}
                  className="text-slate-300 hover:text-red-500 opacity-0 group-hover:opacity-100 transition-all flex-shrink-0 cursor-pointer"
                >
                  <Trash2 size={13} />
                </button>
              )}
            </div>
          ))}
          {iocs.length === 0 && <p className="text-xs text-slate-400 italic">No IOCs added yet.</p>}
        </div>
        {isDraft && (
          <div className="flex gap-2">
            <input
              className="flex-1 border border-slate-200 rounded-lg px-3 py-1.5 text-xs font-mono placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
              placeholder="Add indicator (e.g. PROCESS: fodhelper.exe)..."
              value={newIoc}
              onChange={(e) => setNewIoc(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addIoc()}
            />
            <Button size="sm" variant="secondary" onClick={addIoc}>
              <Plus size={13} />
            </Button>
          </div>
        )}
      </Card>

      {/* Recommended Actions */}
      <Card className="p-5">
        <h3 className="text-sm font-semibold text-slate-900 mb-3">Recommended Actions</h3>
        <ol className="space-y-2 mb-3">
          {actions.map((action, i) => (
            <li key={i} className="flex items-start gap-3 bg-slate-50 rounded-lg px-3 py-2 group">
              <span className="text-xs font-mono text-slate-400 flex-shrink-0 mt-0.5">{i + 1}.</span>
              <span className="text-xs text-slate-700 flex-1">{action}</span>
              {isDraft && (
                <button
                  onClick={() => setActions((prev) => prev.filter((_, j) => j !== i))}
                  className="text-slate-300 hover:text-red-500 opacity-0 group-hover:opacity-100 transition-all flex-shrink-0 cursor-pointer"
                >
                  <Trash2 size={13} />
                </button>
              )}
            </li>
          ))}
          {actions.length === 0 && <p className="text-xs text-slate-400 italic">No actions added yet.</p>}
        </ol>
        {isDraft && (
          <div className="flex gap-2">
            <input
              className="flex-1 border border-slate-200 rounded-lg px-3 py-1.5 text-xs placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
              placeholder="Add recommended action..."
              value={newAction}
              onChange={(e) => setNewAction(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addAction()}
            />
            <Button size="sm" variant="secondary" onClick={addAction}>
              <Plus size={13} />
            </Button>
          </div>
        )}
      </Card>

      {/* Analyst Notes */}
      <Card className="p-5">
        <Textarea
          label="Internal Analyst Notes (Excluded from Public Blockchain Hash)"
          value={analystNotes}
          onChange={(e) => setAnalystNotes(e.target.value)}
          rows={3}
          placeholder="Internal notes for SOC team..."
          disabled={!isDraft}
          className={isDraft ? '' : 'bg-slate-50 cursor-default'}
        />
      </Card>

      {/* Actions */}
      {isDraft && (
        <div className="flex flex-wrap items-center gap-3 pt-2 pb-8">
          <Button onClick={handleSave} loading={saving} variant="secondary">
            Save Draft
          </Button>
          <Button onClick={handlePublish} loading={publishing} disabled={saving}>
            <Fingerprint className="w-4 h-4 mr-1.5" />
            Publish to Polygon Blockchain
          </Button>
          <button
            onClick={() => setShowDiscard(true)}
            className="text-xs text-red-500 hover:text-red-700 transition-colors px-2 cursor-pointer ml-auto"
          >
            Discard Draft
          </button>
        </div>
      )}

      <ConfirmModal
        open={showDiscard}
        onClose={() => setShowDiscard(false)}
        onConfirm={handleDiscard}
        title="Discard CTI Draft"
        message="This draft will be permanently deleted and cannot be recovered."
        confirmLabel="Discard"
        danger
        loading={discarding}
      />
    </div>
  )
}

export default function CTIDraftEditorPage() {
  return (
    <Suspense fallback={<div className="p-8 text-sm text-slate-500">Loading editor...</div>}>
      <CTIDraftEditorContent />
    </Suspense>
  )
}
