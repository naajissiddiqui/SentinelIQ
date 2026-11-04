'use client'

import { useEffect, useState } from 'react'
import { Globe, Lock, Users, Check } from 'lucide-react'
import { useApp } from '@/lib/context'
import type { CTIReport } from '@/lib/types'

type Visibility = 'PRIVATE' | 'SHARED_ALL'

const OPTIONS: { value: Visibility; label: string; help: string; Icon: typeof Lock }[] = [
  { value: 'PRIVATE', label: 'Private', help: 'Only your organization can read this report.', Icon: Lock },
  { value: 'SHARED_ALL', label: 'All organizations', help: 'Every participating organization can read it in their CTI Feed.', Icon: Globe },
]

/**
 * Controls who can read a published report. Sharing changes real backend access control
 * (not just the UI): private reports are never returned to other organizations' APIs.
 * Only shown for the owning organization on a published report.
 */
export function ReportSharingControl({ report }: { report: CTIReport }) {
  const { shareReport } = useApp()
  const isPublished = report.status === 'PUBLISHED' || report.status === 'ANCHORED'

  // SHARED_SELECTED is still a valid backend state; treat it as "shared" for display.
  const [visibility, setVisibility] = useState<Visibility>(report.visibility === 'PRIVATE' || !report.visibility ? 'PRIVATE' : 'SHARED_ALL')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setVisibility(report.visibility === 'PRIVATE' || !report.visibility ? 'PRIVATE' : 'SHARED_ALL')
  }, [report.visibility])

  if (report.owned === false) {
    return (
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-xs text-slate-600">
        <p className="font-semibold text-slate-800 flex items-center gap-1.5"><Users className="w-3.5 h-3.5" /> Shared with your organization</p>
        <p className="mt-1">This report is owned by another organization and was shared with you. You can read and verify it, but not change its sharing.</p>
      </div>
    )
  }
  if (!isPublished) {
    return (
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-xs text-slate-500">
        <p className="font-semibold text-slate-700 flex items-center gap-1.5"><Lock className="w-3.5 h-3.5" /> Private draft</p>
        <p className="mt-1">Publish this report before sharing it with other organizations.</p>
      </div>
    )
  }

  const choose = async (v: Visibility) => {
    if (v === visibility) return
    setVisibility(v)
    setSaving(true)
    try { await shareReport(report._id, v) } catch { setVisibility(report.visibility === 'PRIVATE' || !report.visibility ? 'PRIVATE' : 'SHARED_ALL') } finally { setSaving(false) }
  }

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 space-y-3">
      <p className="text-xs font-bold uppercase tracking-wide text-slate-500">Sharing &amp; access</p>
      <div className="grid gap-2">
        {OPTIONS.map(({ value, label, help, Icon }) => (
          <button
            key={value}
            disabled={saving}
            onClick={() => choose(value)}
            className={`flex items-start gap-2 rounded-lg border p-2.5 text-left transition-colors disabled:opacity-60 ${visibility === value ? 'border-navy-600 bg-navy-50' : 'border-slate-200 hover:bg-slate-50'}`}
          >
            <Icon className="w-4 h-4 mt-0.5 flex-shrink-0 text-slate-600" />
            <span className="flex-1">
              <span className="text-[13px] font-semibold text-slate-900">{label}</span>
              <span className="block text-[11px] text-slate-500">{help}</span>
            </span>
            {visibility === value && <Check className="w-4 h-4 text-navy-700" />}
          </button>
        ))}
      </div>
    </div>
  )
}
