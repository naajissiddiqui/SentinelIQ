'use client'

import { ChevronRight, ExternalLink, ShieldAlert } from 'lucide-react'
import type { Detection } from '@/lib/types'
import { summarizePrivilegeEscalation, redactSecrets } from '@/lib/alertSummary'
import { presentDetectionText } from '@/lib/sanitizers'

const severityText: Record<string, string> = {
  Critical: 'text-red-700',
  High: 'text-orange-600',
  Medium: 'text-yellow-600',
  Low: 'text-slate-600',
}

/** Plain-language summary shown by default for privilege escalation alerts. */
export function PrivilegeEscalationSummaryCard({ detection }: { detection: Detection }) {
  const s = summarizePrivilegeEscalation(detection)
  const rows: Array<[string, React.ReactNode]> = [
    ['Attack', s.attack],
    ['What happened', s.whatHappened],
    ['Severity', <span key="sev" className={`font-semibold ${severityText[s.severity] ?? 'text-slate-700'}`}>{s.severity}</span>],
    ['Risk Score', <span key="risk" className="font-semibold">{s.riskScore}</span>],
    ...(s.evidence.length > 0
      ? [['Evidence', <ul key="ev" className="list-disc pl-4 space-y-0.5">{s.evidence.map((e, i) => <li key={i} className="break-words">{e}</li>)}</ul>] as [string, React.ReactNode]]
      : []),
  ]
  return (
    <div className="rounded-xl border border-amber-200 bg-amber-50/40 p-4">
      <div className="flex items-center gap-2 mb-3">
        <ShieldAlert size={16} className="text-amber-700" />
        <span className="text-sm font-semibold text-slate-900">Alert Summary</span>
      </div>
      <dl className="grid grid-cols-[130px_1fr] gap-y-2 text-sm">
        {rows.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-slate-500 font-medium">{label}</dt>
            <dd className="text-slate-900">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

/** Collapsed-by-default technical evidence for debugging (passwords masked). */
export function PrivilegeEscalationTechnicalDetails({ detection }: { detection: Detection }) {
  const clean = (t: unknown) => redactSecrets(presentDetectionText(t == null ? '' : String(t)))
  return (
    <details className="group rounded-xl border border-slate-200 bg-white">
      <summary className="flex items-center gap-2 px-4 py-3 cursor-pointer select-none text-sm font-semibold text-slate-700 list-none [&::-webkit-details-marker]:hidden">
        <ChevronRight size={16} className="transition-transform group-open:rotate-90" />
        View Details
        <span className="ml-auto text-xs font-normal text-slate-400">Technical evidence for debugging</span>
      </summary>

      <div className="px-4 pb-4 space-y-4 text-xs">
        {detection.indicators?.length > 0 && (
          <section>
            <h4 className="font-semibold text-slate-600 mb-1.5">Indicators</h4>
            <ul className="space-y-1">
              {detection.indicators.map((ind, i) => (
                <li key={i} className="text-slate-700">
                  <span className="font-mono text-[10px] px-1.5 py-0.5 mr-1.5 rounded bg-slate-100 text-slate-600">{ind.type}</span>
                  {clean(ind.description)}
                </li>
              ))}
            </ul>
          </section>
        )}

        {detection.mitre && detection.mitre.length > 0 && (
          <section>
            <h4 className="font-semibold text-slate-600 mb-1.5">MITRE ATT&CK</h4>
            <ul className="space-y-1">
              {detection.mitre.map((m, i) => (
                <li key={i} className="flex items-center gap-2 text-slate-700">
                  <span className="font-mono font-bold text-blue-700">{m.techniqueId}</span>
                  <span>{m.techniqueName}</span>
                  <span className="text-slate-400">({m.tacticName})</span>
                  {m.referenceUrl && (
                    <a href={m.referenceUrl} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline inline-flex items-center gap-0.5">
                      ATT&CK <ExternalLink size={10} />
                    </a>
                  )}
                </li>
              ))}
            </ul>
          </section>
        )}

        {detection.evidence && detection.evidence.length > 0 && (
          <section>
            <h4 className="font-semibold text-slate-600 mb-1.5">Raw Evidence</h4>
            <div className="space-y-2">
              {detection.evidence.map((ev, i) => (
                <div key={i} className="rounded-lg border border-slate-200 bg-slate-50 p-2.5 space-y-1">
                  <div className="flex justify-between font-mono text-[11px] text-slate-500">
                    <span>{ev.source?.toUpperCase()}{ev.eventId ? ` · Event ${ev.eventId}` : ''}</span>
                    <span>{ev.time ? new Date(ev.time).toLocaleTimeString() : ''}</span>
                  </div>
                  <p className="text-slate-700">{clean(ev.description)}</p>
                  {ev.fields && Object.keys(ev.fields).length > 0 && (
                    <div className="font-mono text-[11px] bg-white rounded border border-slate-200 p-2 space-y-0.5">
                      {Object.entries(ev.fields).map(([k, v]) => (
                        <div key={k} className="break-all">
                          <span className="text-slate-400">{k}:</span> <span className="text-slate-800">{clean(v)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </details>
  )
}
