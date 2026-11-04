'use client'

import { Activity, FileArchive, Gauge, Info } from 'lucide-react'
import { Card } from '@/components/ui'
import type { Detection } from '@/lib/types'
import {
  baselineRatioDisplay,
  dataOriginBadge,
  detectorName,
  detectorStatusBadge,
  formatRate,
  isValidRate,
  summarizeDos,
  unansweredFlowDisplay,
} from '@/lib/dosDetection'

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="bg-slate-50 border border-slate-200 rounded-lg px-3 py-2">
      <p className="text-[10px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className="text-sm font-mono font-semibold text-slate-900">{value}</p>
      {sub && <p className="text-[10px] text-slate-500 mt-0.5">{sub}</p>}
    </div>
  )
}

/** A metric that is present but not meaningful for this record: shown as unavailable, never faked. */
function UnavailableStat({ label, reason }: { label: string; reason: string }) {
  return (
    <div className="bg-slate-50 border border-slate-200 rounded-lg px-3 py-2">
      <p className="text-[10px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className="text-sm font-mono font-semibold text-slate-400">Unavailable</p>
      <p className="text-[10px] text-slate-500 mt-0.5">{reason}</p>
    </div>
  )
}

function Pill({ label, className, title }: { label: string; className: string; title: string }) {
  return (
    <span title={title} className={`text-xs font-bold px-2 py-0.5 rounded border ${className}`}>
      {label}
    </span>
  )
}

/** "2018-11-03T14:01:45Z" -> "2018-11-03 14:01:45 UTC" (the time the traffic was captured). */
function utc(iso?: string): string {
  if (!iso) return 'n/a'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : `${d.toISOString().slice(0, 19).replace('T', ' ')} UTC`
}

/**
 * Evidence for one network DoS alert. The main view keeps the few metrics an analyst
 * acts on; everything else (counts, protocol mix, model internals, provenance, timestamps,
 * and metrics that are not meaningful for this capture) sits in Technical Details.
 */
export function DosDetectionPanel({ detection }: { detection: Detection }) {
  const s = summarizeDos(detection)
  if (!s) return null
  const origin = dataOriginBadge(detection.dataOrigin)
  const status = detectorStatusBadge(s.detectorStatus ?? detection.detectorStatus)
  const rateRule = s.detector === 'pps-heuristic'
  const recorded = detection.dataOrigin === 'PCAP_REPLAY'

  const mix = s.protocolMix
    ? Object.entries(s.protocolMix)
        .filter(([, v]) => v > 0.001)
        .map(([k, v]) => `${k.replace('in_', '').replace('_share', '').toUpperCase()} ${(v * 100).toFixed(1)}%`)
        .join(' · ')
    : 'n/a'

  const baseline = baselineRatioDisplay(s)
  const unanswered = unansweredFlowDisplay(s)
  const scoreLabel = rateRule ? 'Measured rate' : 'Detector score'
  const scoreValue =
    s.score === undefined ? 'n/a' : rateRule ? formatRate(s.score) : s.score.toFixed(3)
  const thresholdValue =
    s.threshold === undefined ? 'n/a' : rateRule ? formatRate(s.threshold) : s.threshold.toFixed(3)

  return (
    <Card className="p-5 border-sky-200 bg-sky-50/30 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-sky-900 flex items-center gap-2">
          <Activity size={16} className="text-sky-700" />
          Network DoS Detection
        </h3>
        <div className="flex flex-wrap gap-2">
          <Pill label={origin.label} className={origin.className} title={origin.description} />
          <Pill label={status.label} className={status.className} title={status.description} />
        </div>
      </div>

      <p className="text-xs text-slate-600">
        {recorded
          ? `Traffic captured ${utc(s.windowStartUtc)} and analysed from a recording; this is not live monitoring. `
          : `Traffic observed ${utc(s.windowStartUtc)}. `}
        Raised by the {detectorName(s.detector, s.detectorStatus).toLowerCase()} after the flood persisted across consecutive windows.
      </p>

      {/* Main view: the few metrics an analyst acts on. */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        <Stat label="Target" value={s.target ?? 'n/a'} />
        {isValidRate(s.inPacketsPerSecond) && (
          <Stat label="Inbound packets" value={formatRate(s.inPacketsPerSecond, ' pkt/s')} />
        )}
        {isValidRate(s.inBytesPerSecond) && (
          <Stat label="Inbound bytes" value={formatRate(s.inBytesPerSecond, ' B/s')} />
        )}
        <Stat
          label={scoreLabel}
          value={rateRule ? scoreValue : `${scoreValue} ≥ ${thresholdValue}`}
          sub={rateRule ? 'inbound packets/s vs threshold' : 'not a probability; threshold-relative only'}
        />
      </div>

      {/* Risk severity, kept explicitly distinct from the model score and from any probability. */}
      {typeof detection.riskScore === 'number' && (
        <p className="text-xs text-slate-600">
          <span className="font-semibold text-slate-700">Risk severity:</span>{' '}
          {detection.riskScore}/100{detection.severity ? ` (${detection.severity})` : ''} — a severity ranking of how strong
          and sustained the evidence is, not the model score and not a probability.
        </p>
      )}

      {/* Technical details: counts, protocol mix, model internals, provenance, timestamps,
          and metrics that are present but not meaningful for this capture. */}
      <details className="bg-white border border-slate-200 rounded-lg p-3 text-[11px] text-slate-600">
        <summary className="cursor-pointer font-semibold text-slate-700 flex items-center gap-1">
          <Gauge size={12} /> Technical details
        </summary>

        <div className="grid grid-cols-2 md:grid-cols-3 gap-2 mt-3">
          <Stat label="Window start" value={s.windowStartUtc ? utc(s.windowStartUtc) : 'n/a'} />
          <Stat label="Window length" value={`${s.windowSeconds ?? 5} s`} />
          <Stat
            label="Persistence"
            value={s.persistence ? `${s.persistenceHits ?? s.persistence.k} of ${s.persistence.n} (needs ${s.persistence.k})` : 'n/a'}
          />
          <Stat label="Unique sources" value={s.uniqueSources === undefined ? 'n/a' : String(s.uniqueSources)} />
          <Stat label="New flows (5 s)" value={s.newFlows === undefined ? 'n/a' : String(Math.round(s.newFlows))} />
          <Stat label="Protocol mix" value={mix || 'n/a'} />
          {unanswered.available
            ? <Stat label="Unanswered flows" value={`${((unanswered.value ?? 0) * 100).toFixed(1)}%`} />
            : <UnavailableStat label="Unanswered flows" reason={unanswered.reason ?? 'not available'} />}
          {baseline.available
            ? <Stat label="vs 60 s baseline" value={`${(baseline.value ?? 0).toFixed(1)}×`} />
            : <UnavailableStat label="vs 60 s baseline" reason={baseline.reason ?? 'not available'} />}
        </div>

        <div className="mt-3 space-y-1 border-t border-slate-100 pt-2">
          <p>Detector: {detectorName(s.detector, s.detectorStatus)}{s.detector ? ` (${s.detector})` : ''}</p>
          <p>Model version: <span className="font-mono">{s.modelVersion ?? 'n/a'}</span></p>
          {s.scoreSemantics && <p>Score meaning: {s.scoreSemantics}.</p>}
          {s.riskScoreDerivation && (
            <p>
              Risk severity (not a probability): {s.riskScoreDerivation}
              {s.riskComponents && ` · margin ${s.riskComponents.margin}, persistence ${s.riskComponents.persistence}, volume ${s.riskComponents.volume}`}
            </p>
          )}
          {s.outOfTrainingRange && s.outOfTrainingRange.length > 0 && (
            <p className="text-amber-800 flex items-start gap-1.5 pt-1">
              <Info size={12} className="mt-0.5 flex-shrink-0 text-amber-700" />
              Some window features fell outside the model&apos;s training range ({s.outOfTrainingRange.join(', ')}),
              so the detector score is less reliable for this window than for traffic resembling the training data.
            </p>
          )}
        </div>

        {s.captures && s.captures.length > 0 && (
          <div className="mt-3 border-t border-slate-100 pt-2 font-mono space-y-1">
            <p className="flex items-center gap-1 font-sans font-semibold text-slate-700">
              <FileArchive size={12} /> Capture provenance ({s.captures.length} file{s.captures.length === 1 ? '' : 's'})
            </p>
            {s.captures.map(c => (
              <p key={c.file} className="truncate text-slate-600">
                {c.file} · {c.sha256 ? `sha256 ${c.sha256}` : 'no hash'}
              </p>
            ))}
          </div>
        )}
      </details>
    </Card>
  )
}
