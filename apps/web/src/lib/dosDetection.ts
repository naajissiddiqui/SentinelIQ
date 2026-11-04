// Display rules for DoS/DDoS detections. Pure functions so they can be tested
// with node --test (see dosDetection.test.mjs).
//
// DoS/DDoS alerts are alert-only: the UI shows no isolation or CTI-draft action
// for them, always states where the data came from (recorded traffic is never
// shown as live) and what produced the alert (a rate-threshold rule is never
// presented as a machine-learning model).

// Kept import-free so it can run under node --test. Must match lib/demoData.ts (a test checks they agree).
const DEMO_BADGE = {
  label: 'DEMONSTRATION RECORD',
  className: 'bg-rose-100 text-rose-800 border-rose-300',
  description: 'Demonstration data. Not a security incident and not threat intelligence.',
}
function isDemoDetection(d: { dataOrigin?: string | null; ruleId?: string | null; modelVersion?: string | null }): boolean {
  return d.dataOrigin === 'DEMO' || /^DEMO-/i.test(d.ruleId ?? '') || /^DEMO-/i.test(d.modelVersion ?? '')
}

/** Demonstration or simulated records: never incidents. Mirrors backend detectionProfile.isTestRecord. */
export function isTestRecord(d: { dataOrigin?: string | null; ruleId?: string | null; modelVersion?: string | null }): boolean {
  return isDemoDetection(d) || d.dataOrigin === 'SIMULATED'
}

/** Product names for the detector that produced a DoS alert; model details stay in the evidence panel. */
export function detectorName(detector?: string, status?: string): string {
  if (detector === 'pps-heuristic' || status === 'HEURISTIC') return 'Rate-threshold rule'
  if (status === 'TRAINED' || detector) return 'Machine-learning network detector'
  return 'Network detector'
}

export const DOS_ATTACK_TYPE = 'DOS_DDOS'

export interface DetectionLike {
  attackType?: string
  ruleId?: string
  dataOrigin?: string
  detectorStatus?: string
  modelVersion?: string
  detectedAt?: string
  evidence?: Array<{ id: string; source?: string; time?: string; description?: string; fields?: Record<string, unknown> }>
}

export interface Badge {
  label: string
  className: string
  description: string
}

export function isDosDetection(d: Pick<DetectionLike, 'attackType'>): boolean {
  return (d.attackType || '').toUpperCase() === DOS_ATTACK_TYPE
}

export function attackTypeLabel(attackType?: string): string {
  if ((attackType || '').toUpperCase() === DOS_ATTACK_TYPE) return 'Network DoS'
  return (attackType || 'RANSOMWARE').replace(/_/g, ' ')
}

export function attackTypeBadgeClass(attackType?: string): string {
  const t = (attackType || 'RANSOMWARE').toUpperCase()
  if (t === DOS_ATTACK_TYPE) return 'bg-sky-50 text-sky-800 border-sky-300'
  if (t === 'PRIVILEGE_ESCALATION') return 'bg-amber-50 text-amber-800 border-amber-300'
  return 'bg-red-50 text-red-800 border-red-200'
}

export function dataOriginBadge(origin?: string): Badge {
  if (origin === 'PCAP_REPLAY') {
    return {
      label: 'RECORDED TRAFFIC',
      className: 'bg-violet-100 text-violet-800 border-violet-300',
      description: 'Recorded network capture analysed after it was captured. This is not live monitoring.',
    }
  }
  if (origin === 'LIVE') {
    return { label: 'LIVE TELEMETRY', className: 'bg-emerald-100 text-emerald-800 border-emerald-300', description: 'Telemetry received from a live sensor or endpoint agent.' }
  }
  if (origin === 'DEMO') return DEMO_BADGE
  if (origin === 'SIMULATED') {
    return {
      label: 'SIMULATED TELEMETRY',
      className: 'bg-fuchsia-100 text-fuchsia-800 border-fuchsia-300',
      description: 'Synthetic telemetry from the endpoint agent simulator. Not real endpoint activity.',
    }
  }
  return {
    label: 'SOURCE NOT RECORDED',
    className: 'bg-slate-100 text-slate-700 border-slate-300',
    description: 'The reporting component did not state whether this data was live or recorded.',
  }
}

/** Plain-text data source for detail views; same wording as the source filter. */
export function dataOriginLabel(d: Pick<DetectionLike, 'dataOrigin' | 'ruleId' | 'modelVersion'>): string {
  if (isDemoDetection(d)) return 'Demonstration record'
  switch (d.dataOrigin) {
    case 'PCAP_REPLAY': return 'Recorded traffic'
    case 'LIVE': return 'Live telemetry'
    case 'SIMULATED': return 'Simulated telemetry'
    default: return 'Source not recorded'
  }
}

/**
 * Endpoint name for list views. The network sensor appends its data source in
 * parentheses ("Network Sensor (recorded traffic)"); the list shows the sensor
 * name only. The stored name is unchanged and the source stays in detail views.
 */
export function displayEndpointName(d: Pick<DetectionLike, 'attackType'> & { endpointName?: string }): string {
  const name = (d.endpointName || '').trim()
  if (!name) return 'Unknown Endpoint'
  return isDosDetection(d) ? name.replace(/\s*\([^)]*\)\s*$/, '') || name : name
}

export function detectorStatusBadge(status?: string): Badge {
  if (status === 'TRAINED') {
    return {
      label: 'ML DETECTION',
      className: 'bg-blue-100 text-blue-800 border-blue-300',
      description: 'Machine-learning network detector trained on verified, labelled traffic.',
    }
  }
  if (status === 'HEURISTIC') {
    return {
      label: 'RATE-THRESHOLD RULE',
      className: 'bg-amber-100 text-amber-800 border-amber-300',
      description: 'Packets-per-second threshold rule. Not a machine-learning model; no detection performance is claimed.',
    }
  }
  return {
    label: 'NO NETWORK DETECTIONS',
    className: 'bg-slate-100 text-slate-700 border-slate-300',
    description: 'No network DoS detection has been recorded yet.',
  }
}

export interface DosSummary {
  target?: string
  windowStartUtc?: string
  windowSeconds?: number
  score?: number
  threshold?: number
  detector?: string
  detectorStatus?: string
  modelVersion?: string
  persistence?: { k: number; n: number }
  persistenceHits?: number
  scoreSemantics?: string
  riskComponents?: { margin: number; persistence: number; volume: number }
  riskScoreDerivation?: string
  inPacketsPerSecond?: number
  inBytesPerSecond?: number
  uniqueSources?: number
  newFlows?: number
  unansweredFlowShare?: number
  baselinePpsRatio?: number | null
  protocolMix?: Record<string, number>
  captures?: Array<{ file: string; bytes?: number; sha256?: string }>
  outOfTrainingRange?: string[]
}

function fieldsOf(d: DetectionLike, id: string): Record<string, unknown> {
  return (d.evidence || []).find(e => e.id === id)?.fields || {}
}

/** Pulls the sensor's structured evidence into one object; missing pieces stay undefined. */
export function summarizeDos(d: DetectionLike): DosSummary | null {
  if (!isDosDetection(d)) return null
  const win = fieldsOf(d, 'dos-window')
  const pred = fieldsOf(d, 'dos-prediction')
  const traffic = fieldsOf(d, 'dos-traffic')
  const prov = fieldsOf(d, 'pcap-provenance')
  const when = (d.evidence || []).find(e => e.id === 'dos-window')?.time
  return {
    target: win.target as string | undefined,
    windowStartUtc: when,
    windowSeconds: win.windowSeconds as number | undefined,
    score: pred.score as number | undefined,
    threshold: pred.threshold as number | undefined,
    detector: pred.detector as string | undefined,
    detectorStatus: (pred.detectorStatus as string | undefined) ?? d.detectorStatus,
    modelVersion: (pred.modelVersion as string | undefined) ?? d.modelVersion,
    persistence: pred.persistence as { k: number; n: number } | undefined,
    persistenceHits: pred.persistenceHits as number | undefined,
    scoreSemantics: pred.scoreSemantics as string | undefined,
    riskComponents: pred.riskComponents as DosSummary['riskComponents'],
    riskScoreDerivation: pred.riskScoreDerivation as string | undefined,
    inPacketsPerSecond: traffic.inPacketsPerSecond as number | undefined,
    inBytesPerSecond: traffic.inBytesPerSecond as number | undefined,
    uniqueSources: traffic.uniqueSources as number | undefined,
    newFlows: traffic.newFlows as number | undefined,
    unansweredFlowShare: traffic.unansweredFlowShare as number | undefined,
    baselinePpsRatio: traffic.baselinePpsRatio as number | null | undefined,
    protocolMix: traffic.protocolMix as Record<string, number> | undefined,
    captures: prov.captures as DosSummary['captures'],
    outOfTrainingRange: Array.isArray(traffic.outOfTrainingRange)
      ? (traffic.outOfTrainingRange as string[])
      : undefined,
  }
}

/** CTI drafts have no DoS template yet; the backend refuses them too. */
export function canGenerateCti(d: Pick<DetectionLike, 'attackType'>): boolean {
  return !isDosDetection(d)
}

export const ATTACK_TYPE_FILTERS = ['All types', 'Ransomware', 'Privilege escalation', 'Network DoS'] as const
export type AttackTypeFilter = (typeof ATTACK_TYPE_FILTERS)[number]

export function matchesAttackTypeFilter(d: Pick<DetectionLike, 'attackType'>, filter: AttackTypeFilter): boolean {
  const t = (d.attackType || 'RANSOMWARE').toUpperCase()
  switch (filter) {
    case 'Ransomware': return t === 'RANSOMWARE'
    case 'Privilege escalation': return t === 'PRIVILEGE_ESCALATION'
    case 'Network DoS': return t === DOS_ATTACK_TYPE
    default: return true
  }
}

export const DATA_ORIGIN_FILTERS = ['All sources', 'Recorded traffic', 'Live telemetry', 'Simulated telemetry', 'Demonstration records', 'Source not recorded'] as const
export type DataOriginFilter = (typeof DATA_ORIGIN_FILTERS)[number]

/** Detections from producers that predate dataOrigin (e.g. the endpoint agent) have none: "not stated", never "live". */
export function matchesDataOriginFilter(d: Pick<DetectionLike, 'dataOrigin' | 'ruleId' | 'modelVersion'>, filter: DataOriginFilter): boolean {
  switch (filter) {
    case 'Recorded traffic': return d.dataOrigin === 'PCAP_REPLAY'
    case 'Live telemetry': return d.dataOrigin === 'LIVE'
    case 'Simulated telemetry': return d.dataOrigin === 'SIMULATED'
    case 'Demonstration records': return isDemoDetection(d)
    case 'Source not recorded': return !d.dataOrigin && !isDemoDetection(d)
    case 'All sources': return true
    default: return false   // an unknown filter matches nothing rather than everything
  }
}

/**
 * The DoS detector status to show on the detections list: taken from the most
 * recent DoS detection, or "no network detections" when there is none.
 */
export function dosDetectorStatus(detections: DetectionLike[]): Badge {
  const latest = detections
    .filter(isDosDetection)
    .sort((a, b) => (b.detectedAt || '').localeCompare(a.detectedAt || ''))[0]
  return detectorStatusBadge(latest?.detectorStatus)
}

/** A derived metric's display state: shown with a value, or withheld with a reason. */
export interface MetricDisplay {
  available: boolean
  value?: number
  reason?: string
}

/** Packet/byte rates are shown only when they are a finite, non-negative number. */
export function isValidRate(v?: number | null): v is number {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0
}

/**
 * The 60 s baseline ratio is only meaningful when there is real prior history.
 * With too little history the sensor divides the rate by a 1 pps floor
 * (windows.py PPS_FLOOR), so the ratio collapses to the raw packet rate and is
 * not a measured multiple. We detect that (ratio == pps) and mark it unavailable
 * rather than present a misleading number. Values are never substituted.
 */
export function baselineRatioDisplay(s: Pick<DosSummary, 'baselinePpsRatio' | 'inPacketsPerSecond'>): MetricDisplay {
  const r = s.baselinePpsRatio
  if (r == null || Number.isNaN(r)) return { available: false, reason: 'no baseline history' }
  const pps = s.inPacketsPerSecond
  if (typeof pps === 'number' && Math.abs(r - pps) < 0.5) {
    return { available: false, reason: 'insufficient baseline history' }
  }
  return { available: true, value: r }
}

/**
 * Unanswered-flow share is not meaningful when the capture cannot tell reply
 * direction apart (e.g. loopback traffic makes every packet look both inbound
 * and outbound, so every flow appears "answered"). The sensor signals this by
 * reporting out_packets as out of the model's training range.
 */
export function unansweredFlowDisplay(
  s: Pick<DosSummary, 'unansweredFlowShare' | 'outOfTrainingRange'>
): MetricDisplay {
  const v = s.unansweredFlowShare
  if (v == null || Number.isNaN(v)) return { available: false, reason: 'not recorded' }
  if (s.outOfTrainingRange?.includes('out_packets')) {
    return { available: false, reason: 'reply direction indeterminate in this capture' }
  }
  return { available: true, value: v }
}

export function formatRate(value?: number, unit = '/s'): string {
  if (value === undefined || value === null || Number.isNaN(value)) return 'n/a'
  if (value >= 1e6) return `${(value / 1e6).toFixed(2)}M${unit}`
  if (value >= 1e3) return `${(value / 1e3).toFixed(1)}k${unit}`
  return `${value.toFixed(value < 10 ? 1 : 0)}${unit}`
}
