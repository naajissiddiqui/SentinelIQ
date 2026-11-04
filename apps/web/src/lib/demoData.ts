// Demonstration data must never pass for a real incident. Mirrors the backend's
// isDemoDetection (apps/backend/src/services/detectionProfile.ts).

export interface DemoCheckable {
  dataOrigin?: string | null
  ruleId?: string | null
  modelVersion?: string | null
}

/** dataOrigin DEMO, or seeded records that predate the field (rule / model ids starting DEMO-). */
export function isDemoDetection(d: DemoCheckable): boolean {
  return d.dataOrigin === 'DEMO' || /^DEMO-/i.test(d.ruleId ?? '') || /^DEMO-/i.test(d.modelVersion ?? '')
}

/** Demonstration or simulated records: stored, but never incidents. Mirrors backend isTestRecord. */
export function isTestRecord(d: DemoCheckable): boolean {
  return isDemoDetection(d) || d.dataOrigin === 'SIMULATED'
}

export interface DemoCheckableReport {
  title?: string
  attackSummary?: string
  detector?: { id?: string; version?: string }
}

/** A CTI report generated from demo data (labelled title or summary, or a DEMO- detector). */
export function isDemoReport(r: DemoCheckableReport): boolean {
  return (
    /^\[DEMO\]/.test(r.title ?? '') ||
    /^DEMONSTRATION RECORD/.test(r.attackSummary ?? '') ||
    /^DEMO-/i.test(r.detector?.id ?? '') ||
    /^DEMO-/i.test(r.detector?.version ?? '')
  )
}

export const DEMO_BADGE = {
  label: 'DEMONSTRATION RECORD',
  className: 'bg-rose-100 text-rose-800 border-rose-300',
  description: 'Demonstration data. Not a security incident and not threat intelligence.',
}

/** Maps each report id to the id of the published revision that supersedes it (from the same list). */
export function supersededBy(reports: { reportId?: string; supersedes?: string | null }[]): Map<string, string> {
  const map = new Map<string, string>()
  for (const r of reports) {
    if (r.supersedes && r.reportId) map.set(r.supersedes, r.reportId)
  }
  return map
}
