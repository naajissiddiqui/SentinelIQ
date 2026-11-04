// One risk-score -> severity mapping for the whole UI, identical to the backend's
// severityFromRiskScore (apps/backend/src/models/detection.model.ts). A risk score is a
// 0-100 severity score, never a calibrated probability of attack.

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export const SEVERITY_THRESHOLDS = { CRITICAL: 90, HIGH: 70, MEDIUM: 40 } as const

export function severityFromRiskScore(score: number): Severity {
  if (score >= SEVERITY_THRESHOLDS.CRITICAL) return 'CRITICAL'
  if (score >= SEVERITY_THRESHOLDS.HIGH) return 'HIGH'
  if (score >= SEVERITY_THRESHOLDS.MEDIUM) return 'MEDIUM'
  return 'LOW'
}

export const SEVERITY_HEX: Record<Severity, string> = {
  CRITICAL: '#DC2626',
  HIGH: '#F97316',
  MEDIUM: '#F59E0B',
  LOW: '#16A34A',
}

export const SEVERITY_TEXT_CLASS: Record<Severity, string> = {
  CRITICAL: 'text-red-600',
  HIGH: 'text-orange-500',
  MEDIUM: 'text-yellow-600',
  LOW: 'text-slate-600',
}

export const RISK_SCORE_HELP =
  'Risk score: a 0-100 severity score (LOW < 40 <= MEDIUM < 70 <= HIGH < 90 <= CRITICAL). It is not a probability.'
