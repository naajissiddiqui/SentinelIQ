/**
 * Presentation wording for detection text (indicators, evidence lines).
 *
 * It only replaces internal detector tags written by the network sensor with product names, and
 * normalises whitespace. It never removes provenance: words such as "simulated" or "demo" stay,
 * because hiding them would let synthetic activity pass for a real incident. Model details remain
 * available in the evidence panel; stored records are never changed.
 */
const DETECTOR_TAGS: Array<[RegExp, string]> = [
  [/\(xgboost, TRAINED\)/g, '(machine-learning detector)'],
  [/\(pps-heuristic, HEURISTIC\)/g, '(rate-threshold rule)'],
  [/\bxgboost score\b/g, 'model score'],
  [/\bpps-heuristic score\b/g, 'packet-rate measurement'],
  // Wording stored by endpoint agents before they used product names.
  [/Real Sysmon events triggered local XGBoost thresholds/g, "Live Sysmon events exceeded the machine-learning detector's alert threshold"],
  [/XGBoost behavioral classifier score/g, 'Machine-learning behavioural classifier score'],
]

export function presentDetectionText(text: string | null | undefined): string {
  if (!text) return ''
  let result = String(text)
  for (const [pattern, replacement] of DETECTOR_TAGS) result = result.replace(pattern, replacement)
  return result.replace(/\s{2,}/g, ' ').trim()
}
