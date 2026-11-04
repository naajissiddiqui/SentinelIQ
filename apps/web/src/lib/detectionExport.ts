// CSV export of detection records exactly as the API returned them. Pure, so it
// can be tested with node --test (see detectionExport.test.mjs).

export interface ExportableDetection {
  _id: string
  detectedAt?: string
  endpointName?: string
  attackType?: string
  severity?: string
  riskScore?: number
  status?: string
  confidenceTier?: string
  ruleId?: string
  dataOrigin?: string
  detectorStatus?: string
  modelVersion?: string
  mitre?: Array<{ techniqueId: string }>
}

export const EXPORT_COLUMNS = [
  'id', 'detectedAt', 'endpoint', 'attackType', 'severity', 'riskScore', 'status',
  'confidenceTier', 'ruleId', 'dataOrigin', 'detectorStatus', 'modelVersion', 'mitreTechniques',
] as const

/**
 * One CSV cell. Quotes when needed, and neutralises spreadsheet formulas: a
 * value starting with = + - @ (or tab/CR) is prefixed with ' so a crafted
 * endpoint name or indicator cannot execute when the file is opened.
 */
export function csvCell(value: unknown): string {
  let text = value === undefined || value === null ? '' : String(value)
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

export function detectionsToCsv(detections: ExportableDetection[]): string {
  const rows = detections.map(d => [
    d._id, d.detectedAt, d.endpointName, d.attackType ?? 'RANSOMWARE', d.severity, d.riskScore, d.status,
    d.confidenceTier, d.ruleId, d.dataOrigin ?? '', d.detectorStatus ?? '', d.modelVersion,
    (d.mitre ?? []).map(m => m.techniqueId).join(' '),
  ].map(csvCell).join(','))
  return [EXPORT_COLUMNS.join(','), ...rows].join('\r\n') + '\r\n'
}

export function exportFileName(now: Date = new Date()): string {
  return `sentineliq-detections-${now.toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`
}
