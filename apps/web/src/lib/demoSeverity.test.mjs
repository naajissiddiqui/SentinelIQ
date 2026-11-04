// Run: npm --workspace=apps/web test
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { severityFromRiskScore, RISK_SCORE_HELP } from './severity.ts'
import { isDemoDetection, isDemoReport, supersededBy } from './demoData.ts'
import { dataOriginBadge, matchesDataOriginFilter } from './dosDetection.ts'
import { DEMO_BADGE } from './demoData.ts'
import { presentDetectionText } from './sanitizers.ts'

// Mirrors the backend rule (models/detection.model.ts severityFromRiskScore): keep them identical.
const backendSource = readFileSync(new URL('../../../backend/src/models/detection.model.ts', import.meta.url), 'utf-8')

test('UI severity thresholds are exactly the backend thresholds', () => {
  for (const [score, sev] of [[0, 'LOW'], [39, 'LOW'], [40, 'MEDIUM'], [69, 'MEDIUM'], [70, 'HIGH'], [89, 'HIGH'], [90, 'CRITICAL'], [100, 'CRITICAL']]) {
    assert.equal(severityFromRiskScore(score), sev, String(score))
  }
  assert.match(backendSource, /score >= 90\) return "CRITICAL"/)
  assert.match(backendSource, /score >= 70\) return "HIGH"/)
  assert.match(backendSource, /score >= 40\) return "MEDIUM"/)
  assert.match(RISK_SCORE_HELP, /not a probability/)
})

test('demo detections are recognised, including legacy seeded records', () => {
  assert.equal(isDemoDetection({ dataOrigin: 'DEMO' }), true)
  assert.equal(isDemoDetection({ ruleId: 'DEMO-SEED-16' }), true)          // seeded before dataOrigin existed
  assert.equal(isDemoDetection({ modelVersion: 'DEMO-seed-xgboost-v1.0.0' }), true)
  assert.equal(isDemoDetection({ ruleId: 'RANSOMWARE-XGB', dataOrigin: 'LIVE' }), false)
  assert.equal(isDemoDetection({ ruleId: 'DOS-XGB', dataOrigin: 'PCAP_REPLAY' }), false)
  assert.equal(dataOriginBadge('DEMO').label, 'DEMONSTRATION RECORD')
  assert.equal(matchesDataOriginFilter({ dataOrigin: 'DEMO' }, 'Live telemetry'), false)
  assert.equal(matchesDataOriginFilter({ ruleId: 'DEMO-SEED-1' }, 'Demonstration records'), true)
})

test('demo CTI reports are recognised (the published Amoy demo report included)', () => {
  // Shape of cti-e551e4-mv646myn as published: original title, labelled summary, DEMO-SEED detector.
  const published = { title: 'Ransomware Incident on WORKSTATION-REAL',
                      attackSummary: 'DEMONSTRATION RECORD - NOT THREAT INTELLIGENCE. This report was generated ...',
                      detector: { type: 'xgboost', id: 'DEMO-SEED-16', version: 'xgboost-v1.0.0' } }
  assert.equal(isDemoReport(published), true)
  assert.equal(isDemoReport({ title: '[DEMO] Ransomware Incident on WS-1' }), true)
  assert.equal(isDemoReport({ title: 'Ransomware Incident on WS-1', attackSummary: 'Ransomware-pattern behaviour', detector: { id: 'RANSOMWARE-XGB' } }), false)
})

test('the import-free copy in dosDetection.ts agrees with demoData.ts', () => {
  assert.deepEqual(dataOriginBadge('DEMO'), DEMO_BADGE)
  for (const d of [{ dataOrigin: 'DEMO' }, { ruleId: 'DEMO-SEED-1' }, { modelVersion: 'DEMO-x' }, { ruleId: 'DOS-XGB' }, {}]) {
    assert.equal(matchesDataOriginFilter(d, 'Demonstration records'), isDemoDetection(d), JSON.stringify(d))
  }
})

test('a published correction marks the report it supersedes', () => {
  const m = supersededBy([{ reportId: 'cti-e551e4-mv646myn', supersedes: null },
                          { reportId: 'cti-e551e4-v2-mve3qhum', supersedes: 'cti-e551e4-mv646myn' }])
  assert.equal(m.get('cti-e551e4-mv646myn'), 'cti-e551e4-v2-mve3qhum')
  assert.equal(m.has('cti-e551e4-v2-mve3qhum'), false)
  assert.equal(isDemoReport({ title: '[DEMO] Demonstration record - seeded test data, not a real incident (corrects cti-e551e4-mv646myn)' }), true)
})

test('detection text: detector tags become product names; provenance words are never removed', () => {
  assert.equal(presentDetectionText('24129 packets/s inbound to 192.168.50.4 (xgboost, TRAINED)'),
               '24129 packets/s inbound to 192.168.50.4 (machine-learning detector)')
  assert.equal(presentDetectionText('16150 packets/s inbound to 192.168.50.4 (pps-heuristic, HEURISTIC)'),
               '16150 packets/s inbound to 192.168.50.4 (rate-threshold rule)')
  assert.equal(presentDetectionText('Simulated ransomware burst in ransomware_demo.exe (PID 15760)'),
               'Simulated ransomware burst in ransomware_demo.exe (PID 15760)')
  assert.equal(presentDetectionText('Real Sysmon events triggered local XGBoost thresholds'),
               "Live Sysmon events exceeded the machine-learning detector's alert threshold")
  assert.equal(presentDetectionText('XGBoost behavioral classifier score: 0.912'), 'Machine-learning behavioural classifier score: 0.912')
  assert.equal(presentDetectionText(null), '')
})
