// Run: npm --workspace=apps/web test
// The detection used here is a TEST FIXTURE from sensor/demo/offline_demo.py
// (offline PCAP extraction, pps HEURISTIC, not a trained model).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  attackTypeLabel,
  canGenerateCti,
  baselineRatioDisplay,
  dataOriginBadge,
  dataOriginLabel,
  detectorStatusBadge,
  displayEndpointName,
  isValidRate,
  unansweredFlowDisplay,
  dosDetectorStatus,
  formatRate,
  isDosDetection,
  matchesAttackTypeFilter,
  summarizeDos,
} from './dosDetection.ts'

const fixture = JSON.parse(readFileSync(new URL('./fixtures/dos-pcap-replay-alert.fixture.json', import.meta.url)))

test('fixture renders as a heuristic PCAP-replay DoS alert', () => {
  assert.equal(isDosDetection(fixture), true)
  assert.equal(attackTypeLabel(fixture.attackType), 'Network DoS')
  assert.equal(dataOriginBadge(fixture.dataOrigin).label, 'RECORDED TRAFFIC')
  assert.match(dataOriginBadge(fixture.dataOrigin).description, /not live/)
  assert.equal(detectorStatusBadge(fixture.detectorStatus).label, 'RATE-THRESHOLD RULE')
  assert.match(detectorStatusBadge('HEURISTIC').description, /Not a machine-learning model/)
})

test('evidence summary carries score, threshold, window, traffic and provenance', () => {
  const s = summarizeDos(fixture)
  assert.equal(s.target, '192.168.50.4')
  assert.equal(s.windowStartUtc, '2018-11-03T13:01:35Z')
  assert.equal(s.threshold, 5000)
  assert.ok(s.score >= s.threshold)
  assert.deepEqual(s.persistence, { k: 3, n: 3 })
  assert.equal(s.detectorStatus, 'HEURISTIC')
  assert.ok(s.inPacketsPerSecond > 1000)
  assert.equal(s.captures[0].file, 'SAT-03-11-2018_0')
  assert.equal(s.captures[0].sha256.length, 64)
})

test('no CTI action for DoS; ransomware unchanged', () => {
  assert.equal(canGenerateCti(fixture), false)
  assert.equal(canGenerateCti({ attackType: 'RANSOMWARE' }), true)
  assert.equal(canGenerateCti({}), true)
  assert.equal(summarizeDos({ attackType: 'RANSOMWARE' }), null)
})

test('attack-type filter', () => {
  const ds = [fixture, { attackType: 'RANSOMWARE' }, {}, { attackType: 'PRIVILEGE_ESCALATION' }]
  assert.equal(ds.filter(d => matchesAttackTypeFilter(d, 'Network DoS')).length, 1)
  assert.equal(ds.filter(d => matchesAttackTypeFilter(d, 'Ransomware')).length, 2) // missing type = ransomware
  assert.equal(ds.filter(d => matchesAttackTypeFilter(d, 'All types')).length, 4)
})

test('honest detector status: no network detections without DoS detections, latest status otherwise', () => {
  assert.equal(dosDetectorStatus([{ attackType: 'RANSOMWARE' }]).label, 'NO NETWORK DETECTIONS')
  assert.equal(dosDetectorStatus([fixture]).label, 'RATE-THRESHOLD RULE')
  assert.equal(dataOriginBadge(undefined).label, 'SOURCE NOT RECORDED')
  assert.equal(dataOriginBadge('SIMULATED').label, 'SIMULATED TELEMETRY')
  assert.match(dataOriginBadge('SIMULATED').description, /Not real endpoint activity/)
})

test('trained-model fixture renders as TRAINED with model score and threshold', () => {
  const trained = JSON.parse(readFileSync(new URL('./fixtures/dos-trained-model-alert.fixture.json', import.meta.url)))
  assert.equal(detectorStatusBadge(trained.detectorStatus).label, 'ML DETECTION')
  const s = summarizeDos(trained)
  assert.equal(s.detector, 'xgboost')
  assert.equal(s.detectorStatus, 'TRAINED')
  assert.ok(s.score >= s.threshold && s.threshold > 0 && s.threshold < 1)
  assert.match(s.modelVersion, /^dos-xgb-/)
  assert.equal(dataOriginBadge(trained.dataOrigin).label, 'RECORDED TRAFFIC')
  assert.equal(canGenerateCti(trained), false)
  assert.equal(dosDetectorStatus([trained]).label, 'ML DETECTION')
  assert.match(s.scoreSemantics, /not a probability/)
  assert.deepEqual(Object.keys(s.riskComponents).sort(), ['margin', 'persistence', 'volume'])
  assert.ok(s.persistenceHits >= s.persistence.k && s.persistenceHits <= s.persistence.n)
  assert.match(s.riskScoreDerivation, /not a probability/)
})

test('rate formatting', () => {
  assert.equal(formatRate(16240), '16.2k/s')
  assert.equal(formatRate(undefined), 'n/a')
  assert.equal(formatRate(4148610, ' B/s'), '4.15M B/s')
})

test('list views show the sensor name only; the data source stays available for detail views', () => {
  const dos = { attackType: 'DOS_DDOS', dataOrigin: 'PCAP_REPLAY', endpointName: 'Network Sensor (recorded traffic)' }
  assert.equal(displayEndpointName(dos), 'Network Sensor')
  assert.equal(dataOriginLabel(dos), 'Recorded traffic')            // never presented as live
  assert.equal(dos.endpointName, 'Network Sensor (recorded traffic)') // stored name untouched
  assert.equal(displayEndpointName({ attackType: 'RANSOMWARE', endpointName: 'WS-01 (lab)' }), 'WS-01 (lab)')
  assert.equal(displayEndpointName({ attackType: 'DOS_DDOS', endpointName: '' }), 'Unknown Endpoint')
  assert.equal(dataOriginLabel({ dataOrigin: 'LIVE' }), 'Live telemetry')
  assert.equal(dataOriginLabel({ dataOrigin: 'LIVE', ruleId: 'DEMO-1' }), 'Demonstration record')
  assert.equal(dataOriginLabel({}), 'Source not recorded')
})

test('provenance label reflects the real data origin, never dressing recorded up as live', () => {
  assert.equal(dataOriginLabel({ dataOrigin: 'PCAP_REPLAY' }), 'Recorded traffic')
  assert.equal(dataOriginLabel({ dataOrigin: 'LIVE' }), 'Live telemetry')
  assert.equal(dataOriginLabel({ dataOrigin: 'PCAP_REPLAY', ruleId: 'DEMO-1' }), 'Demonstration record')
})

test('packet/byte rates are shown only when finite and non-negative', () => {
  assert.equal(isValidRate(6000), true)
  assert.equal(isValidRate(0), true)
  assert.equal(isValidRate(-1), false)
  assert.equal(isValidRate(NaN), false)
  assert.equal(isValidRate(undefined), false)
  assert.equal(isValidRate(null), false)
})

test('baseline ratio is withheld when history is insufficient (floored to the raw rate), shown when genuine', () => {
  // Floored: ratio equals the packet rate (6000 / 1 pps floor) -> not meaningful.
  const floored = baselineRatioDisplay({ baselinePpsRatio: 6000, inPacketsPerSecond: 6000 })
  assert.equal(floored.available, false)
  assert.match(floored.reason, /insufficient baseline history/)
  // No baseline at all.
  assert.equal(baselineRatioDisplay({ baselinePpsRatio: null, inPacketsPerSecond: 6000 }).available, false)
  // Genuine multiple over an established baseline.
  const real = baselineRatioDisplay({ baselinePpsRatio: 12.5, inPacketsPerSecond: 6000 })
  assert.equal(real.available, true)
  assert.equal(real.value, 12.5)
})

test('unanswered-flow share is withheld when reply direction is indeterminate, shown otherwise', () => {
  // out_packets out of range => loopback-style capture, reply direction indeterminate.
  const indet = unansweredFlowDisplay({ unansweredFlowShare: 0, outOfTrainingRange: ['out_packets', 'bytes_per_flow_mean'] })
  assert.equal(indet.available, false)
  assert.match(indet.reason, /reply direction indeterminate/)
  // A normal capture with real replies.
  const ok = unansweredFlowDisplay({ unansweredFlowShare: 0.92, outOfTrainingRange: [] })
  assert.equal(ok.available, true)
  assert.equal(ok.value, 0.92)
  // Missing value.
  assert.equal(unansweredFlowDisplay({}).available, false)
})
