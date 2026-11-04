// Run: npm --workspace=apps/web test
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { csvCell, detectionsToCsv, EXPORT_COLUMNS, exportFileName } from './detectionExport.ts'
import { matchesDataOriginFilter } from './dosDetection.ts'

// TEST FIXTURE: a real trained-model alert (offline PCAP replay); see the file's _fixture note.
const trained = JSON.parse(readFileSync(new URL('./fixtures/dos-trained-model-alert.fixture.json', import.meta.url)))

test('CSV cells are quoted and spreadsheet formulas neutralised', () => {
  assert.equal(csvCell('plain'), 'plain')
  assert.equal(csvCell('a,b'), '"a,b"')
  assert.equal(csvCell('say "hi"'), '"say ""hi"""')
  assert.equal(csvCell('=HYPERLINK("x")'), '"\'=HYPERLINK(""x"")"')
  assert.equal(csvCell('+1'), "'+1")
  assert.equal(csvCell('@cmd'), "'@cmd")
  assert.equal(csvCell(undefined), '')
  assert.equal(csvCell(0), '0')
})

test('export contains exactly the given records with origin, detector and MITRE', () => {
  const det = { ...trained, _id: 'abc123', endpointName: 'net-sensor', severity: 'HIGH', status: 'NEW',
                mitre: [{ techniqueId: 'T1498' }] }
  const csv = detectionsToCsv([det, { _id: 'r1', endpointName: 'ws-1', riskScore: 95 }])
  const lines = csv.trim().split('\r\n')
  assert.equal(lines[0], EXPORT_COLUMNS.join(','))
  assert.equal(lines.length, 3)
  assert.ok(lines[1].includes('DOS_DDOS') && lines[1].includes('PCAP_REPLAY') && lines[1].includes('TRAINED'))
  assert.ok(lines[1].endsWith('T1498'))
  assert.ok(lines[2].includes(',RANSOMWARE,'))   // missing attackType is the historical default
  assert.equal(detectionsToCsv([]).trim(), EXPORT_COLUMNS.join(','))  // empty export: header only, no invented rows
})

test('file name is timestamped', () => {
  assert.equal(exportFileName(new Date('2026-10-18T13:01:35Z')), 'sentineliq-detections-2026-10-18-13-01-35.csv')
})

test('data-origin filter never treats a missing origin as live', () => {
  assert.equal(matchesDataOriginFilter(trained, 'Recorded traffic'), true)
  assert.equal(matchesDataOriginFilter(trained, 'Live telemetry'), false)
  assert.equal(matchesDataOriginFilter({}, 'Live telemetry'), false)
  assert.equal(matchesDataOriginFilter({}, 'Source not recorded'), true)
  assert.equal(matchesDataOriginFilter({ dataOrigin: 'LIVE' }, 'Live telemetry'), true)
  assert.equal(matchesDataOriginFilter({ dataOrigin: 'SIMULATED' }, 'Live telemetry'), false)   // simulated is never live
  assert.equal(matchesDataOriginFilter({ dataOrigin: 'SIMULATED' }, 'Simulated telemetry'), true)
  assert.equal(matchesDataOriginFilter({ dataOrigin: 'LIVE' }, 'No such filter'), false)
})
