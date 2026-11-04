// Run: npm --workspace=apps/web test   (node --test with built-in TypeScript type stripping)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildDetectionOverview,
  buildDetectionToast,
  describePrivilegeEscalation,
  emptyIndicatorsMessage,
  isPrivilegeEscalation,
  redactSecrets,
  summarizePrivilegeEscalation,
} from './alertSummary.ts'

const ind = (type, description) => ({ type, description, observedAt: '2026-10-15T00:00:00Z' })

test('PE-03 group add -> exact plain summary from the spec', () => {
  const s = summarizePrivilegeEscalation({
    attackType: 'PRIVILEGE_ESCALATION',
    ruleId: 'PE-03',
    severity: 'HIGH',
    riskScore: 85,
    indicators: [ind('ACCOUNT_MANIPULATION', "Membership added to 'administrators': net localgroup administrators eve /add")],
  })
  assert.deepEqual(s, {
    attack: 'Privilege Escalation',
    whatHappened: 'An account was added to the Administrators group.',
    severity: 'High',
    riskScore: 85,
    ruleId: 'PE-03',
    source: 'Rule-based privilege escalation engine (PE-03)',
    evidence: ["Membership added to 'administrators': net localgroup administrators eve /add"],
  })
})

test('PE-03 grouped create + add (simulation output) mentions both, no command or password', () => {
  const text = describePrivilegeEscalation({
    ruleId: 'PE-03',
    indicators: [
      ind('ACCOUNT_CREATION', 'net user backup_admin S3cure!Pass /add'),
      ind('ACCOUNT_MANIPULATION', "Membership added to 'administrators': net localgroup administrators backup_admin /add"),
      ind('CORRELATION', '2 related PE-03 events from the same attack sequence grouped into one alert'),
    ],
  })
  assert.equal(text, 'A new account was created and added to the Administrators group.')
  assert.doesNotMatch(text, /net |S3cure|\/add/)
})

test('every PE rule has a plain-language sentence without raw paths or commands', () => {
  const cases = {
    'PE-01': [ind('PROCESS', 'High-integrity execution of C:\\Users\\Public\\updater.exe')],
    'PE-02': [ind('PROCESS_CHAIN', 'C:\\Tools\\loader.exe [medium] -> notepad.exe [system]')],
    'PE-04': [ind('PERSISTENCE', 'SYSTEM/highest scheduled task creation: schtasks /create /tn x /ru SYSTEM')],
    'PE-05': [ind('REGISTRY', 'UAC hijack key modified: HKU\\...\\ms-settings\\shell\\open\\command')],
    'PE-06': [ind('REGISTRY', 'IFEO Debugger: HKLM\\...\\Image File Execution Options\\sethc.exe\\Debugger = cmd.exe')],
  }
  const expected = {
    'PE-01': 'A program ran with administrator-level rights from an unusual folder.',
    'PE-02': 'A normal program started another program with higher (SYSTEM) privileges.',
    'PE-04': 'A scheduled task was created to run a program with SYSTEM rights.',
    'PE-05': 'Windows User Account Control (UAC) was bypassed to gain administrator rights.',
    'PE-06': 'A Windows accessibility tool was hijacked to open a hidden admin command prompt.',
  }
  for (const [ruleId, indicators] of Object.entries(cases)) {
    const text = describePrivilegeEscalation({ ruleId, indicators })
    assert.equal(text, expected[ruleId], ruleId)
    assert.doesNotMatch(text, /[A-Z]:\\|HKLM|HKU|schtasks|\.exe/, ruleId)
  }
})

test('PE-04 service variant and unknown rule fallback', () => {
  assert.equal(
    describePrivilegeEscalation({ ruleId: 'PE-04', indicators: [ind('PERSISTENCE', "Service 'evil' -> C:\\Temp\\x.exe")] }),
    'A new Windows service was set up to run a program with SYSTEM rights.',
  )
  assert.equal(describePrivilegeEscalation({ ruleId: 'PE-99' }), 'Suspicious privilege escalation activity was detected.')
})

test('isPrivilegeEscalation only matches PE detections (ransomware keeps its existing view)', () => {
  assert.equal(isPrivilegeEscalation({ attackType: 'PRIVILEGE_ESCALATION' }), true)
  assert.equal(isPrivilegeEscalation({ attackType: 'RANSOMWARE' }), false)
  assert.equal(isPrivilegeEscalation({}), false)
})

test('redactSecrets masks passwords but keeps the rest of the command', () => {
  assert.equal(redactSecrets('net user backup_admin S3cure!Pass /add'), 'net user backup_admin ******** /add')
  assert.equal(redactSecrets('C:\\Windows\\system32\\net1.exe user bob hunter2 /add'), 'C:\\Windows\\system32\\net1.exe user bob ******** /add')
  assert.equal(redactSecrets('net user bob /add'), 'net user bob /add')
  assert.equal(redactSecrets('net localgroup administrators bob /add'), 'net localgroup administrators bob /add')
  assert.equal(redactSecrets('New-LocalUser bob -Password secret1'), 'New-LocalUser bob -Password ********')
  assert.equal(redactSecrets('$p = ConvertTo-SecureString "Pa55" -AsPlainText'), '$p = ConvertTo-SecureString "********" -AsPlainText')
})

// Regression: PE alerts used to render the ransomware/XGBoost template.
const peDetection = {
  attackType: 'PRIVILEGE_ESCALATION',
  ruleId: 'PE-03',
  modelVersion: 'rule-pe-v2.0.0',
  severity: 'HIGH',
  riskScore: 85,
  endpointName: 'WS-042',
  indicators: [ind('ACCOUNT_CREATION', 'net user backup_admin S3cure!Pass /add')],
  evidence: [{ description: 'Event 4720: user account backup_admin created via net user backup_admin S3cure!Pass /add' }],
}

test('PE overview shows activity, risk, severity and evidence without the rule ID, never ransomware/XGBoost', () => {
  const text = buildDetectionOverview(peDetection)
  assert.match(text, /high-severity privilege escalation was detected on WS-042/)
  assert.match(text, /A new user account was created\./)
  assert.match(text, /Risk score 85\/100 \(rule-based score\)\./)
  assert.doesNotMatch(text, /PE-03/)
  assert.match(text, /Evidence: Event 4720: user account backup_admin created/)
  assert.doesNotMatch(text, /ransomware|xgboost|indicator burst/i)
  assert.doesNotMatch(text, /S3cure!Pass/)
})

test('PE toast and empty-indicator fallback are PE-specific', () => {
  const toast = buildDetectionToast(peDetection)
  assert.equal(toast, 'New HIGH privilege escalation on WS-042 — PE-03: A new user account was created. Risk score: 85')
  assert.equal(emptyIndicatorsMessage(peDetection), 'Matched privilege escalation rule PE-03.')
})

test('every rule PE-01..PE-06 is treated as PE even when attackType defaulted to RANSOMWARE', () => {
  for (const n of [1, 2, 3, 4, 5, 6]) {
    const d = { ...peDetection, attackType: 'RANSOMWARE', ruleId: `PE-0${n}`, modelVersion: undefined }
    assert.equal(isPrivilegeEscalation(d), true, d.ruleId)
    assert.doesNotMatch(buildDetectionOverview(d), /ransomware|xgboost/i, d.ruleId)
    assert.match(buildDetectionOverview(d), /privilege escalation was detected/, d.ruleId)
  }
})

test('ransomware notifications name the detector in product terms', () => {
  const rw = { attackType: 'RANSOMWARE', ruleId: 'RANSOMWARE-XGB', modelVersion: 'xgboost-v1.0.0', severity: 'CRITICAL', riskScore: 97, endpointName: 'FIN-01' }
  assert.equal(
    buildDetectionOverview(rw),
    'A critical-severity ransomware indicator burst was detected on FIN-01. Risk score from the machine-learning endpoint detector: 97/100.',
  )
  assert.equal(buildDetectionToast(rw), 'New CRITICAL detection on FIN-01 — Risk score: 97')
  assert.equal(emptyIndicatorsMessage(rw), 'The detector raised this alert without itemised indicators.')
})

test('network DoS overview states recorded traffic and the detector, never the algorithm name', () => {
  const dos = { attackType: 'DOS_DDOS', ruleId: 'DOS-XGB', modelVersion: 'dos-xgb-99b94241-afefb015', detectorStatus: 'TRAINED',
                dataOrigin: 'PCAP_REPLAY', severity: 'HIGH', riskScore: 72, endpointName: 'Network Sensor (recorded traffic)' }
  const text = buildDetectionOverview(dos)
  assert.equal(text, 'A high-severity network denial-of-service flood was detected in recorded network traffic by the machine-learning network detector. Risk score: 72/100.')
  assert.doesNotMatch(text, /xgboost|live/i)
  assert.match(buildDetectionOverview({ ...dos, detectorStatus: 'HEURISTIC' }), /rate-threshold rule/)
})
