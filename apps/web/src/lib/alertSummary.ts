/**
 * Plain-language summaries for privilege escalation detections.
 * The default dashboard view shows these; raw telemetry stays in "View Details".
 * Pure functions (no imports) so they can be unit-tested with `node --test`.
 */

export interface SummarizableDetection {
  attackType?: string
  ruleId?: string
  severity?: string
  riskScore?: number
  modelVersion?: string
  detectorStatus?: string
  dataOrigin?: string
  endpointName?: string
  indicators?: Array<{ type?: string; description?: string } | string>
  evidence?: Array<{ description?: string }>
}

export interface PrivilegeEscalationSummary {
  attack: string
  whatHappened: string
  severity: string
  riskScore: number
  ruleId: string
  source: string
  evidence: string[]
}

const PE_RULE_ID = /^PE-\d+$/i

/**
 * True for privilege escalation detections. Falls back to the PE rule ID / rule engine
 * version because the backend defaults a missing attackType to RANSOMWARE.
 */
export function isPrivilegeEscalation(
  d: { attackType?: string; ruleId?: string; modelVersion?: string } | null | undefined,
): boolean {
  if (!d) return false
  if ((d.attackType || '').toUpperCase() === 'PRIVILEGE_ESCALATION') return true
  return PE_RULE_ID.test(d.ruleId || '') || (d.modelVersion || '').toLowerCase().startsWith('rule-pe')
}

function titleCase(s: string): string {
  return s
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ')
}

/** All technical text attached to a detection, lower-cased, for keyword matching. */
function technicalText(d: SummarizableDetection): string {
  const parts: string[] = []
  for (const ind of d.indicators || []) {
    parts.push(typeof ind === 'string' ? ind : `${ind.type || ''} ${ind.description || ''}`)
  }
  for (const ev of d.evidence || []) parts.push(ev.description || '')
  return parts.join(' \n ').toLowerCase()
}

function privilegedGroup(text: string): string | null {
  const m = text.match(/(?:privileged group|added to|membership added to)\s+'([^']+)'/i)
  return m ? titleCase(m[1]) : null
}

/** One plain-English sentence describing what the rule observed. */
export function describePrivilegeEscalation(d: SummarizableDetection): string {
  const rule = (d.ruleId || '').toUpperCase()
  const text = technicalText(d)

  switch (rule) {
    case 'PE-01':
      if (text.includes('user-writable') || text.includes('\\temp\\') || text.includes('\\users\\public\\')) {
        return 'A program ran with administrator-level rights from an unusual folder.'
      }
      return 'A command tool was started with SYSTEM rights by an unexpected program.'

    case 'PE-02':
      if (text.includes('service-account') || text.includes('token impersonation')) {
        return 'A server process started a command shell with SYSTEM rights.'
      }
      if (text.includes('document') || text.includes('winword') || text.includes('excel') || text.includes('outlook')) {
        return 'A document or script launched a command shell with administrator rights.'
      }
      return 'A normal program started another program with higher (SYSTEM) privileges.'

    case 'PE-03': {
      const group = privilegedGroup(text)
      const created = text.includes('created') || text.includes('account_creation')
      if (group && created) return `A new account was created and added to the ${group} group.`
      if (group) return `An account was added to the ${group} group.`
      return 'A new user account was created.'
    }

    case 'PE-04':
      if (text.includes('service')) return 'A new Windows service was set up to run a program with SYSTEM rights.'
      return 'A scheduled task was created to run a program with SYSTEM rights.'

    case 'PE-05':
      if (text.includes('uac') || text.includes('auto-elevat') || text.includes('fodhelper')) {
        return 'Windows User Account Control (UAC) was bypassed to gain administrator rights.'
      }
      return 'A known privilege-escalation hacking tool was run.'

    case 'PE-06':
      if (text.includes('image file execution options') || text.includes('ifeo')) {
        return text.match(/sethc|utilman|osk\.exe|narrator|magnify/)
          ? 'A Windows accessibility tool was hijacked to open a hidden admin command prompt.'
          : 'A program was secretly redirected to run a different program when it starts.'
      }
      if (text.includes('enablelua') || text.includes('uac')) return 'User Account Control (UAC) was turned off.'
      if (text.includes('defender')) return 'Microsoft Defender protection was turned off.'
      if (text.includes('winlogon')) return 'Windows sign-in settings were changed to run an extra program.'
      if (text.includes('lsa')) return 'Windows credential-protection settings were changed.'
      return 'A security-sensitive Windows setting was changed.'

    default:
      return 'Suspicious privilege escalation activity was detected.'
  }
}

/** Which engine produced the detection's risk score. */
export function detectionSource(d: SummarizableDetection): string {
  if (isPrivilegeEscalation(d)) return `Rule-based privilege escalation engine (${d.ruleId || 'PE rule'})`
  const version = (d.modelVersion || '').toLowerCase()
  if (version.startsWith('rule')) return `Rule-based detection engine (${d.ruleId || d.modelVersion})`
  if ((d.attackType || '').toUpperCase() === 'DOS_DDOS') {
    return d.detectorStatus === 'HEURISTIC' ? 'Network rate-threshold rule' : 'Machine-learning network detector'
  }
  return 'Machine-learning endpoint detector'
}

/** Up to `limit` evidence lines (passwords masked), falling back to indicators. */
export function evidenceSummary(d: SummarizableDetection, limit = 3): string[] {
  const fromEvidence = (d.evidence || []).map((e) => e.description || '')
  const fromIndicators = (d.indicators || []).map((i) => (typeof i === 'string' ? i : i.description || i.type || ''))
  const lines = (fromEvidence.some(Boolean) ? fromEvidence : fromIndicators).filter(Boolean)
  return lines.slice(0, limit).map((l) => redactSecrets(l))
}

export function summarizePrivilegeEscalation(d: SummarizableDetection): PrivilegeEscalationSummary {
  return {
    attack: 'Privilege Escalation',
    whatHappened: describePrivilegeEscalation(d),
    severity: titleCase(d.severity || 'Medium'),
    riskScore: d.riskScore ?? 0,
    ruleId: d.ruleId || '—',
    source: detectionSource(d),
    evidence: evidenceSummary(d),
  }
}

function attackLabel(d: SummarizableDetection): string {
  return titleCase((d.attackType || 'RANSOMWARE').replace(/_/g, ' '))
}

/** Detection overview paragraph shown in the detection drawer. */
export function buildDetectionOverview(d: SummarizableDetection): string {
  const severity = (d.severity || 'medium').toLowerCase()
  const host = d.endpointName || 'the endpoint'
  if (isPrivilegeEscalation(d)) {
    const s = summarizePrivilegeEscalation(d)
    const evidence = s.evidence.length ? ` Evidence: ${s.evidence.join('; ')}.` : ''
    return (
      `A ${severity}-severity privilege escalation was detected on ${host}: ${s.whatHappened} ` +
      `Risk score ${s.riskScore}/100 (rule-based score).${evidence}`
    )
  }
  if ((d.attackType || 'RANSOMWARE').toUpperCase() === 'RANSOMWARE') {
    return (
      `A ${severity}-severity ransomware indicator burst was detected on ${d.endpointName}. ` +
      `Risk score from the machine-learning endpoint detector: ${d.riskScore}/100.`
    )
  }
  if ((d.attackType || '').toUpperCase() === 'DOS_DDOS') {
    const source = d.dataOrigin === 'PCAP_REPLAY' ? ' in recorded network traffic' : d.dataOrigin === 'LIVE' ? ' in live network traffic' : ''
    return `A ${severity}-severity network denial-of-service flood was detected${source} by the ${detectionSource(d).toLowerCase()}. Risk score: ${d.riskScore ?? 0}/100.`
  }
  return `A ${severity}-severity ${attackLabel(d).toLowerCase()} detection was recorded on ${host}. Risk score: ${d.riskScore ?? 0}/100 (source: ${detectionSource(d)}).`
}

/** Text for the real-time "new detection" toast notification. */
export function buildDetectionToast(d: SummarizableDetection): string {
  if (isPrivilegeEscalation(d)) {
    return `New ${d.severity} privilege escalation on ${d.endpointName} — ${d.ruleId || 'PE'}: ${describePrivilegeEscalation(d)} Risk score: ${d.riskScore}`
  }
  if ((d.attackType || 'RANSOMWARE').toUpperCase() === 'RANSOMWARE') {
    return `New ${d.severity} detection on ${d.endpointName} — Risk score: ${d.riskScore}`
  }
  return `New ${d.severity} ${attackLabel(d).toLowerCase()} detection on ${d.endpointName} — Risk score: ${d.riskScore}`
}

/** Fallback line when a detection carries no indicators. */
export function emptyIndicatorsMessage(d: SummarizableDetection): string {
  return isPrivilegeEscalation(d)
    ? `Matched privilege escalation rule ${d.ruleId || ''}`.trim() + '.'
    : 'The detector raised this alert without itemised indicators.'
}

/** Masks passwords that appear in raw command lines (used in the technical details view). */
export function redactSecrets(text: string | null | undefined): string {
  if (!text) return ''
  return String(text)
    // net user <name> <password> [/add]
    .replace(/(\bnet1?(?:\.exe)?\s+user\s+\S+\s+)(?!\/)(\S+)/gi, '$1********')
    // /password:xyz, /p:xyz, -Password xyz, -AccountPassword xyz
    .replace(/(\/(?:password|pass|p):)(\S+)/gi, '$1********')
    .replace(/(-(?:Account)?Password\s+)(\S+)/gi, '$1********')
    // ConvertTo-SecureString "xyz"
    .replace(/(ConvertTo-SecureString\s+)(["'])(.*?)\2/gi, '$1$2********$2')
}
