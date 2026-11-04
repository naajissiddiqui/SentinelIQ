'use client'

import { useState, useEffect, useCallback, useRef, type ReactNode } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import { AppContext } from '@/lib/context'
import type { AppContextType } from '@/lib/context'
import type {
  CurrentUser,
  Endpoint,
  Detection,
  CTIReport,
  TeamUser,
  AuditLog,
  Invitation,
  Toast,
  UserRole,
  TimelineEvent,
  Policy,
  Cascade,
  ThreatIntelIOC,
  CTIMatchResult,
  CTIVerificationResult,
  DetectionPage,
  DetectionSummary,
} from '@/lib/types'
import {
  apiGet,
  apiPost,
  apiPatch,
  apiDelete,
  setAccessToken,
  getAccessToken,
  registerAuthFailureHandler,
  registerTokenRefreshHandler,
  restoreSession,
} from '@/lib/api'
import { initSocket, disconnectSocket, getSocket } from '@/lib/socket'
import { ToastItem } from '@/components/ui'
import { isDemoReport, isTestRecord } from '@/lib/demoData'
import { buildDetectionToast } from '@/lib/alertSummary'

interface ListState<T> {
  data: T[]
  loading: boolean
  error: string | null
}

function initList<T>(defaultData: T[] = []): ListState<T> {
  return { data: defaultData, loading: false, error: null }
}

/** The server's error message, so a failed request is shown as a failure, never as "no data". */
/** The URL for a page id used with navigate(); every id maps to an existing app route. */
function routeFor(page: string, params: Record<string, string>): string {
  const id = params.id ? encodeURIComponent(params.id) : ''
  switch (page) {
    case 'detection-detail': return id ? `/detections/${id}` : '/detections'
    case 'endpoint-detail': return id ? `/endpoints/${id}` : '/endpoints'
    case 'endpoints': return params.endpointId ? `/endpoints/${encodeURIComponent(params.endpointId)}` : '/endpoints'
    case 'cti-draft-editor': return id ? `/cti-draft-editor?id=${id}` : '/cti-center'
    default: return `/${page}`
  }
}

function errorMessage(err: unknown): string {
  return err instanceof Error && err.message ? err.message : 'Request failed'
}

/** Page size for the detections list; the server caps it at 200 and reports the true total. */
const DETECTION_PAGE_SIZE = 100

const PUBLIC_PATHS = ['/', '/login', '/register', '/join-organization', '/forgot-password']

export function AppProvider({ children }: { children: ReactNode }) {
  const router = useRouter()
  const pathname = usePathname()

  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null)
  const [isInitializing, setIsInitializing] = useState(true)
  const [page, setPage] = useState('dashboard')
  const [pageParams, setPageParams] = useState<Record<string, string>>({})
  const [toasts, setToasts] = useState<Toast[]>([])

  // Data states (initialized with empty lists - populated from real backend API)
  const [endpointState, setEndpointState] = useState<ListState<Endpoint>>(initList([]))
  const [detectionState, setDetectionState] = useState<ListState<Detection>>(initList([]))
  const [detectionPaging, setDetectionPaging] = useState<{ total: number; page: number; hasMore: boolean }>({ total: 0, page: 0, hasMore: false })
  const [detectionSummaryState, setDetectionSummaryState] = useState<{ data: DetectionSummary | null; loading: boolean; error: string | null }>({ data: null, loading: false, error: null })
  const [ctiState, setCtiState] = useState<ListState<CTIReport>>(initList([]))
  const [teamState, setTeamState] = useState<ListState<TeamUser>>(initList([]))
  const [invitationState, setInvitationState] = useState<ListState<Invitation>>(initList([]))
  const [auditState, setAuditState] = useState<ListState<AuditLog>>(initList([]))
  const [feedState, setFeedState] = useState<ListState<CTIReport>>(initList([]))
  const [policyState, setPolicyState] = useState<ListState<Policy>>(initList([]))
  const [cascadeState, setCascadeState] = useState<ListState<Cascade>>(initList([]))
  const [threatIntelState, setThreatIntelState] = useState<ListState<ThreatIntelIOC>>(initList([]))

  const currentUserRef = useRef<CurrentUser | null>(null)
  currentUserRef.current = currentUser

  // ─── Navigation ──────────────────────────────────────────────────────────────

  const navigate = useCallback((newPage: string, params: Record<string, string> = {}) => {
    setPage(newPage)
    setPageParams(params)
    if (newPage !== 'login' && newPage !== 'register' && newPage !== 'join-organization') {
      localStorage.setItem('ransomshield_saved_page', newPage)
    }
    router.push(routeFor(newPage, params))
  }, [router])

  // ─── Toasts ───────────────────────────────────────────────────────────────────

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const showToast = useCallback((message: string, type: Toast['type'] = 'info') => {
    const id = Math.random().toString(36).slice(2)
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
    }, 4500)
  }, [])

  // ─── Data fetchers ────────────────────────────────────────────────────────────

  const fetchEndpoints = useCallback(async () => {
    setEndpointState(s => ({ ...s, loading: true, error: null }))
    try {
      const data = await apiGet<{ endpoints: Endpoint[] }>('/endpoints')
      setEndpointState({ data: data.endpoints, loading: false, error: null })
    } catch (err) {
      setEndpointState(s => ({ ...s, loading: false, error: errorMessage(err) }))
    }
  }, [])

  const fetchDetectionSummary = useCallback(async () => {
    setDetectionSummaryState(s => ({ ...s, loading: true, error: null }))
    try {
      const data = await apiGet<{ summary: DetectionSummary }>('/detections/summary')
      setDetectionSummaryState({ data: data.summary, loading: false, error: null })
    } catch (err) {
      setDetectionSummaryState(s => ({ ...s, loading: false, error: errorMessage(err) }))
    }
  }, [])

  const fetchDetections = useCallback(async () => {
    setDetectionState(s => ({ ...s, loading: true, error: null }))
    try {
      const data = await apiGet<DetectionPage>(`/detections?page=1&limit=${DETECTION_PAGE_SIZE}`)
      setDetectionState({ data: data.detections, loading: false, error: null })
      setDetectionPaging({ total: data.total ?? data.detections.length, page: 1, hasMore: Boolean(data.hasMore) })
    } catch (err) {
      setDetectionState(s => ({ ...s, loading: false, error: errorMessage(err) }))
    }
    fetchDetectionSummary()
  }, [fetchDetectionSummary])

  const loadMoreDetections = useCallback(async () => {
    const next = detectionPaging.page + 1
    setDetectionState(s => ({ ...s, loading: true, error: null }))
    try {
      const data = await apiGet<DetectionPage>(`/detections?page=${next}&limit=${DETECTION_PAGE_SIZE}`)
      setDetectionState(s => {
        const seen = new Set(s.data.map(d => d._id))
        return { data: [...s.data, ...data.detections.filter(d => !seen.has(d._id))], loading: false, error: null }
      })
      setDetectionPaging({ total: data.total, page: next, hasMore: Boolean(data.hasMore) })
    } catch (err) {
      setDetectionState(s => ({ ...s, loading: false, error: errorMessage(err) }))
    }
  }, [detectionPaging.page])

  const fetchCTI = useCallback(async () => {
    setCtiState(s => ({ ...s, loading: true, error: null }))
    try {
      const [myData, feedData] = await Promise.all([
        apiGet<{ reports: CTIReport[] }>('/cti?scope=incidents'),
        apiGet<{ reports: CTIReport[] }>('/cti/feed'),
      ])
      setCtiState({ data: myData.reports || [], loading: false, error: null })
      setFeedState({ data: feedData.reports || [], loading: false, error: null })
    } catch (err) {
      setCtiState(s => ({ ...s, loading: false, error: errorMessage(err) }))
      setFeedState(s => ({ ...s, loading: false, error: errorMessage(err) }))
    }
  }, [])

  const refetchFeed = useCallback(async () => {
    setFeedState(s => ({ ...s, loading: true, error: null }))
    try {
      const feedData = await apiGet<{ reports: CTIReport[] }>('/cti/feed')
      setFeedState({ data: feedData.reports || [], loading: false, error: null })
    } catch (err) {
      setFeedState(s => ({ ...s, loading: false, error: errorMessage(err) }))
    }
  }, [])

  const fetchTeam = useCallback(async () => {
    setTeamState(s => ({ ...s, loading: true, error: null }))
    try {
      const data = await apiGet<{ users: TeamUser[] }>('/users')
      setTeamState({ data: data.users, loading: false, error: null })
    } catch (err) {
      setTeamState(s => ({ ...s, loading: false, error: errorMessage(err) }))
    }
  }, [])

  const fetchInvitations = useCallback(async () => {
    setInvitationState(s => ({ ...s, loading: true, error: null }))
    try {
      const data = await apiGet<{ invitations: Invitation[] }>('/users/invitations')
      setInvitationState({ data: data.invitations, loading: false, error: null })
    } catch (err) {
      setInvitationState(s => ({ ...s, loading: false, error: errorMessage(err) }))
    }
  }, [])

  const fetchAuditLogs = useCallback(async () => {
    setAuditState(s => ({ ...s, loading: true, error: null }))
    try {
      const data = await apiGet<{ logs: AuditLog[] }>('/audit-logs')
      setAuditState({ data: data.logs, loading: false, error: null })
    } catch (err) {
      setAuditState(s => ({ ...s, loading: false, error: errorMessage(err) }))
    }
  }, [])

  const fetchPolicies = useCallback(async () => {
    setPolicyState(s => ({ ...s, loading: true, error: null }))
    try {
      const data = await apiGet<{ policies: Policy[] }>('/policies')
      setPolicyState({ data: data.policies || [], loading: false, error: null })
    } catch (err) {
      setPolicyState(s => ({ ...s, loading: false, error: errorMessage(err) }))
    }
  }, [])

  const fetchCascades = useCallback(async () => {
    setCascadeState(s => ({ ...s, loading: true, error: null }))
    try {
      const data = await apiGet<{ cascades: Cascade[] }>('/cascades')
      setCascadeState({ data: data.cascades || [], loading: false, error: null })
    } catch (err) {
      setCascadeState(s => ({ ...s, loading: false, error: errorMessage(err) }))
    }
  }, [])

  const fetchThreatIntel = useCallback(async () => {
    setThreatIntelState(s => ({ ...s, loading: true, error: null }))
    try {
      const data = await apiGet<{ iocs: ThreatIntelIOC[] }>('/threat-intel/iocs')
      setThreatIntelState({ data: data.iocs || [], loading: false, error: null })
    } catch (err) {
      setThreatIntelState(s => ({ ...s, loading: false, error: errorMessage(err) }))
    }
  }, [])

  // Errors propagate to the caller: a failed request is not an empty timeline.
  const fetchEndpointTimeline = useCallback(async (endpointId: string) => {
    const data = await apiGet<{ events: TimelineEvent[] }>(`/endpoints/${endpointId}/timeline`)
    return data.events || []
  }, [])

  const fetchDetectionTimeline = useCallback(async (detectionId: string) => {
    const data = await apiGet<{ events: TimelineEvent[] }>(`/detections/${detectionId}/timeline`)
    return data.events || []
  }, [])

  // ─── Auth Handlers ────────────────────────────────────────────────────────────

  const handleAuthFailure = useCallback(() => {
    setCurrentUser(null)
    setAccessToken(null)
    disconnectSocket()
  }, [])

  const handleTokenRefreshed = useCallback((newToken: string) => {
    initSocket(newToken)
  }, [])

  useEffect(() => {
    registerAuthFailureHandler(handleAuthFailure)
    registerTokenRefreshHandler(handleTokenRefreshed)
  }, [handleAuthFailure, handleTokenRefreshed])

  // ─── Socket.IO event listeners ────────────────────────────────────────────────

  const setupSocketListeners = useCallback(() => {
    const socket = getSocket()
    if (!socket) return

    socket.off('detection:new')
    socket.off('detection:resolved')
    socket.off('cti:published')
    socket.off('endpoint:new')
    socket.off('endpoint:updated')
    socket.off('endpoint:heartbeat')
    socket.off('endpoint:removed')
    socket.off('policy:triggered')
    socket.off('cascade:created')
    socket.off('cascade:updated')
    socket.off('cti:match')

    socket.on('endpoint:new', (endpoint: Endpoint) => {
      setEndpointState(s => {
        if (s.data.some(e => e._id === endpoint._id)) return s
        return { ...s, data: [endpoint, ...s.data] }
      })
    })

    socket.on('endpoint:updated', (endpoint: Endpoint) => {
      setEndpointState(s => ({
        ...s,
        data: s.data.map(e => (e._id === endpoint._id ? { ...e, ...endpoint } : e)),
      }))
    })

    socket.on('endpoint:heartbeat', (endpoint: Endpoint) => {
      setEndpointState(s => ({
        ...s,
        data: s.data.map(e => (e._id === endpoint._id ? { ...e, ...endpoint, status: endpoint.status || 'ONLINE' } : e)),
      }))
    })

    socket.on('endpoint:removed', ({ endpointId }: { endpointId: string }) => {
      setEndpointState(s => ({
        ...s,
        data: s.data.filter(e => e._id !== endpointId),
      }))
    })

    socket.on('detection:new', (detection: Detection) => {
      // Test records (demonstration or simulated) are not incidents: the server leaves them out of
      // incident lists and counts, so live updates do too.
      if (isTestRecord(detection)) return
      setDetectionState(s => {
        if (s.data.some(d => d._id === detection._id)) return s
        return { ...s, data: [detection, ...s.data] }
      })
      setDetectionPaging(p => ({ ...p, total: p.total + 1 }))
      // Endpoint status comes from the server's 'endpoint:updated' event: a DoS/DDoS
      // detection is alert-only and does not move the endpoint to AT_RISK.
      fetchDetectionSummary()
      showToast(
        buildDetectionToast(detection),
        detection.severity === 'CRITICAL' || detection.severity === 'HIGH' ? 'error' : 'info',
      )
    })

    socket.on('detection:resolved', (detection: Detection) => {
      setDetectionState(s => ({
        ...s,
        data: s.data.map(d => (d._id === detection._id ? detection : d)),
      }))
      fetchEndpoints()
      fetchDetectionSummary()
      showToast(
        `Detection on ${detection.endpointName} marked as ${detection.status === 'FALSE_POSITIVE' ? 'False Positive' : 'Resolved'}`,
        'success',
      )
    })

    socket.on('cti:published', (report: CTIReport) => {
      if (isDemoReport(report)) return
      setCtiState(s => {
        const exists = s.data.some(r => r._id === report._id || (r.reportId && r.reportId === report.reportId))
        if (exists) {
          return {
            ...s,
            data: s.data.map(r => (r._id === report._id || r.reportId === report.reportId ? report : r)),
          }
        }
        return { ...s, data: [report, ...s.data] }
      })
      setFeedState(s => {
        const exists = s.data.some(r => r._id === report._id || (r.reportId && r.reportId === report.reportId))
        if (exists) {
          return {
            ...s,
            data: s.data.map(r => (r._id === report._id || r.reportId === report.reportId ? report : r)),
          }
        }
        return { ...s, data: [report, ...s.data] }
      })
      showToast(report.reportId ? `CTI report ${report.reportId} anchored on Polygon Amoy` : 'CTI report anchored on Polygon Amoy', 'success')
    })

    socket.on('policy:triggered', (data: { policyId: string; policyName: string; action: string; endpointId?: string; endpointName?: string }) => {
      fetchPolicies()
      fetchEndpoints()
      showToast(
        `Automated Policy [${data.policyName}] triggered action ${data.action} on ${data.endpointName || data.endpointId || 'system'}`,
        'error',
      )
    })

    socket.on('cascade:created', (cascade: Cascade) => {
      setCascadeState(s => {
        if (s.data.some(c => c._id === cascade._id)) return s
        return { ...s, data: [cascade, ...s.data] }
      })
      showToast(
        `Cross-Endpoint Attack Detected: ${cascade.title} (${cascade.affectedEndpointIds.length} endpoints affected)`,
        'error',
      )
    })

    socket.on('cascade:updated', (cascade: Cascade) => {
      setCascadeState(s => ({
        ...s,
        data: s.data.map(c => (c._id === cascade._id ? cascade : c)),
      }))
    })

    socket.on('cti:match', (match: CTIMatchResult) => {
      showToast(
        `CTI Threat Match: ${match.indicator} (${match.threatCategory || match.type}) [${match.confidence}% confidence]`,
        'warning',
      )
    })
  }, [showToast, fetchEndpoints, fetchPolicies])

  // Periodic polling for live heartbeat/detection/cascade sync
  useEffect(() => {
    if (!currentUser) return
    const interval = setInterval(() => {
      fetchEndpoints()
      fetchDetections()
      fetchCascades()
    }, 8000)
    return () => clearInterval(interval)
  }, [currentUser, fetchEndpoints, fetchDetections, fetchCascades])

  // Session Restoration Effect
  useEffect(() => {
    restoreSession().then(async user => {
      if (user) {
        setCurrentUser(user)
        const token = getAccessToken()
        if (token) {
          const socket = initSocket(token)
          socket.on('connect', () => setupSocketListeners())
          setupSocketListeners()
        }

        await Promise.all([
          fetchEndpoints(),
          fetchDetections(),
          fetchCTI(),
          fetchTeam(),
          fetchPolicies(),
          fetchCascades(),
          fetchThreatIntel(),
          ...(user.role === 'ORG_ADMIN' ? [fetchAuditLogs(), fetchInvitations()] : []),
        ]).catch(() => {})
      } else {
        setCurrentUser(null)
      }
      setIsInitializing(false)
    }).catch(() => {
      setCurrentUser(null)
      setIsInitializing(false)
    })
  }, [fetchEndpoints, fetchDetections, fetchCTI, fetchTeam, fetchPolicies, fetchCascades, fetchThreatIntel, fetchAuditLogs, fetchInvitations, setupSocketListeners])

  // Route Protection Effect
  useEffect(() => {
    if (isInitializing) return
    const isPublic = PUBLIC_PATHS.includes(pathname)
    if (!currentUser && !isPublic) {
      router.push('/login')
    }
  }, [currentUser, isInitializing, pathname, router])

  const login = useCallback(async (email: string, password: string) => {
    const data = await apiPost<{ accessToken: string; user: CurrentUser }>('/auth/login', { email, password })
    setAccessToken(data.accessToken)
    setCurrentUser(data.user)
    const socket = initSocket(data.accessToken)
    socket.on('connect', () => setupSocketListeners())
    setupSocketListeners()

    router.push('/dashboard')

    await Promise.all([
      fetchEndpoints(),
      fetchDetections(),
      fetchCTI(),
      fetchTeam(),
      fetchPolicies(),
      fetchCascades(),
      fetchThreatIntel(),
      ...(data.user.role === 'ORG_ADMIN' ? [fetchAuditLogs(), fetchInvitations()] : []),
    ]).catch(() => {})

    showToast(`Welcome back, ${data.user.name.split(' ')[0]}!`, 'success')
  }, [router, fetchEndpoints, fetchDetections, fetchCTI, fetchTeam, fetchPolicies, fetchCascades, fetchThreatIntel, fetchAuditLogs, fetchInvitations, showToast, setupSocketListeners])

  const logout = useCallback(async () => {
    try {
      await apiPost('/auth/logout')
    } catch {
      // Best-effort
    }
    setAccessToken(null)
    disconnectSocket()
    setCurrentUser(null)
    router.push('/login')
    showToast('Logged out successfully', 'info')
  }, [router, showToast])

  // ─── Policy Mutations ────────────────────────────────────────────────────────

  const createPolicy = useCallback(async (data: Partial<Policy>): Promise<Policy> => {
    try {
      const res = await apiPost<{ policy: Policy }>('/policies', data)
      setPolicyState(s => ({ ...s, data: [res.policy, ...s.data] }))
      showToast(`Policy "${res.policy.name}" created successfully`, 'success')
      return res.policy
    } catch (err: any) {
      showToast(err.message || 'Failed to create policy', 'error')
      throw err
    }
  }, [showToast])

  const updatePolicy = useCallback(async (id: string, data: Partial<Policy>): Promise<Policy> => {
    try {
      const res = await apiPatch<{ policy: Policy }>(`/policies/${id}`, data)
      setPolicyState(s => ({
        ...s,
        data: s.data.map(p => (p._id === id ? res.policy : p)),
      }))
      showToast(`Policy "${res.policy.name}" updated`, 'success')
      return res.policy
    } catch (err: any) {
      showToast(err.message || 'Failed to update policy', 'error')
      throw err
    }
  }, [showToast])

  const togglePolicy = useCallback(async (id: string, enabled?: boolean): Promise<Policy> => {
    try {
      const res = await apiPatch<{ policy: Policy }>(`/policies/${id}/toggle`, { enabled })
      setPolicyState(s => ({
        ...s,
        data: s.data.map(p => (p._id === id ? res.policy : p)),
      }))
      showToast(`Policy "${res.policy.name}" ${res.policy.enabled ? 'enabled' : 'disabled'}`, 'success')
      return res.policy
    } catch (err: any) {
      showToast(err.message || 'Failed to toggle policy', 'error')
      throw err
    }
  }, [showToast])

  const deletePolicy = useCallback(async (id: string): Promise<void> => {
    try {
      await apiDelete(`/policies/${id}`)
      setPolicyState(s => ({
        ...s,
        data: s.data.filter(p => p._id !== id),
      }))
      showToast('Policy deleted', 'success')
    } catch (err: any) {
      showToast(err.message || 'Failed to delete policy', 'error')
      throw err
    }
  }, [showToast])

  // ─── Cascade Mutations ───────────────────────────────────────────────────────

  const containCascade = useCallback(async (id: string) => {
    try {
      const res = await apiPost<{ cascade: Cascade; isolatedEndpoints: string[] }>(`/cascades/${id}/contain`)
      setCascadeState(s => ({
        ...s,
        data: s.data.map(c => (c._id === id ? res.cascade : c)),
      }))
      await fetchEndpoints()
      showToast(`Cascade contained! Isolated ${res.isolatedEndpoints.length} affected endpoints`, 'success')
      return res
    } catch (err: any) {
      showToast(err.message || 'Failed to contain cascade', 'error')
      throw err
    }
  }, [showToast, fetchEndpoints])

  const resolveCascade = useCallback(async (id: string): Promise<Cascade> => {
    try {
      const res = await apiPost<{ cascade: Cascade }>(`/cascades/${id}/resolve`)
      setCascadeState(s => ({
        ...s,
        data: s.data.map(c => (c._id === id ? res.cascade : c)),
      }))
      showToast('Cascade marked as resolved', 'success')
      return res.cascade
    } catch (err: any) {
      showToast(err.message || 'Failed to resolve cascade', 'error')
      throw err
    }
  }, [showToast])

  // ─── Threat Intel Lookup ────────────────────────────────────────────────────

  const lookupIOC = useCallback(async (indicator: string, type?: string): Promise<CTIMatchResult> => {
    try {
      const res = await apiPost<{ match: CTIMatchResult }>('/threat-intel/lookup', { indicator, type })
      return res.match
    } catch (err: any) {
      showToast(err.message || 'CTI lookup failed', 'error')
      throw err
    }
  }, [showToast])

  // ─── Mutations ────────────────────────────────────────────────────────────────

  const generateInvitation = useCallback(async (): Promise<Invitation> => {
    const data = await apiPost<{ invitation: Invitation }>('/users/invitations')
    setInvitationState(s => ({ ...s, data: [data.invitation, ...s.data] }))
    showToast(`Invitation code ${data.invitation.code} generated`, 'success')
    return data.invitation
  }, [showToast])

  const addEndpoint = useCallback(async (name: string) => {
    try {
      const data = await apiPost<{ endpoint: Endpoint; activationToken: string; installInstructions: string }>('/endpoints', { name })
      setEndpointState(s => ({ ...s, data: [...s.data, data.endpoint] }))
      showToast(`Endpoint "${name}" added successfully`, 'success')
      return data
    } catch (err) {
      showToast(`Could not add endpoint: ${errorMessage(err)}`, 'error')
      throw err
    }
  }, [showToast])

  const removeEndpoint = useCallback(async (id: string) => {
    try {
      await apiDelete(`/endpoints/${id}`)
    } catch (err) {
      showToast(`Could not remove endpoint: ${errorMessage(err)}`, 'error')
      throw err
    }
    setEndpointState(s => ({ ...s, data: s.data.filter(e => e._id !== id) }))
    showToast('Endpoint removed', 'success')
  }, [showToast])

  const isolateEndpoint = useCallback(async (id: string, reason?: string) => {
    try {
      const data = await apiPost<{ endpoint: Endpoint; action: any }>(`/endpoints/${id}/isolate`, { reason })
      setEndpointState(s => ({
        ...s,
        data: s.data.map(e => (e._id === id ? { ...e, ...data.endpoint, status: 'ISOLATED' } : e)),
      }))
      showToast(`Endpoint ${data.endpoint.name || id} isolated successfully`, 'success')
    } catch (err: any) {
      // The endpoint's state is unchanged: never show an isolation that did not happen.
      showToast(`Isolation failed: ${errorMessage(err)}`, 'error')
    }
  }, [showToast])

  const unisolateEndpoint = useCallback(async (id: string) => {
    try {
      const data = await apiPost<{ endpoint: Endpoint; action: any }>(`/endpoints/${id}/unisolate`)
      setEndpointState(s => ({
        ...s,
        data: s.data.map(e => (e._id === id ? { ...e, ...data.endpoint } : e)),
      }))
      showToast(`Isolation released for endpoint ${data.endpoint.name || id}`, 'success')
    } catch (err: any) {
      showToast(`Could not release isolation: ${errorMessage(err)}`, 'error')
    }
  }, [showToast])

  const resolveDetection = useCallback(async (id: string, outcome: 'RESOLVED' | 'FALSE_POSITIVE' = 'RESOLVED') => {
    try {
      const data = await apiPost<{ detection: Detection }>(`/detections/${id}/resolve`, { outcome })
      setDetectionState(s => ({
        ...s,
        data: s.data.map(d => (d._id === id ? data.detection : d)),
      }))
      await fetchEndpoints()
      showToast(`Detection marked as ${outcome === 'FALSE_POSITIVE' ? 'False Positive' : 'Resolved'}`, 'success')
    } catch (err: any) {
      showToast(err.message || 'Failed to resolve detection', 'error')
      throw err
    }
  }, [showToast, fetchEndpoints])

  const generateCTI = useCallback(async (detectionId: string): Promise<CTIReport> => {
    try {
      const data = await apiPost<{ report: CTIReport }>('/cti', { detectionId })
      const report = data.report
      setCtiState(s => {
        const exists = s.data.some(r => r._id === report._id || (r.reportId && r.reportId === report.reportId))
        if (exists) {
          return {
            ...s,
            data: s.data.map(r => r._id === report._id || r.reportId === report.reportId ? report : r),
          }
        }
        return { ...s, data: [report, ...s.data] }
      })
      showToast('Structured CTI report generated from detection', 'success')
      return report
    } catch (err: any) {
      showToast(err.message || 'Failed to generate CTI draft', 'error')
      throw err
    }
  }, [showToast])

  const updateCTIDraft = useCallback(async (
    id: string,
    body: Partial<Pick<CTIReport, 'attackSummary' | 'analystNotes' | 'indicatorsOfCompromise' | 'recommendedActions'>>,
  ) => {
    try {
      const data = await apiPatch<{ report: CTIReport }>(`/cti/${id}`, body)
      setCtiState(s => ({
        ...s,
        data: s.data.map(r => (r._id === id || r.reportId === id ? data.report : r)),
      }))
      showToast('Draft saved', 'success')
    } catch (err: any) {
      showToast(err.message || 'Failed to save draft', 'error')
      throw err
    }
  }, [showToast])

  const publishCTI = useCallback(async (id: string) => {
    const replace = (report: CTIReport) => {
      const match = (r: CTIReport) => r._id === id || r.reportId === id || r._id === report._id
      setCtiState(s => ({ ...s, data: s.data.map(r => (match(r) ? report : r)) }))
      setFeedState(s => {
        const rest = s.data.filter(r => !match(r))
        // The feed only lists reports with a confirmed on-chain anchor.
        return { ...s, data: report.status === 'PUBLISHED' ? [report, ...rest] : rest }
      })
    }
    try {
      const data = await apiPost<{ report: CTIReport; pending?: boolean; message?: string }>(`/cti/${id}/publish`)
      replace(data.report)
      if (data.pending) {
        showToast(data.message || 'Transaction submitted; awaiting confirmation. Publish again to re-check.', 'warning')
      } else if (data.report.verificationStatus === 'VERIFIED') {
        showToast(`Anchored on Polygon Amoy in block ${data.report.blockNumber} and verified on-chain`, 'success')
      } else {
        showToast(`Anchored in block ${data.report.blockNumber}; on-chain read-back pending, use Verify Report`, 'warning')
      }
      return data.report
    } catch (err: any) {
      // Reflect the server's real state (FAILED, or PUBLISHING with a pending tx)
      try {
        const fresh = await apiGet<{ report: CTIReport }>(`/cti/${id}`)
        replace(fresh.report)
      } catch {
        /* keep current state */
      }
      showToast(err.message || 'Failed to publish CTI Report to blockchain', 'error')
      throw err
    }
  }, [showToast])

  const verifyCTI = useCallback(async (id: string): Promise<CTIVerificationResult> => {
    try {
      const data = await apiGet<{ verification: CTIVerificationResult }>(`/cti/${id}/verify`)
      const ver = data.verification
      setCtiState(s => ({
        ...s,
        data: s.data.map(r => (r._id === id || r.reportId === id ? { ...r, verificationStatus: ver.status === 'UNAVAILABLE' ? r.verificationStatus : ver.status } : r)),
      }))
      setFeedState(s => ({
        ...s,
        data: s.data.map(r => (r._id === id || r.reportId === id ? { ...r, verificationStatus: ver.status === 'UNAVAILABLE' ? r.verificationStatus : ver.status } : r)),
      }))
      if (ver.status === 'VERIFIED') {
        showToast('Report verified: On-chain content hash matches perfectly', 'success')
      } else if (ver.status === 'TAMPERED') {
        showToast('TAMPER ALERT: Stored report content does not match on-chain hash!', 'error')
      } else if (ver.status === 'UNANCHORED') {
        showToast(ver.error || 'Report is not anchored on-chain', 'warning')
      } else if (ver.status === 'UNAVAILABLE') {
        showToast(ver.error || 'Verification unavailable: could not query Polygon Amoy', 'warning')
      } else {
        showToast('Report was published by an unauthorized publisher', 'error')
      }
      return ver
    } catch (err: any) {
      showToast(err.message || 'Failed to verify CTI report', 'error')
      throw err
    }
  }, [showToast])

  const discardCTI = useCallback(async (id: string) => {
    try {
      await apiDelete(`/cti/${id}`)
    } catch (err) {
      showToast(`Could not discard draft: ${errorMessage(err)}`, 'error')
      throw err
    }
    setCtiState(s => ({ ...s, data: s.data.filter(r => r._id !== id) }))
    showToast('Draft discarded', 'info')
  }, [showToast])

  const shareReport = useCallback(async (
    id: string,
    visibility: 'PRIVATE' | 'SHARED_SELECTED' | 'SHARED_ALL',
    sharedWithOrgIds?: string[],
  ): Promise<CTIReport> => {
    try {
      const data = await apiPost<{ report: CTIReport }>(`/cti/${id}/share`, { visibility, sharedWithOrgIds })
      setCtiState(s => ({ ...s, data: s.data.map(r => (r._id === id || r.reportId === id ? { ...r, ...data.report } : r)) }))
      showToast(
        visibility === 'PRIVATE' ? 'Report set to private'
          : visibility === 'SHARED_ALL' ? 'Report shared with all organizations'
          : `Report shared with ${sharedWithOrgIds?.length ?? 0} organization(s)`,
        'success',
      )
      return data.report
    } catch (err) {
      showToast(`Could not update sharing: ${errorMessage(err)}`, 'error')
      throw err
    }
  }, [showToast])

  const fetchShareTargets = useCallback(async (): Promise<{ id: string; name: string }[]> => {
    const data = await apiGet<{ organizations: { id: string; name: string }[] }>('/cti/share-targets')
    return data.organizations
  }, [])

  const inviteUser = useCallback(async (userData: { name: string; email: string; temporaryPassword: string; role: UserRole }) => {
    try {
      await apiPost('/users', userData)
    } catch (err) {
      showToast(`Could not invite ${userData.email}: ${errorMessage(err)}`, 'error')
      throw err
    }
    await fetchTeam()
    showToast(`Account created for ${userData.email}. Share the temporary password with them securely; no email is sent.`, 'success')
  }, [fetchTeam, showToast])

  const changeUserRole = useCallback(async (id: string, role: UserRole) => {
    try {
      await apiPatch(`/users/${id}/role`, { role })
    } catch (err) {
      showToast(`Could not change role: ${errorMessage(err)}`, 'error')
      throw err
    }
    setTeamState(s => ({
      ...s,
      data: s.data.map(u => (u._id === id ? { ...u, role } : u)),
    }))
    showToast('Role updated', 'success')
  }, [showToast])

  const toggleUserActive = useCallback(async (id: string, currentlyActive: boolean) => {
    try {
      if (currentlyActive) {
        await apiPatch(`/users/${id}/deactivate`)
      } else {
        await apiPatch(`/users/${id}/reactivate`)
      }
    } catch (err) {
      showToast(`Could not update user: ${errorMessage(err)}`, 'error')
      throw err
    }
    setTeamState(s => ({
      ...s,
      data: s.data.map(u => (u._id === id ? { ...u, isActive: !currentlyActive } : u)),
    }))
    showToast('User status updated', 'success')
  }, [showToast])

  // ─── Context Value ────────────────────────────────────────────────────────────

  const ctx: AppContextType = {
    currentUser,
    login,
    logout,
    page,
    pageParams,
    navigate,
    toasts,
    showToast,
    dismissToast,

    endpoints: endpointState.data,
    endpointsLoading: endpointState.loading,
    endpointsError: endpointState.error,
    refetchEndpoints: fetchEndpoints,

    detections: detectionState.data,
    detectionsLoading: detectionState.loading,
    detectionsError: detectionState.error,
    refetchDetections: fetchDetections,
    detectionsTotal: detectionPaging.total,
    detectionsHasMore: detectionPaging.hasMore,
    loadMoreDetections,
    detectionSummary: detectionSummaryState.data,
    detectionSummaryLoading: detectionSummaryState.loading,
    detectionSummaryError: detectionSummaryState.error,
    refetchDetectionSummary: fetchDetectionSummary,

    ctiReports: ctiState.data,
    ctiLoading: ctiState.loading,
    ctiError: ctiState.error,
    refetchCTI: fetchCTI,

    teamUsers: teamState.data,
    teamLoading: teamState.loading,
    teamError: teamState.error,
    refetchTeam: fetchTeam,

    invitations: invitationState.data,
    invitationsLoading: invitationState.loading,
    invitationsError: invitationState.error,
    refetchInvitations: fetchInvitations,

    auditLogs: auditState.data,
    auditLogsLoading: auditState.loading,
    auditLogsError: auditState.error,
    refetchAuditLogs: fetchAuditLogs,

    globalFeed: feedState.data,
    feedLoading: feedState.loading,
    feedError: feedState.error,
    refetchFeed,

    // Policies
    policies: policyState.data,
    policiesLoading: policyState.loading,
    policiesError: policyState.error,
    refetchPolicies: fetchPolicies,
    createPolicy,
    updatePolicy,
    togglePolicy,
    deletePolicy,

    // Cascades
    cascades: cascadeState.data,
    cascadesLoading: cascadeState.loading,
    cascadesError: cascadeState.error,
    refetchCascades: fetchCascades,
    containCascade,
    resolveCascade,

    // Threat Intel
    threatIntelIocs: threatIntelState.data,
    threatIntelLoading: threatIntelState.loading,
    refetchThreatIntel: fetchThreatIntel,
    lookupIOC,

    fetchEndpointTimeline,
    fetchDetectionTimeline,

    addEndpoint,
    removeEndpoint,
    isolateEndpoint,
    unisolateEndpoint,
    resolveDetection,
    generateCTI,
    updateCTIDraft,
    publishCTI,
    verifyCTI,
    discardCTI,
    shareReport,
    fetchShareTargets,
    inviteUser,
    generateInvitation,
    changeUserRole,
    toggleUserActive,
  }

  const isPublicRoute = PUBLIC_PATHS.includes(pathname)

  if (isInitializing && !isPublicRoute) {
    return (
      <div className="min-h-screen bg-slate-50 flex flex-col items-center justify-center space-y-4">
        <div className="w-8 h-8 border-4 border-[#17313E] border-t-transparent rounded-full animate-spin" />
        <p className="text-sm font-medium text-slate-500">Verifying session...</p>
      </div>
    )
  }

  if (!currentUser && !isPublicRoute) {
    return null
  }

  return (
    <AppContext.Provider value={ctx}>
      {children}

      {/* Toast stack */}
      <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2">
        {toasts.map(t => (
          <ToastItem key={t.id} toast={t} onDismiss={() => dismissToast(t.id)} />
        ))}
      </div>
    </AppContext.Provider>
  )
}
