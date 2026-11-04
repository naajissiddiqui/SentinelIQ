import { createContext, useContext } from 'react'
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
  DetectionSummary,
} from './types'

export interface AppContextType {
  // Auth
  currentUser: CurrentUser | null
  login: (email: string, password: string) => Promise<void>
  logout: () => void

  // Navigation
  page: string
  pageParams: Record<string, string>
  navigate: (page: string, params?: Record<string, string>) => void

  // Toasts
  toasts: Toast[]
  showToast: (message: string, type?: Toast['type']) => void
  dismissToast: (id: string) => void

  // Data lists + loading/error/refetch
  endpoints: Endpoint[]
  endpointsLoading: boolean
  endpointsError: string | null
  refetchEndpoints: () => void

  detections: Detection[]
  detectionsLoading: boolean
  detectionsError: string | null
  refetchDetections: () => void
  /** Detections matching the server query (all of them), not just the loaded page. */
  detectionsTotal: number
  detectionsHasMore: boolean
  loadMoreDetections: () => Promise<void>
  /** Organisation-wide counts computed by the server (GET /detections/summary). */
  detectionSummary: DetectionSummary | null
  detectionSummaryLoading: boolean
  detectionSummaryError: string | null
  refetchDetectionSummary: () => void

  ctiReports: CTIReport[]
  ctiLoading: boolean
  ctiError: string | null
  refetchCTI: () => void

  teamUsers: TeamUser[]
  teamLoading: boolean
  teamError: string | null
  refetchTeam: () => void

  invitations: Invitation[]
  invitationsLoading: boolean
  invitationsError: string | null
  refetchInvitations: () => void

  auditLogs: AuditLog[]
  auditLogsLoading: boolean
  auditLogsError: string | null
  refetchAuditLogs: () => void

  globalFeed: CTIReport[]
  feedLoading: boolean
  feedError: string | null
  refetchFeed: () => void

  // Policies
  policies: Policy[]
  policiesLoading: boolean
  policiesError: string | null
  refetchPolicies: () => void
  createPolicy: (data: Partial<Policy>) => Promise<Policy>
  updatePolicy: (id: string, data: Partial<Policy>) => Promise<Policy>
  togglePolicy: (id: string, enabled?: boolean) => Promise<Policy>
  deletePolicy: (id: string) => Promise<void>

  // Attack Cascades
  cascades: Cascade[]
  cascadesLoading: boolean
  cascadesError: string | null
  refetchCascades: () => void
  containCascade: (id: string) => Promise<{ cascade: Cascade; isolatedEndpoints: string[] }>
  resolveCascade: (id: string) => Promise<Cascade>

  // Threat Intelligence
  threatIntelIocs: ThreatIntelIOC[]
  threatIntelLoading: boolean
  refetchThreatIntel: () => void
  lookupIOC: (indicator: string, type?: string) => Promise<CTIMatchResult>

  // Timeline
  fetchEndpointTimeline: (endpointId: string) => Promise<TimelineEvent[]>
  fetchDetectionTimeline: (detectionId: string) => Promise<TimelineEvent[]>

  // Mutations
  addEndpoint: (name: string) => Promise<{ endpoint: Endpoint; activationToken: string; installInstructions: string }>
  removeEndpoint: (id: string) => Promise<void>
  isolateEndpoint: (id: string, reason?: string) => Promise<void>
  unisolateEndpoint: (id: string) => Promise<void>
  resolveDetection: (id: string, outcome?: 'RESOLVED' | 'FALSE_POSITIVE') => Promise<void>
  generateCTI: (detectionId: string) => Promise<CTIReport>
  updateCTIDraft: (id: string, data: Partial<Pick<CTIReport, 'attackSummary' | 'analystNotes' | 'indicatorsOfCompromise' | 'recommendedActions'>>) => Promise<void>
  publishCTI: (id: string) => Promise<CTIReport>
  verifyCTI: (id: string) => Promise<CTIVerificationResult>
  discardCTI: (id: string) => Promise<void>
  shareReport: (id: string, visibility: 'PRIVATE' | 'SHARED_SELECTED' | 'SHARED_ALL', sharedWithOrgIds?: string[]) => Promise<CTIReport>
  fetchShareTargets: () => Promise<{ id: string; name: string }[]>
  inviteUser: (data: { name: string; email: string; temporaryPassword: string; role: UserRole }) => Promise<void>
  generateInvitation: () => Promise<Invitation>
  changeUserRole: (id: string, role: UserRole) => Promise<void>
  toggleUserActive: (id: string, currentlyActive: boolean) => Promise<void>
}

export const AppContext = createContext<AppContextType | null>(null)

export function useApp(): AppContextType {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('useApp must be used within AppContext.Provider')
  return ctx
}
