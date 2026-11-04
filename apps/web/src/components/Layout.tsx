'use client'

import { type ReactNode } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import {
  Shield,
  LayoutDashboard,
  Monitor,
  AlertTriangle,
  FileText,
  Globe,
  Settings,
  Bell,
  ShieldCheck,
  Users,
  LogOut,
  SlidersHorizontal,
  Radio,
  Database,
} from 'lucide-react'
import { useApp } from '@/lib/context'
import { P, STORM, BG, TEXT, MUTED, BORDER, RED } from './ui'

const NAV = [
  { id: 'dashboard', label: 'Dashboard', path: '/dashboard', Icon: LayoutDashboard },
  { id: 'endpoints', label: 'Endpoints', path: '/endpoints', Icon: Monitor },
  { id: 'detections', label: 'Detections', path: '/detections', Icon: AlertTriangle },
  { id: 'cascades', label: 'Attack Cascades', path: '/cascades', Icon: Radio },
  { id: 'policies', label: 'Response Policies', path: '/policies', Icon: SlidersHorizontal },
  { id: 'threat-intel', label: 'Threat Intel (CTI)', path: '/threat-intel', Icon: Database },
  { id: 'cti-center', label: 'CTI Reports', path: '/cti-center', Icon: FileText },
  { id: 'cti-feed', label: 'CTI Feed', path: '/cti-feed', Icon: Globe },
  { id: 'blockchain-verification', label: 'Verify Report', path: '/blockchain-verification', Icon: ShieldCheck },
  { id: 'team', label: 'Team', path: '/team', Icon: Users },
  // Hidden from the sidebar; the /audit-logs page still exists.
  // { id: 'audit-logs', label: 'Audit Log', path: '/audit-logs', Icon: ClipboardList },
]

const ROLE_LABELS: Record<string, string> = {
  ORG_ADMIN: 'Org Admin',
  SECURITY_ANALYST: 'Security Analyst',
  SUPER_ADMIN: 'Super Admin',
}

export default function Layout({ children }: { children: ReactNode }) {
  const router = useRouter()
  const pathname = usePathname()
  const { currentUser, logout, detections } = useApp()
  const activeDetections = detections.filter(d => d.status === 'NEW' || d.status === 'INVESTIGATING').length

  const initials = currentUser?.name
    ? currentUser.name
        .split(' ')
        .map(n => n[0])
        .join('')
        .substring(0, 2)
        .toUpperCase()
    : 'U'

  const roleLabel = (currentUser?.role && ROLE_LABELS[currentUser.role]) || 'User'

  return (
    <div className="flex h-screen overflow-hidden" style={{ backgroundColor: BG }}>
      {/* Sidebar */}
      <aside className="w-[240px] flex-shrink-0 flex flex-col bg-white border-r" style={{ borderColor: BORDER }}>
        <div className="flex items-center gap-2.5 px-5 py-[18px] border-b" style={{ borderColor: BORDER }}>
          <div className="w-7 h-7 rounded-md flex items-center justify-center" style={{ backgroundColor: P }}>
            <Shield className="w-3.5 h-3.5 text-white" />
          </div>
          <span className="font-bold text-[15px]" style={{ color: TEXT }}>SentinelIQ</span>
        </div>

        <nav className="flex-1 px-3 py-4 flex flex-col gap-0.5 overflow-y-auto">
          {NAV.map(({ id, label, path, Icon }) => {
            const active = pathname === path || (pathname === '/' && id === 'dashboard');
            return (
              <button
                key={id}
                onClick={() => router.push(path)}
                className="flex items-center gap-3 px-3 py-2 rounded-lg text-[13px] font-medium w-full text-left transition-colors cursor-pointer"
                style={{
                  backgroundColor: active ? "rgba(23,49,62,0.08)" : "transparent",
                  color: active ? P : MUTED,
                }}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                {label}
              </button>
            );
          })}
          <button
            onClick={() => router.push('/settings')}
            className="flex items-center gap-3 px-3 py-2 rounded-lg text-[13px] font-medium w-full text-left mt-auto cursor-pointer"
            style={{
              backgroundColor: pathname === '/settings' ? "rgba(23,49,62,0.08)" : "transparent",
              color: pathname === '/settings' ? P : MUTED,
            }}
          >
            <Settings className="w-4 h-4 flex-shrink-0" />
            Settings
          </button>
        </nav>

        {/* User Card & Logout */}
        <div className="px-4 py-4 border-t flex items-center justify-between gap-2" style={{ borderColor: BORDER }}>
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-full flex items-center justify-center text-white text-[11px] font-bold flex-shrink-0"
              style={{ backgroundColor: STORM }}>
              {initials}
            </div>
            <div className="min-w-0">
              <p className="text-[12px] font-semibold truncate" style={{ color: TEXT }}>
                {currentUser?.name || 'User'}
              </p>
              <p className="text-[11px] truncate" style={{ color: MUTED }}>
                {roleLabel}
              </p>
            </div>
          </div>

          <button
            onClick={logout}
            title="Sign out"
            className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors cursor-pointer flex-shrink-0"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </aside>

      {/* Right side */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar */}
        <header className="h-16 flex-shrink-0 flex items-center px-6 gap-4 bg-white border-b" style={{ borderColor: BORDER }}>
          <div className="flex items-center gap-1.5 flex-shrink-0">
            <span className="text-[13px] font-semibold" style={{ color: TEXT }}>
              Security Operations
            </span>
          </div>
          <div className="flex-1" />
          <div className="flex items-center gap-3 flex-shrink-0">
            <button
              onClick={() => router.push('/detections')}
              title={activeDetections > 0 ? `${activeDetections} active detection${activeDetections === 1 ? '' : 's'} need review` : 'No active detections'}
              aria-label="Active detections"
              className="relative p-1.5 rounded-lg hover:bg-gray-50 transition-colors cursor-pointer"
            >
              <Bell className="w-4 h-4" style={{ color: MUTED }} />
              {activeDetections > 0 && (
                <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full border-2 border-white"
                  style={{ backgroundColor: RED }} />
              )}
            </button>
            <div className="w-8 h-8 rounded-full flex items-center justify-center text-white text-[11px] font-bold"
              style={{ backgroundColor: STORM }}>
              {initials}
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto">{children}</main>
      </div>
    </div>
  )
}
