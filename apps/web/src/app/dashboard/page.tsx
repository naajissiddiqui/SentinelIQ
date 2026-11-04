'use client'

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import Layout from '@/components/Layout'
import { Globe, ShieldCheck, Radio, SlidersHorizontal, Database, Flame, Zap, ArrowRight } from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell,
} from 'recharts'
import {
  STORM, LAV, TEXT, MUTED, BORDER, RED, AMBER, GREEN,
  StatusBadge, ScoreBadge,
} from '@/components/ui'
import { useApp } from '@/lib/context'

function DashboardContent() {
  const router = useRouter()
  const {
    endpoints, detections, ctiReports, globalFeed, policies, cascades,
    endpointsError, refetchEndpoints,
    detectionSummary, detectionSummaryLoading, detectionSummaryError, refetchDetectionSummary,
  } = useApp()
  // Detection counts come from the server summary (all records), never from the loaded page.
  const summary = detectionSummary

  // ── 1. Endpoint status metrics ───────────────────────────────────────────────
  const totalEndpoints = endpoints.length
  const onlineCount = endpoints.filter(e => e.status === 'ONLINE').length
  const offlineCount = endpoints.filter(e => e.status === 'OFFLINE' || e.status === 'PENDING').length
  const atRiskCount = endpoints.filter(e => e.status === 'AT_RISK').length
  const isolatedCount = endpoints.filter(e => e.status === 'ISOLATED').length

  // ── 2. Detection metrics ─────────────────────────────────────────────────────
  const activeDetections = summary ? summary.active : null

  // ── 3. CTI metrics ───────────────────────────────────────────────────────────
  const ctiPublished = ctiReports.filter(r => r.status === 'PUBLISHED').length
  const ctiReceived = globalFeed.length
  const ctiMatchCount = summary ? summary.ctiMatched : '—'

  // ── 3b. Policy & Cascade metrics ─────────────────────────────────────────────
  const activePoliciesCount = policies.filter(p => p.enabled).length
  const totalPolicyTriggers = policies.reduce((sum, p) => sum + (p.triggerCount || 0), 0)
  const activeCascadesCount = cascades.filter(c => c.status === 'ACTIVE').length

  // ── 4. 30-day detection timeline ─────────────────────────────────────────────
  const lineData = useMemo(
    () => (summary?.timeline ?? []).map((day) => ({ d: day.date.slice(5), dateStr: day.date, v: day.count })),
    [summary],
  )
  const windowTotal = lineData.reduce((n, day) => n + day.v, 0)

  // ── 5. Donut chart datasets ──────────────────────────────────────────────────
  const pieData = useMemo(() => [
    { name: "Online", value: onlineCount, color: GREEN },
    { name: "Offline", value: offlineCount, color: MUTED },
    { name: "At Risk", value: atRiskCount, color: AMBER },
    ...(isolatedCount > 0 ? [{ name: "Isolated", value: isolatedCount, color: "#9333EA" }] : []),
  ], [onlineCount, offlineCount, atRiskCount, isolatedCount])

  const hasEndpoints = totalEndpoints > 0
  const renderedPieData = hasEndpoints
    ? pieData
    : [{ name: "No Endpoints", value: 1, color: BORDER }]

  // ── 6. Risk distribution breakdown ───────────────────────────────────────────
  const riskData = useMemo(() => {
    const sev = summary?.bySeverity ?? {}
    const rows = [
      { label: "Low", count: sev.LOW ?? 0, color: GREEN },
      { label: "Medium", count: sev.MEDIUM ?? 0, color: AMBER },
      { label: "High", count: sev.HIGH ?? 0, color: "#F97316" },
      { label: "Critical", count: sev.CRITICAL ?? 0, color: RED },
    ]
    const total = rows.reduce((n, r) => n + r.count, 0)
    return rows.map(r => ({ ...r, pct: total > 0 ? (r.count / total) * 100 : 0 }))
  }, [summary])

  const originRows = [
    { label: "Recorded traffic", count: summary?.byDataOrigin.PCAP_REPLAY ?? 0 },
    { label: "Live telemetry", count: summary?.byDataOrigin.LIVE ?? 0 },
    { label: "Source not recorded", count: summary?.byDataOrigin.UNSPECIFIED ?? 0 },
  ]

  // ── 7. Recent lists ──────────────────────────────────────────────────────────
  const recentDetections = detections.slice(0, 4)
  const recentCTI = (globalFeed.length > 0 ? globalFeed : ctiReports).slice(0, 4)

  return (
    <div className="p-6 flex flex-col gap-6">
      {/* High-Priority Active Cascade Alert Banner */}
      {activeCascadesCount > 0 && (
        <div className="p-4 rounded-xl border border-red-200 bg-red-50/90 flex items-center justify-between gap-4 shadow-sm">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-red-600 flex items-center justify-center text-white flex-shrink-0">
              <Flame className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <p className="text-sm font-bold text-red-900">
                CRITICAL: {activeCascadesCount} Active Cross-Endpoint Attack {activeCascadesCount > 1 ? 'Cascades' : 'Cascade'}
              </p>
              <p className="text-xs text-red-700">
                Coordinated ransomware or lateral activity detected across multiple endpoints in your organization.
              </p>
            </div>
          </div>
          <button
            onClick={() => router.push('/cascades')}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-bold text-white bg-red-600 hover:bg-red-700 cursor-pointer shadow-sm flex-shrink-0"
          >
            Open Attack Center
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {(detectionSummaryError || endpointsError) && (
        <div role="alert" className="flex items-center justify-between gap-3 px-4 py-3 rounded-xl border border-red-200 bg-red-50 text-[13px] text-red-800">
          <span>
            Some dashboard data could not be loaded from the server
            {detectionSummaryError ? ` (detections: ${detectionSummaryError})` : ''}
            {endpointsError ? ` (endpoints: ${endpointsError})` : ''}. Figures shown as — are unavailable, not zero.
          </span>
          <button
            onClick={() => { refetchDetectionSummary(); refetchEndpoints() }}
            className="px-3 h-8 rounded-lg border border-red-300 bg-white font-medium cursor-pointer"
          >
            Retry
          </button>
        </div>
      )}

      {/* Primary KPI row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          {
            label: "ENDPOINTS ONLINE",
            value: `${onlineCount} / ${totalEndpoints}`,
            sub: `${offlineCount} offline${isolatedCount > 0 ? `, ${isolatedCount} isolated` : ''}`,
            dot: onlineCount > 0 ? GREEN : MUTED,
            path: '/endpoints',
          },
          {
            label: "ACTIVE DETECTIONS",
            value: activeDetections === null ? "—" : `${activeDetections}`,
            sub: activeDetections === null
              ? (detectionSummaryLoading ? "Loading…" : "Unavailable")
              : activeDetections > 0 ? "Requires review" : "No active detections",
            dot: RED,
            alert: (activeDetections ?? 0) > 0,
            path: '/detections',
          },
          {
            label: "CTI PUBLISHED",
            value: `${ctiPublished}`,
            sub: "Reports on-chain",
            accent: LAV,
            path: '/cti-center',
          },
          {
            label: "GLOBAL CTI FEED",
            value: `${ctiReceived}`,
            sub: "From network feed",
            path: '/cti-feed',
          },
        ].map((c, i) => (
          <div
            key={i}
            onClick={() => c.path && router.push(c.path)}
            className="bg-white border rounded-[10px] p-5 shadow-sm hover:border-slate-300 transition-colors cursor-pointer"
            style={{ borderColor: BORDER }}
          >
            <p className="text-[10px] font-bold tracking-[0.1em] mb-3 uppercase" style={{ color: MUTED }}>{c.label}</p>
            <div className="flex items-center gap-2">
              <span className="text-[28px] font-bold leading-none" style={{ color: "alert" in c && c.alert ? RED : TEXT }}>
                {c.value}
              </span>
              {"dot" in c && c.dot && (
                <span
                  className="w-2 h-2 rounded-full flex-shrink-0"
                  style={{
                    backgroundColor: c.dot,
                    boxShadow: "alert" in c && c.alert ? `0 0 0 4px rgba(220,38,38,0.15)` : "none",
                  }}
                />
              )}
              {"accent" in c && c.accent && (
                <div className="w-5 h-5 rounded flex items-center justify-center" style={{ backgroundColor: "rgba(197,176,205,0.15)" }}>
                  <Globe className="w-3 h-3" style={{ color: LAV }} />
                </div>
              )}
            </div>
            <p className="text-[11px] mt-1.5" style={{ color: MUTED }}>{c.sub}</p>
          </div>
        ))}
      </div>

      {/* Security Layer Engine KPI Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div
          onClick={() => router.push('/policies')}
          className="bg-white border rounded-[10px] p-4 shadow-sm hover:border-slate-300 transition-colors cursor-pointer flex items-center justify-between"
          style={{ borderColor: BORDER }}
        >
          <div>
            <p className="text-[10px] font-bold uppercase text-slate-500">Active Policies</p>
            <p className="text-xl font-bold text-slate-900 mt-0.5">{activePoliciesCount}</p>
            <p className="text-[10px] text-slate-400 mt-0.5">Automated rules</p>
          </div>
          <div className="w-8 h-8 rounded-lg bg-teal-50 text-teal-800 flex items-center justify-center">
            <SlidersHorizontal className="w-4 h-4" />
          </div>
        </div>

        <div
          onClick={() => router.push('/policies')}
          className="bg-white border rounded-[10px] p-4 shadow-sm hover:border-slate-300 transition-colors cursor-pointer flex items-center justify-between"
          style={{ borderColor: BORDER }}
        >
          <div>
            <p className="text-[10px] font-bold uppercase text-slate-500">Policy Triggers</p>
            <p className="text-xl font-bold text-red-600 mt-0.5">{totalPolicyTriggers}</p>
            <p className="text-[10px] text-slate-400 mt-0.5">Auto responses</p>
          </div>
          <div className="w-8 h-8 rounded-lg bg-red-50 text-red-600 flex items-center justify-center">
            <Zap className="w-4 h-4" />
          </div>
        </div>

        <div
          onClick={() => router.push('/cascades')}
          className="bg-white border rounded-[10px] p-4 shadow-sm hover:border-slate-300 transition-colors cursor-pointer flex items-center justify-between"
          style={{ borderColor: BORDER }}
        >
          <div>
            <p className="text-[10px] font-bold uppercase text-slate-500">Active Cascades</p>
            <p className={`text-xl font-bold mt-0.5 ${activeCascadesCount > 0 ? 'text-red-600' : 'text-slate-900'}`}>
              {activeCascadesCount}
            </p>
            <p className="text-[10px] text-slate-400 mt-0.5">Cross-endpoint bursts</p>
          </div>
          <div className="w-8 h-8 rounded-lg bg-purple-50 text-purple-700 flex items-center justify-center">
            <Radio className="w-4 h-4" />
          </div>
        </div>

        <div
          onClick={() => router.push('/threat-intel')}
          className="bg-white border rounded-[10px] p-4 shadow-sm hover:border-slate-300 transition-colors cursor-pointer flex items-center justify-between"
          style={{ borderColor: BORDER }}
        >
          <div>
            <p className="text-[10px] font-bold uppercase text-slate-500">CTI Threat Matches</p>
            <p className={`text-xl font-bold mt-0.5 ${typeof ctiMatchCount === 'number' && ctiMatchCount > 0 ? 'text-amber-600' : 'text-slate-900'}`}>
              {ctiMatchCount}
            </p>
            <p className="text-[10px] text-slate-400 mt-0.5">Known malicious IOCs</p>
          </div>
          <div className="w-8 h-8 rounded-lg bg-amber-50 text-amber-700 flex items-center justify-center">
            <Database className="w-4 h-4" />
          </div>
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-3 gap-4">
        {/* Line chart */}
        <div className="col-span-2 bg-white border rounded-[10px] p-5 shadow-sm" style={{ borderColor: BORDER }}>
          <p className="text-[13px] font-semibold mb-4" style={{ color: TEXT }}>
            Detections — Last 30 Days (UTC){summary ? ` · ${windowTotal} in this period · ${summary.total} all time` : ''}
          </p>
          <ResponsiveContainer width="100%" height={170}>
            <LineChart data={lineData} margin={{ top: 5, right: 8, bottom: 0, left: -24 }}>
              <defs>
                <linearGradient id="fillGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={STORM} stopOpacity={0.12} />
                  <stop offset="100%" stopColor={STORM} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={BORDER} vertical={false} />
              <XAxis dataKey="d" tick={{ fontSize: 10, fill: MUTED }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10, fill: MUTED }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ fontSize: 12, borderRadius: 8, border: `1px solid ${BORDER}`, color: TEXT }}
                itemStyle={{ color: STORM }}
                labelFormatter={(label, payload) => {
                  const item = payload?.[0]?.payload
                  return item?.dateStr ?? String(label)
                }}
              />
              <Line
                type="monotone"
                dataKey="v"
                stroke={STORM}
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4, fill: STORM }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Donut */}
        <div className="bg-white border rounded-[10px] p-5 shadow-sm" style={{ borderColor: BORDER }}>
          <p className="text-[13px] font-semibold mb-4" style={{ color: TEXT }}>Endpoint Status</p>
          <div className="flex items-center gap-3">
            <PieChart width={96} height={96}>
              <Pie data={renderedPieData} cx={44} cy={44} innerRadius={28} outerRadius={44} dataKey="value" strokeWidth={0}>
                {renderedPieData.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Pie>
            </PieChart>
            <div className="flex flex-col gap-2.5">
              {pieData.map((d, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: d.color }} />
                  <span className="text-[12px]" style={{ color: MUTED }}>{d.name}</span>
                  <span className="text-[12px] font-bold ml-auto pl-3" style={{ color: TEXT }}>{d.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Risk bars */}
          <div className="mt-5 pt-4 border-t" style={{ borderColor: BORDER }}>
            <p className="text-[11px] font-bold uppercase tracking-wide mb-3" style={{ color: MUTED }}>Risk Distribution</p>
            {riskData.map((r) => (
              <div key={r.label} className="flex items-center gap-2 mb-2">
                <span className="text-[11px] w-14" style={{ color: MUTED }}>{r.label}</span>
                <div className="flex-1 h-1.5 rounded-full" style={{ backgroundColor: BORDER }}>
                  <div className="h-1.5 rounded-full transition-all" style={{ width: `${r.pct}%`, backgroundColor: r.color }} />
                </div>
                <span className="text-[11px] font-semibold w-5 text-right" style={{ color: TEXT }}>{r.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Detection sources and ATT&CK techniques (server summary) */}
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-white border rounded-[10px] p-5 shadow-sm" style={{ borderColor: BORDER }}>
          <p className="text-[13px] font-semibold mb-3" style={{ color: TEXT }}>Detection Sources</p>
          {!summary ? (
            <p className="text-[12px]" style={{ color: MUTED }}>{detectionSummaryLoading ? 'Loading…' : 'Unavailable'}</p>
          ) : (
            <div className="flex flex-col gap-2">
              {originRows.map(r => (
                <div key={r.label} className="flex items-center justify-between text-[12px]">
                  <span style={{ color: MUTED }}>{r.label}</span>
                  <span className="font-semibold" style={{ color: TEXT }}>{r.count}</span>
                </div>
              ))}
              <p className="text-[11px] mt-1" style={{ color: MUTED }}>
                Recorded traffic is a network capture analysed after it was recorded, never live monitoring.
                &quot;Source not recorded&quot; covers detections from components that do not report their data source.
              </p>
            </div>
          )}
        </div>
        <div className="bg-white border rounded-[10px] p-5 shadow-sm" style={{ borderColor: BORDER }}>
          <p className="text-[13px] font-semibold mb-3" style={{ color: TEXT }}>MITRE ATT&CK Techniques in Detections</p>
          {!summary ? (
            <p className="text-[12px]" style={{ color: MUTED }}>{detectionSummaryLoading ? 'Loading…' : 'Unavailable'}</p>
          ) : summary.techniques.length === 0 ? (
            <p className="text-[12px]" style={{ color: MUTED }}>No detections carry an ATT&CK mapping yet.</p>
          ) : (
            <div className="flex flex-col gap-2">
              {summary.techniques.slice(0, 6).map(t => (
                <div key={t.techniqueId} className="flex items-center justify-between gap-2 text-[12px]">
                  <span className="truncate" style={{ color: TEXT }}>
                    <span className="font-mono font-bold text-blue-700">{t.techniqueId}</span> {t.techniqueName}
                    <span style={{ color: MUTED }}> · {t.tacticName}</span>
                  </span>
                  <span className="font-semibold" style={{ color: TEXT }}>{t.count}</span>
                </div>
              ))}
              {summary.unmappedDetections > 0 && (
                <p className="text-[11px] mt-1" style={{ color: MUTED }}>
                  {summary.unmappedDetections} detection{summary.unmappedDetections === 1 ? '' : 's'} have no ATT&CK mapping
                  (no evidence-based technique for their type).
                </p>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Tables */}
      <div className="grid grid-cols-2 gap-4">
        {/* Recent Detections */}
        <div className="bg-white border rounded-[10px] shadow-sm overflow-hidden" style={{ borderColor: BORDER }}>
          <div className="px-5 py-3.5 border-b" style={{ borderColor: BORDER }}>
            <p className="text-[13px] font-semibold" style={{ color: TEXT }}>Recent Detections</p>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b" style={{ borderColor: BORDER }}>
                {["Endpoint", "Time", "Score", "Status"].map(h => (
                  <th key={h} className="px-4 py-2 text-left text-[10px] font-bold uppercase tracking-wide" style={{ color: MUTED }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {recentDetections.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-[12px]" style={{ color: MUTED }}>
                    <div className="flex flex-col items-center gap-1.5">
                      <ShieldCheck className="w-5 h-5" style={{ color: GREEN }} />
                      <span>No active or recent detections. All systems clear.</span>
                    </div>
                  </td>
                </tr>
              ) : (
                recentDetections.map((d) => {
                  const timeFormatted = d.detectedAt
                    ? new Date(d.detectedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
                    : 'Just now'
                  return (
                    <tr key={d._id} className="border-b hover:bg-[#F8FAFC] transition-colors" style={{ borderColor: BORDER }}>
                      <td className="px-4 py-3 text-[12px] font-medium" style={{ color: TEXT }}>{d.endpointName || 'Unknown'}</td>
                      <td className="px-4 py-3 text-[11px] font-mono" style={{ color: MUTED, fontFamily: "var(--font-mono, monospace)" }}>
                        {timeFormatted}
                      </td>
                      <td className="px-4 py-3"><ScoreBadge score={d.riskScore ?? 0} /></td>
                      <td className="px-4 py-3"><StatusBadge status={d.status || 'New'} /></td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>

        {/* CTI Activity */}
        <div className="bg-white border rounded-[10px] shadow-sm overflow-hidden" style={{ borderColor: BORDER }}>
          <div className="px-5 py-3.5 border-b" style={{ borderColor: BORDER }}>
            <p className="text-[13px] font-semibold" style={{ color: TEXT }}>Recent CTI Activity</p>
          </div>
          {recentCTI.length === 0 ? (
            <div className="px-5 py-8 text-center text-[12px]" style={{ color: MUTED }}>
              <div className="flex flex-col items-center gap-1.5">
                <Globe className="w-5 h-5" style={{ color: MUTED }} />
                <span>No CTI reports published or received yet.</span>
              </div>
            </div>
          ) : (
            recentCTI.map((c) => {
              const timeFormatted = c.publishedAt || c.createdAt
                ? new Date(c.publishedAt || c.createdAt).toLocaleDateString([], { month: 'short', day: 'numeric' })
                : 'Recent'
              const summaryPreview = c.attackSummary || 'Automated Threat Intelligence Report'
              const threatType = summaryPreview.toLowerCase().includes('ransomware') ? 'Ransomware' : 'Threat Intelligence'

              return (
                <div key={c._id} className="flex items-start gap-3 px-5 py-3.5 border-b hover:bg-[#F8FAFC] transition-colors" style={{ borderColor: BORDER }}>
                  <div className="w-7 h-7 rounded-lg flex-shrink-0 flex items-center justify-center"
                    style={{ backgroundColor: "rgba(197,176,205,0.15)" }}>
                    <Globe className="w-3.5 h-3.5" style={{ color: LAV }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-[12px] font-semibold" style={{ color: TEXT }}>{threatType}</p>
                      {c.verificationStatus === 'VERIFIED' && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold"
                          style={{ backgroundColor: "rgba(22,163,74,0.1)", color: GREEN }}>Verified</span>
                      )}
                    </div>
                    <p className="text-[11px] truncate" style={{ color: MUTED }}>{summaryPreview} · {timeFormatted}</p>
                  </div>
                </div>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}

export default function DashboardPage() {
  return (
    <Layout>
      <DashboardContent />
    </Layout>
  )
}
