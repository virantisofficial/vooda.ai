"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useEffect, useState, useRef, useCallback } from "react";
import Link from "next/link";
import AppShell from "@/components/layout/AppShell";
import {
  getExecutiveSummary, getAgingReport, getRepoRiskReport,
  getDeveloperActivity, getComplianceReport,
  getOWASPReport, getTrendData, getAIAccuracy,
  getRemediationMetrics, getFindingsMetrics, getRepositories, getBusinessUnits,
  getReleaseReadiness, getSecurityDebt, getFixPriority,
  getDeveloperReport,
} from "@/lib/api";
// getGovernanceReport import removed 2026-05-16 alongside the governance surface.

// ── Export Dropdown ───────────────────────────────────
const EXPORT_FORMATS = [
  { key: "csv", label: "CSV", description: "Spreadsheet-compatible", ext: ".csv", icon: "📊" },
  { key: "json", label: "JSON", description: "Structured data format", ext: ".json", icon: "📋" },
  { key: "sarif", label: "SARIF", description: "Static analysis results format", ext: ".sarif", icon: "🔍" },
  { key: "pdf", label: "PDF Report", description: "Printable summary with charts", ext: ".pdf", icon: "📕" },
];

function ExportDropdown({ reportType = "executive", repositoryId }: { reportType?: string; repositoryId?: string }) {
  const [open, setOpen] = useState(false);
  const [exporting, setExporting] = useState<string | null>(null);

  const handleExport = async (format: string) => {
    setExporting(format);
    try {
      const token = localStorage.getItem("vooda_token");
      const apiBase = typeof window !== "undefined" ? (window.location.port === "3000" ? "http://localhost:8000" : "") : "";
      const params = new URLSearchParams({ report_type: reportType, days: "30" });
      if (repositoryId) params.set("repository_id", repositoryId);
      const response = await fetch(`${apiBase}/api/v1/reports/export/${format}?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        if (errorData?.error) {
          alert(errorData.error);
          return;
        }
        alert(`Export failed: ${response.status}`);
        return;
      }

      // Get filename from content-disposition header or use format-specific fallback
      const disposition = response.headers.get("content-disposition");
      const filenameMatch = disposition?.match(/filename=(.+)/);
      const filename = filenameMatch ? filenameMatch[1] : `vooda-${reportType}-report.${format === "sarif" ? "sarif" : format}`;

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      alert("Export failed. Check your connection.");
    } finally {
      setExporting(null);
      setOpen(false);
    }
  };

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="btn-primary flex items-center gap-2 text-sm"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        Export
        <svg className={`w-3.5 h-3.5 transition-transform ${open ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-30" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-12 z-40 w-72 rounded-xl border border-white/[0.08] shadow-2xl overflow-hidden" style={{ background: "rgba(14,18,40,0.95)",  }}>
            <div className="px-4 py-2.5 border-b border-white/[0.06]">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Export Format</p>
            </div>
            <div className="py-1">
              {EXPORT_FORMATS.map((fmt) => (
                <button
                  key={fmt.key}
                  onClick={() => handleExport(fmt.key)}
                  disabled={!!exporting}
                  className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.04] transition-colors text-left disabled:opacity-50"
                >
                  <span className="text-base w-6 text-center">{fmt.icon}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-slate-200 font-medium">{fmt.label}</p>
                    <p className="text-[10px] text-slate-500">{fmt.description}</p>
                  </div>
                  {exporting === fmt.key ? (
                    <div className="w-4 h-4 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin shrink-0" />
                  ) : (
                    <svg className="w-4 h-4 text-slate-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                    </svg>
                  )}
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── Types ─────────────────────────────────────────────
type ReportTab = "executive" | "compliance" | "aging" | "trends" | "repo_risk" | "ai" | "remediation" | "developer" | "release_readiness" | "security_debt" | "fix_priority" | "developer_report";

// Governance tab removed 2026-05-16 alongside the governance product surface.
const TABS: { key: ReportTab; label: string; icon: string; group?: string }[] = [
  { key: "executive", label: "Exposure Report", icon: "📊", group: "Overview" },
  { key: "release_readiness", label: "Release Gate", icon: "🚦", group: "Enterprise" },
  { key: "security_debt", label: "Unrotated Backlog", icon: "💰", group: "Enterprise" },
  { key: "fix_priority", label: "Rotation Priority", icon: "🎯", group: "Enterprise" },
  { key: "developer_report", label: "Dev Guide", icon: "📖", group: "Enterprise" },
  { key: "aging", label: "Rotation SLA", icon: "⏰", group: "Analytics" },
  { key: "trends", label: "Trends", icon: "📈", group: "Analytics" },
  { key: "repo_risk", label: "Repo Risk", icon: "🏢", group: "Analytics" },
  { key: "ai", label: "AI Performance", icon: "🧠", group: "Analytics" },
  { key: "remediation", label: "Rotation Status", icon: "🔧", group: "Operations" },
  { key: "developer", label: "Activity", icon: "👤", group: "Operations" },
];

// ── Shared components ─────────────────────────────────
function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-4">
      <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${color || "text-white"}`}>{value}</p>
      {sub && <p className="text-[10px] text-slate-600 mt-0.5">{sub}</p>}
    </div>
  );
}

function BarH({ label, value, max, color = "#22d3ee" }: { label: string; value: number; max: number; color?: string }) {
  const pct = max > 0 ? Math.max((value / max) * 100, 2) : 0;
  return (
    <div className="flex items-center gap-3 py-1.5">
      <span className="text-xs text-slate-400 w-40 truncate shrink-0">{label}</span>
      <div className="flex-1 bg-white/[0.03] rounded-full h-2 overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="text-xs font-semibold text-slate-300 w-8 text-right">{value}</span>
    </div>
  );
}

function TableRow({ cells, isHeader }: { cells: (string | number)[]; isHeader?: boolean }) {
  const Tag = isHeader ? "th" : "td";
  return (
    <tr className={isHeader ? "border-b border-white/[0.06]" : "border-b border-white/[0.03] hover:bg-white/[0.02]"}>
      {cells.map((c, i) => (
        <Tag key={i} className={`px-4 py-2.5 text-left ${isHeader ? "text-[10px] font-semibold text-slate-500 uppercase tracking-widest" : "text-sm text-slate-300"}`}>
          {c}
        </Tag>
      ))}
    </tr>
  );
}

function Spinner() {
  return <div className="flex justify-center py-12"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div>;
}

// ═══════════════════════════════════════════════════════
//  REPORT SECTIONS
// ═══════════════════════════════════════════════════════

function ExecutiveReport({ repoId }: { repoId?: string }) {
  const [data, setData] = useState<any>(null);
  const [days, setDays] = useState(30);
  useEffect(() => { setData(null); getExecutiveSummary(days, repoId).then(r => setData(r.data)).catch(() => {}); }, [days, repoId]);
  if (!data) return <Spinner />;

  const gradeColor = data.grade === "A" ? "text-green-400" : data.grade?.startsWith("B") ? "text-red-400" : data.grade?.startsWith("C") ? "text-yellow-400" : "text-red-400";
  const scoreColor = data.security_score >= 80 ? "#22c55e" : data.security_score >= 60 ? "#22d3ee" : data.security_score >= 40 ? "#eab308" : "#ef4444";
  const r = 42, c = 2 * Math.PI * r;

  // SLA
  const sla = data.sla_compliance || {};
  const critInSla = sla.critical_in_compliance ?? 0;
  const critOverdue = sla.critical_overdue ?? 0;
  const highInSla = sla.high_in_compliance ?? 0;
  const highOverdue = sla.high_overdue ?? 0;

  return (
    <div className="space-y-5">
      {/* ═══ Section 1: Header + Posture ═══ */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <select value={days} onChange={e => setDays(Number(e.target.value))} className="select-dark text-xs">
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
            <option value={180}>Last 6 months</option>
          </select>
          {data.posture_statement && (
            <p className="text-xs text-slate-400 max-w-xl hidden lg:block">{data.posture_statement}</p>
          )}
        </div>
        <span className="text-[10px] text-slate-600">Generated {data.generated_at ? new Date(data.generated_at).toLocaleString() : "now"}</span>
      </div>

      {/* ═══ Section 2: KPI Cards ═══ */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Score gauge */}
        <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-4 flex flex-col items-center justify-center">
          <div className="relative w-[96px] h-[96px]">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 96 96">
              <circle cx="48" cy="48" r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="6" />
              <circle cx="48" cy="48" r={r} fill="none" stroke={scoreColor} strokeWidth="6" strokeLinecap="round"
                strokeDasharray={c} strokeDashoffset={c - (data.security_score / 100) * c} className="transition-all duration-700" />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-xl font-bold text-white">{data.security_score}</span>
              <span className="text-[9px] text-slate-500">/100</span>
            </div>
          </div>
          <p className={`text-sm font-bold mt-1 ${gradeColor}`}>{data.grade}</p>
        </div>
        <StatCard label="Total Findings" value={data.total_findings} sub={`${data.new_findings_period} new`} />
        <StatCard label="FP Reduction" value={data.fp_rate > 0 ? `${(data.fp_rate * 100).toFixed(1)}%` : "—"} sub={`${data.fp_count} false positives`} color="text-green-400" />
        <StatCard label="Critical / High" value={`${data.criticals}/${data.highs}`} color={data.criticals > 0 ? "text-red-400" : "text-green-400"} sub="Open vulnerabilities" />
        <StatCard label="Scan Coverage" value={`${(data.scan_coverage * 100).toFixed(0)}%`} sub={`${data.total_scans} scans · ${data.total_repos} repos`} color="text-red-400" />
        <StatCard label="Resolved" value={data.resolved_period} sub={`in last ${days} days`} color="text-purple-400" />
      </div>

      {/* ═══ Section 3: Trend + Severity + Classification ═══ */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Trend chart */}
        <div className="lg:col-span-5 card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Finding Trend</h3>
          {data.daily_trend?.length > 0 ? (
            <div className="flex items-end gap-[2px] h-[100px]">
              {data.daily_trend.map((d: any, i: number) => {
                const maxVal = Math.max(...data.daily_trend.map((t: any) => t.count), 1);
                const pct = Math.max((d.count / maxVal) * 100, 4);
                return (
                  <div key={i} className="flex-1 flex flex-col items-center gap-1 group relative" title={`${d.date}: ${d.count} findings`}>
                    <div className="w-full rounded-t-sm bg-gradient-to-t from-red-500/40 to-orange-500/80 transition-all" style={{ height: `${pct}%` }} />
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="text-sm text-slate-600 py-8 text-center">No trend data for this period</p>
          )}
          {data.daily_trend?.length > 0 && (
            <div className="flex justify-between text-[9px] text-slate-600 mt-1">
              <span>{data.daily_trend[0]?.date}</span>
              <span>{data.daily_trend[data.daily_trend.length - 1]?.date}</span>
            </div>
          )}
        </div>

        {/* Severity */}
        <div className="lg:col-span-3 card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Severity</h3>
          {Object.entries(data.by_severity).filter(([,v]) => (v as number) > 0).map(([sev, count]) => (
            <BarH key={sev} label={sev.replace("Severity.", "").replace(/^./, c => c.toUpperCase())} value={count as number} max={data.total_findings}
              color={sev.includes("CRITICAL") || sev === "critical" ? "#ef4444" : sev.includes("HIGH") || sev === "high" ? "#f97316" : sev.includes("MEDIUM") || sev === "medium" ? "#eab308" : "#22c55e"} />
          ))}
        </div>

        {/* Classification */}
        <div className="lg:col-span-4 card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Classification</h3>
          {Object.entries(data.by_classification).filter(([,v]) => (v as number) > 0).map(([cls, count]) => (
            <BarH key={cls} label={cls.replace("Classification.", "").replace(/_/g, " ").replace(/^./, c => c.toUpperCase())} value={count as number} max={data.total_findings}
              color={cls.includes("true_positive") ? "#ef4444" : cls.includes("false_positive") ? "#22c55e" : cls.includes("accepted") ? "#f97316" : "#eab308"} />
          ))}
        </div>
      </div>

      {/* ═══ Section 4: Top Risky Repos + Top Categories ═══ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Top Risky Applications</h3>
          {data.top_repos?.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-white/[0.06]">
                  <th className="py-2 text-left text-[10px] font-semibold text-slate-500 uppercase">Application</th>
                  <th className="py-2 text-right text-[10px] font-semibold text-slate-500 uppercase">Findings</th>
                  <th className="py-2 text-right text-[10px] font-semibold text-slate-500 uppercase">Critical</th>
                  <th className="py-2 text-right text-[10px] font-semibold text-slate-500 uppercase">High</th>
                </tr></thead>
                <tbody>
                  {data.top_repos.map((repo: any, i: number) => (
                    <tr key={repo.id} className="border-b border-white/[0.03] hover:bg-white/[0.02]">
                      <td className="py-2">
                        <Link href={`/repositories/${repo.id}`} className="text-slate-200 hover:text-red-400 font-medium">{repo.name}</Link>
                      </td>
                      <td className="py-2 text-right text-slate-400">{repo.findings}</td>
                      <td className="py-2 text-right"><span className={repo.critical > 0 ? "text-red-400 font-semibold" : "text-slate-600"}>{repo.critical}</span></td>
                      <td className="py-2 text-right"><span className={repo.high > 0 ? "text-orange-400 font-semibold" : "text-slate-600"}>{repo.high}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="text-sm text-slate-600 py-4 text-center">No repository data</p>}
        </div>

        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Top Secret Types</h3>
          {data.top_categories?.length > 0 ? (
            <div className="space-y-2">
              {data.top_categories.map((cat: any, i: number) => {
                const maxCount = data.top_categories[0]?.count || 1;
                return (
                  <div key={cat.category} className="flex items-center gap-3">
                    <span className="text-[10px] text-slate-600 w-4 text-right">{i + 1}</span>
                    <div className="flex-1">
                      <div className="flex justify-between mb-0.5">
                        <span className="text-xs text-slate-300 truncate max-w-[250px]">{cat.category}</span>
                        <span className="text-xs font-semibold text-slate-400 ml-2">{cat.count}</span>
                      </div>
                      <div className="w-full bg-white/[0.03] rounded-full h-1">
                        <div className="h-1 rounded-full bg-gradient-to-r from-red-500/60 to-orange-500/60 transition-all" style={{ width: `${(cat.count / maxCount) * 100}%` }} />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : <p className="text-sm text-slate-600 py-4 text-center">No category data</p>}
        </div>
      </div>

      {/* ═══ Section 5: Remediation Pipeline + AI Performance + SLA ═══ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Remediation pipeline */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Remediation Pipeline</h3>
          {(() => {
            const p = data.remediation_pipeline || {};
            const stages = [
              { label: "Open", value: (p["RemediationStatus.NONE"] ?? 0) + (p["none"] ?? 0), color: "bg-slate-500" },
              { label: "Pending", value: (p["RemediationStatus.PENDING"] ?? 0) + (p["pending"] ?? 0), color: "bg-yellow-500" },
              { label: "Patch Generated", value: (p["RemediationStatus.PATCH_GENERATED"] ?? 0) + (p["patch_generated"] ?? 0), color: "bg-purple-500" },
              { label: "Approved", value: (p["RemediationStatus.APPROVED"] ?? 0) + (p["approved"] ?? 0), color: "bg-red-500" },
              { label: "Applied", value: (p["RemediationStatus.APPLIED"] ?? 0) + (p["applied"] ?? 0), color: "bg-green-500" },
            ];
            const total = stages.reduce((s, st) => s + st.value, 0) || 1;
            return (
              <div className="space-y-2">
                {/* Funnel bar */}
                <div className="flex gap-0.5 h-3 rounded-full overflow-hidden bg-white/[0.03]">
                  {stages.filter(s => s.value > 0).map(s => (
                    <div key={s.label} className={`${s.color} transition-all`} style={{ width: `${(s.value / total) * 100}%` }} title={`${s.label}: ${s.value}`} />
                  ))}
                </div>
                {stages.map(s => (
                  <div key={s.label} className="flex items-center gap-2 text-xs">
                    <span className={`w-2 h-2 rounded-full ${s.color} shrink-0`} />
                    <span className="text-slate-400 flex-1">{s.label}</span>
                    <span className="font-semibold text-slate-300">{s.value}</span>
                  </div>
                ))}
              </div>
            );
          })()}
        </div>

        {/* AI Performance */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">AI Performance</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
              <span className="text-xs text-slate-400">Findings Triaged by AI</span>
              <span className="text-sm font-bold text-purple-400">{data.ai_triaged ?? 0}</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
              <span className="text-xs text-slate-400">User Decisions</span>
              <span className="text-sm font-bold text-red-400">{data.user_decisions ?? 0}</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
              <span className="text-xs text-slate-400">FP Reduction Value</span>
              <span className="text-sm font-bold text-green-400">{data.fp_count > 0 ? `${data.fp_count} noise removed` : "Pending"}</span>
            </div>
            {data.fp_count > 0 && (
              <p className="text-[10px] text-slate-600 text-center">Est. {Math.round(data.fp_count * 15)} min saved @ 15 min/review</p>
            )}
          </div>
        </div>

        {/* SLA Compliance */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">SLA Compliance</h3>
          <div className="space-y-3">
            <div className="p-3 rounded-lg border border-white/[0.04]" style={{ background: critOverdue > 0 ? "rgba(239,68,68,0.03)" : "rgba(34,197,94,0.03)" }}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-slate-400">Critical ({sla.critical_sla_days || 7}d SLA)</span>
                <span className={`text-xs font-bold ${critOverdue > 0 ? "text-red-400" : "text-green-400"}`}>
                  {critOverdue > 0 ? `${critOverdue} overdue` : "All in SLA"}
                </span>
              </div>
              <div className="flex gap-0.5 h-2 rounded-full overflow-hidden bg-white/[0.03]">
                {critInSla > 0 && <div className="bg-green-500 transition-all" style={{ width: `${(critInSla / Math.max(critInSla + critOverdue, 1)) * 100}%` }} />}
                {critOverdue > 0 && <div className="bg-red-500 transition-all" style={{ width: `${(critOverdue / Math.max(critInSla + critOverdue, 1)) * 100}%` }} />}
              </div>
            </div>
            <div className="p-3 rounded-lg border border-white/[0.04]" style={{ background: highOverdue > 0 ? "rgba(249,115,22,0.03)" : "rgba(34,197,94,0.03)" }}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-slate-400">High ({sla.high_sla_days || 30}d SLA)</span>
                <span className={`text-xs font-bold ${highOverdue > 0 ? "text-orange-400" : "text-green-400"}`}>
                  {highOverdue > 0 ? `${highOverdue} overdue` : "All in SLA"}
                </span>
              </div>
              <div className="flex gap-0.5 h-2 rounded-full overflow-hidden bg-white/[0.03]">
                {highInSla > 0 && <div className="bg-green-500 transition-all" style={{ width: `${(highInSla / Math.max(highInSla + highOverdue, 1)) * 100}%` }} />}
                {highOverdue > 0 && <div className="bg-orange-500 transition-all" style={{ width: `${(highOverdue / Math.max(highInSla + highOverdue, 1)) * 100}%` }} />}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ComplianceReport({ repoId }: { repoId?: string }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => {
    setData(null);
    getComplianceReport(repoId).then(r => setData(r.data)).catch(() => {});
  }, [repoId]);
  if (!data) return <Spinner />;

  const scoreColor = (s: number) => s >= 80 ? "#22c55e" : s >= 50 ? "#eab308" : "#ef4444";
  const scoreTextColor = (s: number) => s >= 80 ? "text-green-400" : s >= 50 ? "text-yellow-400" : "text-red-400";
  const r = 24, c = 2 * Math.PI * r;

  const ScoreRing = ({ score, label }: { score: number; label: string }) => (
    <div className="flex flex-col items-center">
      <div className="relative w-16 h-16">
        <svg className="w-16 h-16 -rotate-90" viewBox="0 0 56 56">
          <circle cx="28" cy="28" r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="4" />
          <circle cx="28" cy="28" r={r} fill="none" stroke={scoreColor(score)} strokeWidth="4" strokeLinecap="round"
            strokeDasharray={`${c}`} strokeDashoffset={`${c * (1 - score / 100)}`} />
        </svg>
        <span className={`absolute inset-0 flex items-center justify-center text-sm font-bold ${scoreTextColor(score)}`}>{score}%</span>
      </div>
      <p className="text-[10px] text-slate-500 mt-1 text-center">{label}</p>
    </div>
  );

  return (
    <div className="space-y-5">
      {/* Compliance Scores */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Compliance Scores</h3>
          <span className="text-xs text-slate-500">{data.total_findings} findings analyzed</span>
        </div>
        <div className="flex items-center justify-around py-2">
          <ScoreRing score={data.owasp_score || 0} label={`OWASP Top 10\n${data.owasp_categories_clean}/${data.owasp_categories_total} clean`} />
          <ScoreRing score={data.cwe_top_25_score || 0} label={`CWE Top 25\n${25 - (data.cwe_top_25_matches || 0)}/25 clean`} />
          <ScoreRing score={data.pci_dss_score || 0} label={`PCI DSS 4.0\n${data.pci_dss_requirements_clean}/${data.pci_dss_requirements_total} clean`} />
        </div>
      </div>

      {/* OWASP Top 10 */}
      <div className="card">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">OWASP Top 10 (2021)</h3>
        <div className="space-y-0">
          {Object.entries(data.owasp_top_10 || {}).map(([cat, detail]: any) => (
            <div key={cat} className="flex items-center gap-3 py-2 border-b border-white/[0.03] last:border-0">
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${detail.status === "pass" ? "bg-green-500/15 text-green-400" : "bg-red-500/15 text-red-400"}`}>
                {detail.status === "pass" ? "PASS" : "FAIL"}
              </span>
              <span className="text-xs text-slate-300 flex-1 truncate">{cat}</span>
              <span className="text-xs text-slate-400 w-16 text-right">{detail.count}</span>
              {detail.count > 0 && (
                <div className="flex gap-1">
                  {detail.severity?.critical > 0 && <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/15 text-red-400">C:{detail.severity.critical}</span>}
                  {detail.severity?.high > 0 && <span className="text-[9px] px-1 py-0.5 rounded bg-orange-500/15 text-orange-400">H:{detail.severity.high}</span>}
                  {detail.severity?.medium > 0 && <span className="text-[9px] px-1 py-0.5 rounded bg-yellow-500/15 text-yellow-400">M:{detail.severity.medium}</span>}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* PCI DSS */}
      <div className="card">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">PCI DSS 4.0 — Requirement 6</h3>
        <div className="space-y-0">
          {Object.entries(data.pci_dss || {}).map(([req, detail]: any) => (
            <div key={req} className="flex items-center gap-3 py-2.5 border-b border-white/[0.03] last:border-0">
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${detail.status === "pass" ? "bg-green-500/15 text-green-400" : "bg-red-500/15 text-red-400"}`}>
                {detail.status === "pass" ? "PASS" : "FAIL"}
              </span>
              <span className="text-xs text-slate-300 flex-1">{req}</span>
              <span className="text-xs text-slate-400 w-16 text-right">{detail.count}</span>
              {detail.count > 0 && (
                <div className="flex gap-1">
                  {detail.severity?.critical > 0 && <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/15 text-red-400">C:{detail.severity.critical}</span>}
                  {detail.severity?.high > 0 && <span className="text-[9px] px-1 py-0.5 rounded bg-orange-500/15 text-orange-400">H:{detail.severity.high}</span>}
                  {detail.severity?.medium > 0 && <span className="text-[9px] px-1 py-0.5 rounded bg-yellow-500/15 text-yellow-400">M:{detail.severity.medium}</span>}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* CWE Top 25 */}
      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">CWE Top 25 (2023)</h3>
          <span className="text-xs text-slate-500">{data.cwe_top_25_matches} of 25 CWEs found in codebase</span>
        </div>
        {(data.cwe_top_25_findings || []).length === 0 ? (
          <p className="text-sm text-green-400 py-2">No CWE Top 25 vulnerabilities detected</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {Array.from(new Set((data.cwe_top_25_findings || []).map((f: any) => f.cwe))).map((cwe: any) => {
              const match = (data.cwe_top_25_findings || []).find((f: any) => f.cwe === cwe);
              return (
                <span key={cwe} className="text-xs px-2 py-1 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                  {cwe}: {match?.name}
                </span>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function SLAAgingReport({ repoId }: { repoId?: string }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => { setData(null); getAgingReport(repoId).then(r => setData(r.data)).catch(() => {}); }, [repoId]);
  if (!data) return <Spinner />;

  const bucketColors: Record<string, string> = { "0-7 days": "#22c55e", "8-30 days": "#eab308", "31-90 days": "#f97316", "90+ days": "#ef4444" };
  const maxBucket = Math.max(...Object.values(data.buckets as Record<string, number> || {}), 1);
  const SEV_BADGE: Record<string, string> = { critical: "bg-red-500/15 text-red-400", high: "bg-orange-500/15 text-orange-400", medium: "bg-yellow-500/15 text-yellow-400", low: "bg-blue-500/15 text-blue-400" };
  const SEV_COLORS: Record<string, { border: string; text: string; bg: string; bar: string }> = {
    critical: { border: "border-red-500/20", text: "text-red-400", bg: "bg-red-500/15", bar: "#ef4444" },
    high: { border: "border-orange-500/20", text: "text-orange-400", bg: "bg-orange-500/15", bar: "#f97316" },
    medium: { border: "border-yellow-500/20", text: "text-yellow-400", bg: "bg-yellow-500/15", bar: "#eab308" },
    low: { border: "border-blue-500/20", text: "text-blue-400", bg: "bg-blue-500/15", bar: "#3b82f6" },
  };
  const complianceColor = (data.compliance_pct ?? 100) >= 90 ? "text-green-400" : (data.compliance_pct ?? 100) >= 70 ? "text-yellow-400" : "text-red-400";
  const policy = data.sla_policy || {};
  const bySev = data.by_severity || {};

  return (
    <div className="space-y-5">
      {/* SLA Policy badges */}
      <div className="flex items-center gap-2 px-1 flex-wrap">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">SLA Policy:</span>
        {["critical", "high", "medium", "low"].map(sev => (
          <span key={sev} className={`text-[10px] px-1.5 py-0.5 rounded ${SEV_COLORS[sev].bg} ${SEV_COLORS[sev].text}`}>
            {sev.charAt(0).toUpperCase() + sev.slice(1)} {policy[sev] || "\u2014"}d
          </span>
        ))}
      </div>

      {/* KPI Cards — 6 compact */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
        <div className="bg-white/[0.02] border border-white/[0.06] rounded-lg p-3 flex flex-col items-center">
          <p className={`text-2xl font-bold ${complianceColor}`}>{data.compliance_pct ?? 100}%</p>
          <p className="text-[9px] text-slate-500">SLA Compliance</p>
        </div>
        <StatCard label="Overdue" value={data.total_overdue || 0} sub={`${data.unassigned_overdue || 0} unassigned`} color={(data.total_overdue || 0) > 0 ? "text-red-400" : "text-green-400"} />
        <StatCard label="Open Findings" value={data.total_open || 0} />
        <StatCard label="Avg Age" value={`${data.avg_age_days || 0}d`} color={(data.avg_age_days || 0) > 30 ? "text-orange-400" : "text-green-400"} />
        <StatCard label="90+ Days" value={(data.buckets || {})["90+ days"] || 0} color={((data.buckets || {})["90+ days"] || 0) > 0 ? "text-red-400" : "text-green-400"} />
        <StatCard label="In SLA" value={data.in_sla || 0} sub={`of ${data.total_applicable || 0}`} color="text-green-400" />
      </div>

      {/* Compliance by Severity bars */}
      {Object.keys(bySev).length > 0 && (
        <div className="card">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">SLA Compliance by Severity</h3>
          <div className="space-y-1.5">
            {["critical", "high", "medium", "low"].map(sev => {
              const info = bySev[sev] || { total: 0, in_sla: 0 };
              const pct = info.total > 0 ? Math.round((info.in_sla / info.total) * 100) : 100;
              return (
                <div key={sev} className="flex items-center gap-2">
                  <span className="text-[9px] text-slate-400 uppercase w-14 font-semibold">{sev}</span>
                  <div className="flex-1 h-2.5 rounded-full bg-white/[0.04] overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: SEV_COLORS[sev].bar }} />
                  </div>
                  <span className="text-[10px] text-slate-400 w-20 text-right">{info.in_sla}/{info.total} ({pct}%)</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Age Distribution — horizontal bars */}
      <div className="card">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Age Distribution</h3>
        <div className="space-y-1.5">
          {Object.entries(data.buckets || {}).map(([bucket, count]) => {
            const pct = Math.max(((count as number) / maxBucket) * 100, 2);
            const sev = data.bucket_severity?.[bucket] || {};
            return (
              <div key={bucket} className="flex items-center gap-2">
                <span className="text-[9px] text-slate-400 w-16 font-semibold text-right">{bucket}</span>
                <div className="flex-1 h-3 rounded-full bg-white/[0.04] overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: bucketColors[bucket] || "#22d3ee" }} />
                </div>
                <span className="text-xs font-bold text-slate-300 w-10 text-right">{count as number}</span>
                <div className="flex gap-1 w-32">
                  {(count as number) > 0 ? (<>
                    {sev.critical > 0 && <span className="text-[8px] px-1 rounded bg-red-500/15 text-red-400">C:{sev.critical}</span>}
                    {sev.high > 0 && <span className="text-[8px] px-1 rounded bg-orange-500/15 text-orange-400">H:{sev.high}</span>}
                    {sev.medium > 0 && <span className="text-[8px] px-1 rounded bg-yellow-500/15 text-yellow-400">M:{sev.medium}</span>}
                  </>) : null}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Top Aged Findings */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Oldest Open Findings</h3>
          {(data.top_aged_findings || []).length === 0 ? (
            <p className="text-xs text-slate-500 py-4 text-center">No open findings</p>
          ) : (
            <div className="space-y-0">
              {(data.top_aged_findings || []).slice(0, 8).map((f: any, i: number) => (
                <div key={i} className="flex items-center gap-2 py-1.5 border-b border-white/[0.03] last:border-0">
                  <span className="text-xs font-bold text-slate-400 w-8">{f.age_days}d</span>
                  <span className={`text-[9px] px-1.5 py-0.5 rounded font-medium ${SEV_BADGE[f.severity] || "text-slate-400"}`}>{f.severity}</span>
                  <span className="text-xs text-slate-300 flex-1 truncate">{f.title}</span>
                  <span className="text-[10px] text-slate-500 truncate max-w-[100px]">{f.repo_name || ""}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Age by Repository */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Age by Project</h3>
          {(data.age_by_repository || []).length === 0 ? (
            <p className="text-xs text-slate-500 py-4 text-center">No data</p>
          ) : (
            <div className="space-y-0">
              {(data.age_by_repository || []).slice(0, 8).map((r: any) => (
                <div key={r.repo_id} className="flex items-center gap-3 py-1.5 border-b border-white/[0.03] last:border-0">
                  <span className="text-xs text-slate-200 font-medium flex-1 truncate">{r.repo_name}</span>
                  <span className="text-[10px] text-slate-500">{r.total_findings}</span>
                  <span className="text-xs text-slate-400 w-14 text-right">avg {r.avg_age_days}d</span>
                  <span className="text-xs text-slate-500 w-12 text-right">max {r.max_age_days}d</span>
                  {r.over_30_days > 0 && <span className="text-[9px] px-1 rounded bg-orange-500/15 text-orange-400">&gt;30d:{r.over_30_days}</span>}
                  {r.over_90_days > 0 && <span className="text-[9px] px-1 rounded bg-red-500/15 text-red-400">&gt;90d:{r.over_90_days}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Overdue tables per severity */}
      {["critical", "high", "medium", "low"].map(sev => {
        const overdue = data[`${sev}_overdue`] || [];
        if (overdue.length === 0) return null;
        const overdueCount = data[`${sev}_overdue_count`] || overdue.length;
        const colors = SEV_COLORS[sev];
        return (
          <div key={sev} className={`card ${colors.border}`}>
            <h3 className={`text-xs font-semibold ${colors.text} uppercase tracking-wider mb-2`}>
              {sev.charAt(0).toUpperCase() + sev.slice(1)} Overdue ({overdueCount})
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs table-fixed">
                <colgroup>
                  <col style={{ width: "22%" }} />
                  <col style={{ width: "6%" }} />
                  <col style={{ width: "8%" }} />
                  <col style={{ width: "12%" }} />
                  <col style={{ width: "12%" }} />
                  <col style={{ width: "40%" }} />
                </colgroup>
                <thead>
                  <tr className="border-b border-white/[0.06]">
                    <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Finding</th>
                    <th className="py-1.5 text-right text-[9px] font-semibold text-slate-500 uppercase">Age</th>
                    <th className="py-1.5 text-right text-[9px] font-semibold text-slate-500 uppercase">Overdue</th>
                    <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase pl-3">Repository</th>
                    <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Owner</th>
                    <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Location</th>
                  </tr>
                </thead>
                <tbody>
                  {overdue.map((f: any) => (
                    <tr key={f.id} className="border-b border-white/[0.03] last:border-0 hover:bg-white/[0.02]">
                      <td className="py-1.5 pr-2 truncate">
                        <Link href={`/findings/${f.id}`} className="text-xs text-slate-300 hover:text-red-400">{f.title}</Link>
                      </td>
                      <td className="py-1.5 text-right text-xs text-slate-400">{f.age_days}d</td>
                      <td className="py-1.5 text-right">
                        <span className={`text-xs font-bold ${colors.text}`}>+{f.overdue_by}d</span>
                      </td>
                      <td className="py-1.5 text-left text-xs text-slate-400 truncate pl-3">{f.repo_name || "\u2014"}</td>
                      <td className="py-1.5 text-left truncate">
                        <span className={`text-xs ${f.assignee === "Unassigned" ? "text-amber-400 font-medium" : "text-slate-400"}`}>
                          {f.assignee || "Unassigned"}
                        </span>
                      </td>
                      <td className="py-1.5 text-left text-[10px] text-slate-500 truncate font-mono">{f.file || "\u2014"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function TrendsReport() {
  const [data, setData] = useState<any>(null);
  const [days, setDays] = useState(30);
  useEffect(() => { setData(null); getTrendData(days).then(r => setData(r.data)).catch(() => {}); }, [days]);
  if (!data) return <Spinner />;

  const maxCount = Math.max(...(data.daily_counts || []).map((d: any) => d.count), 1);
  const summary = data.period_summary || {};
  const sevTrend = data.severity_trend || [];
  const maxSev = Math.max(...sevTrend.map((d: any) => (d.critical || 0) + (d.high || 0) + (d.medium || 0)), 1);

  const trendColor = summary.trend === "decreasing" ? "text-green-400" : summary.trend === "increasing" ? "text-red-400" : "text-yellow-400";
  const trendIcon = summary.trend === "decreasing" ? "↓" : summary.trend === "increasing" ? "↑" : "→";

  return (
    <div className="space-y-5">
      <select value={days} onChange={e => setDays(Number(e.target.value))} className="select-dark text-xs">
        <option value={7}>Last 7 days</option>
        <option value={30}>Last 30 days</option>
        <option value={90}>Last 90 days</option>
      </select>

      {/* Period Summary KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="New This Period" value={summary.new_findings || 0} />
        <StatCard label="Previous Period" value={summary.previous_period || 0} />
        <StatCard label="Change" value={`${summary.change_pct > 0 ? "+" : ""}${summary.change_pct || 0}%`} color={trendColor} />
        <div className="card flex flex-col justify-center">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider">Trend</p>
          <p className={`text-xl font-bold ${trendColor}`}>{trendIcon} {summary.trend || "stable"}</p>
        </div>
      </div>

      {/* Daily Finding Count */}
      <div className="card">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Daily Findings</h3>
        {(data.daily_counts || []).length === 0 ? (
          <p className="text-sm text-slate-500 py-8 text-center">No data for this period</p>
        ) : (
          <div className="flex items-end gap-1 h-40">
            {(data.daily_counts || []).map((d: any, i: number) => {
              const pct = Math.max((d.count / maxCount) * 100, 3);
              return (
                <div key={i} className="flex-1 flex flex-col items-center gap-1 group" title={`${d.date}: ${d.count} findings`}>
                  <span className="text-[9px] text-slate-500 opacity-0 group-hover:opacity-100 transition-opacity">{d.count}</span>
                  <div className="w-full rounded-t transition-all duration-300 bg-gradient-to-t from-red-500/60 to-orange-500/60 group-hover:from-red-400 group-hover:to-purple-400"
                    style={{ height: `${pct}%` }} />
                  {i % Math.ceil((data.daily_counts || []).length / 8) === 0 && (
                    <span className="text-[8px] text-slate-600">{d.date?.split("-").slice(1).join("/")}</span>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Severity Trend */}
      {sevTrend.length > 0 && (
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Severity Trend</h3>
          <div className="flex items-end gap-1 h-40">
            {sevTrend.map((d: any, i: number) => {
              const total = (d.critical || 0) + (d.high || 0) + (d.medium || 0) + (d.low || 0);
              const cPct = total > 0 ? (d.critical || 0) / maxSev * 100 : 0;
              const hPct = total > 0 ? (d.high || 0) / maxSev * 100 : 0;
              const mPct = total > 0 ? (d.medium || 0) / maxSev * 100 : 0;
              return (
                <div key={i} className="flex-1 flex flex-col items-center gap-0 group" title={`${d.date}: C:${d.critical} H:${d.high} M:${d.medium}`}>
                  <span className="text-[9px] text-slate-500 opacity-0 group-hover:opacity-100 transition-opacity">{total}</span>
                  <div className="w-full flex flex-col-reverse">
                    {mPct > 0 && <div className="w-full rounded-t-sm bg-yellow-500/60" style={{ height: `${Math.max(mPct, 2)}px` }} />}
                    {hPct > 0 && <div className="w-full bg-orange-500/70" style={{ height: `${Math.max(hPct, 2)}px` }} />}
                    {cPct > 0 && <div className="w-full rounded-t-sm bg-red-500/80" style={{ height: `${Math.max(cPct, 2)}px` }} />}
                  </div>
                  {i % Math.ceil(sevTrend.length / 8) === 0 && (
                    <span className="text-[8px] text-slate-600 mt-1">{d.date?.split("-").slice(1).join("/")}</span>
                  )}
                </div>
              );
            })}
          </div>
          <div className="flex items-center gap-4 mt-3 justify-center">
            <span className="flex items-center gap-1.5 text-[10px] text-slate-500"><span className="w-3 h-2 rounded-sm bg-red-500/80" />Critical</span>
            <span className="flex items-center gap-1.5 text-[10px] text-slate-500"><span className="w-3 h-2 rounded-sm bg-orange-500/70" />High</span>
            <span className="flex items-center gap-1.5 text-[10px] text-slate-500"><span className="w-3 h-2 rounded-sm bg-yellow-500/60" />Medium</span>
          </div>
        </div>
      )}
    </div>
  );
}

function RepoRiskReport() {
  const [data, setData] = useState<any>(null);
  useEffect(() => { getRepoRiskReport().then(r => setData(r.data)).catch(() => {}); }, []);
  if (!data) return <Spinner />;

  return (
    <div className="space-y-5">
      <div className="card p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-white/[0.06]">
              {["Repository", "Score", "Critical", "High", "Total", "Languages", "Last Scan"].map(h => (
                <th key={h} className="px-4 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-widest">{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {(data.repositories || []).map((repo: any) => {
                const scoreColor = repo.risk_score >= 80 ? "text-green-400" : repo.risk_score >= 60 ? "text-red-400" : repo.risk_score >= 40 ? "text-yellow-400" : "text-red-400";
                return (
                  <tr key={repo.id} className="border-b border-white/[0.03] hover:bg-white/[0.02]">
                    <td className="px-4 py-3">
                      <Link href={`/repositories/${repo.id}`} className="text-sm text-slate-200 hover:text-red-400 font-medium">{repo.name}</Link>
                    </td>
                    <td className="px-4 py-3"><span className={`text-sm font-bold ${scoreColor}`}>{repo.risk_score}</span></td>
                    <td className="px-4 py-3"><span className={`text-sm ${repo.criticals > 0 ? "text-red-400 font-bold" : "text-slate-500"}`}>{repo.criticals}</span></td>
                    <td className="px-4 py-3"><span className={`text-sm ${repo.highs > 0 ? "text-orange-400" : "text-slate-500"}`}>{repo.highs}</span></td>
                    <td className="px-4 py-3 text-sm text-slate-300">{repo.total_findings}</td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1 flex-wrap">
                        {(repo.languages || []).slice(0, 3).map((l: string) => (
                          <span key={l} className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.04] text-slate-400">{l}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500">{repo.last_scan ? new Date(repo.last_scan).toLocaleDateString() : "Never"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function AIReport({ repoId }: { repoId?: string }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => { setData(null); getAIAccuracy(repoId).then(r => setData(r.data)).catch(() => {}); }, [repoId]);
  if (!data) return <Spinner />;

  const accuracy = data.accuracy || 0;
  const conf = data.confidence_distribution || {};
  const bySev = data.by_severity || {};
  const byCat = data.by_category || [];
  const confTotal = Math.max(Object.values(conf).reduce((a: number, b: any) => a + (b as number), 0) as number, 1);

  const SEV_COLORS: Record<string, { text: string; bg: string; bar: string }> = {
    critical: { text: "text-red-400", bg: "bg-red-500/15", bar: "#ef4444" },
    high: { text: "text-orange-400", bg: "bg-orange-500/15", bar: "#f97316" },
    medium: { text: "text-yellow-400", bg: "bg-yellow-500/15", bar: "#eab308" },
    low: { text: "text-blue-400", bg: "bg-blue-500/15", bar: "#3b82f6" },
  };

  return (
    <div className="space-y-4">
      {/* KPI Cards — 6 compact */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
        <StatCard label="AI Triaged" value={data.ai_triaged_findings} color="text-red-400" />
        <StatCard label="Confirmed" value={data.user_confirmed_decisions} color="text-blue-400" />
        <StatCard label="Accuracy" value={data.accuracy_pct} color={accuracy >= 0.8 ? "text-green-400" : accuracy >= 0.5 ? "text-yellow-400" : "text-red-400"} />
        <StatCard label="Disagreements" value={data.disagreement_count || 0} color={data.disagreement_count > 0 ? "text-red-400" : "text-green-400"} />
        <StatCard label="Low Confidence" value={data.low_confidence_count || 0} sub="needs review" color={data.low_confidence_count > 0 ? "text-orange-400" : "text-green-400"} />
        <StatCard label="Auto-Close" value={data.high_conf_fp_unreviewed || 0} sub="high conf FP" color={data.high_conf_fp_unreviewed > 0 ? "text-green-400" : "text-slate-500"} />
      </div>

      {/* Confidence Distribution */}
      {confTotal > 1 && (
        <div className="card">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Confidence Distribution</h3>
          <div className="space-y-1.5">
            {([["0–25% (Low)", conf.low || 0, "#ef4444"], ["25–50% (Medium)", conf.medium || 0, "#f97316"], ["50–75% (High)", conf.high || 0, "#3b82f6"], ["75–100% (Very High)", conf.very_high || 0, "#22c55e"]] as [string, number, string][]).map(([label, count, color]) => (
              <div key={label} className="flex items-center gap-2">
                <span className="text-[9px] text-slate-400 w-28 font-semibold">{label}</span>
                <div className="flex-1 h-2.5 rounded-full bg-white/[0.04] overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-500" style={{ width: `${Math.round((count / confTotal) * 100)}%`, background: color }} />
                </div>
                <span className="text-[10px] text-slate-400 w-12 text-right">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Accuracy by Severity */}
      {Object.keys(bySev).length > 0 && (
        <div className="card">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Accuracy by Severity</h3>
          <div className="space-y-1.5">
            {["critical", "high", "medium", "low"].map(sev => {
              const s = bySev[sev];
              if (!s) return null;
              const pct = s.accuracy_pct || 0;
              const sc = SEV_COLORS[sev];
              return (
                <div key={sev} className="flex items-center gap-2">
                  <span className={`text-[9px] uppercase w-14 font-semibold ${sc.text}`}>{sev}</span>
                  <div className="flex-1 h-2.5 rounded-full bg-white/[0.04] overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: sc.bar }} />
                  </div>
                  <span className="text-[10px] text-slate-400 w-28 text-right">{s.correct}/{s.confirmed} ({pct}%)</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Accuracy by Category */}
      {byCat.length > 0 && (
        <div className="card">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Accuracy by Category</h3>
          <div className="space-y-1.5">
            {byCat.map((cat: any) => {
              const pct = cat.accuracy_pct || 0;
              return (
                <div key={cat.category} className="flex items-center gap-2">
                  <span className="text-[10px] text-slate-300 w-40 truncate font-medium">{cat.category}</span>
                  <div className="flex-1 h-2.5 rounded-full bg-white/[0.04] overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-500 bg-red-500/60" style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-[10px] text-slate-400 w-28 text-right">{cat.correct}/{cat.confirmed} ({pct}%)</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Low Confidence — Needs Review */}
      {(data.low_confidence || []).length > 0 && (
        <div className="card border-orange-500/20">
          <h3 className="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-2">
            Low Confidence — Needs Review ({data.low_confidence_count || 0})
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs table-fixed">
              <colgroup>
                <col style={{ width: "24%" }} />
                <col style={{ width: "8%" }} />
                <col style={{ width: "9%" }} />
                <col style={{ width: "15%" }} />
                <col style={{ width: "12%" }} />
                <col style={{ width: "32%" }} />
              </colgroup>
              <thead>
                <tr className="border-b border-white/[0.06]">
                  <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Finding</th>
                  <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Severity</th>
                  <th className="py-1.5 text-right text-[9px] font-semibold text-slate-500 uppercase">Conf.</th>
                  <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase pl-2">Classification</th>
                  <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Repository</th>
                  <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Location</th>
                </tr>
              </thead>
              <tbody>
                {(data.low_confidence || []).map((f: any) => {
                  const sc = SEV_COLORS[f.severity] || { text: "text-slate-400", bg: "bg-slate-500/15" };
                  return (
                    <tr key={f.id} className="border-b border-white/[0.03] last:border-0 hover:bg-white/[0.02]">
                      <td className="py-1.5 pr-2 truncate">
                        <Link href={`/findings/${f.id}`} className="text-xs text-slate-300 hover:text-red-400">{f.title}</Link>
                      </td>
                      <td className="py-1.5"><span className={`text-[10px] px-1.5 py-0.5 rounded ${sc.bg} ${sc.text}`}>{f.severity}</span></td>
                      <td className="py-1.5 text-right text-xs text-orange-400 font-bold">{f.ai_confidence}</td>
                      <td className="py-1.5 text-left text-xs text-slate-400 truncate pl-2">{f.classification}</td>
                      <td className="py-1.5 text-left text-xs text-slate-400 truncate">{f.repo_name || "—"}</td>
                      <td className="py-1.5 text-left text-[10px] text-slate-500 truncate font-mono">{f.file || "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* AI Disagreements */}
      {(data.disagreements || []).length > 0 && (
        <div className="card border-red-500/20">
          <h3 className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-2">
            AI Disagreements ({data.disagreement_count || 0})
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs table-fixed">
              <colgroup>
                <col style={{ width: "24%" }} />
                <col style={{ width: "8%" }} />
                <col style={{ width: "15%" }} />
                <col style={{ width: "9%" }} />
                <col style={{ width: "12%" }} />
                <col style={{ width: "32%" }} />
              </colgroup>
              <thead>
                <tr className="border-b border-white/[0.06]">
                  <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Finding</th>
                  <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Severity</th>
                  <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase pl-2">AI Said</th>
                  <th className="py-1.5 text-right text-[9px] font-semibold text-slate-500 uppercase">Conf.</th>
                  <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Repository</th>
                  <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Location</th>
                </tr>
              </thead>
              <tbody>
                {(data.disagreements || []).map((f: any) => {
                  const sc = SEV_COLORS[f.severity] || { text: "text-slate-400", bg: "bg-slate-500/15" };
                  return (
                    <tr key={f.id} className="border-b border-white/[0.03] last:border-0 hover:bg-white/[0.02]">
                      <td className="py-1.5 pr-2 truncate">
                        <Link href={`/findings/${f.id}`} className="text-xs text-slate-300 hover:text-red-400">{f.title}</Link>
                      </td>
                      <td className="py-1.5"><span className={`text-[10px] px-1.5 py-0.5 rounded ${sc.bg} ${sc.text}`}>{f.severity}</span></td>
                      <td className="py-1.5 text-left text-xs text-red-400 truncate pl-2">{f.ai_said}</td>
                      <td className="py-1.5 text-right text-xs text-slate-400">{f.ai_confidence}</td>
                      <td className="py-1.5 text-left text-xs text-slate-400 truncate">{f.repo_name || "—"}</td>
                      <td className="py-1.5 text-left text-[10px] text-slate-500 truncate font-mono">{f.file || "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function RemediationReport({ repoId }: { repoId?: string }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => { setData(null); getRemediationMetrics(repoId).then(r => setData(r.data)).catch(() => {}); }, [repoId]);
  if (!data) return <Spinner />;

  const statuses = data.by_remediation_status || {};
  const entries = Object.entries(statuses).map(([k, v]) => [k.replace("RemediationStatus.", "").replace(/_/g, " "), v as number] as [string, number]);
  const maxVal = Math.max(...entries.map(([, v]) => v), 1);
  const bySev = data.by_severity || {};
  const patchRate = data.patch_rate || 0;

  const SEV_COLORS: Record<string, { text: string; bg: string }> = {
    critical: { text: "text-red-400", bg: "bg-red-500/15" },
    high: { text: "text-orange-400", bg: "bg-orange-500/15" },
    medium: { text: "text-yellow-400", bg: "bg-yellow-500/15" },
    low: { text: "text-blue-400", bg: "bg-blue-500/15" },
  };

  const ActionTable = ({ title, items, color }: { title: string; items: any[]; color: string }) => {
    if (!items || items.length === 0) return null;
    return (
      <div className={`card border-${color}-500/20`}>
        <h3 className={`text-xs font-semibold text-${color}-400 uppercase tracking-wider mb-2`}>{title}</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs table-fixed">
            <colgroup>
              <col style={{ width: "22%" }} />
              <col style={{ width: "8%" }} />
              <col style={{ width: "10%" }} />
              <col style={{ width: "7%" }} />
              <col style={{ width: "13%" }} />
              <col style={{ width: "12%" }} />
              <col style={{ width: "28%" }} />
            </colgroup>
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Finding</th>
                <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Severity</th>
                <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Status</th>
                <th className="py-1.5 text-right text-[9px] font-semibold text-slate-500 uppercase">Age</th>
                <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase pl-2">Repository</th>
                <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Owner</th>
                <th className="py-1.5 text-left text-[9px] font-semibold text-slate-500 uppercase">Location</th>
              </tr>
            </thead>
            <tbody>
              {items.map((f: any) => {
                const sc = SEV_COLORS[f.severity] || { text: "text-slate-400", bg: "bg-slate-500/15" };
                return (
                  <tr key={f.id} className="border-b border-white/[0.03] last:border-0 hover:bg-white/[0.02]">
                    <td className="py-1.5 pr-2 truncate">
                      <Link href={`/findings/${f.id}`} className="text-xs text-slate-300 hover:text-red-400">{f.title}</Link>
                    </td>
                    <td className="py-1.5"><span className={`text-[10px] px-1.5 py-0.5 rounded ${sc.bg} ${sc.text}`}>{f.severity}</span></td>
                    <td className="py-1.5 text-xs text-slate-400 truncate">{f.status}</td>
                    <td className="py-1.5 text-right text-xs text-slate-400">{f.age_days}d</td>
                    <td className="py-1.5 text-left text-xs text-slate-400 truncate pl-2">{f.repo_name || "—"}</td>
                    <td className="py-1.5 text-left truncate">
                      <span className={`text-xs ${f.assignee === "Unassigned" ? "text-amber-400 font-medium" : "text-slate-400"}`}>{f.assignee}</span>
                    </td>
                    <td className="py-1.5 text-left text-[10px] text-slate-500 truncate font-mono">{f.file || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-4">
      {/* KPI Cards — compact row */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
        <StatCard label="Total" value={data.total_findings || 0} color="text-red-400" />
        <StatCard label="Patched" value={data.patched || 0} color="text-green-400" />
        <StatCard label="Fix Rate" value={`${patchRate}%`} color={patchRate > 50 ? "text-green-400" : "text-yellow-400"} />
        <StatCard label="Pending" value={data.pending_review || 0} color={data.pending_review > 0 ? "text-orange-400" : "text-green-400"} />
        <StatCard label="Stalled" value={data.stalled_count || 0} sub=">7 days" color={data.stalled_count > 0 ? "text-red-400" : "text-green-400"} />
        <StatCard label="Unassigned" value={data.unassigned_count || 0} color={data.unassigned_count > 0 ? "text-red-400" : "text-green-400"} />
      </div>

      {/* Pipeline by Status */}
      <div className="card">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Pipeline by Status</h3>
        {entries.length === 0 ? (
          <p className="text-sm text-slate-500 py-4 text-center">No remediation data</p>
        ) : entries.map(([status, count]) => (
          <BarH key={status} label={status} value={count} max={maxVal}
            color={status.includes("applied") ? "#22c55e" : status.includes("approved") ? "#22d3ee" : status.includes("generated") || status.includes("patch") ? "#a855f7" : status.includes("pending") ? "#f97316" : "#64748b"} />
        ))}
      </div>

      {/* Pipeline by Severity */}
      {Object.keys(bySev).length > 0 && (
        <div className="card">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Pipeline by Severity</h3>
          <div className="space-y-1.5">
            {["critical", "high", "medium", "low"].map(sev => {
              const sevData = bySev[sev];
              if (!sevData) return null;
              const total = Object.values(sevData as Record<string, number>).reduce((a: number, b: number) => a + b, 0);
              const fixed = (sevData.approved || 0) + (sevData.applied || 0) + (sevData.patch_generated || 0);
              const pct = total > 0 ? Math.round((fixed / total) * 100) : 0;
              const sc = SEV_COLORS[sev] || { text: "text-slate-400", bg: "" };
              return (
                <div key={sev} className="flex items-center gap-2">
                  <span className={`text-[9px] uppercase w-14 font-semibold ${sc.text}`}>{sev}</span>
                  <div className="flex-1 h-2.5 rounded-full bg-white/[0.04] overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-500 bg-red-500/60" style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-[10px] text-slate-400 w-24 text-right">{fixed}/{total} fixed ({pct}%)</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Actionable tables */}
      <ActionTable title={`Awaiting Approval (${data.awaiting_approval_count || 0})`} items={data.awaiting_approval || []} color="purple" />
      <ActionTable title={`Stalled > 7 Days (${data.stalled_count || 0})`} items={data.stalled || []} color="red" />
      <ActionTable title={`Unassigned (${data.unassigned_count || 0})`} items={data.unassigned || []} color="amber" />
    </div>
  );
}

function DeveloperReport() {
  const [data, setData] = useState<any>(null);
  const [days, setDays] = useState(30);
  useEffect(() => { getDeveloperActivity(days).then(r => setData(r.data)).catch(() => {}); }, [days]);
  if (!data) return <Spinner />;

  return (
    <div className="space-y-5">
      <select value={days} onChange={e => setDays(Number(e.target.value))} className="select-dark text-xs">
        <option value={7}>Last 7 days</option>
        <option value={30}>Last 30 days</option>
        <option value={90}>Last 90 days</option>
      </select>

      {(data.users || []).length === 0 ? (
        <div className="card text-center py-12"><p className="text-slate-500">No triage activity yet</p></div>
      ) : (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-white/[0.06]">
              {["User", "Total Actions", "Mark FP", "Mark TP", "Accept Risk", "Other"].map(h => (
                <th key={h} className="px-4 py-3 text-left text-[10px] font-semibold text-slate-500 uppercase tracking-widest">{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {(data.users || []).map((u: any) => (
                <tr key={u.user_id} className="border-b border-white/[0.03] hover:bg-white/[0.02]">
                  <td className="px-4 py-3 text-sm text-slate-200 font-medium">{u.name}</td>
                  <td className="px-4 py-3 text-sm font-bold text-red-400">{u.total}</td>
                  <td className="px-4 py-3 text-sm text-green-400">{u.actions.mark_fp || 0}</td>
                  <td className="px-4 py-3 text-sm text-red-400">{u.actions.mark_tp || 0}</td>
                  <td className="px-4 py-3 text-sm text-yellow-400">{u.actions.accept_risk || 0}</td>
                  <td className="px-4 py-3 text-sm text-slate-500">{u.total - (u.actions.mark_fp || 0) - (u.actions.mark_tp || 0) - (u.actions.accept_risk || 0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════
//  ENTERPRISE REPORT SECTIONS
// ═══════════════════════════════════════════════════════

function ReleaseReadinessReport({ repoId }: { repoId?: string }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => { setData(null); getReleaseReadiness(repoId).then(r => setData(r.data)).catch(() => {}); }, [repoId]);
  if (!data) return <Spinner />;
  const isGo = data.release_status === "GO";
  return (
    <div className="space-y-6">
      {/* GO / NO-GO Banner */}
      <div className={`rounded-xl p-6 text-center ${isGo ? "bg-emerald-500/20 border border-emerald-500/30" : "bg-red-500/20 border border-red-500/30"}`}>
        <p className={`text-4xl font-black ${isGo ? "text-emerald-400" : "text-red-400"}`}>{data.release_status}</p>
        <p className="text-sm text-slate-400 mt-2">{data.recommendation}</p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Security Score" value={data.security_score} color={data.security_score >= 60 ? "text-emerald-400" : "text-red-400"} />
        <StatCard label="Open Findings" value={data.open_findings} color="text-red-400" />
        <StatCard label="Review Coverage" value={`${data.review_coverage_pct}%`} color={data.review_coverage_pct >= 80 ? "text-emerald-400" : "text-amber-400"} />
        <StatCard label="New Critical (7d)" value={data.new_critical_7d} color={data.new_critical_7d > 0 ? "text-red-400" : "text-emerald-400"} />
      </div>

      {/* Severity */}
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-5">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Severity Breakdown</h3>
        {Object.entries(data.severity_counts || {}).map(([sev, count]: [string, any]) => (
          <BarH key={sev} label={sev.toUpperCase()} value={count} max={Math.max(...Object.values(data.severity_counts || {}).map(Number))}
            color={sev === "critical" ? "#ef4444" : sev === "high" ? "#f97316" : sev === "medium" ? "#eab308" : "#22c55e"} />
        ))}
      </div>

      {/* Violations */}
      {data.violations?.length > 0 && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-red-400 uppercase tracking-wider mb-3">Policy Violations ({data.violation_count})</h3>
          <ul className="space-y-2">
            {data.violations.map((v: string, i: number) => (
              <li key={i} className="text-sm text-red-300 flex items-start gap-2">
                <span className="text-red-500 mt-0.5">&#9679;</span>
                <span>{v}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function SecurityDebtReport({ repoId }: { repoId?: string }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => { setData(null); getSecurityDebt(repoId).then(r => setData(r.data)).catch(() => {}); }, [repoId]);
  if (!data) return <Spinner />;
  const mttr = data.mttr || {};
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total Debt" value={`${data.total_hours}h`} sub={data.debt_rating} color={data.debt_rating === "Critical" ? "text-red-400" : "text-amber-400"} />
        <StatCard label="Estimated Cost" value={`$${(data.total_cost_usd || 0).toLocaleString()}`} sub={`@ $${data.hourly_rate_used}/hr`} color="text-red-400" />
        <StatCard label="Overdue Debt" value={`${data.overdue_hours}h`} sub={`$${(data.overdue_cost_usd || 0).toLocaleString()}`} color="text-red-400" />
        <StatCard label="Fix Rate" value={`${mttr.fix_rate_pct || 0}%`} sub={`MTTR: ${mttr.mttr_overall_days || 0}d`} color={mttr.fix_rate_pct >= 50 ? "text-emerald-400" : "text-amber-400"} />
      </div>

      {/* Debt by Severity */}
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-5">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Debt by Severity (hours)</h3>
        {Object.entries(data.by_severity || {}).map(([sev, hours]: [string, any]) => (
          <BarH key={sev} label={sev.toUpperCase()} value={hours} max={Math.max(...Object.values(data.by_severity || {}).map(Number))}
            color={sev === "critical" ? "#ef4444" : sev === "high" ? "#f97316" : sev === "medium" ? "#eab308" : "#22c55e"} />
        ))}
      </div>

      {/* MTTR by Severity */}
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-5">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Mean Time to Remediate (days)</h3>
        <table className="w-full">
          <thead><TableRow cells={["Severity", "MTTR (days)", "Open Mean Age", "Resolved", "Open"]} isHeader /></thead>
          <tbody>
            {["critical", "high", "medium", "low"].map(sev => (
              <TableRow key={sev} cells={[
                sev.charAt(0).toUpperCase() + sev.slice(1),
                (mttr.mttr_by_severity || {})[sev] ?? "N/A",
                (mttr.open_mean_age_by_severity || {})[sev] ?? "N/A",
                "-", "-",
              ]} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function FixPriorityReport({ repoId }: { repoId?: string }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => { setData(null); getFixPriority(repoId).then(r => setData(r.data)).catch(() => {}); }, [repoId]);
  if (!data) return <Spinner />;
  return (
    <div className="space-y-6">
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-5">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
          Top {data.top_fixes?.length || 0} Fixes (of {data.total_analyzed} analyzed)
        </h3>
        <table className="w-full">
          <thead><TableRow cells={["#", "Title", "Severity", "Score", "Age", "Est.", "Reason"]} isHeader /></thead>
          <tbody>
            {(data.top_fixes || []).map((fix: any) => (
              <TableRow key={fix.rank} cells={[
                fix.rank, (fix.title || "").slice(0, 40), fix.severity,
                fix.priority_score?.toFixed(2), `${fix.age_days}d`,
                `${fix.estimated_fix_hours}h`, (fix.reason || "").slice(0, 40),
              ]} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DeveloperGuideReport({ repoId }: { repoId?: string }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => { setData(null); getDeveloperReport(repoId).then(r => setData(r.data)).catch(() => {}); }, [repoId]);
  if (!data) return <Spinner />;
  const sevColors: Record<string, string> = { critical: "border-red-500/30 bg-red-500/5", high: "border-orange-500/30 bg-orange-500/5", medium: "border-amber-500/30 bg-amber-500/5", low: "border-emerald-500/30 bg-emerald-500/5" };
  const sevText: Record<string, string> = { critical: "text-red-400", high: "text-orange-400", medium: "text-amber-400", low: "text-emerald-400" };
  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-500">{data.total_findings} findings with remediation guidance</p>
      {(data.findings || []).map((f: any, idx: number) => {
        const g = f.guidance || {};
        const cvss = f.cvss || {};
        return (
          <div key={f.id || idx} className={`border rounded-xl p-5 ${sevColors[f.severity] || "border-white/[0.06] bg-white/[0.02]"}`}>
            <div className="flex items-start justify-between mb-3">
              <div>
                <h3 className={`text-sm font-bold ${sevText[f.severity] || "text-white"}`}>
                  {f.title}
                </h3>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  {f.file_path}{f.line_start ? `:${f.line_start}` : ""} {f.cwe ? `| ${f.cwe}` : ""} {f.function_name ? `| ${f.function_name}()` : ""}
                </p>
              </div>
              <div className="text-right shrink-0">
                <span className={`text-xs font-bold px-2 py-1 rounded ${sevColors[f.severity]}`}>{f.severity?.toUpperCase()}</span>
                {cvss.score && <p className="text-[10px] text-slate-500 mt-1">CVSS {cvss.score} ({cvss.rating})</p>}
              </div>
            </div>

            {g.explanation && (
              <div className="mb-3">
                <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mb-1">What is this?</p>
                <p className="text-xs text-slate-400">{g.explanation}</p>
              </div>
            )}

            {g.exploitation_scenario && (
              <div className="mb-3">
                <p className="text-[10px] font-semibold text-red-400 uppercase tracking-widest mb-1">Exploitation Scenario</p>
                <p className="text-xs text-slate-400">{g.exploitation_scenario}</p>
              </div>
            )}

            {g.fix_strategy && (
              <div className="mb-3">
                <p className="text-[10px] font-semibold text-emerald-400 uppercase tracking-widest mb-1">Fix Strategy</p>
                <p className="text-xs text-slate-400">{g.fix_strategy}</p>
              </div>
            )}

            {g.before_code && g.after_code && (
              <div className="grid grid-cols-2 gap-3 mb-3">
                <div>
                  <p className="text-[10px] font-semibold text-red-400 uppercase tracking-widest mb-1">Vulnerable</p>
                  <pre className="text-[10px] text-slate-400 bg-red-500/5 border border-red-500/10 rounded p-2 overflow-x-auto whitespace-pre-wrap">{g.before_code}</pre>
                </div>
                <div>
                  <p className="text-[10px] font-semibold text-emerald-400 uppercase tracking-widest mb-1">Secure</p>
                  <pre className="text-[10px] text-slate-400 bg-emerald-500/5 border border-emerald-500/10 rounded p-2 overflow-x-auto whitespace-pre-wrap">{g.after_code}</pre>
                </div>
              </div>
            )}

            {g.best_practices && (
              <div className="mb-3">
                <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mb-1">Best Practices</p>
                <ul className="space-y-1">
                  {g.best_practices.map((bp: string, i: number) => (
                    <li key={i} className="text-[11px] text-slate-400 flex items-start gap-1.5">
                      <span className="text-red-500 mt-0.5 shrink-0">&#8227;</span>
                      <span>{bp}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="flex items-center gap-4 text-[10px] text-slate-600">
              {g.fix_difficulty && <span>Difficulty: <span className="text-slate-400">{g.fix_difficulty}</span></span>}
              {g.estimated_fix_minutes && <span>Est. Fix: <span className="text-slate-400">{g.estimated_fix_minutes} min</span></span>}
              {g.guidance_source && <span>Source: <span className="text-slate-400">{g.guidance_source}</span></span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Section map ───────────────────────────────────────
function getContent(tab: ReportTab, repoId?: string): React.ReactNode {
  switch (tab) {
    case "executive": return <ExecutiveReport key={repoId || "all"} repoId={repoId} />;
    case "compliance": return <ComplianceReport key={repoId || "all"} repoId={repoId} />;
    case "aging": return <SLAAgingReport key={repoId || "all"} repoId={repoId} />;
    case "trends": return <TrendsReport />;
    case "repo_risk": return <RepoRiskReport />;
    case "ai": return <AIReport key={repoId || "all"} repoId={repoId} />;
    case "remediation": return <RemediationReport key={repoId || "all"} repoId={repoId} />;
    case "developer": return <DeveloperReport />;
    case "release_readiness": return <ReleaseReadinessReport key={repoId || "all"} repoId={repoId} />;
    case "security_debt": return <SecurityDebtReport key={repoId || "all"} repoId={repoId} />;
    case "fix_priority": return <FixPriorityReport key={repoId || "all"} repoId={repoId} />;
    // "governance" case removed 2026-05-16 alongside the governance surface.
    case "developer_report": return <DeveloperGuideReport key={repoId || "all"} repoId={repoId} />;
    default: return null;
  }
}

// ═══════════════════════════════════════════════════════
//  MAIN PAGE
// ═══════════════════════════════════════════════════════
function ScopePicker({ bus, selectedRepo, onRepoChange }: {
  bus: any[]; selectedRepo: string; onRepoChange: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [repos, setRepos] = useState<any[]>([]);
  const [searching, setSearching] = useState(false);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  // Fetch repos with server-side search
  const fetchRepos = useCallback((query: string) => {
    setSearching(true);
    const params: Record<string, string | number> = { page_size: 30 };
    if (query) params.search = query;
    getRepositories(params).then(r => {
      const d = r.data;
      setRepos(d?.items ?? (Array.isArray(d) ? d : []));
    }).catch(() => setRepos([])).finally(() => setSearching(false));
  }, []);

  // Load initial repos when dropdown opens
  useEffect(() => {
    if (open) fetchRepos("");
  }, [open, fetchRepos]);

  // Debounced search
  const handleSearch = useCallback((val: string) => {
    setSearch(val);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => fetchRepos(val), 300);
  }, [fetchRepos]);

  // Resolve selected name (might not be in current search results)
  useEffect(() => {
    if (!selectedRepo) { setSelectedName(null); return; }
    const found = repos.find((r: any) => r.id === selectedRepo);
    if (found) { setSelectedName(found.name); return; }
    // Fetch the specific repo to get its name
    if (!selectedName) {
      getRepositories({ page_size: 1, search: "" }).catch(() => {});
      // Just use the ID as fallback until the repo appears in results
    }
  }, [selectedRepo, repos]);

  return (
    <div ref={ref} className="relative">
      {/* Trigger */}
      <button onClick={() => { setOpen(!open); setSearch(""); }}
        className="flex items-center gap-2 px-3 py-2.5 rounded-lg border border-white/[0.08] bg-white/[0.02] hover:border-white/[0.15] text-sm text-left transition-all min-w-[240px]"
      >
        <svg className="w-4 h-4 text-slate-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
        </svg>
        <span className={`flex-1 truncate ${selectedName ? "text-slate-200" : "text-slate-500"}`}>
          {selectedName || "Organization (all)"}
        </span>
        {selectedRepo ? (
          <button onClick={(e) => { e.stopPropagation(); onRepoChange(""); setSelectedName(null); setOpen(false); }} className="text-slate-500 hover:text-slate-300">
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        ) : (
          <svg className={`w-3.5 h-3.5 text-slate-500 transition-transform ${open ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        )}
      </button>

      {/* Dropdown */}
      {open && (
        <div className="absolute left-0 top-full mt-1 z-30 w-80 rounded-lg border border-white/[0.1] bg-[#1a2332] shadow-2xl overflow-hidden">
          <div className="px-3 py-2 border-b border-white/[0.06]">
            <div className="flex items-center gap-2">
              {searching ? (
                <div className="w-3.5 h-3.5 rounded-full border-2 animate-spin shrink-0" style={{ borderColor: "rgba(239,68,68,0.2)", borderTopColor: "#ef4444" }} />
              ) : (
                <svg className="w-3.5 h-3.5 text-slate-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              )}
              <input value={search} onChange={(e) => handleSearch(e.target.value)} autoFocus
                placeholder="Search projects..." className="flex-1 bg-transparent text-xs text-slate-200 placeholder-slate-500 outline-none" />
            </div>
          </div>
          <div className="max-h-64 overflow-y-auto">
            {/* Organization level */}
            {!search && (
              <button onClick={() => { onRepoChange(""); setSelectedName(null); setOpen(false); }}
                className={`w-full flex items-center gap-2.5 px-3 py-2 text-left text-xs hover:bg-purple-500/10 transition-colors ${!selectedRepo ? "bg-white/[0.03] text-purple-400 font-medium" : "text-slate-300"}`}
              >
                <span className="text-sm w-5 text-center">🏢</span>
                <span>Organization (all projects)</span>
              </button>
            )}

            {/* BU level — only shown when not searching */}
            {!search && bus.length > 0 && (
              <div className="px-3 pt-2 pb-1">
                <p className="text-[9px] font-semibold text-slate-600 uppercase tracking-widest">Business Units</p>
              </div>
            )}
            {!search && bus.map((b: any) => (
              <button key={b.id} onClick={() => { /* BU-level placeholder */ setOpen(false); }}
                className="w-full flex items-center gap-2.5 px-3 py-1.5 text-left text-xs hover:bg-amber-500/10 transition-colors text-amber-400/80">
                <span className="text-sm w-5 text-center">🏗️</span>
                <span className="font-medium">{b.name}</span>
              </button>
            ))}

            {/* Projects — from server-side search results */}
            {repos.length > 0 && (
              <div className="px-3 pt-2 pb-1">
                <p className="text-[9px] font-semibold text-slate-600 uppercase tracking-widest">
                  {search ? "Search Results" : "Projects"}
                </p>
              </div>
            )}
            {repos.map((r: any) => (
              <button key={r.id} onClick={() => { onRepoChange(r.id); setSelectedName(r.name); setOpen(false); }}
                className={`w-full flex items-center gap-2.5 px-3 py-1.5 text-left text-xs hover:bg-red-500/10 transition-colors ${selectedRepo === r.id ? "bg-white/[0.03] text-red-400 font-medium" : "text-slate-400"}`}
              >
                <span className="text-sm w-5 text-center">📁</span>
                <span className="truncate">{r.name}</span>
              </button>
            ))}

            {search && repos.length === 0 && !searching && (
              <div className="px-3 py-4 text-xs text-slate-500 text-center">No matches for &ldquo;{search}&rdquo;</div>
            )}
          </div>
          <div className="px-3 py-1.5 border-t border-white/[0.06]">
            <span className="text-[10px] text-slate-600">
              {searching ? "Searching..." : `${repos.length} project${repos.length !== 1 ? "s" : ""}`}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ReportsPage() {
  const [activeTab, setActiveTab] = useState<ReportTab>("executive");
  const [bus, setBus] = useState<any[]>([]);
  const [selectedRepo, setSelectedRepo] = useState("");

  useEffect(() => {
    getBusinessUnits().then(r => setBus(r.data || [])).catch(() => {});
  }, []);

  // Hero actions for the Reports page: jump to filtered findings
  // list + export dropdown. Both ride in the sticky header band.
  const headerActions = (
    <>
      <Link href={`/findings${selectedRepo ? `?repository_id=${selectedRepo}` : ""}`}
        className="btn-secondary-sm flex items-center gap-1.5">
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        View Findings
      </Link>
      <ExportDropdown reportType={activeTab} repositoryId={selectedRepo || undefined} />
    </>
  );

  return (
    <AppShell pageActions={headerActions}>
      <div className="space-y-5 max-w-[1400px]">
        <p className="text-sm text-slate-400">Security analytics and compliance reporting</p>

        {/* Report selector + Project filter */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative">
            <select
              value={activeTab}
              onChange={(e) => setActiveTab(e.target.value as ReportTab)}
              className="select-dark text-sm pl-10 pr-10 py-3 min-w-[280px] font-medium"
            >
              {TABS.map((t) => (
                <option key={t.key} value={t.key}>{t.icon} {t.label} Report</option>
              ))}
            </select>
            <svg className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-red-400 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <ScopePicker bus={bus} selectedRepo={selectedRepo} onRepoChange={setSelectedRepo} />
        </div>

        {/* Content */}
        {getContent(activeTab, selectedRepo || undefined)}
      </div>
    </AppShell>
  );
}
