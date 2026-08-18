"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect, useMemo, useCallback } from "react";
import Link from "next/link";
import AppShell from "@/components/layout/AppShell";
import { getFindings, getRotationSummary, getRotationEvents, triageFinding } from "@/lib/api";

// ── Helpers ────────────────────────────────────────────────────────
// Full unit names with proper singular/plural — matches the dashboard's
// fmtDuration helper. Easier to read at a glance than "12h Median".
const fmtDuration = (s: number | null | undefined): string => {
  if (!s || s <= 0) return "—";
  const p = fmtDurationParts(s);
  return p.value === "—" ? "—" : `${p.value} ${p.unit}`;
};
// Split form so the value can render at one size and the unit at another
// (matching the statistic word for visual coherence). Mirrors the
// dashboard's helper.
const fmtDurationParts = (s: number | null | undefined): { value: string; unit: string } => {
  if (!s || s <= 0) return { value: "—", unit: "" };
  if (s < 60) {
    const v = Math.round(s);
    return { value: String(v), unit: v === 1 ? "Second" : "Seconds" };
  }
  if (s < 3600) {
    const v = Math.round(s / 60);
    return { value: String(v), unit: v === 1 ? "Minute" : "Minutes" };
  }
  if (s < 86400) {
    const v = Math.round(s / 3600);
    return { value: String(v), unit: v === 1 ? "Hour" : "Hours" };
  }
  const v = Math.round(s / 86400);
  return { value: String(v), unit: v === 1 ? "Day" : "Days" };
};

// Gap between detection-time (or first-seen-active) and now. Used for
// "age" (how long has this leak been visible) and to colour rows when
// no explicit rotation deadline is set on the finding.
const ageInDays = (iso: string | null | undefined): number | null => {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  return Math.max(0, Math.floor((Date.now() - t) / 86400000));
};

const ageColor = (days: number | null): { bg: string; text: string; label: string } => {
  if (days === null) return { bg: "bg-slate-500/10", text: "text-slate-500", label: "—" };
  const dayWord = days === 1 ? "Day" : "Days";
  if (days >= 7) return { bg: "bg-red-500/15", text: "text-red-400", label: `${days} ${dayWord} Overdue` };
  if (days >= 3) return { bg: "bg-orange-500/15", text: "text-orange-400", label: `${days} ${dayWord} Open` };
  return { bg: "bg-yellow-500/15", text: "text-yellow-400", label: `${days} ${dayWord} Open` };
};

const providerColor = (p: string): string => {
  const map: Record<string, string> = {
    aws: "bg-orange-500/15 text-orange-400",
    gcp: "bg-blue-500/15 text-blue-400",
    azure: "bg-blue-600/15 text-blue-400",
    github: "bg-slate-500/15 text-slate-300",
    gitlab: "bg-orange-500/15 text-orange-400",
    stripe: "bg-purple-500/15 text-purple-400",
    slack: "bg-purple-600/15 text-purple-400",
    twilio: "bg-red-500/15 text-red-400",
    npm: "bg-red-700/15 text-red-400",
    docker: "bg-blue-500/15 text-blue-400",
    anthropic: "bg-orange-500/15 text-orange-400",
    openai: "bg-emerald-500/15 text-emerald-400",
    cloudflare: "bg-amber-500/15 text-amber-400",
  };
  return map[p.toLowerCase()] || "bg-slate-500/15 text-slate-400";
};

interface RotationItem {
  id: string;
  title: string;
  secret_type: string;
  provider: string;
  file_path: string;
  line_start: number | null;
  severity: string;
  validation_status: string;
  first_seen_active_at: string | null;
  first_seen_at: string | null;
  verification_details: string;
}

interface RotationEvent {
  id: string;
  provider: string;
  rotated_at: string;
  time_to_rotation_s: number | null;
  detected_via: string;
}

type SortField = "age" | "severity" | "provider";
type SortDir = "asc" | "desc";

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export default function RotationPage() {
  const [items, setItems] = useState<RotationItem[]>([]);
  const [recentEvents, setRecentEvents] = useState<RotationEvent[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const [providerFilter, setProviderFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [sortField, setSortField] = useState<SortField>("age");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [actionLoading, setActionLoading] = useState<string>("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      // Active credentials are the rotation queue — verifier-confirmed
      // live credentials that need rotation. We use the new
      // validation_status URL filter (committed 2026-04-25) so the API
      // does the work in SQL rather than us pulling 200 findings and
      // filtering client-side.
      const [findingsRes, summaryRes, eventsRes] = await Promise.all([
        getFindings({
          page_size: "200",
          validation_status: "active",
          sort_by: "created_at",
          sort_dir: "desc",
        } as Record<string, string>),
        getRotationSummary(30).catch(() => ({ data: null })),
        getRotationEvents({ days: 30, limit: 8 }).catch(() => ({ data: { items: [] } })),
      ]);

      // Bug fix 2026-04-26: previous version read .findings which the
      // API never returns (it returns .items). The list was permanently
      // empty even when active credentials existed.
      const rows = findingsRes.data?.items || [];
      setItems(
        rows.map((f: any) => {
          const sm = f.source_metadata || {};
          return {
            id: f.id,
            title: f.title,
            secret_type: sm.secret_type || "unknown",
            provider: sm.provider || "unknown",
            file_path: f.file_path,
            line_start: f.line_start,
            severity: f.severity,
            validation_status: sm.validation_status || "unknown",
            first_seen_active_at: sm.first_seen_active_at || null,
            first_seen_at: f.first_seen_at,
            verification_details: sm.verification_details || "",
          };
        }),
      );
      setSummary(summaryRes.data);
      const events = eventsRes.data?.items || eventsRes.data || [];
      setRecentEvents(Array.isArray(events) ? events.slice(0, 8) : []);
    } catch {
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const filtered = useMemo(() => {
    let xs = items;
    if (providerFilter) xs = xs.filter((i) => i.provider === providerFilter);
    if (severityFilter) xs = xs.filter((i) => i.severity === severityFilter);
    xs = [...xs].sort((a, b) => {
      let cmp = 0;
      if (sortField === "age") {
        const aa = ageInDays(a.first_seen_active_at || a.first_seen_at) ?? -1;
        const bb = ageInDays(b.first_seen_active_at || b.first_seen_at) ?? -1;
        cmp = aa - bb;
      } else if (sortField === "severity") {
        cmp = (SEV_RANK[a.severity] ?? 5) - (SEV_RANK[b.severity] ?? 5);
      } else if (sortField === "provider") {
        cmp = a.provider.localeCompare(b.provider);
      }
      return sortDir === "desc" ? -cmp : cmp;
    });
    return xs;
  }, [items, providerFilter, severityFilter, sortField, sortDir]);

  const providers = useMemo(() => {
    const s = new Set<string>();
    items.forEach((i) => s.add(i.provider));
    return Array.from(s).sort();
  }, [items]);

  const overdueCount = items.filter((i) => {
    const a = ageInDays(i.first_seen_active_at || i.first_seen_at);
    return a !== null && a >= 7;
  }).length;

  const handleMarkRotated = async (id: string) => {
    setActionLoading(id);
    try {
      // mark_fp removes the finding from the rotation queue once the
      // user confirms they've rotated at the provider. The next scan
      // either re-detects (if they didn't actually rotate) or stays
      // clean. A cleaner future API would add an explicit "rotated"
      // action but this maps onto existing triage semantics today.
      await triageFinding(id, {
        action: "mark_fp",
        comment: "Rotated at provider — marked from rotation tracker",
      });
      await load();
    } finally {
      setActionLoading("");
    }
  };

  const totalRotations = summary?.total_rotations ?? 0;
  const mttrMedian = summary?.mttr_median_s ?? 0;
  const mttrP90 = summary?.mttr_p90_s ?? 0;

  // "View as full findings list" link is the page-level secondary
  // action; rides in the header alongside notifications.
  const headerAction = (
    <Link
      href="/findings?validation_status=active"
      className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1"
    >
      View as full findings list <span>&rarr;</span>
    </Link>
  );

  return (
    <AppShell pageActions={headerAction}>
      <div className="space-y-6">
        <p className="text-sm text-slate-400">
          Verifier-confirmed live credentials waiting to be rotated. Rows turn red after 7
          days — industry SLA for committed-secret remediation.
        </p>

        {/* Stat row — five compact cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <div className="card p-4">
            <p className="text-[10px] text-red-400 uppercase tracking-wider">In Queue</p>
            <p className="text-2xl font-bold text-red-400 mt-1">{items.length}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">Verified Active</p>
          </div>
          <div className="card p-4">
            <p className="text-[10px] text-orange-400 uppercase tracking-wider">Overdue</p>
            <p className="text-2xl font-bold text-orange-400 mt-1">{overdueCount}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">7+ Days Open</p>
          </div>
          <div className="card p-4">
            <p className="text-[10px] text-green-400 uppercase tracking-wider">Rotated · 30 Days</p>
            <p className="text-2xl font-bold text-green-400 mt-1">{totalRotations}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">Closed-Loop</p>
          </div>
          <div className="card p-4">
            <p className="text-[10px] text-blue-400 uppercase tracking-wider">MTTR (Median)</p>
            {(() => {
              const p = fmtDurationParts(mttrMedian);
              return (
                <p className="mt-1 flex items-baseline gap-1.5">
                  <span className="text-2xl font-bold text-blue-400">{p.value}</span>
                  {p.unit && <span className="text-[10px] text-blue-400">{p.unit}</span>}
                </p>
              );
            })()}
            <p className="text-[10px] text-slate-500 mt-0.5">Last 30 Days</p>
          </div>
          <div className="card p-4">
            <p className="text-[10px] text-purple-400 uppercase tracking-wider">MTTR (p90)</p>
            {(() => {
              const p = fmtDurationParts(mttrP90);
              return (
                <p className="mt-1 flex items-baseline gap-1.5">
                  <span className="text-2xl font-bold text-purple-400">{p.value}</span>
                  {p.unit && <span className="text-[10px] text-purple-400">{p.unit}</span>}
                </p>
              );
            })()}
            <p className="text-[10px] text-slate-500 mt-0.5">Slowest 10%</p>
          </div>
        </div>

        {/* Recent rotation timeline */}
        {recentEvents.length > 0 && (
          <div className="card p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Recent Rotations
              </h2>
              <span className="text-[10px] text-slate-500">Last 8 Events · 30 Day Window</span>
            </div>
            <div className="flex gap-2 overflow-x-auto pb-1">
              {recentEvents.map((e) => (
                <div
                  key={e.id}
                  className="shrink-0 px-3 py-2 rounded-lg border border-white/[0.06] bg-white/[0.02] min-w-[140px]"
                >
                  <div className="flex items-center gap-1.5 mb-1">
                    <span className={`text-[9px] px-1.5 py-0.5 rounded font-medium ${providerColor(e.provider)}`}>
                      {e.provider}
                    </span>
                    <span className="text-[9px] text-slate-500">
                      {e.detected_via?.replace(/_/g, " ") || "verifier"}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-slate-300">{fmtDuration(e.time_to_rotation_s)}</p>
                  <p className="text-[9px] text-slate-500">
                    {e.rotated_at ? new Date(e.rotated_at).toLocaleDateString() : ""}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Filter bar */}
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={providerFilter}
            onChange={(e) => setProviderFilter(e.target.value)}
            className="select-dark text-xs"
          >
            <option value="">All providers ({providers.length})</option>
            {providers.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="select-dark text-xs"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            value={sortField}
            onChange={(e) => setSortField(e.target.value as SortField)}
            className="select-dark text-xs"
          >
            <option value="age">Sort by age</option>
            <option value="severity">Sort by severity</option>
            <option value="provider">Sort by provider</option>
          </select>
          <button
            onClick={() => setSortDir(sortDir === "desc" ? "asc" : "desc")}
            className="btn-secondary text-xs"
            title="Toggle sort direction"
          >
            {sortDir === "desc" ? "↓ Desc" : "↑ Asc"}
          </button>
          {(providerFilter || severityFilter) && (
            <button
              onClick={() => {
                setProviderFilter("");
                setSeverityFilter("");
              }}
              className="btn-secondary text-xs text-slate-400"
            >
              Clear filters
            </button>
          )}
          <span className="text-[10px] text-slate-500 ml-auto">
            {filtered.length} of {items.length} shown
          </span>
        </div>

        {/* Table */}
        <div className="card p-0 overflow-hidden">
          {loading ? (
            <div className="text-center py-20 text-slate-500">
              <div className="inline-block w-5 h-5 border-2 border-red-400/30 border-t-red-400 rounded-full animate-spin mb-3" />
              <p>Loading rotation queue...</p>
            </div>
          ) : items.length === 0 ? (
            <div className="text-center py-20 px-6">
              <p className="text-slate-300 text-sm font-medium">Rotation queue is clear</p>
              <p className="text-slate-500 text-xs mt-2 max-w-md mx-auto">
                No verifier-confirmed live credentials currently in the queue. The verifier
                stamps <code className="text-slate-400">validation_status=active</code> when it
                successfully authenticates a candidate against the provider&apos;s API. Findings
                appear here automatically the moment that happens.
              </p>
              <Link
                href="/docs#scanning"
                className="inline-block mt-4 text-xs text-red-400 hover:text-red-300"
              >
                Learn how the verifier works &rarr;
              </Link>
            </div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <p className="text-sm">No rows match your filters.</p>
              <button
                onClick={() => {
                  setProviderFilter("");
                  setSeverityFilter("");
                }}
                className="text-xs text-red-400 hover:text-red-300 mt-2"
              >
                Clear filters
              </button>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/[0.06] bg-white/[0.02]">
                  <th className="text-left py-3 px-3 text-[10px] text-slate-500 uppercase tracking-wider">Provider</th>
                  <th className="text-left py-3 px-3 text-[10px] text-slate-500 uppercase tracking-wider">Secret</th>
                  <th className="text-left py-3 px-3 text-[10px] text-slate-500 uppercase tracking-wider">File</th>
                  <th className="text-left py-3 px-3 text-[10px] text-slate-500 uppercase tracking-wider">Severity</th>
                  <th className="text-left py-3 px-3 text-[10px] text-slate-500 uppercase tracking-wider">Age</th>
                  <th className="text-right py-3 px-3 text-[10px] text-slate-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((item) => {
                  const a = ageInDays(item.first_seen_active_at || item.first_seen_at);
                  const aS = ageColor(a);
                  return (
                    <tr
                      key={item.id}
                      className="border-b border-white/[0.03] hover:bg-white/[0.02] transition-colors group"
                    >
                      <td className="py-2.5 px-3">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium capitalize ${providerColor(item.provider)}`}>
                          {item.provider}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <Link
                          href={`/findings/${item.id}`}
                          className="text-slate-300 hover:text-red-400 transition-colors capitalize"
                        >
                          {item.secret_type.replace(/_/g, " ")}
                        </Link>
                      </td>
                      <td className="py-2.5 px-3 text-slate-500 text-xs font-mono truncate max-w-[260px]" title={item.file_path}>
                        {item.file_path}
                        {item.line_start ? <span className="text-slate-600">:{item.line_start}</span> : null}
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded ${
                            item.severity === "critical"
                              ? "bg-red-500/15 text-red-400"
                              : item.severity === "high"
                              ? "bg-orange-500/15 text-orange-400"
                              : "bg-yellow-500/15 text-yellow-400"
                          }`}
                        >
                          {item.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${aS.bg} ${aS.text}`}>
                          {aS.label}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center justify-end gap-1.5">
                          <Link
                            href={`/findings/${item.id}#rotation`}
                            className="text-[10px] px-2 py-1 rounded bg-white/[0.04] text-slate-400 hover:bg-white/[0.08] hover:text-slate-200 transition-colors"
                            title="Open rotation playbook for this provider"
                          >
                            Playbook
                          </Link>
                          <button
                            onClick={() => handleMarkRotated(item.id)}
                            disabled={actionLoading === item.id}
                            className="text-[10px] px-2 py-1 rounded bg-green-500/15 text-green-400 hover:bg-green-500/25 transition-colors disabled:opacity-50"
                            title="Mark as rotated at the provider — removes from this queue"
                          >
                            {actionLoading === item.id ? "..." : "Mark Rotated"}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </AppShell>
  );
}
