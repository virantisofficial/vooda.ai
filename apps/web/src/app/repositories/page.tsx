"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useEffect, useState, useMemo, useCallback } from "react";
import Link from "next/link";
import AppShell from "@/components/layout/AppShell";
import AddRepositoryModal from "@/components/repositories/AddRepositoryModal";
import EditRepositoryModal from "@/components/repositories/EditRepositoryModal";
import {
  getRepositories, getRepositoryFacets, createRepository, deleteRepository,
  getRepoStats, uploadToRepository, triggerScan,
  getRepositoryDeletePreview, getRepositoryBulkDeletePreview, archiveRepository,
  unarchiveRepository, getRepoSeverityTrend,
} from "@/lib/api";
import { useToast } from "@/components/ui/Toast";
import DeleteConfirmModal, { type DeletePreview } from "@/components/ui/DeleteConfirmModal";
import BulkDeleteConfirmModal, { type BulkDeletePreview } from "@/components/ui/BulkDeleteConfirmModal";
import type { Repository } from "@/types";

// ── Types ──────────────────────────────────────────────────────
interface RepoStats {
  total_findings: number;
  open_criticals: number;
  open_highs: number;
  last_scan_date: string | null;
  last_scan_status: string | null;
  by_severity: Record<string, number>;
  policy_status: "passed" | "failed" | "warning" | "not_scanned";
  active_scan: {
    id: string;
    status: string;
    progress_pct: number;
    status_message: string | null;
  } | null;
}

type ViewMode = "table" | "cards";
type SortField = "name" | "findings" | "criticals" | "last_scan" | "created";
type SortDir = "asc" | "desc";
type RiskLevel = "" | "critical" | "high" | "medium" | "low" | "clean";

const ITEMS_PER_PAGE = 50;

// ── Helpers ────────────────────────────────────────────────────
function getRisk(stats?: RepoStats): { level: RiskLevel; score: number } {
  if (!stats) return { level: "", score: -1 };
  if (stats.open_criticals > 0) return { level: "critical", score: 4 };
  const high = Object.entries(stats.by_severity).find(([k]) => k.includes("HIGH"))?.[1] || 0;
  if (high > 0) return { level: "high", score: 3 };
  if (stats.total_findings > 0) return { level: "medium", score: 2 };
  return { level: "clean", score: 0 };
}

const RISK_BADGE: Record<string, { bg: string; text: string; label: string }> = {
  critical: { bg: "bg-red-500/15",    text: "text-red-400",    label: "Critical" },
  high:     { bg: "bg-orange-500/15", text: "text-orange-400", label: "High"     },
  medium:   { bg: "bg-yellow-500/15", text: "text-yellow-400", label: "Medium"   },
  low:      { bg: "bg-green-500/15",  text: "text-green-400",  label: "Low"      },
  clean:    { bg: "bg-green-500/10",  text: "text-green-400",  label: "Clean"    },
};

const POLICY_BADGE: Record<string, { icon: string; bg: string; text: string; label: string }> = {
  failed:      { icon: "✕", bg: "bg-red-500/15",    text: "text-red-400",    label: "Failed"      },
  warning:     { icon: "!", bg: "bg-yellow-500/15", text: "text-yellow-400", label: "Warning"     },
  passed:      { icon: "✓", bg: "bg-green-500/15",  text: "text-green-400",  label: "Passed"      },
  not_scanned: { icon: "—", bg: "bg-slate-500/10",  text: "text-slate-500",  label: "Not Scanned" },
};

const SCAN_STATUS: Record<string, { dot: string; label: string }> = {
  completed: { dot: "bg-green-400",              label: "Passed"  },
  failed:    { dot: "bg-red-400",                label: "Failed"  },
  running:   { dot: "bg-red-400 animate-pulse",  label: "Running" },
  pending:   { dot: "bg-yellow-400",             label: "Pending" },
};

// ── Webhook health badge ───────────────────────────────────────
// Three-state health pill driven by `last_webhook_event_at` and
// `last_webhook_event_status` on the Repository row.  Same pattern
// GitGuardian + Aikido ship.  Green ≤ 7d, yellow 8-30d, red > 30d
// or `last_status === "failed"`.  Returns `null` (renders an em-dash
// dash cell instead) when there's no webhook history at all — that's
// not "stale," it's "never connected."
//
// Click-through: the row already links to /repositories/{id}.  No
// independent click target needed here; the badge is a status
// glance, the row click takes you to the detail view where the
// webhook event log lives.
type WebhookHealth = "healthy" | "stale" | "dead" | "failed" | "never";
function webhookHealthState(repo: Repository): { state: WebhookHealth; ageDays: number | null } {
  const ts = repo.last_webhook_event_at;
  if (!ts) return { state: "never", ageDays: null };
  const status = repo.last_webhook_event_status;
  const ageMs = Date.now() - new Date(ts).getTime();
  const ageDays = Math.floor(ageMs / 86400000);
  if (status === "failed") return { state: "failed", ageDays };
  if (ageDays <= 7) return { state: "healthy", ageDays };
  if (ageDays <= 30) return { state: "stale", ageDays };
  return { state: "dead", ageDays };
}

function WebhookHealthBadge({ repo }: { repo: Repository }) {
  const { state, ageDays } = webhookHealthState(repo);

  // Repo never had a webhook event — render the same em-dash style
  // the other "no data" cells use.  We don't want every uploaded /
  // archive repo screaming red.
  if (state === "never") {
    return (
      <span className="text-[10px] text-slate-700" title="No webhook events recorded">—</span>
    );
  }

  const palette: Record<WebhookHealth, { dot: string; bg: string; border: string; text: string; label: string }> = {
    healthy: { dot: "#22c55e", bg: "rgba(34,197,94,0.08)",  border: "rgba(34,197,94,0.22)",  text: "#86efac", label: "Healthy" },
    stale:   { dot: "#eab308", bg: "rgba(234,179,8,0.08)",  border: "rgba(234,179,8,0.22)",  text: "#fde68a", label: "Stale" },
    dead:    { dot: "#ef4444", bg: "rgba(239,68,68,0.08)",  border: "rgba(239,68,68,0.22)",  text: "#fca5a5", label: "Dead" },
    failed:  { dot: "#ef4444", bg: "rgba(239,68,68,0.08)",  border: "rgba(239,68,68,0.22)",  text: "#fca5a5", label: "Failed" },
    never:   { dot: "#64748b", bg: "rgba(100,116,139,0.08)", border: "rgba(100,116,139,0.22)", text: "#cbd5e1", label: "—" },
  };
  const p = palette[state];
  const ageLabel = ageDays === null ? ""
    : ageDays === 0 ? "Today"
    : ageDays === 1 ? "1 Day Ago"
    : `${ageDays} Days Ago`;
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium whitespace-nowrap"
      style={{ background: p.bg, border: `1px solid ${p.border}`, color: p.text }}
      title={`Webhook ${p.label} · Last Event ${ageLabel}`}
    >
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: p.dot }} />
      {p.label}
    </span>
  );
}

// ── 30-day severity-trend sparkline ────────────────────────────
// Tiny SVG sparkline keyed off /repositories/{id}/severity-trend.
// Per-day bars (vs. an area chart) read better at this small size —
// each day stands out as one tick rather than smoothing across days.
// Renders dashes when there's no data so the row stays aligned.
function MiniSparkline({ series, width = 70, height = 24 }: {
  series: Array<{ date: string; weighted: number }>;
  width?: number;
  height?: number;
}) {
  if (!series || series.length === 0) {
    return <span className="text-[10px] text-slate-700">—</span>;
  }
  const max = Math.max(...series.map(s => s.weighted), 1);
  const allZero = series.every(s => s.weighted === 0);
  if (allZero) {
    // Render a flat baseline rather than dashes — visually communicates
    // "we measured and saw nothing" vs the dashes which mean "no data
    // at all."
    return (
      <svg width={width} height={height} className="overflow-visible">
        <line x1={0} y1={height - 2} x2={width} y2={height - 2} stroke="rgba(100,116,139,0.35)" strokeWidth={1} />
      </svg>
    );
  }
  const barW = Math.max(1, (width / series.length) - 1);
  return (
    <svg width={width} height={height} className="overflow-visible">
      {series.map((s, i) => {
        const h = Math.max(1, (s.weighted / max) * (height - 2));
        const x = i * (width / series.length);
        const y = height - h;
        // Color-grade the bar by relative magnitude.  Tallest 25%
        // reads red, middle 50% orange, lowest 25% slate.
        const ratio = s.weighted / max;
        const color =
          ratio === 0 ? "rgba(100,116,139,0.25)" :
          ratio >= 0.75 ? "rgba(239,68,68,0.7)" :
          ratio >= 0.4  ? "rgba(251,146,60,0.7)" :
                          "rgba(96,165,250,0.55)";
        return <rect key={i} x={x} y={y} width={barW} height={h} fill={color} rx={0.5}><title>{s.date}: {s.weighted}</title></rect>;
      })}
    </svg>
  );
}

// ── Language / Framework chips ─────────────────────────────────
function LangChips({ items, color }: { items: string[]; color: "blue" | "purple" }) {
  const cls = color === "blue"
    ? "bg-blue-500/10 text-blue-400 border-blue-500/15"
    : "bg-purple-500/10 text-purple-400 border-purple-500/15";
  if (!items.length) return <span className="text-[10px] text-slate-700">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {items.slice(0, 2).map((v) => (
        <span key={v} className={`text-[9px] px-1.5 py-0.5 rounded border whitespace-nowrap ${cls}`}>{v}</span>
      ))}
      {items.length > 2 && <span className="text-[9px] text-slate-600">+{items.length - 2}</span>}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  CARD VIEW
// ═══════════════════════════════════════════════════════════════
function RepoCard({ repo, stats, selected, onSelect, onDelete, onEdit, onUnarchive, ticketingMap }: {
  repo: Repository; stats?: RepoStats; selected: boolean; onSelect: (id: string) => void; onDelete: (id: string) => void; onEdit: (repo: Repository) => void;
  // Provided in the Archived view — shows an Unarchive icon button.
  onUnarchive?: (id: string, name: string) => void;
  // Map of integration_id -> "Board Name → PROJECT_KEY" used to
  // render a small badge when a repo has a per-repo ticketing
  // destination set. Empty map = no badges shown.
  ticketingMap: Record<string, string>;
}) {
  const risk = getRisk(stats);
  const rb = RISK_BADGE[risk.level] || {};
  const isArchived = (repo as any).is_archived === true;
  return (
    <div className={`card card-hover group relative ${selected ? "border-red-500/30 bg-red-500/[0.02]" : ""} ${isArchived ? "opacity-75 grayscale" : ""}`}
      style={isArchived ? { background: "rgba(120, 113, 108, 0.04)", borderColor: "rgba(120, 113, 108, 0.18)" } : undefined}>
      <div className="absolute top-3 left-3 z-10">
        <input type="checkbox" checked={selected} onChange={() => onSelect(repo.id)}
          className="w-3.5 h-3.5 rounded border-slate-600 bg-dark-950 text-red-500 opacity-0 group-hover:opacity-100 checked:opacity-100 transition-opacity cursor-pointer" />
      </div>
      {/* Actions — Edit + Delete, top-right of the card. Hover-
          revealed so the card stays uncluttered at rest. Edit opens
          a modal in place (was a full-page nav until 2026-04-27 —
          user-reported as heavy for a rename). */}
      {/* Always-visible Unarchive pill on archived cards — primary
          action for the Archived view, so it shouldn't hide behind
          hover.  Edit/Delete still hover-revealed (secondary). */}
      {onUnarchive && isArchived && (
        <div className="absolute top-3 right-3 z-10">
          <button type="button"
            onClick={(e) => { e.stopPropagation(); e.preventDefault(); onUnarchive(repo.id, repo.name); }}
            title="Unarchive — resume scanning"
            aria-label={`Unarchive ${repo.name}`}
            className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium transition-colors"
            style={{
              background: "rgba(16, 185, 129, 0.12)",
              color: "#34d399",
              border: "1px solid rgba(16, 185, 129, 0.3)",
            }}>
            <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
            Unarchive
          </button>
        </div>
      )}
      <div className={`absolute z-10 transition-opacity inline-flex items-center gap-1 ${isArchived ? "top-3 right-24 opacity-0 group-hover:opacity-100" : "top-3 right-3 opacity-0 group-hover:opacity-100"}`}>
        <button type="button"
          onClick={(e) => { e.stopPropagation(); e.preventDefault(); onEdit(repo); }}
          title="Edit repository"
          aria-label={`Edit ${repo.name}`}
          className="p-1.5 rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
          </svg>
        </button>
        <button type="button"
          onClick={(e) => { e.stopPropagation(); e.preventDefault(); onDelete(repo.id); }}
          title="Delete repository"
          aria-label={`Delete ${repo.name}`}
          className="p-1.5 rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
          </svg>
        </button>
      </div>
      <Link href={`/repositories/${repo.id}`} className="block pl-4">
        <div className="flex items-start gap-3 mb-3">
          <div className="w-9 h-9 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0 mt-0.5">
            <svg className="w-4.5 h-4.5" style={{ color: "#ef4444" }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
            </svg>
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5 flex-wrap">
              <h3 className="font-semibold text-slate-200 group-hover:text-red-400 transition-colors truncate text-sm">{repo.name}</h3>
              <span className="text-[8px] px-1.5 py-0.5 rounded font-medium shrink-0 whitespace-nowrap bg-red-500/10 text-red-400 border border-red-500/20">
                Vooda AI
              </span>
              {isArchived && (
                <span className="inline-flex items-center gap-1 text-[8px] px-1.5 py-0.5 rounded font-medium shrink-0 whitespace-nowrap bg-slate-500/15 text-slate-400 border border-slate-500/25">
                  <svg className="w-2 h-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
                  </svg>
                  Archived
                </span>
              )}
            </div>
            <p className="text-[10px] text-slate-600 mt-0.5 truncate">
              {repo.url || repo.source_type}
            </p>
          </div>
          {rb.label && (
            <span className={`text-[9px] px-2 py-0.5 rounded-full ${rb.bg} ${rb.text} border border-current/20 font-medium shrink-0`}>
              {rb.label}
            </span>
          )}
        </div>
        {/* Language / Framework tags + Ticketing-destination badge */}
        {((repo.languages?.length || 0) > 0 || (repo.frameworks?.length || 0) > 0 || ((repo as any).ticketing_integration_id && ticketingMap[(repo as any).ticketing_integration_id])) && (
          <div className="flex gap-1 flex-wrap mb-2.5">
            {(repo.languages || []).slice(0, 2).map((l) => (
              <span key={l} className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/15">{l}</span>
            ))}
            {(repo.frameworks || []).slice(0, 1).map((f) => (
              <span key={f} className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/15">{f}</span>
            ))}
            {(repo as any).ticketing_integration_id && ticketingMap[(repo as any).ticketing_integration_id] && (
              <span className="inline-flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20" title="Findings from this repo file to this board">
                <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                </svg>
                {ticketingMap[(repo as any).ticketing_integration_id]}
              </span>
            )}
          </div>
        )}
        <div className="flex items-center justify-between pt-2.5 border-t border-white/[0.04] text-[10px]">
          {stats ? (
            <>
              <span className="text-slate-400"><span className="font-semibold text-slate-300">{stats.total_findings}</span> secrets</span>
              <span className="text-slate-600">{stats.last_scan_date ? new Date(stats.last_scan_date).toLocaleDateString() : "Never"}</span>
            </>
          ) : (
            <span className="text-slate-700">{new Date(repo.created_at).toLocaleDateString()}</span>
          )}
        </div>
      </Link>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  TABLE ROW
// ═══════════════════════════════════════════════════════════════
function RepoRow({ repo, stats, trendSeries, selected, onSelect, onDelete, onEdit, onUnarchive, ticketingMap }: {
  repo: Repository; stats?: RepoStats;
  // Per-repo 30-day severity-weighted series — fetched in batch from
  // the parent and passed down rather than each row firing its own
  // request.  Undefined while the batch is in flight.
  trendSeries?: Array<{ date: string; weighted: number }>;
  selected: boolean; onSelect: (id: string) => void; onDelete: (id: string) => void; onEdit: (repo: Repository) => void;
  // Provided in the Archived view — when present, an Unarchive
  // action appears in the row's actions column.  Undefined in the
  // active view (where archived repos don't appear).
  onUnarchive?: (id: string, name: string) => void;
  ticketingMap: Record<string, string>;
}) {
  const scanSt = stats?.last_scan_status ? SCAN_STATUS[stats.last_scan_status] : null;
  const policyStatus = stats?.policy_status || "not_scanned";
  const pb = POLICY_BADGE[policyStatus] || POLICY_BADGE.not_scanned;
  const activeScan = stats?.active_scan;
  const isArchived = (repo as any).is_archived === true;

  return (
    <tr className={`hover:bg-white/[0.04] transition-colors group ${selected ? "bg-red-500/[0.03]" : ""}`}
      style={isArchived ? { background: "rgba(120, 113, 108, 0.05)", filter: "grayscale(0.5) opacity(0.75)" } : undefined}>
      {/* Checkbox */}
      <td className="px-3 py-3 w-10">
        <input type="checkbox" checked={selected} onChange={() => onSelect(repo.id)}
          className="w-3.5 h-3.5 rounded border-slate-600 bg-dark-950 text-red-500 cursor-pointer" />
      </td>

      {/* Repository name */}
      <td className="px-3 py-3 min-w-[180px]">
        <Link href={`/repositories/${repo.id}`} className="group/link block">
          <span className="text-sm text-slate-200 group-hover/link:text-red-400 font-medium transition-colors">
            {repo.name}
          </span>
          {isArchived && (
            <span className="ml-2 inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full font-semibold uppercase tracking-wider align-middle"
              style={{
                background: "rgba(245, 158, 11, 0.12)",
                color: "#fbbf24",
                border: "1px solid rgba(245, 158, 11, 0.3)",
              }}>
              <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
              </svg>
              Archived
            </span>
          )}
          <span className="text-[10px] text-slate-600 block mt-0.5 truncate max-w-[220px]">
            {repo.url || repo.source_type}
          </span>
          {/* Ticketing-destination badge — shown only when this
              repo has a per-repo override set. Surfaces the board
              name + project key inline so a dev team scanning the
              list immediately sees "this repo files to X". */}
          {(repo as any).ticketing_integration_id && ticketingMap[(repo as any).ticketing_integration_id] && (
            <span className="inline-flex items-center gap-1 mt-1 text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
              <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
              </svg>
              {ticketingMap[(repo as any).ticketing_integration_id]}
            </span>
          )}
        </Link>
        {activeScan && (
          <div className="mt-1.5 flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse shrink-0" />
            <span className="text-[9px] font-medium" style={{ color: "#ef4444" }}>
              {activeScan.status === "analyzing" ? "AI Analyzing" : "Scanning"}... {activeScan.progress_pct}%
            </span>
            <div className="flex-1 max-w-[100px] bg-white/[0.04] rounded-full h-1 overflow-hidden">
              <div className="h-full rounded-full bg-gradient-to-r from-red-500 to-orange-400 transition-all duration-500"
                style={{ width: `${activeScan.progress_pct}%` }} />
            </div>
          </div>
        )}
      </td>

      {/* Source */}
      <td className="px-3 py-3">
        {(() => {
          const st = repo.source_type || "git_url";
          const labels: Record<string, { label: string; bg: string; text: string }> = {
            git_url: { label: "Git", bg: "bg-blue-500/10", text: "text-blue-400" },
            upload: { label: "Upload", bg: "bg-purple-500/10", text: "text-purple-400" },
            archive: { label: "Archive", bg: "bg-slate-500/10", text: "text-slate-400" },
            scanner_import: { label: "Import", bg: "bg-orange-500/10", text: "text-orange-400" },
          };
          const s = labels[st] || labels.git_url;
          return <span className={`text-[9px] px-1.5 py-0.5 rounded ${s.bg} ${s.text} font-medium whitespace-nowrap`}>{s.label}</span>;
        })()}
      </td>

      {/* Language */}
      <td className="px-3 py-3">
        <LangChips items={repo.languages || []} color="blue" />
      </td>

      {/* Framework */}
      <td className="px-3 py-3">
        <LangChips items={repo.frameworks || []} color="purple" />
      </td>

      {/* Secrets */}
      <td className="px-3 py-3 text-center">
        {stats ? (
          <span className="text-sm font-semibold text-slate-300">{stats.total_findings}</span>
        ) : (
          <span className="text-[10px] text-slate-700">—</span>
        )}
      </td>

      {/* Critical */}
      <td className="px-3 py-3 text-center">
        {stats ? (
          <span className={`text-sm font-semibold ${stats.open_criticals > 0 ? "text-red-400" : "text-slate-600"}`}>
            {stats.open_criticals}
          </span>
        ) : (
          <span className="text-[10px] text-slate-700">—</span>
        )}
      </td>

      {/* Last Scan */}
      <td className="px-3 py-3">
        {scanSt ? (
          <div className="flex items-center gap-1.5">
            <span className={`w-1.5 h-1.5 rounded-full ${scanSt.dot} shrink-0`} />
            <span className="text-[10px] text-slate-500">
              {stats?.last_scan_date ? new Date(stats.last_scan_date).toLocaleDateString() : "—"}
            </span>
          </div>
        ) : (
          <span className="text-[10px] text-slate-700">Never</span>
        )}
      </td>

      {/* Webhook health — 3-state pill driven by last_webhook_event_at
          + last_webhook_event_status.  Renders an em-dash for repos
          that never received a webhook event (uploaded / archive
          imports) rather than screaming red. */}
      <td className="px-3 py-3">
        <WebhookHealthBadge repo={repo} />
      </td>

      {/* 30-day trend sparkline — severity-weighted (critical-heavy
          days read taller).  Loaded in a batch fetch from the parent
          so this row doesn't fire its own request. */}
      <td className="px-3 py-3">
        <MiniSparkline series={trendSeries || []} />
      </td>

      {/* Actions — Edit + Delete. Visible on row hover so the table
          stays uncluttered at rest. Edit opens an in-place modal
          (was a full-page nav until 2026-04-27 — user-reported as
          heavy for a rename). Delete routes through the same
          single-row confirm dialog the bulk-delete bar uses. */}
      <td className="px-3 py-3 text-right whitespace-nowrap w-24">
        <div className="inline-flex items-center gap-1">
          {onUnarchive && isArchived && (
            <button type="button"
              onClick={(e) => { e.stopPropagation(); e.preventDefault(); onUnarchive(repo.id, repo.name); }}
              title="Unarchive — resume scanning"
              aria-label={`Unarchive ${repo.name}`}
              className="inline-flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-colors"
              style={{
                background: "rgba(16, 185, 129, 0.1)",
                color: "#34d399",
                border: "1px solid rgba(16, 185, 129, 0.25)",
              }}>
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
              </svg>
              Unarchive
            </button>
          )}
          <div className={`inline-flex items-center gap-1 transition-opacity ${isArchived ? "opacity-60 group-hover:opacity-100" : "opacity-0 group-hover:opacity-100"}`}>
            <button type="button"
              onClick={(e) => { e.stopPropagation(); e.preventDefault(); onEdit(repo); }}
              title="Edit repository"
              aria-label={`Edit ${repo.name}`}
              className="p-1.5 rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors">
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
              </svg>
            </button>
            <button type="button"
              onClick={(e) => { e.stopPropagation(); e.preventDefault(); onDelete(repo.id); }}
              title="Delete repository"
              aria-label={`Delete ${repo.name}`}
              className="p-1.5 rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors">
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
            </button>
          </div>
        </div>
      </td>
    </tr>
  );
}

// ═══════════════════════════════════════════════════════════════
//  SORT HEADER
// ═══════════════════════════════════════════════════════════════
function SortHeader({ label, field, current, dir, onSort, className = "" }: {
  label: string; field: SortField; current: SortField; dir: SortDir;
  onSort: (f: SortField) => void; className?: string;
}) {
  const isActive = current === field;
  return (
    <th onClick={() => onSort(field)}
      className={`px-3 py-2.5 text-[10px] font-semibold text-slate-500 uppercase tracking-widest cursor-pointer hover:text-slate-300 transition-colors select-none whitespace-nowrap ${className}`}>
      <span className="flex items-center gap-1">
        {label}
        {isActive && (
          <svg className={`w-3 h-3 text-red-400 ${dir === "asc" ? "rotate-180" : ""}`} fill="currentColor" viewBox="0 0 20 20">
            <path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" />
          </svg>
        )}
      </span>
    </th>
  );
}

// ═══════════════════════════════════════════════════════════════
//  MAIN PAGE
// ═══════════════════════════════════════════════════════════════
export default function RepositoriesPage() {
  const { toast } = useToast();

  // ── Server data ──────────────────────────────────────────────
  const [repos, setRepos] = useState<Repository[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [repoStats, setRepoStats] = useState<Record<string, RepoStats>>({});
  // Per-repo 30-day severity-weighted trend series for the sparkline
  // column.  Loaded in the same batch as repo stats so the list view
  // paints once with both signals.  `undefined` = batch in flight,
  // `[]` = backend returned empty / errored (renders as dashes).
  const [repoTrends, setRepoTrends] = useState<Record<string, Array<{ date: string; weighted: number }>>>({});
  const [facets, setFacets] = useState<{ languages: string[]; frameworks: string[] }>({ languages: [], frameworks: [] });

  // ── UI state ─────────────────────────────────────────────────
  const [showAdd, setShowAdd] = useState(false);
  // Open/close state for the "Filter" popover that holds the
  // secondary filters (Risk Level + Scan Status).
  const [showMoreFilters, setShowMoreFilters] = useState(false);
  // Edit modal target — when set, EditRepositoryModal is rendered
  // pre-filled with this repo's values. Cleared on close or after
  // a successful save (the list reloads so the user sees their
  // changes on the row immediately).
  const [editingRepo, setEditingRepo] = useState<Repository | null>(null);
  // Lookup map for the per-repo ticketing-destination badge:
  // integration_id -> "Board Name → PROJECT". Loaded once on mount
  // alongside the repository list. Empty map = no badges shown
  // (the rest of the page still works fine).
  const [ticketingMap, setTicketingMap] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  // Preview payload for the destructive-action modal.  Null while the
  // preview is loading; populated by getRepositoryDeletePreview on
  // open.  Carries findings / incidents / active-credentials counts
  // so the modal can render the impact summary before the user types
  // the confirmation.
  const [deletePreview, setDeletePreview] = useState<DeletePreview | null>(null);
  const [deletePreviewError, setDeletePreviewError] = useState<string | null>(null);
  // Disable the confirm button while the cascade is running so a double-click
  // can't fire two DELETEs (or make the user think nothing happened).
  const [deletingRepo, setDeletingRepo] = useState(false);
  const [confirmBulkDelete, setConfirmBulkDelete] = useState(false);
  // Aggregated impact preview for the bulk modal — same idea as
  // `deletePreview` but the payload is rolled up across selected repos
  // (incidents that span selections are deduped server-side, so the
  // numbers are not just a sum of per-repo previews).
  const [bulkDeletePreview, setBulkDeletePreview] = useState<BulkDeletePreview | null>(null);
  const [bulkDeletePreviewError, setBulkDeletePreviewError] = useState<string | null>(null);

  // ── View / sort ───────────────────────────────────────────────
  const [viewMode, setViewMode] = useState<ViewMode>(() => {
    if (typeof window !== "undefined") return (localStorage.getItem("vooda_repo_view") as ViewMode) || "table";
    return "table";
  });
  const [searchInput, setSearchInput] = useState("");  // immediate — bound to <input>
  const [search, setSearch] = useState("");            // debounced — sent to API
  const [sortField, setSortField] = useState<SortField>("findings");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // ── Filters ──────────────────────────────────────────────────
  const [filterLang, setFilterLang] = useState("");
  const [filterFramework, setFilterFramework] = useState("");
  const [filterRisk, setFilterRisk] = useState<RiskLevel>("");
  const [filterScanStatus, setFilterScanStatus] = useState("");
  // Active vs Archived view.  "active" hides archived repos (the
  // default — archived = paused, shouldn't clutter the working view).
  // "archived" surfaces only archived repos so the user can review or
  // unarchive them.  Backend filters via ?archived_only / ?include_archived.
  const [archiveView, setArchiveView] = useState<"active" | "archived">("active");

  // ── Debounce search input ────────────────────────────────────
  useEffect(() => {
    const t = setTimeout(() => { setSearch(searchInput); setPage(1); }, 400);
    return () => clearTimeout(t);
  }, [searchInput]);

  // ── Load facets once ─────────────────────────────────────────
  useEffect(() => {
    getRepositoryFacets()
      .then((r) => setFacets(r.data || { languages: [], frameworks: [] }))
      .catch(() => {});
  }, []);

  // ── Load ticketing integrations once for the destination badge.
  // Quiet failure → empty map → no badges shown. Independent from
  // the main repo load so a slow integrations endpoint doesn't
  // delay the table rendering.
  useEffect(() => {
    import("@/lib/api").then(({ default: api }) => {
      api.get("/integrations").then((r: any) => {
        const items = (r.data?.items || r.data || []) as any[];
        const map: Record<string, string> = {};
        for (const i of (Array.isArray(items) ? items : [])) {
          if (i.integration_type === "ticketing" && i.is_active) {
            const projectKey = i.config?.project_key;
            map[i.id] = projectKey ? `${i.name} → ${projectKey}` : i.name;
          }
        }
        setTicketingMap(map);
      }).catch(() => setTicketingMap({}));
    }).catch(() => {});
  }, []);

  // ── Server-side data load ────────────────────────────────────
  // Only name/created are server-side sorts; stats sorts run client-side on the page.
  const serverSortBy = sortField === "name" ? "name" : "created_at";
  const serverSortDir = ["name", "created"].includes(sortField) ? sortDir : "desc";

  const load = useCallback(() => {
    setLoading(true);
    const params: Record<string, string | number> = {
      page,
      page_size: ITEMS_PER_PAGE,
      sort_by: serverSortBy,
      sort_dir: serverSortDir,
    };
    if (search) params.search = search;
    if (filterLang) params.language = filterLang;
    if (filterFramework) params.framework = filterFramework;
    if (archiveView === "archived") params.archived_only = "true";

    getRepositories(params)
      .then((r) => {
        const data = r.data;
        const items: Repository[] = data?.items ?? (Array.isArray(data) ? data : []);
        setRepos(items);
        setTotal(data?.total ?? items.length);
        setTotalPages(data?.total_pages ?? 1);
        // Reset stats + trend series, then fetch fresh for current page.
        // Trend fetch parallels stats — both keyed by repo.id — so the
        // sparkline column paints in the same tick as the Critical/
        // Findings counts rather than visibly catching up.
        setRepoStats({});
        setRepoTrends({});
        items.forEach((repo) => {
          getRepoStats(repo.id)
            .then((sr) => setRepoStats((prev) => ({ ...prev, [repo.id]: sr.data })))
            .catch(() => {});
          getRepoSeverityTrend(repo.id, 30)
            .then((tr) => setRepoTrends((prev) => ({ ...prev, [repo.id]: tr.data?.series || [] })))
            .catch(() => setRepoTrends((prev) => ({ ...prev, [repo.id]: [] })));
        });
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page, serverSortBy, serverSortDir, search, filterLang, filterFramework, archiveView]);

  useEffect(() => { load(); }, [load]);

  // Persist view mode
  useEffect(() => {
    if (typeof window !== "undefined") localStorage.setItem("vooda_repo_view", viewMode);
  }, [viewMode]);

  // ── Client-side risk/status filter + stats-based sort ────────
  const displayRepos = useMemo(() => {
    let items = [...repos];
    if (filterRisk) items = items.filter((r) => getRisk(repoStats[r.id]).level === filterRisk);
    if (filterScanStatus) items = items.filter((r) => repoStats[r.id]?.last_scan_status === filterScanStatus);
    if (["findings", "criticals", "last_scan"].includes(sortField)) {
      items.sort((a, b) => {
        const sa = repoStats[a.id], sb = repoStats[b.id];
        let cmp = 0;
        switch (sortField) {
          case "findings":  cmp = (sa?.total_findings ?? -1) - (sb?.total_findings ?? -1); break;
          case "criticals": cmp = (sa?.open_criticals ?? -1) - (sb?.open_criticals ?? -1); break;
          case "last_scan": {
            const da = sa?.last_scan_date ? new Date(sa.last_scan_date).getTime() : 0;
            const db2 = sb?.last_scan_date ? new Date(sb.last_scan_date).getTime() : 0;
            cmp = da - db2; break;
          }
        }
        return sortDir === "desc" ? -cmp : cmp;
      });
    }
    // Pin actively-scanning repos to the top — the rows the user is watching
    // right now — regardless of the chosen sort. Array.sort is stable, so the
    // existing order WITHIN the scanning and non-scanning groups is preserved.
    items.sort((a, b) => {
      const as = repoStats[a.id]?.active_scan ? 1 : 0;
      const bs = repoStats[b.id]?.active_scan ? 1 : 0;
      return bs - as;
    });
    return items;
  }, [repos, repoStats, filterRisk, filterScanStatus, sortField, sortDir]);

  const hasFilters = !!filterLang || !!filterFramework || !!filterRisk || !!filterScanStatus || !!searchInput;

  // ── Selection ─────────────────────────────────────────────────
  const toggleSelect = (id: string) => {
    setSelected((prev) => { const n = new Set(prev); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  };
  const selectAll = () => {
    if (selected.size === displayRepos.length && displayRepos.length > 0) setSelected(new Set());
    else setSelected(new Set(displayRepos.map((r) => r.id)));
  };
  const clearSelection = () => setSelected(new Set());

  // ── Sort ──────────────────────────────────────────────────────
  const handleSort = (field: SortField) => {
    if (sortField === field) setSortDir((d) => d === "asc" ? "desc" : "asc");
    else { setSortField(field); setSortDir("desc"); setPage(1); }
  };

  // ── Page-level summary (current page only) ────────────────────
  const pageFindingsTotal  = Object.values(repoStats).reduce((s, v) => s + (v?.total_findings || 0), 0);
  const pageCriticalsTotal = Object.values(repoStats).reduce((s, v) => s + (v?.open_criticals || 0), 0);

  // ── Clear filters ─────────────────────────────────────────────
  const clearFilters = () => {
    setFilterRisk(""); setFilterScanStatus("");
    setFilterLang(""); setFilterFramework("");
    setSearchInput(""); setSearch(""); setPage(1);
  };

  // ── Add repository ────────────────────────────────────────────
  const handleAdd = async (data: any) => {
    try {
      const repoRes = await createRepository({
        name: data.name, url: data.url, source_type: data.source_type,
        default_branch: data.default_branch, auth: data.auth, provider: data.provider,
        ticketing_integration_id: data.ticketing_integration_id,
      });
      if (data.file && repoRes?.data?.id) {
        try {
          await uploadToRepository(repoRes.data.id, data.file);
        } catch {
          toast("warning", "Repository created but file upload failed", "You can upload the file from the project settings");
        }
      }
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.message || "Failed to create project";
      toast("error", "Error", detail);
      return;
    }
    setShowAdd(false); load();
  };

  const confirmDeleteAction = async () => {
    if (!confirmDelete || deletingRepo) return;
    setDeletingRepo(true);
    try {
      const res = await deleteRepository(confirmDelete);
      const data: any = (res as any)?.data || {};
      // Server now returns cleanup counts on permanent delete.  Surface
      // them in the toast so the user gets an immediate audit-trail
      // summary of what was destroyed (parity with the impact preview
      // they saw before confirming).
      const summary = data.findings_deleted !== undefined
        ? `Removed ${data.findings_deleted} findings · ${data.incidents_closed || 0} incidents closed${data.incidents_survived ? ` · ${data.incidents_survived} stay open via other locations` : ""}`
        : "The repository and all associated data have been removed";
      toast("success", "Repository Deleted", summary);
      setConfirmDelete(null);
      setDeletePreview(null);
      load();
    } catch (err: any) {
      toast("error", "Delete Failed", err?.response?.data?.detail || "Could not delete the repository");
      setConfirmDelete(null);
      setDeletePreview(null);
    } finally {
      setDeletingRepo(false);
    }
  };

  // Archive (soft-delete) — keeps findings + history, hides from
  // active list.  Default action when the user wants to stop scanning
  // but preserve audit trail.  Wired from the menu AND from the
  // delete-modal's "Archive instead" suggestion link.
  const archiveAction = async (id: string) => {
    try {
      await archiveRepository(id);
      toast("success", "Repository Archived", "Hidden from active list · scanning paused · findings preserved. Toggle to Archived view to restore.");
      setConfirmDelete(null);
      setDeletePreview(null);
      load();
    } catch (err: any) {
      toast("error", "Archive Failed", err?.response?.data?.detail || "Could not archive the repository");
    }
  };

  // Unarchive — restores the repo to the active list and resumes
  // scheduled scans.  Called from the row action in the Archived view.
  const unarchiveAction = async (id: string, name?: string) => {
    try {
      await unarchiveRepository(id);
      toast("success", "Repository Unarchived", `${name || "Repository"} restored to active list · scanning resumed`);
      load();
    } catch (err: any) {
      toast("error", "Unarchive Failed", err?.response?.data?.detail || "Could not unarchive the repository");
    }
  };

  // Load the impact preview whenever the user opens the delete modal.
  // Done with a useEffect rather than inline so the modal can mount
  // immediately with a skeleton while the preview fetch is in flight.
  useEffect(() => {
    if (!confirmDelete) {
      setDeletePreview(null);
      setDeletePreviewError(null);
      return;
    }
    let cancelled = false;
    setDeletePreview(null);
    setDeletePreviewError(null);
    getRepositoryDeletePreview(confirmDelete)
      .then((r) => { if (!cancelled) setDeletePreview(r.data as DeletePreview); })
      .catch((err: any) => {
        if (!cancelled) setDeletePreviewError(err?.response?.data?.detail || "Could not load deletion preview");
      });
    return () => { cancelled = true; };
  }, [confirmDelete]);

  // Fetch aggregated impact when the bulk-delete modal opens.  Bound
  // to a serialized list of ids so re-opening with a different
  // selection re-fetches (otherwise we'd show stale counts).
  const selectedIdsKey = Array.from(selected).sort().join(",");
  useEffect(() => {
    if (!confirmBulkDelete || selected.size === 0) {
      setBulkDeletePreview(null);
      setBulkDeletePreviewError(null);
      return;
    }
    let cancelled = false;
    setBulkDeletePreview(null);
    setBulkDeletePreviewError(null);
    getRepositoryBulkDeletePreview(Array.from(selected))
      .then((r) => { if (!cancelled) setBulkDeletePreview(r.data as BulkDeletePreview); })
      .catch((err: any) => {
        if (!cancelled) setBulkDeletePreviewError(err?.response?.data?.detail || "Could not load bulk-deletion preview");
      });
    return () => { cancelled = true; };
  }, [confirmBulkDelete, selectedIdsKey]);

  const confirmBulkDeleteAction = async () => {
    if (selected.size === 0) return;
    let deleted = 0, failed = 0;
    let totalFindings = 0, totalIncidentsClosed = 0, totalIncidentsSurvived = 0;
    for (const id of selected) {
      try {
        const resp = await deleteRepository(id);
        const data = resp?.data as { findings_deleted?: number; incidents_closed?: number; incidents_survived?: number } | undefined;
        totalFindings += data?.findings_deleted || 0;
        totalIncidentsClosed += data?.incidents_closed || 0;
        totalIncidentsSurvived += data?.incidents_survived || 0;
        deleted++;
      } catch { failed++; }
    }
    setConfirmBulkDelete(false);
    clearSelection();
    load();
    const projectWord = deleted === 1 ? "Project" : "Projects";
    if (failed === 0) {
      const detail = totalFindings > 0
        ? `${totalFindings.toLocaleString()} findings removed · ${totalIncidentsClosed} incident${totalIncidentsClosed === 1 ? "" : "s"} closed${totalIncidentsSurvived > 0 ? ` · ${totalIncidentsSurvived} kept (other locations)` : ""}`
        : "All selected projects and associated data have been removed";
      toast("success", `${deleted} ${projectWord} Deleted`, detail);
    } else {
      toast("warning", `${deleted} Deleted, ${failed} Failed`, "Some projects could not be deleted");
    }
  };

  const archiveAllSelected = async () => {
    if (selected.size === 0) return;
    let archived = 0, failed = 0;
    for (const id of selected) {
      try { await archiveRepository(id); archived++; }
      catch { failed++; }
    }
    setConfirmBulkDelete(false);
    clearSelection();
    load();
    if (failed === 0) {
      toast("success", `${archived} ${archived === 1 ? "Project" : "Projects"} Archived`, "Scanning paused; findings and triage preserved");
    } else {
      toast("warning", `${archived} Archived, ${failed} Failed`, "Some projects could not be archived");
    }
  };

  const isEmpty = !loading && total === 0 && !hasFilters;

  // Count of "extra" filters (Risk + Scan Status) — drives the badge
  // on the collapsed "Filter" popover button so the user knows
  // filters are active without opening the popover.
  const extraFilterCount = (filterRisk ? 1 : 0) + (filterScanStatus ? 1 : 0);

  return (
    <AppShell>
      <div className="space-y-4 max-w-[1600px]">

        {/* ═══ Toolbar ═══
            Single horizontal row carries every page-level control:
            search · primary filters (Language/Framework) · collapsed
            secondary filters (Risk/Status behind "Filter ▼") · clear ·
            view-toggle · Add Repository CTA on the far right.

            The page-level subtitle and the right-side count strip
            ("N repositories · M secrets · X critical") were removed —
            redundant with the dashboard posture strip and the table
            below.  Net effect: one clean toolbar, no orphan rows. */}
        {/* Toolbar — always rendered so the Active/Archived toggle
            stays reachable.  Previously gated on !isEmpty, which
            stranded the user with no toggle once everything was
            archived (active=0, archived>0). */}
        {(true) && (
          <div className="space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              {/* Active / Archived view toggle — first control in the
                  toolbar so the user always knows which slice they're
                  looking at.  Default is Active; Archived shows only
                  paused repos with an Unarchive action per row. */}
              <div className="inline-flex items-center rounded-md overflow-hidden border border-white/[0.08] bg-white/[0.02]">
                {(["active", "archived"] as const).map((v) => (
                  <button
                    key={v}
                    onClick={() => { setArchiveView(v); setPage(1); clearSelection(); }}
                    className={`px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
                      archiveView === v
                        ? "bg-red-500/15 text-red-300"
                        : "text-slate-500 hover:text-slate-300"
                    }`}
                    aria-pressed={archiveView === v}
                  >
                    {v === "active" ? "Active" : "Archived"}
                  </button>
                ))}
              </div>

              {/* Search */}
              <div className="relative flex-1 min-w-[180px] max-w-xs">
                <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                <input value={searchInput} onChange={(e) => setSearchInput(e.target.value)}
                  placeholder="Search by name, URL..."
                  className="input-dark pl-10 text-sm" />
              </div>

              {/* Primary filters — kept visible because they're the
                  most discoverable filtering axis (most users filter
                  by language or framework first). */}
              <select value={filterLang} onChange={(e) => { setFilterLang(e.target.value); setPage(1); }} className="select-dark text-xs">
                <option value="">All Languages</option>
                {facets.languages.map((l) => <option key={l} value={l}>{l}</option>)}
              </select>

              <select value={filterFramework} onChange={(e) => { setFilterFramework(e.target.value); setPage(1); }} className="select-dark text-xs">
                <option value="">All Frameworks</option>
                {facets.frameworks.map((f) => <option key={f} value={f}>{f}</option>)}
              </select>

              {/* Secondary filters collapsed into a popover.
                  The badge on the button surfaces the active count so
                  the user knows filtering is in play without opening
                  the popover. */}
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setShowMoreFilters((v) => !v)}
                  className="select-dark text-xs flex items-center gap-1.5"
                  style={{ paddingRight: "0.75rem", backgroundImage: "none" }}
                >
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 4a1 1 0 011-1h16a1 1 0 01.78 1.625l-6.78 8.475V18l-4 2v-7.9L3.22 4.625A1 1 0 013 4z" />
                  </svg>
                  Filter
                  {extraFilterCount > 0 && (
                    <span className="ml-0.5 text-[9px] font-bold px-1.5 py-0.5 rounded-full"
                      style={{ background: "rgba(239,68,68,0.18)", color: "#fca5a5", border: "1px solid rgba(239,68,68,0.3)" }}>
                      {extraFilterCount}
                    </span>
                  )}
                </button>
                {showMoreFilters && (
                  <>
                    <div className="fixed inset-0 z-10" onClick={() => setShowMoreFilters(false)} />
                    <div className="absolute left-0 top-full mt-1 z-20 w-56 p-3 rounded-lg space-y-3"
                      style={{
                        background: "rgba(10, 13, 30, 0.98)",
                        border: "1px solid rgba(255,255,255,0.08)",
                        boxShadow: "0 20px 60px rgba(0, 0, 0, 0.6)",
                      }}
                    >
                      <div>
                        <label className="text-[10px] uppercase tracking-wider font-medium text-slate-500 block mb-1.5">Risk Level</label>
                        <select value={filterRisk} onChange={(e) => { setFilterRisk(e.target.value as RiskLevel); setPage(1); }} className="select-dark text-xs w-full">
                          <option value="">All Risk Levels</option>
                          <option value="critical">Critical</option>
                          <option value="high">High</option>
                          <option value="medium">Medium</option>
                          <option value="clean">Clean</option>
                        </select>
                      </div>
                      <div>
                        <label className="text-[10px] uppercase tracking-wider font-medium text-slate-500 block mb-1.5">Scan Status</label>
                        <select value={filterScanStatus} onChange={(e) => { setFilterScanStatus(e.target.value); setPage(1); }} className="select-dark text-xs w-full">
                          <option value="">All Scan Status</option>
                          <option value="completed">Completed</option>
                          <option value="failed">Failed</option>
                          <option value="running">Running</option>
                        </select>
                      </div>
                    </div>
                  </>
                )}
              </div>

              {hasFilters && (
                <button onClick={clearFilters} className="text-xs text-slate-500 hover:text-slate-300 transition-colors whitespace-nowrap">
                  Clear filters
                </button>
              )}

              <div className="flex-1" />

              {/* View toggle */}
              <div className="flex items-center bg-white/[0.03] rounded-lg p-0.5 border border-white/[0.06]">
                <button onClick={() => setViewMode("table")}
                  className={`p-1.5 rounded-md transition-all ${viewMode === "table" ? "bg-white/[0.08] text-red-400" : "text-slate-500 hover:text-slate-300"}`}
                  title="Table view">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
                  </svg>
                </button>
                <button onClick={() => setViewMode("cards")}
                  className={`p-1.5 rounded-md transition-all ${viewMode === "cards" ? "bg-white/[0.08] text-red-400" : "text-slate-500 hover:text-slate-300"}`}
                  title="Card view">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM14 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM4 15a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1v-4zM14 15a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z" />
                  </svg>
                </button>
              </div>

              {/* Add Repository — primary CTA at the far right of the
                  toolbar. Moved here from the global header band so the
                  red accent doesn't sit in the chrome alongside the
                  bell/avatar; it now reads as a page-level action where
                  the eye naturally lands after scanning the filters. */}
              <button onClick={() => setShowAdd(true)} className="btn-primary-sm shrink-0">
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
                Add Repository
              </button>
            </div>

            {/* Bulk actions bar */}
            {selected.size > 0 && (
              <div className="flex items-center gap-3 px-4 py-2.5 rounded-lg bg-red-500/[0.05] border border-red-500/15">
                <span className="text-sm text-red-400 font-medium">{selected.size} selected</span>
                <div className="h-4 w-px bg-white/[0.08]" />
                <button
                  onClick={() => {
                    // Single selection → route through the per-row
                    // modal (typed-name gate, full single preview).
                    // Multi selection → bulk modal with aggregated
                    // counts + DELETE-token gate.
                    if (selected.size === 1) {
                      setConfirmDelete(Array.from(selected)[0]);
                    } else {
                      setConfirmBulkDelete(true);
                    }
                  }}
                  className="text-xs text-red-400 hover:text-red-300 transition-colors"
                >
                  Delete
                </button>
                <div className="flex-1" />
                <button onClick={clearSelection} className="text-xs text-slate-500 hover:text-slate-300 transition-colors">Clear</button>
              </div>
            )}
          </div>
        )}

        {/* Modal — Add */}
        {showAdd && <AddRepositoryModal onClose={() => setShowAdd(false)} onSubmit={handleAdd} />}

        {/* Modal — Edit. Renders when the user clicks the pencil
            icon on any row / card. Closes on success (after
            triggering load() so the list reflects the new values
            without requiring a manual refresh). */}
        {editingRepo && (
          <EditRepositoryModal
            repo={editingRepo}
            onClose={() => setEditingRepo(null)}
            onSaved={() => { setEditingRepo(null); load(); }}
          />
        )}

        {/* Permanent-delete confirmation — shared modal.  Renders the
            impact preview from /repositories/{id}/delete-preview and
            gates the destructive action behind typed confirmation.
            Same component used by /sources for parity. */}
        {confirmDelete && (
          <DeleteConfirmModal
            preview={deletePreview}
            error={deletePreviewError}
            onCancel={() => setConfirmDelete(null)}
            onConfirm={confirmDeleteAction}
            onArchive={() => archiveAction(confirmDelete)}
          />
        )}

        {/* Bulk-delete confirmation — shared component.  Renders the
            aggregated impact preview from POST /bulk-delete-preview
            and gates the destructive action behind a typed "DELETE"
            token.  Same friction tier as the per-row delete, scaled
            up for multi-selection. */}
        {confirmBulkDelete && selected.size > 0 && (
          <BulkDeleteConfirmModal
            preview={bulkDeletePreview}
            error={bulkDeletePreviewError}
            onCancel={() => setConfirmBulkDelete(false)}
            onConfirm={confirmBulkDeleteAction}
            onArchiveAll={archiveAllSelected}
          />
        )}

        {/* ═══ Content ═══ */}
        {loading ? (
          <div className="text-center py-16 text-slate-500">
            <div className="w-5 h-5 border-2 border-red-400/30 border-t-red-400 rounded-full animate-spin mx-auto mb-2" />
            Loading projects...
          </div>
        ) : displayRepos.length === 0 && hasFilters ? (
          <div className="text-center py-16">
            <p className="text-slate-400">No projects match your filters</p>
            <button onClick={clearFilters} className="text-xs text-red-400 mt-2 hover:text-red-300">Clear filters</button>
          </div>
        ) : isEmpty ? (
          <div className="text-center py-20">
            <div className="w-16 h-16 rounded-xl bg-red-500/10 flex items-center justify-center mx-auto mb-4">
              <svg className="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
              </svg>
            </div>
            <p className="text-slate-400">No scans yet</p>
            <p className="text-sm text-slate-600 mt-1">Create a new scan to start securing your code</p>
            <button onClick={() => setShowAdd(true)} className="btn-primary mt-4 inline-flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Create your first scan
            </button>
          </div>
        ) : viewMode === "table" ? (
          /* ═══ TABLE VIEW ═══ */
          <div className="card p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="glass-table w-full text-sm">
                <thead>
                  <tr className="border-b border-white/[0.06]">
                    <th className="px-3 py-2.5 w-10">
                      <input type="checkbox"
                        checked={selected.size === displayRepos.length && displayRepos.length > 0}
                        onChange={selectAll}
                        className="w-3.5 h-3.5 rounded border-slate-600 bg-dark-950 text-red-500 cursor-pointer" />
                    </th>
                    <SortHeader label="Repository" field="name"      current={sortField} dir={sortDir} onSort={handleSort} className="text-left min-w-[160px]" />
                    <th className="px-3 py-2.5 text-[10px] font-semibold text-slate-500 uppercase tracking-widest text-left whitespace-nowrap">Source</th>
                    <th className="px-3 py-2.5 text-[10px] font-semibold text-slate-500 uppercase tracking-widest text-left whitespace-nowrap">Language</th>
                    <th className="px-3 py-2.5 text-[10px] font-semibold text-slate-500 uppercase tracking-widest text-left whitespace-nowrap">Framework</th>
                    <SortHeader label="Secrets"    field="findings"  current={sortField} dir={sortDir} onSort={handleSort} className="text-center" />
                    <SortHeader label="Critical"   field="criticals" current={sortField} dir={sortDir} onSort={handleSort} className="text-center" />
                    <SortHeader label="Last Scan"  field="last_scan" current={sortField} dir={sortDir} onSort={handleSort} className="text-left" />
                    <th className="px-3 py-2.5 text-[10px] font-semibold text-slate-500 uppercase tracking-widest text-left whitespace-nowrap">Webhook</th>
                    <th className="px-3 py-2.5 text-[10px] font-semibold text-slate-500 uppercase tracking-widest text-left whitespace-nowrap">30D Trend</th>
                    {/* Actions column header — kept blank so the
                        hover-revealed icons feel light, but the
                        column reserves space so row heights don't
                        shift on hover. */}
                    <th className="px-3 py-2.5 w-24"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.04]">
                  {displayRepos.map((repo) => (
                    <RepoRow key={repo.id} repo={repo} stats={repoStats[repo.id]}
                      trendSeries={repoTrends[repo.id]}
                      selected={selected.has(repo.id)} onSelect={toggleSelect}
                      onDelete={(id) => setConfirmDelete(id)}
                      onEdit={(r) => setEditingRepo(r)}
                      onUnarchive={archiveView === "archived" ? unarchiveAction : undefined}
                      ticketingMap={ticketingMap} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          /* ═══ CARD VIEW ═══ */
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {displayRepos.map((repo) => (
              <RepoCard key={repo.id} repo={repo} stats={repoStats[repo.id]}
                selected={selected.has(repo.id)} onSelect={toggleSelect}
                onDelete={(id) => setConfirmDelete(id)}
                onEdit={(r) => setEditingRepo(r)}
                onUnarchive={archiveView === "archived" ? unarchiveAction : undefined}
                ticketingMap={ticketingMap} />
            ))}
          </div>
        )}

        {/* ═══ Pagination ═══ */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between pt-2">
            <span className="text-xs text-slate-500">
              Showing {((page - 1) * ITEMS_PER_PAGE + 1).toLocaleString()}–{Math.min(page * ITEMS_PER_PAGE, total).toLocaleString()} of {total.toLocaleString()}
            </span>
            <div className="flex items-center gap-1">
              <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1}
                className="px-2.5 py-1.5 rounded-md text-xs text-slate-400 hover:bg-white/[0.04] disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
                ← Prev
              </button>
              {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                let pageNum: number;
                if (totalPages <= 7) pageNum = i + 1;
                else if (page <= 4) pageNum = i + 1;
                else if (page >= totalPages - 3) pageNum = totalPages - 6 + i;
                else pageNum = page - 3 + i;
                return (
                  <button key={pageNum} onClick={() => setPage(pageNum)}
                    className={`w-8 h-8 rounded-md text-xs transition-colors ${page === pageNum ? "bg-red-500/15 text-red-400 font-medium" : "text-slate-500 hover:bg-white/[0.04]"}`}>
                    {pageNum}
                  </button>
                );
              })}
              <button onClick={() => setPage(Math.min(totalPages, page + 1))} disabled={page === totalPages}
                className="px-2.5 py-1.5 rounded-md text-xs text-slate-400 hover:bg-white/[0.04] disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
                Next →
              </button>
            </div>
          </div>
        )}

      </div>
    </AppShell>
  );
}
