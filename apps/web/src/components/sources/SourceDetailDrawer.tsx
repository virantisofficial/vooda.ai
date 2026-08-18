"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * SourceDetailDrawer — right-side drawer that opens when a user clicks
 * a Source card on /sources.  Replaces the "build a new /sources/[id]
 * route" instinct because:
 *   - Source config is small (schedule, target binding, source-specific
 *     fields).  A whole page would be mostly whitespace.
 *   - Detail content (recent scans, rule overrides) fits comfortably
 *     in 720px of drawer width.
 *   - Keeps the user's filter/scroll context on /sources intact.
 *
 * Tab layout:
 *   - Overview — meta + recent activity dots + key stats
 *   - Scans — most recent 20 scan jobs with status / findings / duration
 *   - Settings — read-only summary + "Edit in main form" CTA (delegates
 *     to the existing inline edit panel; no form duplication)
 *   - Rule Overrides — embeds RuleOverridesContent with sourceFilter
 *
 * Findings tab is INTENTIONALLY OMITTED — clicking "View N findings"
 * deep-links to /findings?scan_source_id=X which already supports the
 * filter.  Adding a Findings tab here would duplicate that surface.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";

import { RuleOverridesContent } from "@/components/secrets/RuleOverridesContent";
import { SideDrawer } from "@/components/ui/SideDrawer";
import { getSourceScans, triggerSourceScan } from "@/lib/api";

interface SourceLike {
  id: string;
  name: string;
  source_type: string;
  is_active: boolean;
  scan_schedule: string;
  last_scan_at: string | null;
  stats: Record<string, any>;
  target_repository_id: string | null;
  target_business_unit_id: string | null;
  is_stale?: boolean;
}

interface ScanRow {
  id: string;
  status: string;
  scan_type?: string;
  progress_pct?: number;
  status_message?: string | null;
  stats?: Record<string, any> | null;
  created_at: string;
  updated_at?: string | null;
  error_detail?: string | null;
}

type TabKey = "overview" | "scans" | "settings" | "rule_overrides";

interface Props {
  source: SourceLike | null;
  /** Display label for the source-type pill (e.g. "Slack" not "slack"). */
  typeLabel?: string;
  /** Optional brand glyph for the drawer header — mirrors the source
   *  card's icon so a user opening the drawer feels they're "zooming
   *  in" on the same card. */
  icon?: React.ReactNode;
  /** Tailwind gradient class for the brand glyph background. */
  iconGradient?: string;
  /** Tab to land on when the drawer opens.  Defaults to "overview"; the
   *  card's Edit button passes "settings" so clicking Edit drops users
   *  directly on the edit form. */
  initialTab?: "overview" | "scans" | "settings" | "rule_overrides";
  onClose: () => void;
  /**
   * Render the Settings tab body inline (no ping-pong).  When omitted,
   * the Settings tab falls back to a read-only summary + "Edit" CTA
   * that delegates to onEditRequest.  When provided, the parent owns
   * the form rendering so the existing connect-wizard form state can
   * be reused without duplication.
   *
   * Receives `source` so the render fn can hydrate the form from the
   * exact source being viewed.
   */
  renderSettings?: (source: SourceLike) => React.ReactNode;
  /**
   * Legacy fallback handler: only invoked when `renderSettings` is NOT
   * provided.  Kept for backward compatibility with anywhere else that
   * mounts this drawer.
   */
  onEditRequest?: (source: SourceLike) => void;
}

function fmtAge(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "—";
  const diff = (Date.now() - t) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 86400 * 7) return `${Math.floor(diff / 86400)}d ago`;
  return new Date(iso).toLocaleDateString();
}

const STATUS_STYLE: Record<string, string> = {
  completed: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  running: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  pending: "bg-slate-500/10 text-slate-400 border-slate-500/20",
  failed: "bg-red-500/10 text-red-400 border-red-500/20",
  cancelled: "bg-slate-500/10 text-slate-500 border-slate-500/20",
};

export function SourceDetailDrawer({
  source,
  typeLabel,
  icon,
  iconGradient,
  initialTab = "overview",
  onClose,
  renderSettings,
  onEditRequest,
}: Props) {
  const [activeTab, setActiveTab] = useState<TabKey>(initialTab);
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [scansLoading, setScansLoading] = useState(false);
  const [scansError, setScansError] = useState<string | null>(null);
  const [triggering, setTriggering] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const open = source !== null;

  // Reset tab to the requested initial tab whenever a different source
  // is opened (or the initialTab changes between opens — e.g. Edit on
  // the card passes "settings" while a body click passes "overview").
  useEffect(() => {
    if (source) setActiveTab(initialTab);
  }, [source?.id, initialTab]);

  const loadScans = useCallback(async () => {
    if (!source) return;
    try {
      setScansLoading(true);
      setScansError(null);
      const r = await getSourceScans(source.id);
      setScans(Array.isArray(r.data) ? r.data : (r.data?.items || []));
    } catch (e: any) {
      setScansError(e?.response?.data?.detail || "Failed to load scan history.");
      setScans([]);
    } finally {
      setScansLoading(false);
    }
  }, [source]);

  // Lazy-load scans only when the Scans tab is opened (don't pay the
  // round-trip for users who only open Overview).
  useEffect(() => {
    if (open && activeTab === "scans") loadScans();
  }, [open, activeTab, loadScans, refreshKey]);

  const handleTriggerScan = async () => {
    if (!source) return;
    try {
      setTriggering(true);
      await triggerSourceScan(source.id);
      // Bump refreshKey so the Scans tab reloads if open, and switch to
      // it so the user can watch progress.
      setActiveTab("scans");
      setRefreshKey((k) => k + 1);
    } catch (e: any) {
      // Soft fail — show in the scans list error slot if visible, else
      // surface via the existing toast on the parent.
      setScansError(e?.response?.data?.detail || "Failed to start scan.");
    } finally {
      setTriggering(false);
    }
  };

  // Subtitle: "<type label> · <schedule> · <last scan age>".  Compact
  // so the drawer title row stays clean.
  const subtitle = useMemo(() => {
    if (!source) return undefined;
    const parts: string[] = [];
    parts.push(typeLabel || source.source_type);
    const sched = source.scan_schedule === "on_demand"
      ? "On demand"
      : source.scan_schedule.charAt(0).toUpperCase() + source.scan_schedule.slice(1);
    parts.push(sched);
    parts.push(`Last scan: ${fmtAge(source.last_scan_at)}`);
    return parts.join(" · ");
  }, [source, typeLabel]);

  if (!source) return null;

  const tabs = [
    { key: "overview", label: "Overview" },
    {
      key: "scans",
      label: "Scans",
      badge: scans.length > 0 ? String(scans.length) : undefined,
    },
    { key: "settings", label: "Settings" },
    { key: "rule_overrides", label: "Rule Overrides" },
  ];

  const lastStatus = (source.stats as any)?.last_scan_status as string | undefined;
  const lastError = (source.stats as any)?.last_error as string | undefined;
  const findingsCount = (source.stats as any)?.findings_count ?? (source.stats as any)?.last_findings_count;

  return (
    <SideDrawer
      open={open}
      onClose={onClose}
      title={source.name}
      subtitle={subtitle}
      icon={icon}
      iconGradient={iconGradient}
      tabs={tabs}
      activeTab={activeTab}
      onTabChange={(k) => setActiveTab(k as TabKey)}
      width="lg"
      headerExtras={
        <button
          onClick={handleTriggerScan}
          disabled={triggering || !source.is_active}
          className="text-xs px-3 py-1.5 rounded bg-red-500/15 text-red-400 hover:bg-red-500/25 disabled:opacity-40 disabled:cursor-not-allowed font-medium transition-colors"
        >
          {triggering ? "Triggering…" : "Run scan"}
        </button>
      }
    >
      {/* ── Overview ─────────────────────────────────────────── */}
      {activeTab === "overview" && (
        <div className="space-y-5">
          {source.is_stale && (
            <div className="rounded border border-amber-500/30 bg-amber-500/[0.06] px-4 py-3">
              <p className="text-xs font-medium text-amber-300">
                Stale — scheduler may have stopped firing
              </p>
              <p className="text-[11px] text-amber-200/70 mt-1">
                This source is set to scan{" "}
                <span className="font-medium">{source.scan_schedule}</span> but the last
                successful scan was{" "}
                <span className="font-medium">{fmtAge(source.last_scan_at)}</span>. Try
                running a scan now — if that succeeds, the scheduler should resume.
              </p>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <Stat label="Status" value={source.is_active ? "Active" : "Archived"} tone={source.is_active ? "emerald" : "slate"} />
            <Stat label="Last scan" value={fmtAge(source.last_scan_at)} subtle={lastStatus} subtleTone={lastStatus === "failed" ? "red" : lastStatus === "success" ? "emerald" : undefined} />
            <Stat label="Findings (cumulative)" value={String(findingsCount ?? "—")} />
            <Stat label="Schedule" value={source.scan_schedule === "on_demand" ? "On demand" : source.scan_schedule} />
          </div>

          {lastError && (
            <div className="rounded border border-red-500/20 bg-red-500/[0.06] px-3 py-2">
              <p className="text-[10px] text-red-300 uppercase tracking-wider">Last error</p>
              <p className="text-xs text-red-200 mt-1 break-all">{lastError}</p>
            </div>
          )}

          <div className="rounded border border-white/[0.05] bg-white/[0.02] px-4 py-3">
            <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Scope</p>
            {source.target_repository_id ? (
              <p className="text-xs text-blue-300">
                Findings bound to repository <span className="font-mono">{source.target_repository_id.slice(0, 8)}…</span>
              </p>
            ) : source.target_business_unit_id ? (
              <p className="text-xs text-purple-300">
                Findings bound to business unit <span className="font-mono">{source.target_business_unit_id.slice(0, 8)}…</span>
              </p>
            ) : (
              <p className="text-xs text-slate-400">Org-wide (no repo / BU binding)</p>
            )}
          </div>

          <div className="flex gap-2 pt-1">
            <Link
              href={`/findings?scan_source_id=${source.id}`}
              className="text-xs text-violet-400 hover:text-violet-300 underline underline-offset-2"
            >
              View findings →
            </Link>
          </div>
        </div>
      )}

      {/* ── Scans ────────────────────────────────────────────── */}
      {activeTab === "scans" && (
        <div className="space-y-3">
          {scansLoading ? (
            <p className="text-center text-xs text-slate-500 py-12">Loading scan history…</p>
          ) : scansError ? (
            <div className="rounded border border-red-500/20 bg-red-500/5 px-3 py-2 text-xs text-red-300">
              {scansError}
            </div>
          ) : scans.length === 0 ? (
            <p className="text-center text-xs text-slate-500 py-12">
              No scans yet.  Click <span className="text-slate-300 font-medium">Run scan</span> above to trigger the first one.
            </p>
          ) : (
            scans.map((s) => {
              const statusKey = (s.status || "").toLowerCase().split(".").pop() || "";
              const statusClass = STATUS_STYLE[statusKey] || "bg-slate-500/10 text-slate-400 border-slate-500/20";
              const findingsTotal = (s.stats as any)?.findings_total ?? (s.stats as any)?.findings_count;
              return (
                <div key={s.id} className="rounded border border-white/[0.05] bg-white/[0.02] px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] px-2 py-0.5 rounded border ${statusClass}`}>
                          {statusKey}
                        </span>
                        <span className="text-[11px] text-slate-500">{fmtAge(s.created_at)}</span>
                        {typeof s.progress_pct === "number" && statusKey === "running" && (
                          <span className="text-[10px] text-blue-300">{s.progress_pct}%</span>
                        )}
                      </div>
                      {s.status_message && (
                        <p className="text-xs text-slate-300 mt-1.5 truncate" title={s.status_message}>{s.status_message}</p>
                      )}
                      {s.error_detail && statusKey === "failed" && (
                        <p className="text-xs text-red-300 mt-1.5 break-all">{s.error_detail}</p>
                      )}
                    </div>
                    {typeof findingsTotal === "number" && (
                      <div className="text-right shrink-0">
                        <p className="text-xs text-slate-200 font-medium">{findingsTotal}</p>
                        <p className="text-[10px] text-slate-500">finding{findingsTotal === 1 ? "" : "s"}</p>
                      </div>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* ── Settings ─────────────────────────────────────────── */}
      {/* When the parent passes `renderSettings`, the full edit form
          lives inline in this tab — no ping-pong to a separate drawer.
          Falls back to a read-only summary + CTA only when the parent
          doesn't supply a render fn (legacy / standalone use). */}
      {activeTab === "settings" && (
        renderSettings ? (
          renderSettings(source)
        ) : (
          <div className="space-y-4">
            <div className="rounded border border-white/[0.05] bg-white/[0.02] px-4 py-3 space-y-2 text-xs">
              <Row label="Name" value={source.name} />
              <Row label="Type" value={typeLabel || source.source_type} />
              <Row label="Schedule" value={source.scan_schedule === "on_demand" ? "On demand" : source.scan_schedule} />
              <Row
                label="Binding"
                value={
                  source.target_repository_id
                    ? `Repository · ${source.target_repository_id.slice(0, 8)}…`
                    : source.target_business_unit_id
                      ? `Business unit · ${source.target_business_unit_id.slice(0, 8)}…`
                      : "Org-wide"
                }
              />
              <Row label="Active" value={source.is_active ? "Yes" : "No (archived)"} />
            </div>
            {onEditRequest && (
              <>
                <button
                  onClick={() => {
                    onEditRequest(source);
                    onClose();
                  }}
                  className="w-full text-xs px-3 py-2 rounded bg-violet-500/15 text-violet-300 hover:bg-violet-500/25 transition-colors font-medium"
                >
                  Edit source settings →
                </button>
                <p className="text-[10px] text-slate-500 leading-relaxed">
                  Editing opens the full configuration form (credentials,
                  source-specific options, scope binding).
                </p>
              </>
            )}
          </div>
        )
      )}

      {/* ── Rule Overrides ───────────────────────────────────── */}
      {activeTab === "rule_overrides" && (
        <RuleOverridesContent
          sourceFilter={{ id: source.id, name: source.name }}
          embedded
        />
      )}
    </SideDrawer>
  );
}

// ── Internal helpers ───────────────────────────────────────────────

function Stat({
  label,
  value,
  tone,
  subtle,
  subtleTone,
}: {
  label: string;
  value: string;
  tone?: "emerald" | "slate" | "amber" | "red";
  subtle?: string;
  subtleTone?: "emerald" | "red";
}) {
  const toneClass: Record<string, string> = {
    emerald: "text-emerald-400",
    slate: "text-slate-300",
    amber: "text-amber-400",
    red: "text-red-400",
  };
  const subtleClass: Record<string, string> = {
    emerald: "text-emerald-400",
    red: "text-red-400",
  };
  return (
    <div className="rounded border border-white/[0.05] bg-white/[0.02] px-4 py-3">
      <p className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</p>
      <p className={`text-base font-semibold mt-1 ${tone ? toneClass[tone] : "text-slate-100"}`}>{value}</p>
      {subtle && (
        <p className={`text-[10px] mt-0.5 ${subtleTone ? subtleClass[subtleTone] : "text-slate-500"}`}>
          {subtle}
        </p>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1">
      <span className="text-slate-500">{label}</span>
      <span className="text-slate-200 truncate text-right">{value}</span>
    </div>
  );
}
