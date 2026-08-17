"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useEffect, useState, useRef, useMemo, Suspense } from "react";
import { useParams, useRouter, useSearchParams } from "next/navigation";

import Link from "next/link";
import AppShell from "@/components/layout/AppShell";
// DefectTable moved to New Scan modal
import {
  getRepository, triggerScan,
  getRepoScans, updateRepository, deleteRepository, archiveRepository,
  getRepoBranches, getAIStatus, cancelScan, deleteScan, runAiTriage,
  updateRepoScanConfig,
} from "@/lib/api";
import { useToast } from "@/components/ui/Toast";
// Per-repo Rule Overrides card.  Re-uses the admin component in
// `embedded` mode and scopes the table + Create form to this repo
// via `repositoryFilter`.  See RuleOverridesContent and
// apps/api/app/models/rule_override.py for the proactive-vs-reactive
// rationale.
import { RuleOverridesContent } from "@/components/secrets/RuleOverridesContent";
import { useScanProgressWS } from "@/lib/useScanProgressWS";
import { ScanDetailDrawer } from "@/components/scans/ScanDetailDrawer";
import type { Repository, ScanJob } from "@/types";

// ── Scan History Card ────────────────────────────────────
const STATUS_COLORS: Record<string, { bg: string; text: string; label: string }> = {
  pending:   { bg: "bg-slate-500/15", text: "text-slate-400", label: "Pending" },
  running:   { bg: "bg-red-500/15",  text: "text-red-400",  label: "Running" },
  analyzing: { bg: "bg-purple-500/15", text: "text-purple-400", label: "AI Analyzing" },
  completed: { bg: "bg-green-500/15", text: "text-green-400", label: "Completed" },
  failed:    { bg: "bg-red-500/15",   text: "text-red-400",   label: "Failed" },
  cancelled: { bg: "bg-orange-500/15", text: "text-orange-400", label: "Cancelled" },
};

function ScanJobCard({ scan, repoId, onCancel, onDelete, onOpenDetail, onTriage }: { scan: ScanJob; repoId: string; onCancel?: (scanId: string) => void; onDelete?: (scanId: string) => void; onOpenDetail?: (scanId: string) => void; onTriage?: (scanId: string) => Promise<void> | void }) {
  const s = STATUS_COLORS[scan.status] || STATUS_COLORS.pending;
  const isActive = ["running", "analyzing", "pending"].includes(scan.status);
  const [cancelling, setCancelling] = useState(false);
  const [triaging, setTriaging] = useState(false);
  const doTriage = async (e: { stopPropagation: () => void }) => {
    e.stopPropagation();
    if (!onTriage || triaging) return;
    setTriaging(true);
    try { await onTriage(scan.id); } finally { setTriaging(false); }
  };
  // Active cards are clickable → opens the ScanDetailDrawer with live
  // WS progress.  Inactive cards stay non-interactive at the card level
  // (the "View secrets" link below still routes to /findings).  Buttons
  // inside the card use stopPropagation so Cancel / Delete don't also
  // open the drawer.
  const clickable = isActive && !!onOpenDetail;

  return (
    <div
      className={`bg-white/[0.02] border border-white/[0.06] rounded-xl p-4 ${isActive ? "border-red-500/20" : ""} ${clickable ? "cursor-pointer hover:bg-white/[0.04] hover:border-red-500/30 transition-colors" : ""}`}
      onClick={clickable ? () => onOpenDetail!(scan.id) : undefined}
      role={clickable ? "button" : undefined}
      tabIndex={clickable ? 0 : undefined}
      onKeyDown={clickable ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onOpenDetail!(scan.id); } } : undefined}
      aria-label={clickable ? `Open live progress for scan ${scan.id.slice(0, 8)}` : undefined}
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${s.bg} ${s.text} border border-white/[0.04]`}>
            {isActive && <span className="inline-block w-1.5 h-1.5 rounded-full bg-current mr-1.5 animate-pulse" />}
            {s.label}
          </span>
          <span className="text-xs text-slate-600">{scan.scan_type}</span>
        </div>
        <div className="flex items-center gap-2">
          {isActive && onCancel && (
            <button
              onClick={(e) => { e.stopPropagation(); setCancelling(true); onCancel(scan.id); }}
              disabled={cancelling}
              className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg text-red-400 border border-red-400/20 hover:bg-red-400/10 transition-all disabled:opacity-50"
            >
              {cancelling ? (
                <div className="w-3 h-3 border border-red-400/50 border-t-red-400 rounded-full animate-spin" />
              ) : (
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
              )}
              Cancel
            </button>
          )}
          {!isActive && onDelete && (
            <button
              onClick={(e) => { e.stopPropagation(); onDelete(scan.id); }}
              title="Delete this scan"
              className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg text-slate-500 border border-white/[0.06] hover:text-red-400 hover:border-red-400/20 hover:bg-red-400/5 transition-all"
            >
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
              Delete
            </button>
          )}
          <span className="text-xs text-slate-600">{new Date(scan.created_at).toLocaleString()}</span>
        </div>
      </div>
      {isActive && (
        <div className="mb-3">
          <div className="flex justify-between text-xs mb-1">
            <span className="text-slate-400">{scan.status_message || "Processing..."}</span>
            <span className="text-red-400">{scan.progress_pct}%</span>
          </div>
          <div className="w-full bg-white/[0.04] rounded-full h-1.5 overflow-hidden">
            <div className="h-full rounded-full bg-gradient-to-r from-red-500 to-orange-500 transition-all duration-500" style={{ width: `${scan.progress_pct}%` }} />
          </div>
        </div>
      )}
      {scan.status === "completed" && scan.stats && (
        <div className="space-y-3">
          {/* Primary stats */}
          <div className="flex gap-4 flex-wrap text-xs">
            {scan.stats.files_analyzed != null && (
              <span className="text-slate-400">
                <svg className="w-3 h-3 inline mr-1 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                <span className="text-slate-300 font-medium">{scan.stats.files_analyzed.toLocaleString()}</span> files scanned
              </span>
            )}
            {scan.stats.findings_total != null && (
              <span className="text-slate-400">
                <svg className="w-3 h-3 inline mr-1 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>
                <span className="text-white font-semibold">{scan.stats.findings_total}</span> secrets found
              </span>
            )}
            {scan.stats.rules_matched != null && (
              <span className="text-slate-400">
                <span className="text-slate-300 font-medium">{scan.stats.rules_matched}</span> rules matched
              </span>
            )}
          </div>

          {/* Severity breakdown */}
          {scan.stats.findings_by_severity && (
            <div className="flex gap-2 flex-wrap">
              {Object.entries(scan.stats.findings_by_severity as Record<string, number>)
                .filter(([, c]) => c > 0)
                .sort((a, b) => {
                  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                  return (order[a[0]] ?? 5) - (order[b[0]] ?? 5);
                })
                .map(([sev, c]) => {
                  const colors: Record<string, string> = {
                    critical: "bg-red-500/15 text-red-400 border-red-500/20",
                    high: "bg-orange-500/15 text-orange-400 border-orange-500/20",
                    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
                    low: "bg-blue-500/15 text-blue-400 border-blue-500/20",
                    info: "bg-slate-500/10 text-slate-400 border-slate-500/20",
                  };
                  return (
                    <span key={sev} className={`text-[10px] px-2 py-0.5 rounded-md border font-medium ${colors[sev] || colors.info}`}>
                      {c} {sev}
                    </span>
                  );
                })}
            </div>
          )}

          {/* Secret-scanning specific stats */}
          <div className="flex gap-3 flex-wrap text-[10px]">
            {scan.stats.detection_methods && (
              <>
                {(scan.stats.detection_methods as any).regex > 0 && (
                  <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/10 text-red-400">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>
                    {(scan.stats.detection_methods as any).regex} regex
                  </span>
                )}
                {(scan.stats.detection_methods as any).entropy > 0 && (
                  <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-purple-500/10 text-purple-400">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10" /></svg>
                    {(scan.stats.detection_methods as any).entropy} entropy
                  </span>
                )}
              </>
            )}
            {scan.stats.providers_detected && Object.keys(scan.stats.providers_detected as Record<string, number>).length > 0 && (
              <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-white/[0.04] text-slate-400">
                {Object.keys(scan.stats.providers_detected as Record<string, number>).length} providers
              </span>
            )}
            {scan.stats.validation_active != null && scan.stats.validation_active > 0 && (
              <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/10 text-red-400">
                {scan.stats.validation_active} active (live)
              </span>
            )}
            {scan.stats.validation_inactive != null && scan.stats.validation_inactive > 0 && (
              <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-green-500/10 text-green-400">
                {scan.stats.validation_inactive} inactive
              </span>
            )}
          </div>

          {/* AI pipeline stats */}
          <div className="flex gap-3 flex-wrap text-[10px]">
            {scan.stats.ai_triaged > 0 && (
              <span className="flex items-center gap-1 text-purple-400">
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
                {scan.stats.ai_triaged} AI-triaged
              </span>
            )}
            {scan.stats.false_positives > 0 && (
              <span className="flex items-center gap-1 text-green-400">
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                {scan.stats.false_positives} false positives removed
              </span>
            )}
            {scan.stats.auto_remediated > 0 && (
              <span className="flex items-center gap-1 text-red-400">
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>
                {scan.stats.auto_remediated} auto-remediated
              </span>
            )}
            {/*
              AI status messaging precision.  Old single-branch
              message ("AI triage pending — configure AI model in
              Settings") fired any time ai_triaged was 0 — including
              when the user deliberately picked "Scan Without AI" OR
              when every new finding had a cached AI classification
              from prior scans.  Both cases produced misleading
              "go configure AI" text in customers who'd already
              configured AI.  Fixed 2026-05-24 (Vooda Scan
              Intelligence audit follow-up) by branching on the
              actual cause:
                1. User explicitly skipped — neutral grey label
                2. Every new finding cached against prior AI —
                   render nothing (system worked as designed)
                3. AI genuinely missing or broken — keep the
                   amber "configure" prompt
            */}
            {(() => {
              if (scan.stats.findings_total <= 0) return null;
              if (scan.stats.ai_triaged > 0) return null;  // AI ran on something

              // Case 1 — user picked "Scan Without AI"
              if (scan.config?.skip_ai) {
                return (
                  <span className="text-slate-500 italic">AI triage skipped (user choice)</span>
                );
              }
              // Case 2 — healthy fast-path: every new finding hit
              // the decision cache.  No warning warranted.
              const cacheHits = scan.stats.cache_hits ?? 0;
              const newFindings = scan.stats.findings_new ?? 0;
              if (newFindings > 0 && cacheHits >= newFindings) {
                return null;  // all new findings already had AI classifications cached
              }
              // Case 3 — real misconfiguration
              return (
                <span className="text-yellow-400/70 italic">AI triage pending — configure AI model in Settings</span>
              );
            })()}
            {/* Run-AI-triage CTA: when a completed scan has findings but AI
                triage never ran (no model at scan time, or skip_ai), let the
                user trigger it in place — no full re-scan. The endpoint guards
                on a configured model (400 → toast otherwise). */}
            {scan.status === "completed" && (scan.stats?.findings_total ?? 0) > 0
              && (scan.stats?.ai_triaged ?? 0) === 0 && onTriage && (
              <button
                onClick={doTriage}
                disabled={triaging}
                title="Run AI triage on these findings now — no re-scan"
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-purple-500/15 text-purple-300 hover:bg-purple-500/25 border border-purple-500/25 text-[10px] font-medium disabled:opacity-50 transition-colors"
              >
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
                {triaging ? "Starting…" : "Run AI Triage"}
              </button>
            )}
          </div>
        </div>
      )}
      {scan.status === "completed" && (scan.stats?.findings_total ?? 0) > 0 && (
        <Link href={`/findings?repository_id=${repoId}`} className="inline-flex items-center gap-1.5 mt-3 text-xs text-red-400 hover:text-red-300">
          View secrets <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
        </Link>
      )}
    </div>
  );
}

// ── Main Page ────────────────────────────────────────────
type PageTab = "scan" | "settings";

// ── Webhook & PR Scans card (Phase 1 Stage 3) ──────────────────
// Renders the per-repo push/PR scan toggles plus the most recent
// webhook-event line.  Optimistic update — toggle flips visually
// immediately, the PATCH fires in the background, and the parent's
// state is reconciled with the server response on success (rolls
// back on failure with a toast).  Matches the pattern GitGuardian /
// Snyk / Aikido ship.
function WebhookAndPRScansCard({ repo, onChange }: {
  repo: Repository;
  onChange: (updated: Repository) => void;
}) {
  const { toast } = useToast();
  const [busy, setBusy] = useState<"push" | "pr" | null>(null);

  const flip = async (field: "push_scan_enabled" | "pr_scan_enabled", next: boolean) => {
    const key: "push" | "pr" = field === "push_scan_enabled" ? "push" : "pr";
    setBusy(key);
    // Optimistic update so the toggle feels instant — UX rule of
    // thumb for binary toggles is < 100ms perceived latency.
    onChange({ ...repo, [field]: next });
    try {
      const r = await updateRepoScanConfig(repo.id, { [field]: next });
      onChange(r.data);
    } catch (e: any) {
      // Roll back on failure so the UI doesn't lie about server state.
      onChange({ ...repo, [field]: !next });
      toast("error", `Failed To Update ${key === "push" ? "Push" : "PR"} Scan`, e?.message || "Unknown Error");
    } finally {
      setBusy(null);
    }
  };

  // Time-ago formatter for the last-event line.  Matches the format
  // used across the rest of the dashboard ("2h Ago", "3d Ago").
  const fmtTimeAgo = (iso: string | null | undefined): string => {
    if (!iso) return "Never";
    try {
      const diffS = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
      if (diffS < 60) return `${diffS}s Ago`;
      const m = Math.floor(diffS / 60);
      if (m < 60) return `${m}m Ago`;
      const h = Math.floor(m / 60);
      if (h < 24) return `${h}h Ago`;
      const d = Math.floor(h / 24);
      return `${d}d Ago`;
    } catch { return "Never"; }
  };

  // Single-letter helper for the event-type chip.  Compact so the
  // last-event line fits on one row at narrow widths.
  const eventTypeLabel = (t: string | null | undefined): string => {
    if (!t) return "—";
    if (t === "push") return "Push";
    if (t === "pull_request") return "Pull Request";
    if (t === "merge_request") return "Merge Request";
    return t;
  };

  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Webhook & PR Scans</h3>
      <p className="text-sm text-slate-500 mb-4">
        Control which webhook events trigger a scan on this repository.
        Toggles take effect immediately — disabling does not unregister
        the webhook itself, so the health badge stays accurate.
      </p>

      {/* ── Push-scan toggle ── */}
      <div className="flex items-start justify-between gap-4 p-4 rounded-lg bg-white/[0.02] border border-white/[0.04] mb-3">
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-slate-200">Scan Pushes To Default Branch</p>
          <p className="text-xs text-slate-500 mt-1">
            Each push to <code className="text-slate-400">{repo.default_branch}</code> triggers an incremental scan
            of the new commits.  Turn off for repos with high commit churn
            where per-push scans are noise.
          </p>
        </div>
        <Toggle
          checked={!!repo.push_scan_enabled}
          disabled={busy === "push"}
          onChange={(v) => flip("push_scan_enabled", v)}
        />
      </div>

      {/* ── PR-scan toggle ── */}
      <div className="flex items-start justify-between gap-4 p-4 rounded-lg bg-white/[0.02] border border-white/[0.04] mb-4">
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-slate-200">Scan Pull Requests</p>
          <p className="text-xs text-slate-500 mt-1">
            Each PR open / reopen / synchronize triggers a scan of the diff.
            Findings post back as a commit status check so reviewers see
            them in the PR before merge.
          </p>
        </div>
        <Toggle
          checked={!!repo.pr_scan_enabled}
          disabled={busy === "pr"}
          onChange={(v) => flip("pr_scan_enabled", v)}
        />
      </div>

      {/* ── Last webhook event row ── */}
      <div className="flex items-center justify-between gap-4 p-4 rounded-lg bg-white/[0.02] border border-white/[0.04]">
        <div className="flex-1 min-w-0">
          <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">Last Webhook Event</p>
          {repo.last_webhook_event_at ? (
            <div className="flex items-center gap-2 text-sm">
              <span className="text-slate-200 font-medium">{eventTypeLabel(repo.last_webhook_event_type)}</span>
              <span className="text-slate-600">·</span>
              <span className="text-slate-400">{fmtTimeAgo(repo.last_webhook_event_at)}</span>
              <span className="text-slate-600">·</span>
              <span className={`text-[11px] px-1.5 py-0.5 rounded ${
                repo.last_webhook_event_status === "failed"
                  ? "bg-red-500/15 text-red-400"
                  : repo.last_webhook_event_status === "skipped"
                  ? "bg-slate-500/15 text-slate-400"
                  : "bg-emerald-500/15 text-emerald-400"
              }`}>
                {(repo.last_webhook_event_status || "Unknown").charAt(0).toUpperCase() + (repo.last_webhook_event_status || "Unknown").slice(1)}
              </span>
            </div>
          ) : (
            <p className="text-sm text-slate-500">No Events Received Yet</p>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Branch Monitoring card ──────────────────────────────────
// Per-repo branch-pattern configuration.  Lets a customer narrow
// webhook-triggered scans from "every branch" (the default) down to
// specific branches or fnmatch globs.  Three radio modes mirror what
// GitGuardian / Snyk Code / Aikido ship: all branches, default
// branch only, or custom patterns.
//
// Pattern syntax = fnmatch globs (``main``, ``release/*``,
// ``feature-?``).  No regex — customers don't want to write regex
// in a Settings form.
function BranchMonitoringCard({ repo, onChange }: {
  repo: Repository;
  onChange: (updated: Repository) => void;
}) {
  const { toast } = useToast();
  // Mode derived from current state.  Effects of the three modes on
  // the backend payload:
  //   "all"     → branch_patterns = null
  //   "default" → branch_patterns = [repo.default_branch]
  //   "custom"  → branch_patterns = <input list, server normalises>
  type Mode = "all" | "default" | "custom";
  const deriveMode = (): Mode => {
    const p = repo.branch_patterns;
    if (!p || p.length === 0) return "all";
    if (p.length === 1 && p[0] === repo.default_branch) return "default";
    return "custom";
  };

  const [mode, setMode] = useState<Mode>(deriveMode());
  const [customInput, setCustomInput] = useState<string>(
    (repo.branch_patterns || []).join(", ")
  );
  const [saving, setSaving] = useState(false);
  // Re-derive on prop change (e.g. parent reconciled after a save).
  useEffect(() => {
    setMode(deriveMode());
    setCustomInput((repo.branch_patterns || []).join(", "));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [repo.branch_patterns, repo.default_branch]);

  const save = async (nextPatterns: string[] | null) => {
    setSaving(true);
    try {
      const r = await updateRepoScanConfig(repo.id, { branch_patterns: nextPatterns });
      onChange(r.data);
    } catch (e: any) {
      toast("error", "Failed To Update Branch Monitoring", e?.message || "Unknown Error");
    } finally {
      setSaving(false);
    }
  };

  const onModeChange = async (m: Mode) => {
    setMode(m);
    if (m === "all") {
      await save(null);
    } else if (m === "default") {
      await save([repo.default_branch || "main"]);
    }
    // "custom" mode: don't auto-save; user types patterns and hits Save.
  };

  const saveCustom = async () => {
    const patterns = customInput
      .split(/[,\n]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    await save(patterns.length > 0 ? patterns : null);
  };

  // Pretty-print the currently-effective set of branches.
  const effectiveLabel = (() => {
    if (mode === "all") return "All Branches";
    if (mode === "default") return `Only \`${repo.default_branch || "main"}\``;
    const ps = repo.branch_patterns || [];
    if (ps.length === 0) return "All Branches";
    return ps.map((p) => `\`${p}\``).join(", ");
  })();

  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Branch Monitoring</h3>
      <p className="text-sm text-slate-500 mb-4">
        Choose which branches trigger a scan on webhook delivery.
        Customers with monorepos or noisy feature-branch traffic narrow
        this from the default (all branches) to specific patterns.
      </p>

      <div className="space-y-2 mb-4">
        {([
          { id: "all" as Mode, label: "All Branches", desc: "Every push or PR event triggers a scan, on any branch.  Default behaviour." },
          { id: "default" as Mode, label: "Default Branch Only", desc: `Only events on \`${repo.default_branch || "main"}\` trigger a scan.  Recommended for repos with high feature-branch churn.` },
          { id: "custom" as Mode, label: "Custom Patterns", desc: "Provide a comma-separated list of fnmatch globs.  Examples: `main`, `release/*`, `feature-?`." },
        ] as const).map((opt) => (
          <label
            key={opt.id}
            className="flex items-start gap-3 p-3 rounded-lg cursor-pointer transition-colors"
            style={{
              background: mode === opt.id ? "rgba(239,68,68,0.06)" : "rgba(255,255,255,0.02)",
              border: `1px solid ${mode === opt.id ? "rgba(239,68,68,0.25)" : "rgba(255,255,255,0.05)"}`,
            }}
          >
            <input
              type="radio"
              name="branch-monitoring-mode"
              checked={mode === opt.id}
              disabled={saving}
              onChange={() => onModeChange(opt.id)}
              className="mt-1 shrink-0"
              style={{ accentColor: "#ef4444" }}
            />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-slate-200">{opt.label}</p>
              <p className="text-xs text-slate-500 mt-1">{opt.desc}</p>
            </div>
          </label>
        ))}
      </div>

      {mode === "custom" && (
        <div className="space-y-2 mb-4 p-3 rounded-lg" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)" }}>
          <label className="block text-xs text-slate-400 font-medium">Patterns</label>
          <textarea
            value={customInput}
            onChange={(e) => setCustomInput(e.target.value)}
            disabled={saving}
            rows={3}
            className="input-dark w-full font-mono text-sm"
            placeholder="main, release/*, develop"
          />
          <p className="text-[11px] text-slate-600">
            Comma- or newline-separated.  Each entry is an fnmatch glob.
            Whitespace and empty entries are ignored.  Max 50 patterns,
            200 characters each.
          </p>
          <div className="flex justify-end">
            <button
              onClick={saveCustom}
              disabled={saving}
              className="btn-primary text-xs px-3 py-1.5"
            >
              {saving ? "Saving..." : "Save Patterns"}
            </button>
          </div>
        </div>
      )}

      <div className="flex items-center justify-between gap-4 p-3 rounded-lg" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)" }}>
        <div className="flex-1 min-w-0">
          <p className="text-[10px] text-slate-600 uppercase tracking-wider">Currently Monitoring</p>
          <p className="text-sm text-slate-300 font-mono mt-1 truncate">{effectiveLabel}</p>
        </div>
      </div>
    </div>
  );
}

// ── Simple toggle switch ────────────────────────────────────
// Lightweight on/off control used by WebhookAndPRScansCard.  Matches
// the visual weight of the existing card-form controls (input-dark,
// btn-secondary) — slate background, red accent when on.
function Toggle({ checked, disabled, onChange }: {
  checked: boolean;
  disabled?: boolean;
  onChange: (next: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="relative inline-flex items-center shrink-0 transition-colors"
      style={{
        width: 36,
        height: 20,
        borderRadius: 999,
        background: checked ? "rgba(239,68,68,0.85)" : "rgba(100,116,139,0.4)",
        opacity: disabled ? 0.5 : 1,
        cursor: disabled ? "wait" : "pointer",
      }}
    >
      <span
        className="absolute rounded-full bg-white transition-transform"
        style={{
          width: 14,
          height: 14,
          top: 3,
          left: 3,
          transform: checked ? "translateX(16px)" : "translateX(0)",
          boxShadow: "0 1px 2px rgba(0,0,0,0.3)",
        }}
      />
    </button>
  );
}

// Inner component reads useSearchParams; default export wraps it in
// <Suspense> so Next.js 15 can suspend on the bailout boundary.
function RepositoryDetailPageInner() {
  const params = useParams();
  const id = params?.id as string;
  const { toast } = useToast();

  const [repo, setRepo] = useState<Repository | null>(null);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [scanLoading, setScanLoading] = useState(false);
  const [showScanMenu, setShowScanMenu] = useState(false);
  // Allow callers to deep-link straight into the edit form via
  // `?edit=1` (e.g. the Edit pencil icon on the /repositories list).
  // Defaults to "scan" otherwise so the page opens to its dashboard.
  const searchParams = useSearchParams();
  const startInEditMode = searchParams?.get("edit") === "1";
  const [pageTab, setPageTab] = useState<PageTab>(startInEditMode ? "settings" : "scan");
  const [editForm, setEditForm] = useState<any>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteScanTarget, setDeleteScanTarget] = useState<ScanJob | null>(null);
  // Track the in-flight repo delete so the button can disable + show a
  // spinner. Without this the cascading backend delete (can take 1–2s)
  // looked like "nothing happened" and forced users to click twice.
  const [deletingRepo, setDeletingRepo] = useState(false);
  const [branches, setBranches] = useState<{ name: string; is_default: boolean }[]>([]);
  const [branchesLoading, setBranchesLoading] = useState(false);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Which active scan's live-progress drawer is open.  `null` =
  // drawer closed.  Drives the useScanProgressWS subscription below
  // — the hook does nothing when given null so we pay zero WS cost
  // when the drawer isn't open.  Track-A Rec #1 (2026-05-22).
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const { update: liveScanUpdate, connected: wsConnected, reconnecting: wsReconnecting, gaveUp: wsGaveUp } =
    useScanProgressWS(selectedScanId);

  // If the selected scan disappears from the list (e.g. user deleted
  // it from another tab, or its row got pruned), close the drawer
  // gracefully instead of rendering against a stale id.
  useEffect(() => {
    if (selectedScanId && !scans.some((s) => s.id === selectedScanId)) {
      setSelectedScanId(null);
    }
  }, [selectedScanId, scans]);

  // Stable reference for the RuleOverridesContent prop.  Without this,
  // every parent re-render (e.g. when the 5-second scan poll updates
  // `scans`) produces a brand-new `{id, name}` object → child's
  // useCallback(fetchAll, [repositoryFilter]) sees new identity →
  // useEffect refires → /rule-overrides + /rule-overrides/stats fetch
  // again.  Track-A live UX audit (2026-05-22) measured this as a
  // 3-endpoint refetch on every scan-poll tick.  useMemo with primitive
  // dependencies stabilises the reference so the child only refetches
  // when the repo's id or name actually changes.
  const ruleOverridesRepoFilter = useMemo(
    () => (repo ? { id: repo.id, name: repo.name } : null),
    [repo?.id, repo?.name],
  );

  const loadBranches = () => {
    setBranchesLoading(true);
    getRepoBranches(id)
      .then((r) => {
        setBranches(r.data.branches || []);
      })
      .catch(() => {})
      .finally(() => setBranchesLoading(false));
  };

  useEffect(() => {
    getRepository(id).then((r) => setRepo(r.data)).catch(() => {});
    loadScans();
    loadBranches();
    return () => { if (pollingRef.current) clearInterval(pollingRef.current); };
  }, [id]);

  const loadScans = () => {
    getRepoScans(id).then((r) => {
      setScans(r.data || []);
      const hasActive = (r.data || []).some((s: ScanJob) => ["running", "analyzing", "pending"].includes(s.status));
      if (hasActive && !pollingRef.current) {
        // 5s cadence (was 2s — Track-A live UX audit, 2026-05-22).
        // The 2s rate produced a "polling storm" on the scan-detail page:
        // 17 /scans requests in 8s combined with re-renders that
        // re-triggered rule-overrides fetches in the Settings tab,
        // for a total of 113 API requests in 8s on a single page.
        // 5s still feels live (progress bar redraws within a beat
        // of the worker's step transition) and cuts request volume
        // by 60% without changing perceived freshness.  When we move
        // to WebSocket-based scan progress this constant goes away
        // entirely — see audit Recommendation #2.
        pollingRef.current = setInterval(() => {
          getRepoScans(id).then((r2) => {
            setScans(r2.data || []);
            if (!(r2.data || []).some((s: ScanJob) => ["running", "analyzing", "pending"].includes(s.status)) && pollingRef.current) {
              clearInterval(pollingRef.current);
              pollingRef.current = null;
            }
          });
        }, 5000);
      }
    }).catch(() => {});
  };

  // AI status check before scan
  const [showAIPrompt, setShowAIPrompt] = useState(false);
  const [aiConfigured, setAiConfigured] = useState<boolean | null>(null);
  const [aiStatusMsg, setAiStatusMsg] = useState("");

  const handleFreshScan = async () => {
    // Check AI status first
    try {
      const statusRes = await getAIStatus();
      const status = statusRes.data;
      if (!status.ai_configured) {
        setAiConfigured(false);
        setAiStatusMsg(status.message);
        setShowAIPrompt(true);
        return; // Don't start scan — show prompt first
      }
    } catch {
      // If status check fails, proceed anyway
    }
    // AI is configured — start scan directly
    await startScan();
  };

  // Options-object signature (refactored 2026-05-24 from positional
  // booleans).  Previous shape `startScan(skipAI, scanType, forceFull)`
  // produced a class of bugs where callers wrote `startScan(true,
  // "history")` thinking `true` meant "trigger" or "history mode" —
  // when in fact it set skip_ai=true and silently disabled AI triage.
  // Named-argument call sites like `startScan({ scanType: "history" })`
  // make the bug class impossible because no positional `true` exists.
  type StartScanOptions = {
    skipAI?: boolean;
    scanType?: "standalone" | "history";
    forceFull?: boolean;
  };

  const startScan = async (opts: StartScanOptions = {}) => {
    const { skipAI = false, scanType = "standalone", forceFull = false } = opts;
    setScanLoading(true);
    setShowAIPrompt(false);
    try {
      // Build the config payload. ``force_full`` tells the worker to
      // bypass the incremental ``scan_diff`` path and re-walk every
      // file even when the repo has a stored ``last_scanned_commit``.
      // Used for "Force Full Re-Scan" after rule pack updates, or
      // when the user suspects the previous checkpoint missed
      // something.
      const cfg: Record<string, unknown> = {};
      if (skipAI) cfg.skip_ai = true;
      if (forceFull) cfg.force_full = true;
      await triggerScan(id, {
        scan_type: scanType,
        config: cfg,
      });
      loadScans();
      if (scanType === "history") {
        toast("success", "History Scan Started", "Scanning all git commits for secrets. This may take several minutes.");
      } else if (forceFull) {
        toast("success", "Full Re-Scan Started", "Re-walking the entire repository. The next scan will resume incremental mode automatically.");
      }
    } finally {
      setScanLoading(false);
    }
  };

  const handleCancelScan = async (scanId: string) => {
    try {
      await cancelScan(id, scanId);
      toast("success", "Scan Cancelled", "The scan has been stopped successfully");
      loadScans();
    } catch (err: any) {
      const msg = err?.response?.data?.detail || "Failed to cancel scan";
      toast("error", "Cancel Failed", msg);
    }
  };

  const handleRunTriage = async (scanId: string) => {
    try {
      await runAiTriage(id, scanId);
      toast("info", "AI Triage Started", "Triaging the existing findings — this can take a few minutes. The card will show live progress.");
      loadScans();
    } catch (err: any) {
      const msg = err?.response?.data?.detail || "Failed to start AI triage";
      toast("error", "AI Triage Failed", msg);
    }
  };

  const handleDeleteScan = (scanId: string) => {
    const target = scans.find((s) => s.id === scanId) || null;
    setDeleteScanTarget(target);
  };

  const confirmDeleteScan = async () => {
    if (!deleteScanTarget) return;
    try {
      await deleteScan(id, deleteScanTarget.id);
      setDeleteScanTarget(null);
      toast("success", "Scan Deleted", "Scan and all associated findings have been permanently removed");
      loadScans();
    } catch (err: any) {
      const msg = err?.response?.data?.detail || "Failed to delete scan";
      setDeleteScanTarget(null);
      toast("error", "Delete Failed", msg);
    }
  };

  if (!repo) return <AppShell pageTitle="Loading…"><div className="flex items-center justify-center py-20"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div></AppShell>;

  // Run Scan split-button — lives on the tab row, right-aligned, so
  // the tabs (Scans / Settings) and the primary action share a single
  // horizontal band.  URL moved into Repository Details as a proper
  // field; the standalone URL subtitle is gone.
  // The tab was previously "Scan & Import" — the import half was
  // retired alongside the defect-import flow removal (2026-05-16) so
  // the label is now plain "Scans".
  const runScanButton = (
    <div className="flex items-center gap-0">
      <button onClick={handleFreshScan} disabled={scanLoading} className="btn-primary-sm rounded-r-none">
        {scanLoading ? (
          <><div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />Scanning…</>
        ) : (
          <><svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" /></svg>Run Scan</>
        )}
      </button>
      <div className="relative">
        <button
          onClick={() => setShowScanMenu(!showScanMenu)}
          disabled={scanLoading}
          className="btn-primary-sm rounded-l-none border-l border-white/20 px-1.5"
          aria-label="More scan options"
        >
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
        </button>
        {showScanMenu && (
          <>
            <div className="fixed inset-0 z-10" onClick={() => setShowScanMenu(false)} />
            <div className="absolute right-0 top-full mt-1 z-20 w-56 py-1 rounded-lg card border border-white/[0.1] shadow-xl">
              <button
                onClick={() => { setShowScanMenu(false); handleFreshScan(); }}
                className="w-full text-left px-4 py-2.5 hover:bg-white/[0.04] transition-colors"
              >
                <p className="text-sm text-slate-200 font-medium">Scan Current Code</p>
                <p className="text-[10px] text-slate-500">Re-scans only the files that have changed.</p>
              </button>
              <button
                onClick={() => { setShowScanMenu(false); startScan({ forceFull: true }); }}
                className="w-full text-left px-4 py-2.5 hover:bg-white/[0.04] transition-colors"
              >
                <p className="text-sm text-slate-200 font-medium">Force Full Re-Scan</p>
                <p className="text-[10px] text-slate-500">Re-scans every file from scratch.</p>
              </button>
              <button
                // BUG FIX 2026-05-24: previously called
                // `startScan(true, "history")` — the first positional
                // arg was `skipAI`, NOT a "run" flag.  This made
                // every Scan Git History click silently disable AI
                // triage, which then surfaced as "AI triage pending
                // — configure AI model in Settings" on the resulting
                // scan card and confused users who hadn't asked to
                // skip AI.  Discovered via Vooda Scan Intelligence
                // audit follow-up — the user reasonably asked "when
                // did the user ask to skip the AI triage?".
                //
                // Now uses the options-object call shape — same fix
                // intent, plus the named argument makes the bug class
                // impossible going forward.
                onClick={() => { setShowScanMenu(false); startScan({ scanType: "history" }); }}
                className="w-full text-left px-4 py-2.5 hover:bg-white/[0.04] transition-colors"
              >
                <p className="text-sm text-slate-200 font-medium">Scan Git History</p>
                <p className="text-[10px] text-slate-500">Scans every commit, including removed code.</p>
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );

  return (
    <AppShell pageTitle={repo.name}>
      <div className="space-y-4 max-w-6xl">
        {/* ═══ Page-level tabs + Run Scan (right-aligned) ═══
            One horizontal band carries the tab navigation on the left
            and the primary action on the right.  No standalone URL row
            here — URL moved into Repository Details below as a proper
            field. */}
        <div className="flex items-center gap-1 border-b border-white/[0.06] -mb-1">
          {[
            { key: "scan" as PageTab, label: "Scans", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /> },
            { key: "settings" as PageTab, label: "Settings", icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /> },
          ].map((tab) => (
            <button
              key={tab.key}
              onClick={() => setPageTab(tab.key)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-all ${
                pageTab === tab.key
                  ? "border-red-400 text-red-400"
                  : "border-transparent text-slate-400 hover:text-slate-200 hover:border-white/[0.1]"
              }`}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">{tab.icon}</svg>
              {tab.label}
            </button>
          ))}
          {/* Right-aligned Run Scan — `ml-auto` pushes it to the end of
              the tab row. `pb-2` aligns the button vertically with the
              tab labels above the bottom border. */}
          <div className="ml-auto pb-2 pr-1">{runScanButton}</div>
        </div>

        {/* ═══ SCAN TAB ═══ */}
        {pageTab === "scan" && (<>

        {/* Repo details */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Repository Details</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            {/* URL spans the full width so the long github.com path
                isn't crammed into a single 240px column. Clickable
                link opens the upstream repo in a new tab. */}
            {repo.url && (
              <div className="md:col-span-4">
                <span className="text-slate-500">URL</span>
                <p className="mt-0.5">
                  <a
                    href={repo.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-slate-300 hover:text-red-400 transition-colors break-all"
                  >
                    <svg className="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                    </svg>
                    {repo.url}
                  </a>
                </p>
              </div>
            )}
            <div><span className="text-slate-500">Branch</span><p className="text-slate-300 mt-0.5">{repo.default_branch}</p></div>
            <div><span className="text-slate-500">Source</span><p className="text-slate-300 mt-0.5 capitalize">{repo.source_type?.replace("_", " ")}</p></div>
            <div>
              <span className="text-slate-500">Languages</span>
              <div className="flex gap-1 mt-1 flex-wrap">
                {repo.languages?.length ? repo.languages.map((l) => (
                  <span key={l} className="text-xs px-2 py-0.5 rounded bg-white/[0.04] text-slate-400">{l}</span>
                )) : <span className="text-slate-600 text-xs">Pending</span>}
              </div>
            </div>
            <div>
              <span className="text-slate-500">Frameworks</span>
              <div className="flex gap-1 mt-1 flex-wrap">
                {repo.frameworks?.length ? repo.frameworks.map((f) => (
                  <span key={f} className="text-xs px-2 py-0.5 rounded bg-purple-500/10 text-purple-400">{f}</span>
                )) : <span className="text-slate-600 text-xs">Pending</span>}
              </div>
            </div>
          </div>
        </div>

        {/* ═══ Scan History ═══ */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Scan History</h3>
            {scans.length > 0 && (
              <Link href={`/findings?repository_id=${id}`} className="text-xs text-red-400 hover:text-red-300">View all secrets</Link>
            )}
          </div>
          {scans.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-sm text-slate-500">No scans yet</p>
              <p className="text-xs text-slate-600 mt-1">Click Run Scan to get started</p>
            </div>
          ) : (
            <div className="space-y-3">
              {scans.map((scan) => <ScanJobCard key={scan.id} scan={scan} repoId={id} onCancel={handleCancelScan} onDelete={handleDeleteScan} onOpenDetail={setSelectedScanId} onTriage={handleRunTriage} />)}
            </div>
          )}
        </div>

        </>)}

        {/* ═══ SETTINGS TAB ═══ */}
        {pageTab === "settings" && (
          <div className="space-y-6">
            {/* General Settings */}
            <div className="card">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">General</h3>
              <div className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-6">
                  <label className="sm:w-1/3 text-sm font-medium text-slate-400">Repository Name</label>
                  <input
                    defaultValue={repo.name}
                    onChange={(e) => setEditForm((f: any) => ({ ...f, name: e.target.value }))}
                    className="input-dark flex-1"
                  />
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-6">
                  <label className="sm:w-1/3 text-sm font-medium text-slate-400">Repository URL</label>
                  <input
                    defaultValue={repo.url || ""}
                    onChange={(e) => setEditForm((f: any) => ({ ...f, url: e.target.value }))}
                    className="input-dark flex-1"
                  />
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-6">
                  <label className="sm:w-1/3 text-sm font-medium text-slate-400">
                    Default Branch
                    {branchesLoading && <span className="ml-2 text-xs text-slate-600 font-normal">(loading...)</span>}
                  </label>
                  <div className="flex-1 flex gap-2">
                    {branches.length > 0 ? (
                      <select
                        defaultValue={repo.default_branch}
                        onChange={(e) => setEditForm((f: any) => ({ ...f, default_branch: e.target.value }))}
                        className="select-dark flex-1"
                      >
                        {branches.map((b) => (
                          <option key={b.name} value={b.name}>
                            {b.name}{b.is_default ? " (default)" : ""}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        defaultValue={repo.default_branch}
                        onChange={(e) => setEditForm((f: any) => ({ ...f, default_branch: e.target.value }))}
                        className="input-dark flex-1"
                        placeholder="main"
                      />
                    )}
                    <button
                      onClick={loadBranches}
                      disabled={branchesLoading}
                      className="px-3 py-2 rounded-lg border border-white/[0.08] hover:bg-white/[0.04] transition-colors shrink-0"
                      title="Refresh branches"
                    >
                      <svg className={`w-4 h-4 text-slate-400 ${branchesLoading ? "animate-spin" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                    </button>
                  </div>
                </div>
                <div className="pt-2">
                  <button
                    onClick={async () => {
                      if (editForm) {
                        await updateRepository(id, editForm);
                        getRepository(id).then((r) => setRepo(r.data));
                      }
                    }}
                    className="btn-primary text-sm"
                  >
                    Save Changes
                  </button>
                </div>
              </div>
            </div>

            {/* Scan Configuration */}
            <div className="card">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Scan Configuration</h3>
              <div className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-6">
                  <label className="sm:w-1/3 text-sm font-medium text-slate-400">Scan Schedule</label>
                  <select
                    defaultValue={repo.metadata_?.scan_schedule || "on_demand"}
                    onChange={(e) => setEditForm((f: any) => ({ ...f, scan_schedule: e.target.value }))}
                    className="select-dark flex-1"
                  >
                    <option value="on_demand">On Demand</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="on_pr">On Pull Request</option>
                  </select>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-6">
                  <label className="sm:w-1/3 text-sm font-medium text-slate-400">
                    Scan Branch
                    <span className="text-xs text-slate-600 block font-normal">Which branch to scan by default</span>
                  </label>
                  <div className="flex-1 flex gap-2">
                    {branches.length > 0 ? (
                      <select
                        defaultValue={repo.metadata_?.scan_branch || repo.default_branch}
                        onChange={(e) => setEditForm((f: any) => ({ ...f, scan_branch: e.target.value }))}
                        className="select-dark flex-1"
                      >
                        {branches.map((b) => (
                          <option key={b.name} value={b.name}>
                            {b.name}{b.is_default ? " (default)" : ""}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        defaultValue={repo.metadata_?.scan_branch || repo.default_branch}
                        onChange={(e) => setEditForm((f: any) => ({ ...f, scan_branch: e.target.value }))}
                        className="input-dark flex-1"
                        placeholder={repo.default_branch}
                      />
                    )}
                  </div>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-start gap-2 sm:gap-6">
                  <label className="sm:w-1/3 text-sm font-medium text-slate-400 pt-2">Scan Paths <span className="text-xs text-slate-600 block font-normal">Leave empty to scan entire repo</span></label>
                  <input
                    defaultValue={(repo.metadata_?.scan_paths || []).join(", ")}
                    placeholder="src/, lib/"
                    onChange={(e) => setEditForm((f: any) => ({ ...f, scan_paths: e.target.value.split(",").map((s: string) => s.trim()).filter(Boolean) }))}
                    className="input-dark flex-1"
                  />
                </div>
                <div className="flex flex-col sm:flex-row sm:items-start gap-2 sm:gap-6">
                  <label className="sm:w-1/3 text-sm font-medium text-slate-400 pt-2">Exclude Patterns <span className="text-xs text-slate-600 block font-normal">Glob patterns to skip</span></label>
                  <input
                    defaultValue={(repo.metadata_?.exclude_patterns || []).join(", ")}
                    placeholder="**/test/**, **/vendor/**"
                    onChange={(e) => setEditForm((f: any) => ({ ...f, exclude_patterns: e.target.value.split(",").map((s: string) => s.trim()).filter(Boolean) }))}
                    className="input-dark flex-1"
                  />
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-6">
                  <label className="sm:w-1/3 text-sm font-medium text-slate-400">Team Owner</label>
                  <input
                    defaultValue={repo.metadata_?.team_owner || ""}
                    placeholder="e.g. Platform Security"
                    onChange={(e) => setEditForm((f: any) => ({ ...f, team_owner: e.target.value }))}
                    className="input-dark flex-1"
                  />
                </div>
                <div className="pt-2">
                  <button
                    onClick={async () => {
                      if (editForm) {
                        await updateRepository(id, editForm);
                        getRepository(id).then((r) => setRepo(r.data));
                      }
                    }}
                    className="btn-primary text-sm"
                  >
                    Save Scan Config
                  </button>
                </div>
              </div>
            </div>

            {/* Authentication */}
            <div className="card">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Authentication</h3>
              <p className="text-sm text-slate-500 mb-3">Update credentials if the repository requires authentication.</p>
              <div className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-6">
                  <label className="sm:w-1/3 text-sm font-medium text-slate-400">Personal Access Token</label>
                  <input type="password" placeholder="ghp_... or glpat-..." className="input-dark flex-1" />
                </div>
                <div className="pt-2">
                  <button className="btn-secondary text-sm">Update Credentials</button>
                </div>
              </div>
            </div>

            {/* Webhook & PR Scans — Phase 1 Stage 3.
                Per-repo push/PR scan toggles + webhook last-event display.
                Backed by /repositories/{id}/scan-config PATCH and the
                last_webhook_event_* fields on the Repository model. */}
            <WebhookAndPRScansCard repo={repo} onChange={(updated) => setRepo(updated)} />

            {/* Branch Monitoring — Phase 2.
                Per-repo branch-pattern config (fnmatch globs).  Same
                /scan-config endpoint; payload field is branch_patterns. */}
            <BranchMonitoringCard repo={repo} onChange={(updated) => setRepo(updated)} />

            {/* Rule Overrides (per-repo card).
                Re-uses the admin Rule Overrides surface in `embedded`
                mode.  Shows muted scanner rules scoped to this repo +
                org-wide overrides that also apply to it, with a quick
                Add Override button that pre-selects this repo as the
                scope.  See components/secrets/RuleOverridesContent. */}
            <div className="card">
              {/* repositoryFilter is memoised on the parent to keep its
                  identity stable across scan-polling re-renders.  Without
                  the memo, every scan-poll tick caused the child to
                  refetch /rule-overrides + /rule-overrides/stats (the
                  "polling storm" identified in the Track-A live UX audit). */}
              <RuleOverridesContent
                repositoryFilter={ruleOverridesRepoFilter ?? undefined}
                embedded
              />
            </div>

            {/* Danger Zone */}
            <div className="card border-red-500/10">
              <h3 className="text-sm font-semibold text-red-400 uppercase tracking-wider mb-4">Danger Zone</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                  <div>
                    <p className="text-sm font-medium text-slate-200">Archive Repository</p>
                    <p className="text-xs text-slate-500">Hide from active list. Scan data preserved. Can be restored.</p>
                  </div>
                  <button
                    onClick={async () => {
                      await archiveRepository(id);
                    }}
                    className="px-4 py-2 text-sm font-medium text-yellow-400 border border-yellow-400/30 rounded-lg hover:bg-yellow-400/10 transition-all"
                  >
                    Archive
                  </button>
                </div>
                <div className="flex items-center justify-between p-4 rounded-lg bg-red-500/[0.03] border border-red-500/10">
                  <div>
                    <p className="text-sm font-medium text-slate-200">Delete Repository</p>
                    <p className="text-xs text-slate-500">Soft-delete. Findings preserved but repo hidden. Reversible by admin.</p>
                  </div>
                  <button
                    onClick={() => setShowDeleteConfirm(true)}
                    className="btn-danger text-sm"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>

            {/* Delete confirmation modal */}
            {showDeleteConfirm && (
              <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
                <div className="card border-red-500/20 max-w-md w-full mx-4" style={{ background: "rgba(14,18,40,0.7)" }}>
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0">
                      <svg className="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </div>
                    <h3 className="text-base font-semibold text-white">Delete &ldquo;{repo.name}&rdquo;?</h3>
                  </div>
                  <div className="bg-red-500/5 border border-red-500/10 rounded-lg p-3 mb-4">
                    <div className="flex items-start gap-2">
                      <svg className="w-4 h-4 text-red-400 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                      <div className="text-xs text-slate-400 leading-relaxed">
                        <p className="text-red-400 font-medium mb-1">This action is permanent and will delete all associated data:</p>
                        <ul className="space-y-0.5 text-slate-500">
                          <li>• All scan history and scan artifacts</li>
                          <li>• All findings, AI analysis, and classifications</li>
                          <li>• All remediation plans and patches</li>
                          <li>• All triage decisions and comments</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                  <div className="flex gap-3 justify-end">
                    <button
                      onClick={() => setShowDeleteConfirm(false)}
                      disabled={deletingRepo}
                      className="btn-secondary text-sm"
                    >Cancel</button>
                    <button
                      disabled={deletingRepo}
                      onClick={async () => {
                        if (deletingRepo) return;
                        setDeletingRepo(true);
                        try {
                          await deleteRepository(id);
                          window.location.href = "/repositories";
                        } catch (err: any) {
                          setDeletingRepo(false);
                          toast("error", "Delete Failed", err?.response?.data?.detail || err?.message || "Could not delete the project. Please retry.");
                        }
                      }}
                      className="btn-danger text-sm flex items-center gap-1.5"
                    >
                      {deletingRepo ? (
                        <>
                          <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                          Deleting…
                        </>
                      ) : (
                        <>
                          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                          Delete Project
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            )}

          </div>
        )}
      </div>

      {/* Delete Scan confirmation modal */}
      {deleteScanTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="card border-red-500/20 max-w-md w-full mx-4" style={{ background: "rgba(14,18,40,0.7)" }}>
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0">
                <svg className="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </div>
              <div>
                <h3 className="text-base font-semibold text-white">Delete scan?</h3>
                <p className="text-xs text-slate-500 mt-0.5">{new Date(deleteScanTarget.created_at).toLocaleString()} &middot; {deleteScanTarget.scan_type}</p>
              </div>
            </div>
            <div className="bg-red-500/5 border border-red-500/10 rounded-lg p-3 mb-4">
              <div className="flex items-start gap-2">
                <svg className="w-4 h-4 text-red-400 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                <div className="text-xs text-slate-400 leading-relaxed">
                  <p className="text-red-400 font-medium mb-1">This action is permanent and will delete all associated data:</p>
                  <ul className="space-y-0.5 text-slate-500">
                    <li>• All findings detected in this scan</li>
                    <li>• AI triage results and classifications</li>
                    <li>• Remediation plans and patches</li>
                    <li>• Scan artifacts and metrics</li>
                  </ul>
                </div>
              </div>
            </div>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setDeleteScanTarget(null)} className="btn-secondary text-sm">Cancel</button>
              <button
                onClick={confirmDeleteScan}
                className="btn-danger text-sm flex items-center gap-1.5"
              >
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
                Delete Scan
              </button>
            </div>
          </div>
        </div>
      )}

      {/* AI Not Configured Prompt — outside tab sections so it's always renderable */}
      {showAIPrompt && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="card border-yellow-500/20 max-w-md w-full mx-4">
            <div className="flex items-start gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-yellow-500/10 flex items-center justify-center shrink-0">
                <svg className="w-5 h-5 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div>
                <h3 className="text-base font-semibold text-white">AI Model Not Configured</h3>
                <p className="text-sm text-slate-400 mt-1">{aiStatusMsg || "No AI model configured. False positive analysis and auto-remediation will be skipped."}</p>
              </div>
            </div>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setShowAIPrompt(false)} className="btn-secondary text-sm">Cancel</button>
              <button
                onClick={() => startScan({ skipAI: true })}
                className="px-4 py-2 rounded-lg text-sm font-medium text-yellow-400 border border-yellow-400/30 hover:bg-yellow-400/10 transition-all"
              >
                Scan Without AI
              </button>
              <button
                onClick={() => { setShowAIPrompt(false); window.location.href = "/integrations?category=ai_models"; }}
                className="btn-primary text-sm"
              >
                Configure AI
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Live scan progress drawer — opens when the user clicks a
          running / analyzing / pending ScanJobCard.  Subscribes to
          /api/v1/ws/scan/{id} via useScanProgressWS; falls back to
          the 5s polling cadence already populating `scans` if WS
          fails (corporate proxies often block WS).  Track-A Rec #1.
          Stale-selection cleanup runs in a useEffect above, so by
          the time we get here `selectedScan` is either current or
          the drawer will be closed on the next render tick. */}
      {selectedScanId && scans.find((s) => s.id === selectedScanId) && (
        <ScanDetailDrawer
          scan={scans.find((s) => s.id === selectedScanId)!}
          liveUpdate={liveScanUpdate}
          wsConnected={wsConnected}
          wsReconnecting={wsReconnecting}
          wsGaveUp={wsGaveUp}
          onClose={() => setSelectedScanId(null)}
          onCancel={handleCancelScan}
        />
      )}
    </AppShell>
  );
}

export default function RepositoryDetailPage() {
  return (
    <Suspense fallback={<AppShell><div className="flex justify-center py-20"><div className="w-6 h-6 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div></AppShell>}>
      <RepositoryDetailPageInner />
    </Suspense>
  );
}
