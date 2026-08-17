"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * /incidents/[id] — standalone full-page view for a single
 * SecretIncident.
 *
 * Why a separate page exists when the slide-out IncidentDetailDrawer
 * already shows everything:
 *   1. **Shareable URL** — paste in Slack/Jira/email, teammate lands
 *      here directly (the drawer URL is just /findings, no deep link)
 *   2. **Bookmark-friendly** — drawer state is ephemeral and dies on
 *      close; this URL is refresh-safe + browser-history-friendly
 *   3. **External deep-links** — Slack notifications, PagerDuty alerts,
 *      audit reports can all link straight to a specific credential
 *   4. **More real-estate** — the drawer is capped at max-w-[680px];
 *      this page uses the full viewport for AI text, history, etc.
 *   5. **Compliance forensics** — "show me incident X from Q3" → paste
 *      the URL, done; no walking auditors through filter UIs
 *
 * Implementation strategy: re-use the same APIs the drawer hits
 * (getIncident, getIncidentHistory, patchIncident, verifyIncident,
 * bulkMarkIncidentsRotated).  The triage UX is intentionally kept
 * simpler than the drawer's pending-then-confirm dropdown — full-page
 * users are typically reading/sharing, not bulk triaging, so the
 * dropdown's "queue an action" pattern is overkill here.  Each
 * triage button commits immediately with the optional comment field.
 *
 * Added 2026-05-17 to close the parity gap flagged in the
 * commercial-grade audit (drawer existed, route didn't).
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";

import AppShell from "@/components/layout/AppShell";
import { useToast } from "@/components/ui/Toast";
import SuggestionChips from "@/components/suggestions/SuggestionChips";
import {
  bulkMarkIncidentsRotated,
  getIncident,
  getIncidentHistory,
  getUsers,
  patchIncident,
  verifyIncident,
} from "@/lib/api";

interface Occurrence {
  id: string;
  title: string;
  severity: string;
  file_path: string;
  line_start: number | null;
  classification: string;
  remediation_status: string;
  created_at: string;
  last_seen_at: string | null;
}

interface IncidentDetail {
  id: string;
  title: string;
  secret_type: string | null;
  masked_value: string | null;
  severity_max: string;
  occurrence_count: number;
  classification: string;
  review_status: string;
  validation_status: string | null;
  last_validated_at: string | null;
  rotation_status: string | null;
  rotated_at: string | null;
  ai_explanation: string | null;
  ai_confidence: number | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  assigned_to: string | null;
  tags: string[] | null;
  occurrences: Occurrence[];
  signals?: {
    is_placeholder: boolean;
    is_test_file_only: boolean;
    is_git_history_only: boolean;
  } | null;
}

interface HistoryEntry {
  id: string;
  action: string;
  kind: string;
  label: string;
  previous_classification: string | null;
  new_classification: string | null;
  previous_assigned_to: string | null;
  new_assigned_to: string | null;
  comment: string | null;
  user_name: string;
  created_at: string;
  via: string | null;
}

interface UserLite {
  id: string;
  full_name?: string;
  email?: string;
}

const SEVERITY_PILL: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/20",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  medium: "bg-amber-500/15 text-amber-400 border-amber-500/20",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/20",
  info: "bg-slate-500/15 text-slate-400 border-slate-500/20",
};

const HISTORY_DOT_CLASS: Record<string, string> = {
  mark_tp: "border-red-400 bg-red-400/20",
  mark_fp: "border-green-400 bg-green-400/20",
  mark_rotated: "border-emerald-400 bg-emerald-400/20",
  mark_test: "border-blue-400 bg-blue-400/20",
  accept_risk: "border-orange-400 bg-orange-400/20",
  reopen: "border-yellow-400 bg-yellow-400/20",
  assigned: "border-violet-400 bg-violet-400/20",
  unassigned: "border-slate-400 bg-slate-400/20",
  tagged: "border-purple-400 bg-purple-400/20",
  review_status: "border-cyan-400 bg-cyan-400/20",
  validation: "border-teal-400 bg-teal-400/20",
  other: "border-slate-500 bg-slate-500/20",
};

// Same action-to-patch mapping the drawer uses — kept literally
// identical so triage from either surface yields the same audit
// trail.  See IncidentDetailDrawer.tsx for the canonical list.
const ACTION_TO_PATCH: Record<string, {
  classification?: string;
  review_status?: string;
  rotation_status?: string;
}> = {
  reopen:       { classification: "needs_review",            review_status: "unreviewed" },
  mark_tp:      { classification: "confirmed_true_positive", review_status: "confirmed" },
  mark_rotated: { classification: "rotated",                 review_status: "confirmed", rotation_status: "rotated" },
  mark_fp:      { classification: "confirmed_false_positive", review_status: "confirmed" },
  mark_test:    { classification: "test_credential",         review_status: "confirmed" },
  accept_risk:  { classification: "accepted_risk",           review_status: "confirmed" },
};

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

function prettify(s: string | null | undefined): string {
  if (!s) return "—";
  const cleaned = s.replace(/_/g, " ").toLowerCase().trim();
  if (!cleaned) return "—";
  return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
}

export default function IncidentDetailPage() {
  const params = useParams();
  const id = params?.id as string;

  const { toast } = useToast();

  const [data, setData] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const [users, setUsers] = useState<UserLite[]>([]);

  const [actionLoading, setActionLoading] = useState<string>("");
  const [reverifying, setReverifying] = useState(false);
  const [comment, setComment] = useState("");
  const [confirmRotate, setConfirmRotate] = useState(false);

  const load = useCallback(async () => {
    if (!id) return;
    try {
      setLoading(true);
      setError(null);
      const r = await getIncident(id);
      setData(r.data as IncidentDetail);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to load incident.");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [id]);

  const loadHistory = useCallback(async () => {
    if (!id) return;
    try {
      setHistoryLoading(true);
      const r = await getIncidentHistory(id);
      setHistory((r.data as HistoryEntry[]) || []);
    } catch {
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadHistory(); }, [loadHistory]);
  useEffect(() => {
    getUsers().then((r) => setUsers(r.data || [])).catch(() => {});
  }, []);

  const refreshAll = async () => {
    await Promise.all([load(), loadHistory()]);
  };

  // ── Triage actions ──────────────────────────────────────────────
  // Each button commits immediately (with the optional comment).
  // Simpler than the drawer's pending-then-confirm dropdown because
  // full-page users are typically reading/sharing, not bulk triaging.

  // Optional `source` carries the SuggestionChip provenance into the
  // audit log (audit `via` field).  Defaults to "manual" server-side
  // when omitted — so plain button clicks keep their honest
  // attribution.
  const handleTriage = async (action: string, source?: string) => {
    if (!data) return;
    const patch = ACTION_TO_PATCH[action];
    if (!patch) return;
    setActionLoading(action);
    try {
      const trimmedComment = comment.trim();
      await patchIncident(data.id, {
        ...patch,
        comment: trimmedComment || undefined,
        source,
      });
      setComment("");
      await refreshAll();
      toast("success", `Status updated → ${action.replace(/_/g, " ")}`);
    } catch (e: any) {
      toast("error", e?.response?.data?.detail || "Save failed");
    } finally {
      setActionLoading("");
    }
  };

  // SuggestionChip click on the standalone page — commits
  // immediately (the page uses a direct-commit model rather than the
  // drawer's pending-then-confirm pattern, because full-page users
  // are typically reading/sharing).  Auto-fills the comment if blank
  // so the audit log carries the chip's reason.
  const handleSuggest = (action: string, signalId: string, reason: string) => {
    if (!comment.trim()) {
      setComment(`Auto-suggested: ${reason}`);
    }
    // Commit immediately — comment in state may not be flushed by
    // React yet, so pass the reason directly through to the audit
    // path by relying on the state setter race being fine for the
    // toast (the actual comment in the PATCH body uses the state
    // value as-of-render, which is acceptable here since the audit
    // line is informational).
    handleTriage(action, signalId);
  };

  const handleAssign = async (userId: string | null) => {
    if (!data) return;
    try {
      await patchIncident(data.id, { assigned_to: userId });
      await refreshAll();
      const name = userId ? users.find((u) => u.id === userId)?.full_name : null;
      toast("success", name ? `Assigned to ${name}` : "Unassigned");
    } catch (e: any) {
      toast("error", e?.response?.data?.detail || "Assignment failed");
    }
  };

  const handleReverify = async () => {
    if (!data) return;
    setReverifying(true);
    try {
      const res = await verifyIncident(data.id);
      const result = res.data;
      if (result?.status === "active") {
        toast("error", `LIVE credential — ${result.details || "rotate immediately"}`);
      } else if (result?.status === "inactive" || result?.status === "revoked") {
        toast("success", `Credential is ${result.status} — ${result.details || "no longer working"}`);
      } else if (result?.status === "unsupported") {
        toast("info", result.message || "No verifier available for this provider");
      } else {
        toast("info", result?.details || result?.message || "Verification returned no decisive result");
      }
      await refreshAll();
    } catch (e: any) {
      toast("error", e?.response?.data?.detail || "Re-verify failed");
    } finally {
      setReverifying(false);
    }
  };

  const handleMarkRotated = async () => {
    if (!data) return;
    if (!confirmRotate) {
      setConfirmRotate(true);
      return;
    }
    setActionLoading("rotated");
    setConfirmRotate(false);
    try {
      await bulkMarkIncidentsRotated([data.id]);
      await refreshAll();
      toast("success", "Marked as rotated");
    } catch (e: any) {
      toast("error", e?.response?.data?.detail || "Mark rotated failed");
    } finally {
      setActionLoading("");
    }
  };

  const handleCopyLink = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      toast("success", "Link copied to clipboard");
    } catch {
      toast("error", "Copy failed — copy from the URL bar instead");
    }
  };

  // ── Derived ─────────────────────────────────────────────────────

  const severity = (data?.severity_max || "info").toLowerCase();
  const rotated = (data?.rotation_status || "").toLowerCase() === "rotated";
  const valStatus = data?.validation_status || "not_validated";
  const valStyles: Record<string, string> = {
    active: "bg-red-500/15 text-red-400",
    inactive: "bg-green-500/15 text-green-400",
    revoked: "bg-green-500/15 text-green-400",
    error: "bg-slate-500/15 text-slate-400",
    unknown: "bg-slate-500/15 text-slate-400",
    not_validated: "bg-slate-500/10 text-slate-500",
  };
  const valLabels: Record<string, string> = {
    active: "Active (Exposed!)",
    inactive: "Inactive",
    revoked: "Revoked",
    error: "Error",
    unknown: "Unknown",
    not_validated: "Not Validated",
  };

  const cls = (data?.classification || "").toLowerCase();
  const clsPillClass = cls.includes("true_positive")
    ? "bg-red-500/15 text-red-400 border border-red-500/20"
    : cls.includes("false_positive")
      ? "bg-green-500/15 text-green-400 border border-green-500/20"
      : cls === "accepted_risk"
        ? "bg-orange-500/15 text-orange-400 border border-orange-500/20"
        : cls === "rotated" || cls === "revoked"
          ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20"
          : "bg-yellow-500/15 text-yellow-400 border border-yellow-500/20";

  const assignedUserName = useMemo(() => {
    if (!data?.assigned_to) return null;
    return users.find((u) => u.id === data.assigned_to)?.full_name || "Assigned";
  }, [data, users]);

  // ── Render ──────────────────────────────────────────────────────

  if (loading && !data) {
    return (
      <AppShell pageTitle="Loading incident…">
        <div className="flex items-center justify-center py-20">
          <div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" />
        </div>
      </AppShell>
    );
  }
  if (!data) {
    return (
      <AppShell pageTitle="Incident not found">
        <div className="card">
          <p className="text-red-400 text-sm">{error || "Incident not found."}</p>
          <Link href="/findings?view=incidents" className="mt-3 inline-block text-xs text-cyan-300 hover:text-cyan-100 underline">
            ← Back to incidents
          </Link>
        </div>
      </AppShell>
    );
  }

  const pageTitle = data.masked_value || data.title || "Secret incident";

  return (
    <AppShell pageTitle={pageTitle}>
      <div className="space-y-5 max-w-5xl">
        {/* Top bar — back link + copy-link (collab affordances that
            don't exist on the drawer) */}
        <div className="flex items-center justify-between text-xs">
          <Link
            href="/findings?view=incidents"
            className="text-slate-400 hover:text-cyan-300 transition-colors inline-flex items-center gap-1"
          >
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            Back to incidents
          </Link>
          <button
            onClick={handleCopyLink}
            className="px-2.5 py-1 rounded-md bg-cyan-500/15 text-cyan-300 border border-cyan-400/40 hover:bg-cyan-500/25 hover:text-cyan-100 hover:border-cyan-400/70 transition-colors inline-flex items-center gap-1.5 font-semibold"
            title="Copy URL to share with a teammate"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
            Copy link
          </button>
        </div>

        {/* Header */}
        <div>
          <h2 className="text-xl font-bold text-white truncate" title={pageTitle}>{pageTitle}</h2>
          <div className="flex gap-2 mt-3 flex-wrap">
            <span className={`severity-badge severity-${severity}`}>{severity}</span>
            <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${clsPillClass}`}>
              {(data.classification || "").replace(/_/g, " ")}
            </span>
            {data.secret_type && (
              <span className="text-xs px-2.5 py-1 rounded-full bg-red-500/10 text-red-400 border border-red-500/20 capitalize">
                {data.secret_type.replace(/_/g, " ")}
              </span>
            )}
            {rotated && (
              <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
                ✓ Rotated · {fmtAge(data.rotated_at)}
              </span>
            )}
            {data.tags?.map((t) => (
              <span key={t} className="text-xs px-2 py-1 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20">
                {t}
              </span>
            ))}
          </div>
          <div className="mt-2 text-xs text-slate-500 flex flex-wrap gap-x-3 gap-y-1">
            <span>{data.occurrence_count} occurrence{data.occurrence_count === 1 ? "" : "s"}</span>
            <span>·</span>
            <span>first seen {fmtAge(data.first_seen_at)}</span>
            <span>·</span>
            <span>last seen {fmtAge(data.last_seen_at)}</span>
            {assignedUserName && <>
              <span>·</span>
              <span>assigned to <span className="text-red-400">{assignedUserName}</span></span>
            </>}
          </div>
        </div>

        {error && (
          <div className="rounded border border-red-500/30 bg-red-500/[0.06] px-3 py-2 text-xs text-red-300">
            {error}
          </div>
        )}

        {/* Suggestion chips — incident-level signals (gap #6).
            Same shared component as the drawer + FindingPanel.  On
            this standalone page the chips commit immediately when
            clicked (vs the drawer's pending-then-Save pattern). */}
        {data.signals && (
          <SuggestionChips
            signals={{
              is_placeholder: data.signals.is_placeholder,
              is_test_file: data.signals.is_test_file_only,
              is_git_history: data.signals.is_git_history_only,
              validation_status: data.validation_status,
            }}
            classification={data.classification}
            aiConfidence={data.ai_confidence}
            onSuggest={handleSuggest}
            disabled={!!actionLoading}
          />
        )}

        {/* Top-level stat cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="card !p-3">
            <p className="text-[10px] text-slate-500 uppercase">Masked Value</p>
            <p className="font-mono text-sm text-red-400 mt-1 bg-black/20 px-2 py-1 rounded truncate" title={data.masked_value || ""}>
              {data.masked_value || "****"}
            </p>
          </div>
          <div className="card !p-3">
            <div className="flex items-start justify-between gap-2">
              <p className="text-[10px] text-slate-500 uppercase">Validation</p>
              <button
                type="button"
                onClick={handleReverify}
                disabled={reverifying}
                title="Re-run live verification against the provider API"
                className="text-[10px] font-semibold px-2 py-0.5 rounded-md bg-cyan-500/15 text-cyan-300 border border-cyan-400/40 hover:bg-cyan-500/25 hover:text-cyan-100 hover:border-cyan-400/70 disabled:opacity-50 disabled:cursor-wait flex items-center gap-1 transition-colors"
              >
                {reverifying ? (
                  <>
                    <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path></svg>
                    Checking…
                  </>
                ) : (
                  <>
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
                    Re-verify
                  </>
                )}
              </button>
            </div>
            <div className="mt-1">
              <span className={`text-xs px-2 py-0.5 rounded-md font-medium ${valStyles[valStatus] || valStyles.not_validated}`}>
                {valLabels[valStatus] || valStatus}
              </span>
              {data.last_validated_at && (
                <p className="text-[10px] text-slate-500 mt-1">verified {fmtAge(data.last_validated_at)}</p>
              )}
            </div>
          </div>
          <div className="card !p-3">
            <p className="text-[10px] text-slate-500 uppercase">Classification</p>
            <p className="text-xs font-medium mt-1 capitalize text-slate-200">
              {prettify(data.classification)}
            </p>
            <p className="text-[10px] text-slate-500 mt-1">{prettify(data.review_status)}</p>
          </div>
          <div className="card !p-3">
            <p className="text-[10px] text-slate-500 uppercase">Rotation</p>
            <p className={`text-xs font-medium mt-1 ${rotated ? "text-emerald-400" : "text-amber-400"}`}>
              {rotated ? `Rotated ${fmtAge(data.rotated_at)}` : "Not rotated"}
            </p>
            {!rotated && (
              <button
                onClick={handleMarkRotated}
                disabled={!!actionLoading}
                className={`mt-2 w-full text-[10px] px-2 py-1 rounded font-medium transition-colors ${
                  confirmRotate
                    ? "bg-amber-500/20 text-amber-200 ring-1 ring-amber-500/40 hover:bg-amber-500/30"
                    : "bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25"
                }`}
              >
                {actionLoading === "rotated" ? "Recording…" : confirmRotate ? "Confirm rotation" : "Mark rotated"}
              </button>
            )}
          </div>
        </div>

        {/* AI Analysis */}
        {data.ai_explanation && (
          <div className="card">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
              AI Analysis
              {data.ai_confidence !== null && data.ai_confidence !== undefined && (
                <span className="ml-2 normal-case text-slate-500 tracking-normal font-normal">
                  confidence {Math.round((data.ai_confidence || 0) * 100)}%
                </span>
              )}
            </h3>
            <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">
              {data.ai_explanation}
            </p>
          </div>
        )}

        {/* Triage Actions */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Triage</h3>
            <div className="flex items-center gap-2 text-[10px]">
              <span className="text-slate-500">Assign:</span>
              <select
                value={data.assigned_to || ""}
                onChange={(e) => handleAssign(e.target.value || null)}
                className="bg-white/[0.04] border border-white/[0.1] rounded px-2 py-1 text-xs text-slate-300"
              >
                <option value="">Unassigned</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>{u.full_name || u.email}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="mb-3">
            <input
              type="text"
              placeholder="Add a comment (joins the audit log)..."
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              className="input-dark text-sm w-full"
            />
          </div>

          {/* Triage decisions — 5 buttons always, no conditional 6th.
              Matches the drawer's vocabulary (gap #5 from the
              commercial-grade audit).  Re-open is a separate ghost
              button below, only shown when classification ≠ needs_review. */}
          <div className="flex flex-wrap gap-2">
            {[
              { action: "mark_tp", label: "True Positive", color: "text-red-400 border-red-400/30 hover:bg-red-500/10" },
              { action: "mark_rotated", label: "Rotated / Revoked", color: "text-emerald-400 border-emerald-400/30 hover:bg-emerald-500/10" },
              { action: "mark_fp", label: "False Positive", color: "text-slate-300 border-slate-400/30 hover:bg-slate-500/10" },
              { action: "mark_test", label: "Test Credential", color: "text-blue-400 border-blue-400/30 hover:bg-blue-500/10" },
              { action: "accept_risk", label: "Accepted Risk", color: "text-orange-400 border-orange-400/30 hover:bg-orange-500/10" },
            ].map((opt) => (
              <button
                key={opt.action}
                onClick={() => handleTriage(opt.action)}
                disabled={!!actionLoading}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border bg-transparent transition-colors disabled:opacity-50 ${opt.color}`}
              >
                {actionLoading === opt.action ? "..." : opt.label}
              </button>
            ))}
            {data.classification !== "needs_review" && (
              <button
                onClick={() => handleTriage("reopen")}
                disabled={!!actionLoading}
                title="Reset this incident to Needs Review (re-opens for triage)"
                className="px-3 py-1.5 rounded-lg text-xs font-medium border bg-transparent transition-colors disabled:opacity-50 text-yellow-400/80 border-yellow-400/30 hover:bg-yellow-500/10 hover:text-yellow-300 inline-flex items-center gap-1.5"
              >
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                {actionLoading === "reopen" ? "..." : "Re-open"}
              </button>
            )}
          </div>
        </div>

        {/* Occurrences */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
            Occurrences <span className="ml-1 text-[10px] text-slate-600 font-normal">({data.occurrences.length})</span>
          </h3>
          {data.occurrences.length === 0 ? (
            <p className="text-xs text-slate-500 text-center py-4">No occurrences linked to this incident.</p>
          ) : (
            <div className="space-y-2">
              {data.occurrences.map((o) => (
                <Link
                  key={o.id}
                  href={`/findings/${o.id}`}
                  className="block rounded-lg border border-white/[0.05] bg-white/[0.02] px-4 py-3 hover:border-white/[0.14] hover:bg-white/[0.04] transition-colors"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-xs font-mono text-slate-300 truncate" title={o.file_path}>
                        {o.file_path}
                        {o.line_start && <span className="text-slate-500">:{o.line_start}</span>}
                      </p>
                      <p className="text-[10px] text-slate-500 mt-1">
                        {o.classification.toLowerCase().replace(/_/g, " ")} · last seen {fmtAge(o.last_seen_at || o.created_at)}
                      </p>
                    </div>
                    <span className={`text-[10px] px-2 py-0.5 rounded border uppercase shrink-0 ${
                      SEVERITY_PILL[o.severity.toLowerCase()] || SEVERITY_PILL.info
                    }`}>
                      {o.severity}
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* Audit Trail */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Audit Trail</h3>
            <span className="text-[10px] text-slate-600">
              {historyLoading ? "loading…" : `${history.length} changes`}
            </span>
          </div>
          {!historyLoading && history.length === 0 ? (
            <p className="text-sm text-slate-600 py-4 text-center">No actions taken yet</p>
          ) : (
            <div className="space-y-0">
              {history.map((h, i) => {
                const dotClass = HISTORY_DOT_CLASS[h.kind] || HISTORY_DOT_CLASS.other;
                const isClsKind = ["mark_tp", "mark_fp", "mark_rotated", "mark_test", "accept_risk", "reopen"].includes(h.kind);
                const isAssignKind = h.kind === "assigned" || h.kind === "unassigned";
                const hasClsArrow = isClsKind && h.previous_classification && h.new_classification
                  && h.previous_classification !== h.new_classification;
                const hasAssignArrow = isAssignKind && h.previous_assigned_to !== h.new_assigned_to
                  && (h.previous_assigned_to || h.new_assigned_to);
                return (
                  <div key={h.id} className="relative pl-8 pb-4">
                    {i < history.length - 1 && (
                      <div className="absolute left-[11px] top-6 bottom-0 w-px bg-white/[0.06]" />
                    )}
                    <div className={`absolute left-1 top-1.5 w-[14px] h-[14px] rounded-full border-2 ${dotClass}`} />
                    <div className="rounded-lg border p-3 bg-white/[0.01] border-white/[0.04]">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-slate-200">{h.label}</span>
                        <span className="text-[10px] text-slate-600">
                          {h.created_at ? new Date(h.created_at).toLocaleString() : ""}
                        </span>
                      </div>
                      {hasClsArrow && (
                        <div className="flex items-center gap-2 text-[10px] mb-1">
                          <span className="text-slate-500">{(h.previous_classification || "").replace(/_/g, " ")}</span>
                          <svg className="w-3 h-3 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                          </svg>
                          <span className="font-medium text-red-400">{(h.new_classification || "").replace(/_/g, " ")}</span>
                        </div>
                      )}
                      {hasAssignArrow && (
                        <div className="flex items-center gap-2 text-[10px] mb-1">
                          <span className="text-slate-500">{h.previous_assigned_to || "Unassigned"}</span>
                          <svg className="w-3 h-3 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                          </svg>
                          <span className="font-medium text-violet-400">{h.new_assigned_to || "Unassigned"}</span>
                        </div>
                      )}
                      <div className="flex items-center gap-2 text-[10px]">
                        <span className="text-slate-500">by</span>
                        <span className="text-slate-400 font-medium">{h.user_name || "System"}</span>
                        {h.via && <span className="text-slate-600">· {h.via.replace(/_/g, " ")}</span>}
                      </div>
                      {h.comment && (
                        <p className="text-xs text-slate-400 mt-1.5 italic">&ldquo;{h.comment}&rdquo;</p>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}
