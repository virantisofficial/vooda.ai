"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * IncidentDetailDrawer — Findings-drawer twin for SecretIncident rows.
 *
 * v3 (2026-05-17): Brought to **literal sibling parity** with
 * FindingPanel after multiple half-shipped iterations.  Every element
 * present on FindingPanel that has a sensible incident analogue is
 * mounted here in the same layout slot:
 *
 *   Header
 *     • Title
 *     • Severity badge · classification pill · secret-type pill · rotated pill
 *     • Close button (no "Open full page" — no standalone /incidents/[id] page exists)
 *   Meta bar
 *     • Document icon · secret_type · N occurrences · first seen X ago
 *     • Assignee dropdown (patchIncident { assigned_to })
 *     • Tag editor (patchIncident { tags })
 *   Section tabs: Overview / Occurrences / Rotation
 *   Content (scrollable):
 *     • Overview: stat grid + AI explanation
 *     • Occurrences: linked finding rows
 *     • Rotation: status panel + Mark rotated CTA
 *   Action bar (sticky bottom)
 *     • Comment textarea
 *     • Status dropdown (pending-then-confirm) + Save + Close
 *
 * Status dropdown matches FindingPanel's pattern exactly:
 *   - Single trigger button shows current OR pending classification
 *     with amber dashed border + animated dot when a change is queued
 *   - Menu lists 6 actions: Needs Review, True Positive,
 *     Rotated / Revoked, False Positive, Test Credential, Accepted Risk
 *   - Picking an option queues a pendingAction; clicking it again
 *     discards.  Save commits pendingAction + comment in one PATCH.
 *
 * The intent is that the user should not be able to tell the two
 * drawers apart at a glance — only the meta-bar facts differ (file
 * path → secret-type/occurrence-count) and the section content.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";

import {
  bulkMarkIncidentsRotated,
  getIncident,
  getIncidentHistory,
  getUsers,
  patchIncident,
  verifyIncident,
} from "@/lib/api";
import { useToast } from "@/components/ui/Toast";
import SuggestionChips from "@/components/suggestions/SuggestionChips";

interface IncidentLite {
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
  // Derived scanner signals — populated by the backend on GET
  // /incidents/{id}.  Drives the SuggestionChips component.  All
  // three are "ALL occurrences agree" aggregations (see
  // apps/api/app/routers/incidents.py IncidentSignals docstring).
  signals?: {
    is_placeholder: boolean;
    is_test_file_only: boolean;
    is_git_history_only: boolean;
  } | null;
}

interface Occurrence {
  id: string;
  title: string;
  severity: string;
  file_path: string;
  line_start: number | null;
  scan_source_id: string | null;
  repository_id: string | null;
  classification: string;
  remediation_status: string;
  created_at: string;
  last_seen_at: string | null;
}

interface UserLite {
  id: string;
  full_name?: string;
  email?: string;
}

interface Props {
  incidentId: string | null;
  onClose: () => void;
  onMutate?: () => void;
}

type TabKey = "overview" | "occurrences" | "rotation" | "history";

interface HistoryEntry {
  id: string;
  action: string;
  kind: string;
  label: string;
  previous_classification: string | null;
  new_classification: string | null;
  previous_review_status: string | null;
  new_review_status: string | null;
  previous_rotation_status: string | null;
  new_rotation_status: string | null;
  previous_assigned_to: string | null;
  new_assigned_to: string | null;
  comment: string | null;
  user_id: string | null;
  user_name: string;
  created_at: string;
  detail: string | null;
  via: string | null;
}

// Maps each history entry's `kind` to a dot colour + border colour.
// Same palette FindingPanel uses for its decisions timeline.
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

const SEVERITY_PILL: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/20",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  medium: "bg-amber-500/15 text-amber-400 border-amber-500/20",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/20",
  info: "bg-slate-500/15 text-slate-400 border-slate-500/20",
};

// ── Triage action ⇆ classification/review_status mapping ─────────
//
// Mirrors FindingPanel exactly (the same 6 actions in the same order)
// so the status dropdown options match across drawers.  The shape is
// `action → { classification, review_status }` because the incidents
// API accepts those two fields directly (FindingPanel posts an action
// keyword instead, but the server-side effect is identical).
//
// Keep IN SYNC with the menu options below + the human-label map.
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

const HUMAN_LABEL: Record<string, string> = {
  reopen: "Needs Review",
  mark_tp: "True Positive",
  mark_rotated: "Rotated / Revoked",
  mark_fp: "False Positive",
  mark_test: "Test Credential",
  accept_risk: "Accepted Risk",
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

export function IncidentDetailDrawer({ incidentId, onClose, onMutate }: Props) {
  const [data, setData] = useState<(IncidentLite & { occurrences: Occurrence[] }) | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [rotating, setRotating] = useState(false);
  // Two-step "Mark as rotated" confirm — see handleMarkRotated for
  // why this replaces window.confirm().
  const [confirmRotate, setConfirmRotate] = useState(false);
  // Manual re-verify state — mirrors FindingPanel's pattern.  See
  // handleReverify below.
  const [reverifying, setReverifying] = useState(false);
  const { toast } = useToast();
  const [error, setError] = useState<string | null>(null);

  // ── Pending-then-confirm triage flow (FindingPanel parity) ─────
  // Same as Findings: dropdown click QUEUES a pending action; Save
  // commits it (+ optional comment) in a single PATCH.  No silent
  // writes on dropdown click.
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  // Tracks which signal (if any) sourced the pending action — set by
  // SuggestionChips clicks, cleared by manual dropdown picks.
  // Threaded into patchIncident's `source` field on Save so the
  // audit metadata records signal provenance.
  const [pendingSource, setPendingSource] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const [saving, setSaving] = useState(false);
  const [statusDropdownOpen, setStatusDropdownOpen] = useState(false);

  // Assignee
  const [users, setUsers] = useState<UserLite[]>([]);
  const [assignDropdownOpen, setAssignDropdownOpen] = useState(false);

  // Tag editor
  const [tagInput, setTagInput] = useState("");
  const [showTagInput, setShowTagInput] = useState(false);

  // History tab — lazily fetched the first time the tab is opened
  // and re-fetched after any triage save so the timeline is always
  // current.  Keeping it lazy keeps the initial drawer-open payload
  // small (one round trip for the incident + occurrences).
  const [history, setHistory] = useState<HistoryEntry[] | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  const open = incidentId !== null;

  // Esc closes the drawer (matches FindingPanel).
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);

  // Discard any pending change when switching to a different incident
  // — stale pendingAction from incident A must not silently apply to
  // incident B on the next Save click.  Same defensive reset as
  // FindingPanel on finding.id change.
  useEffect(() => {
    if (incidentId) {
      setActiveTab("overview");
      setPendingAction(null);
      setPendingSource(null);
      setComment("");
      setStatusDropdownOpen(false);
      setAssignDropdownOpen(false);
      setShowTagInput(false);
      setTagInput("");
      setConfirmRotate(false);
      setHistory(null);
      setHistoryError(null);
      setError(null);
    }
  }, [incidentId]);

  // Load users for the assignee dropdown.  One-time on mount.
  useEffect(() => {
    getUsers().then((r) => setUsers(r.data || [])).catch(() => {});
  }, []);

  const load = useCallback(async () => {
    if (!incidentId) return;
    try {
      setLoading(true);
      setError(null);
      const r = await getIncident(incidentId);
      setData(r.data as any);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to load incident.");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => {
    if (open) load();
  }, [open, load]);

  // History fetcher.  Called on first visit to the History tab and
  // after every save (so the timeline grows in lockstep with the
  // user's actions, no manual refresh required).  Failure surfaces
  // an inline error in the tab instead of the top-level error bar —
  // history failures shouldn't block the rest of the drawer.
  const loadHistory = useCallback(async () => {
    if (!incidentId) return;
    try {
      setHistoryLoading(true);
      setHistoryError(null);
      const r = await getIncidentHistory(incidentId);
      setHistory((r.data as HistoryEntry[]) || []);
    } catch (e: any) {
      setHistoryError(e?.response?.data?.detail || "Failed to load history.");
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  }, [incidentId]);

  // Lazy load on first visit to the History tab.  We don't pre-fetch
  // because most drawer opens never reach the History tab; saving the
  // round trip keeps the hot path snappy.
  useEffect(() => {
    if (open && activeTab === "history" && history === null && !historyLoading) {
      loadHistory();
    }
  }, [open, activeTab, history, historyLoading, loadHistory]);

  // Manual re-verify — kicks the per-provider verifier against the
  // live API for THIS credential (via the most-recently-seen
  // occurrence's source_metadata, since the credential is identical
  // across occurrences).  Mirrors FindingPanel's handleReverify
  // exactly, including the toast tone choice:
  //   active   → red/error toast ("LIVE — rotate immediately")
  //   inactive → green/success toast
  //   revoked  → green/success toast
  //   unsupported → info toast
  // Reloads the incident afterwards so the Validation Status pill +
  // History timeline reflect the new result immediately.
  const handleReverify = async () => {
    if (!data) return;
    setReverifying(true);
    try {
      const res = await verifyIncident(data.id);
      const result = res.data;
      if (result?.status === "active") {
        toast("error", `LIVE credential confirmed — ${result.details || "rotate immediately"}`);
      } else if (result?.status === "inactive" || result?.status === "revoked") {
        toast("success", `Credential is ${result.status} — ${result.details || "no longer working"}`);
      } else if (result?.status === "unsupported") {
        toast("info", result.message || "No verifier available for this provider");
      } else {
        toast("info", result?.details || result?.message || "Verification returned no decisive result");
      }
      await load();
      onMutate?.();
      // Invalidate the cached history so the next visit re-fetches —
      // verify writes an audit entry that should show up immediately.
      if (activeTab === "history") {
        loadHistory();
      } else {
        setHistory(null);
      }
    } catch (e: any) {
      toast("error", e?.response?.data?.detail || e?.message || "Re-verify failed");
    } finally {
      setReverifying(false);
    }
  };

  // Inline two-step confirmation for Mark as rotated.  Avoids native
  // window.confirm() which (a) freezes the browser, (b) blocks
  // automation / E2E tests, and (c) is unstyled so it breaks the
  // Findings-drawer visual parity.  First click flips
  // `confirmRotate=true`, swapping the CTA to an amber "Confirm
  // rotation" + a cancel button; second click actually commits.
  const handleMarkRotated = async () => {
    if (!data) return;
    if (!confirmRotate) {
      setConfirmRotate(true);
      return;
    }
    try {
      setRotating(true);
      setConfirmRotate(false);
      await bulkMarkIncidentsRotated([data.id]);
      await load();
      onMutate?.();
      // Invalidate the cached history so the next visit re-fetches —
      // or re-fetch immediately if the user is already on the tab.
      if (activeTab === "history") {
        loadHistory();
      } else {
        setHistory(null);
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to mark as rotated.");
    } finally {
      setRotating(false);
    }
  };

  // Dropdown click queues a pending status change.  Picking the SAME
  // action twice clears the queue (acts as a discard).  Picking a
  // DIFFERENT action replaces the queued one.  Nothing hits the API
  // until Save.  FindingPanel parity.
  const handleSelectStatus = (action: string) => {
    setPendingAction((prev) => (prev === action ? null : action));
    // Manual pick — clear chip-source attribution so the audit log
    // doesn't lie about provenance.
    setPendingSource(null);
    setStatusDropdownOpen(false);
  };

  // SuggestionChip click — same pending-then-Save pattern as the
  // dropdown but additionally records the signal id (audit `via`)
  // and pre-fills the comment with the chip's reason.  Keeps the
  // human in the loop: nothing commits until Save.
  const handleSuggest = (action: string, signalId: string, reason: string) => {
    setPendingAction(action);
    setPendingSource(signalId);
    if (!comment.trim()) {
      setComment(`Auto-suggested: ${reason}`);
    }
  };

  // Single Save handler — commits whichever combination is pending:
  //   - pendingAction + comment   → patch with both
  //   - pendingAction only        → patch with comment undefined
  //   - comment only              → patch with comment only (audit log)
  // No-op if neither is set (button is disabled in that case anyway).
  const handleSave = async () => {
    const trimmedComment = comment.trim();
    if (!pendingAction && !trimmedComment) return;
    if (!data) return;
    try {
      setSaving(true);
      const body: Parameters<typeof patchIncident>[1] = {};
      if (pendingAction) {
        Object.assign(body, ACTION_TO_PATCH[pendingAction] || {});
      }
      if (trimmedComment) body.comment = trimmedComment;
      if (pendingSource) body.source = pendingSource;
      // Optimistic-lock token: server rejects with 409 if another
      // reviewer beat us to the row.  See main.py's StaleDataError
      // handler.  We re-load on the catch path so the user sees the
      // live state and can re-decide.
      body.expected_version = (data as any).version;
      await patchIncident(data.id, body);
      await load();
      onMutate?.();
      // Invalidate the cached history so the next visit re-fetches —
      // or re-fetch immediately if the user is already on the tab.
      if (activeTab === "history") {
        loadHistory();
      } else {
        setHistory(null);
      }
      setPendingAction(null);
      setPendingSource(null);
      setComment("");
    } catch (e: any) {
      if (e?.response?.status === 409) {
        setError("This incident was modified by another reviewer. Reloaded — please review and try again.");
        // Refresh state so the user sees what landed.
        await load();
        onMutate?.();
      } else {
        setError(e?.response?.data?.detail || "Save failed.");
      }
    } finally {
      setSaving(false);
    }
  };

  const handleClose = () => {
    setPendingAction(null);
    setPendingSource(null);
    setComment("");
    onClose();
  };

  const handleAssign = async (userId: string | null) => {
    setAssignDropdownOpen(false);
    if (!data) return;
    try {
      await patchIncident(data.id, { assigned_to: userId });
      await load();
      onMutate?.();
      // Invalidate the cached history so the next visit re-fetches —
      // or re-fetch immediately if the user is already on the tab.
      if (activeTab === "history") {
        loadHistory();
      } else {
        setHistory(null);
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Assignment failed.");
    }
  };

  const handleAddTag = async (tag: string) => {
    const t = tag.trim().toLowerCase();
    if (!t || !data) return;
    const newTags = Array.from(new Set([...(data.tags || []), t]));
    try {
      await patchIncident(data.id, { tags: newTags });
      setTagInput("");
      setShowTagInput(false);
      await load();
      onMutate?.();
      // Invalidate the cached history so the next visit re-fetches —
      // or re-fetch immediately if the user is already on the tab.
      if (activeTab === "history") {
        loadHistory();
      } else {
        setHistory(null);
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to add tag.");
    }
  };

  const handleRemoveTag = async (tag: string) => {
    if (!data) return;
    const newTags = (data.tags || []).filter((t) => t !== tag);
    try {
      await patchIncident(data.id, { tags: newTags });
      await load();
      onMutate?.();
      // Invalidate the cached history so the next visit re-fetches —
      // or re-fetch immediately if the user is already on the tab.
      if (activeTab === "history") {
        loadHistory();
      } else {
        setHistory(null);
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to remove tag.");
    }
  };

  // Subtitle / meta bar text built once.
  const metaParts = useMemo(() => {
    if (!data) return [];
    const parts: string[] = [];
    if (data.secret_type) parts.push(data.secret_type);
    parts.push(`${data.occurrence_count} occurrence${data.occurrence_count === 1 ? "" : "s"}`);
    parts.push(`first seen ${fmtAge(data.first_seen_at)}`);
    return parts;
  }, [data]);

  if (!open) return null;

  // Sections (matches FindingPanel's tab pattern + count badges).
  // History count is only shown once the tab has been visited (i.e.
  // history is loaded) — avoids an extra API round trip on every
  // drawer open just to populate a small badge.
  const sections = [
    { key: "overview" as const, label: "Overview" },
    { key: "occurrences" as const, label: "Occurrences", count: data?.occurrences.length },
    { key: "rotation" as const, label: "Rotation" },
    { key: "history" as const, label: "History", count: history?.length },
  ];

  const severity = (data?.severity_max || "info").toLowerCase();
  const rotated = (data?.rotation_status || "").toLowerCase() === "rotated";

  // Classification pill colour mirrors FindingPanel.
  const cls = (data?.classification || "").toLowerCase();
  const clsPillClass = cls.includes("true_positive")
    ? "bg-red-500/15 text-red-400 border border-red-500/20"
    : cls.includes("false_positive")
      ? "bg-green-500/15 text-green-400 border border-green-500/20"
      : cls === "accepted_risk"
        ? "bg-orange-500/15 text-orange-400 border border-orange-500/20"
        : "bg-yellow-500/15 text-yellow-400 border border-yellow-500/20";
  const clsDotClass = cls.includes("true_positive")
    ? "bg-red-400"
    : cls.includes("false_positive")
      ? "bg-green-400"
      : cls === "accepted_risk"
        ? "bg-orange-400"
        : "bg-yellow-400";

  // ── Status dropdown trigger styling ──────────────────────────────
  // The effective classification shown on the trigger button is the
  // pending one if a change is queued, otherwise the saved value.
  // This keeps the user oriented while still revertible.
  const effectiveCls = pendingAction
    ? (ACTION_TO_PATCH[pendingAction]?.classification || data?.classification || "needs_review")
    : (data?.classification || "needs_review");

  const triggerBg =
    effectiveCls.includes("true_positive") ? "bg-red-500/10 text-red-400 border-red-500/20" :
    effectiveCls === "rotated" || effectiveCls === "revoked" || effectiveCls === "resolved" ? "bg-green-500/10 text-green-400 border-green-500/20" :
    effectiveCls.includes("false_positive") ? "bg-slate-500/10 text-slate-400 border-slate-500/20" :
    effectiveCls === "test_credential" ? "bg-blue-500/10 text-blue-400 border-blue-500/20" :
    effectiveCls === "accepted_risk" ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
    "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
  const triggerDot =
    effectiveCls.includes("true_positive") ? "bg-red-400" :
    effectiveCls === "rotated" || effectiveCls === "revoked" || effectiveCls === "resolved" ? "bg-green-400" :
    effectiveCls.includes("false_positive") ? "bg-slate-400" :
    effectiveCls === "test_credential" ? "bg-blue-400" :
    effectiveCls === "accepted_risk" ? "bg-orange-400" :
    "bg-yellow-400";
  const triggerLabel =
    effectiveCls === "needs_review" ? "Needs Review"
    : effectiveCls === "likely_true_positive" ? "True Positive"
    : effectiveCls === "confirmed_true_positive" ? "True Positive"
    : effectiveCls === "likely_false_positive" ? "False Positive"
    : effectiveCls === "confirmed_false_positive" ? "False Positive"
    : (effectiveCls === "rotated" || effectiveCls === "revoked" || effectiveCls === "resolved") ? "Rotated / Revoked"
    : effectiveCls === "test_credential" ? "Test Credential"
    : effectiveCls === "accepted_risk" ? "Accepted Risk"
    : effectiveCls?.replace(/_/g, " ");

  const pendingHint = pendingAction
    ? "border-amber-500/60 ring-1 ring-amber-500/30 [border-style:dashed]"
    : "";

  const assignedUserName = data?.assigned_to
    ? (users.find((u) => u.id === data.assigned_to)?.full_name || "Assigned")
    : null;

  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true">
      {/* Backdrop — click closes (matches FindingPanel) */}
      <div className="absolute inset-0 bg-black/40 backdrop-blur-[2px]" onClick={onClose} />

      {/* Panel — same chrome contract as FindingPanel */}
      <div
        className="relative w-full max-w-[680px] border-l border-white/[0.08] h-full flex flex-col shadow-2xl animate-slide-in"
        style={{ background: "rgba(8,11,28,0.95)" }}
      >
        {/* Header */}
        <div className="px-5 py-4 border-b border-white/[0.06] shrink-0">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <h3 className="text-base font-semibold text-white leading-snug truncate" title={data?.masked_value || data?.title || ""}>
                {data?.masked_value || data?.title || (loading ? "Loading…" : "Incident")}
              </h3>
              <div className="flex gap-2 mt-2 flex-wrap">
                <span className={`severity-badge severity-${severity}`}>{severity}</span>
                {data && (
                  <span className={`inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full ${clsPillClass}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${clsDotClass}`} />
                    {(data.classification || "").replace(/_/g, " ")}
                  </span>
                )}
                {data?.secret_type && (
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/20 capitalize">
                    {data.secret_type.replace(/_/g, " ")}
                  </span>
                )}
                {rotated && (
                  <span className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    Rotated · {fmtAge(data?.rotated_at)}
                  </span>
                )}
              </div>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              {/* Open in full page — gives users a shareable
                  /incidents/{id} URL they can paste into Slack / Jira
                  / email.  Higher contrast (cyan + label) than
                  FindingPanel's original slate-on-slate icon, which
                  was so faint nobody noticed it existed.  Audit on
                  2026-05-17 — see /incidents/[id]/page.tsx. */}
              {data && (
                <Link
                  href={`/incidents/${data.id}`}
                  className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-1 rounded-md bg-cyan-500/15 text-cyan-300 border border-cyan-400/40 hover:bg-cyan-500/25 hover:text-cyan-100 hover:border-cyan-400/70 transition-colors"
                  title="Open this incident in a full page (shareable URL)"
                >
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                  Open page
                </Link>
              )}
              <button
                onClick={onClose}
                className="p-1.5 rounded-lg hover:bg-white/[0.06] transition-colors"
                title="Close (Esc)"
              >
                <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>

          {/* Meta bar — replaces FindingPanel's file-path bar with
              incident-appropriate facts.  Same visual rhythm: small
              document icon, vertical-bar separators, assignee dropdown
              and tag editor occupy the same slots as in Findings. */}
          {data && (
            <div className="mt-3 flex items-center gap-2 text-xs flex-wrap">
              <svg className="w-3.5 h-3.5 text-slate-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              {metaParts.map((p, i) => (
                <span key={i} className="flex items-center gap-2 text-slate-400">
                  {i > 0 && <span className="text-slate-700">|</span>}
                  <span>{p}</span>
                </span>
              ))}

              <span className="text-slate-700">|</span>

              {/* Assignee */}
              <div className="relative">
                <button
                  onClick={() => setAssignDropdownOpen(!assignDropdownOpen)}
                  className="flex items-center gap-1 px-2 py-0.5 rounded-md hover:bg-white/[0.06] transition-colors text-slate-400"
                >
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                  </svg>
                  {assignedUserName ? (
                    <span className="text-red-400">{assignedUserName}</span>
                  ) : (
                    <span className="text-slate-600">Assign</span>
                  )}
                  <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {assignDropdownOpen && (
                  <>
                    <div className="fixed inset-0 z-10" onClick={() => setAssignDropdownOpen(false)} />
                    <div
                      className="absolute left-0 top-full mt-1 z-20 w-52 py-1 rounded-lg border border-white/[0.1] shadow-xl max-h-48 overflow-y-auto"
                      style={{ background: "rgba(8,11,28,0.95)" }}
                    >
                      <button
                        onClick={() => handleAssign(null)}
                        className="w-full text-left px-3 py-2 text-xs text-slate-400 hover:bg-white/[0.04]"
                      >
                        <span className="flex items-center gap-2">
                          <svg className="w-3.5 h-3.5 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                          </svg>
                          Unassign
                        </span>
                      </button>
                      {users.map((u) => (
                        <button
                          key={u.id}
                          onClick={() => handleAssign(u.id)}
                          className={`w-full text-left px-3 py-2 text-xs hover:bg-white/[0.04] flex items-center gap-2 ${u.id === data.assigned_to ? "text-red-400" : "text-slate-300"}`}
                        >
                          <div className="w-5 h-5 rounded-full bg-gradient-to-br from-red-500/30 to-orange-500/30 flex items-center justify-center text-[8px] font-bold text-red-400 shrink-0">
                            {(u.full_name || "?").split(" ").map((n) => n[0]).join("").toUpperCase().slice(0, 2)}
                          </div>
                          {u.full_name || u.email}
                          {u.id === data.assigned_to && (
                            <svg className="w-3 h-3 ml-auto text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                            </svg>
                          )}
                        </button>
                      ))}
                    </div>
                  </>
                )}
              </div>

              <span className="text-slate-700">|</span>

              {/* Tags */}
              <div className="flex items-center gap-1 flex-wrap">
                {(data.tags || []).map((tag) => (
                  <span key={tag} className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 text-[9px] border border-purple-500/20">
                    {tag}
                    <button onClick={() => handleRemoveTag(tag)} className="ml-0.5 hover:text-white transition-colors">
                      <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </span>
                ))}
                {showTagInput ? (
                  <input
                    type="text"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") handleAddTag(tagInput);
                      if (e.key === "Escape") { setShowTagInput(false); setTagInput(""); }
                      e.stopPropagation();
                    }}
                    onClick={(e) => e.stopPropagation()}
                    onBlur={() => { if (tagInput) handleAddTag(tagInput); else setShowTagInput(false); }}
                    placeholder="tag name"
                    autoFocus
                    className="w-20 px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.1] text-[9px] text-slate-300 outline-none focus:border-purple-400/40"
                  />
                ) : (
                  <button
                    onClick={() => setShowTagInput(true)}
                    className="text-[9px] text-slate-600 hover:text-purple-400 transition-colors px-1"
                  >
                    + tag
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Suggestion chips — incident-level, derived from
              ALL-occurrences-agree aggregation server-side
              (data.signals).  Same display rules as FindingPanel:
              chip only renders when AI hasn't run, agrees, or is
              low-confidence.  See components/suggestions/
              SuggestionChips.tsx for full logic. */}
          {data?.signals && (
            <div className="mt-3">
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
                disabled={saving}
              />
            </div>
          )}
        </div>

        {/* Section tabs — identical pattern to FindingPanel */}
        <div className="px-5 border-b border-white/[0.06] shrink-0">
          <div className="flex gap-0.5 -mb-px">
            {sections.map((s) => (
              <button
                key={s.key}
                onClick={() => setActiveTab(s.key)}
                className={`px-3 py-2.5 text-xs font-medium border-b-2 transition-colors ${
                  activeTab === s.key
                    ? "border-red-400 text-red-400"
                    : "border-transparent text-slate-500 hover:text-slate-300"
                }`}
              >
                {s.label}
                {"count" in s && s.count != null && s.count > 0 && (
                  <span className="ml-1 text-[9px] text-slate-600">({s.count})</span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Content — scrollable */}
        <div className="flex-1 overflow-y-auto px-5 py-4">
          {error && (
            <div className="mb-4 rounded border border-red-500/30 bg-red-500/[0.06] px-3 py-2 text-xs text-red-300">
              {error}
            </div>
          )}

          {loading && !data ? (
            <p className="text-xs text-slate-500 text-center py-12">Loading incident…</p>
          ) : !data ? (
            <p className="text-xs text-slate-500 text-center py-12">Incident not found.</p>
          ) : (
            <>
              {/* ── Overview ────────────────────────────────────── */}
              {/* Mirrors FindingPanel's Overview layout 1:1:
                    1. Provider-icon header (colored tile + secret type
                       + one-line description)
                    2. Masked Value card + Validation Status card
                       (grid-cols-2)
                    3. Classification + Review Status + Confidence
                       (grid-cols-3)
                    4. Rotation status card (full-width)
                    5. AI Analysis box (violet, when ai_explanation)
                  Differences vs Findings are data-driven: incidents
                  have no per-occurrence Code / blast-radius detail,
                  and we omit Detection / Secret Hash rows that aren't
                  yet on the IncidentOut schema. */}
              {activeTab === "overview" && (() => {
                const providerKey = (data.secret_type || "unknown").toLowerCase();
                // Heuristic provider→colour map.  Same palette as
                // FindingPanel's providerColors for visual continuity —
                // not every secret_type maps cleanly, so fall back to
                // slate for unknown.
                const providerColors: Record<string, string> = {
                  aws: "bg-orange-500", aws_access_key: "bg-orange-500", aws_secret_key: "bg-orange-500",
                  gcp: "bg-blue-500", gcp_service_account_key: "bg-blue-500",
                  azure: "bg-blue-600",
                  github: "bg-slate-600", github_pat: "bg-slate-600", github_app_private_key: "bg-slate-600",
                  gitlab: "bg-orange-500", gitlab_pat: "bg-orange-500",
                  stripe: "bg-purple-500", stripe_secret_key: "bg-purple-500",
                  slack: "bg-purple-600", slack_webhook_url: "bg-purple-600",
                  vercel: "bg-slate-700", vercel_token_v2: "bg-slate-700",
                  docker: "bg-blue-500", docker_secret: "bg-blue-500",
                  jdbc_connection_string: "bg-teal-500",
                  structured_yaml: "bg-amber-500",
                  entropy_base64: "bg-violet-500",
                  basic_auth: "bg-red-500",
                };
                const iconColor = providerColors[providerKey] || "bg-slate-600";
                const iconLetter = (data.secret_type || data.title || "?")[0]?.toUpperCase() || "?";

                const valStatus = data.validation_status || "not_validated";
                const valStyles: Record<string, string> = {
                  active: "bg-red-500/15 text-red-400",
                  inactive: "bg-green-500/15 text-green-400",
                  revoked: "bg-green-500/15 text-green-400",
                  unknown: "bg-slate-500/15 text-slate-400",
                  not_validated: "bg-slate-500/10 text-slate-500",
                };
                const valLabels: Record<string, string> = {
                  active: "Active (Exposed!)",
                  inactive: "Inactive",
                  revoked: "Revoked",
                  unknown: "Unknown",
                  not_validated: "Not Validated",
                };

                const conf = data.ai_confidence ?? 0;
                const confPct = Math.round(conf * 100);
                const confBarColor =
                  confPct >= 80 ? "bg-green-400" :
                  confPct >= 50 ? "bg-yellow-400" :
                  "bg-red-400";

                return (
                  <div className="space-y-4">
                    {/* Secret Identity */}
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-xl ${iconColor} flex items-center justify-center shrink-0`}>
                        <span className="text-sm font-bold text-white">{iconLetter}</span>
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-white capitalize truncate">
                          {(data.secret_type || "unknown").replace(/_/g, " ")}
                        </p>
                        <p className="text-xs text-slate-500">
                          {data.occurrence_count === 1
                            ? "Sensitive credential found in 1 location."
                            : `Sensitive credential found in ${data.occurrence_count} locations.`}
                        </p>
                      </div>
                    </div>

                    {/* Masked Value + Validation Status — grid-cols-2,
                        same card chrome as FindingPanel */}
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                        <span className="text-[10px] text-slate-500 uppercase">Masked Value</span>
                        <p className="font-mono text-sm text-red-400 mt-1 bg-black/20 px-2 py-1 rounded truncate" title={data.masked_value || ""}>
                          {data.masked_value || "****"}
                        </p>
                      </div>
                      <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                        <div className="flex items-start justify-between gap-2">
                          <span className="text-[10px] text-slate-500 uppercase">Validation Status</span>
                          {/* Re-verify — same cyan visual as the
                              equivalent button on FindingPanel.  Calls
                              POST /incidents/{id}/verify which picks
                              the most-recently-seen occurrence's
                              source_metadata, runs the per-provider
                              verifier, and propagates the result to
                              the incident + every occurrence so the
                              Findings drawer stays in lockstep. */}
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
                          <span className={`text-xs px-2.5 py-1 rounded-md font-medium ${valStyles[valStatus] || valStyles.not_validated}`}>
                            {valLabels[valStatus] || valStatus}
                          </span>
                          {data.last_validated_at ? (
                            <span className="text-[10px] text-slate-500 ml-2">
                              verified {fmtAge(data.last_validated_at)}
                            </span>
                          ) : data.last_seen_at && (
                            <span className="text-[10px] text-slate-500 ml-2">
                              last seen {fmtAge(data.last_seen_at)}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Classification + Review Status + Confidence —
                        grid-cols-3, same as FindingPanel's secondary
                        row. Confidence renders the same coloured bar. */}
                    <div className="grid grid-cols-3 gap-3">
                      <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                        <span className="text-[10px] text-slate-500 uppercase">Classification</span>
                        <p className={`text-xs font-medium mt-1 capitalize ${
                          cls.includes("true_positive") ? "text-red-400" :
                          cls.includes("false_positive") ? "text-green-400" :
                          cls === "accepted_risk" ? "text-orange-400" :
                          "text-yellow-400"
                        }`}>
                          {(data.classification || "needs review").replace(/_/g, " ")}
                        </p>
                      </div>
                      <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                        <span className="text-[10px] text-slate-500 uppercase">Review Status</span>
                        <p className="text-xs font-medium text-slate-200 mt-1 capitalize">
                          {(data.review_status || "unreviewed").replace(/_/g, " ")}
                        </p>
                      </div>
                      <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                        <span className="text-[10px] text-slate-500 uppercase">Confidence</span>
                        {data.ai_confidence != null ? (
                          <div className="mt-1 flex items-center gap-2">
                            <div className="flex-1 h-1.5 bg-white/[0.05] rounded-full overflow-hidden">
                              <div className={`h-full ${confBarColor} transition-all`} style={{ width: `${confPct}%` }} />
                            </div>
                            <span className="text-xs font-medium text-slate-200">{confPct}%</span>
                          </div>
                        ) : (
                          <p className="text-xs text-slate-500 mt-1">—</p>
                        )}
                      </div>
                    </div>

                    {/* Rotation Status — single row card.  Green when
                        rotated, amber otherwise. */}
                    <div className={`rounded-lg p-3 border ${
                      rotated
                        ? "bg-emerald-500/[0.04] border-emerald-500/20"
                        : "bg-amber-500/[0.04] border-amber-500/20"
                    }`}>
                      <div className="flex items-center justify-between gap-2">
                        <div>
                          <span className="text-[10px] text-slate-500 uppercase">Rotation</span>
                          <p className={`text-xs font-medium mt-1 ${rotated ? "text-emerald-400" : "text-amber-400"}`}>
                            {rotated ? `Rotated ${fmtAge(data.rotated_at)}` : "Not rotated"}
                          </p>
                        </div>
                        <span className="text-[10px] text-slate-500">
                          {data.occurrence_count} occurrence{data.occurrence_count === 1 ? "" : "s"} · first seen {fmtAge(data.first_seen_at)}
                        </span>
                      </div>
                    </div>

                    {/* AI Analysis — violet box, identical chrome to
                        the AI Analysis section in FindingPanel. */}
                    {data.ai_explanation && (
                      <div className="rounded-lg border border-violet-500/20 bg-violet-500/[0.04] px-4 py-3">
                        <p className="text-[10px] text-violet-300 uppercase tracking-wider mb-1.5">
                          AI Analysis
                          {data.ai_confidence !== null && (
                            <span className="ml-2 normal-case text-slate-500 tracking-normal">
                              confidence {Math.round((data.ai_confidence || 0) * 100)}%
                            </span>
                          )}
                        </p>
                        <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">
                          {data.ai_explanation}
                        </p>
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* ── Occurrences ────────────────────────────────── */}
              {activeTab === "occurrences" && (
                <div className="space-y-2">
                  {data.occurrences.length === 0 ? (
                    <p className="text-xs text-slate-500 text-center py-8">
                      No occurrences linked to this incident.
                    </p>
                  ) : (
                    data.occurrences.map((o) => (
                      <Link
                        key={o.id}
                        href={`/findings/${o.id}`}
                        className="block rounded border border-white/[0.05] bg-white/[0.02] px-4 py-3 hover:border-white/[0.14] hover:bg-white/[0.04] transition-colors"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p className="text-xs font-mono text-slate-300 truncate" title={o.file_path}>
                              {o.file_path}
                              {o.line_start && <span className="text-slate-500">:{o.line_start}</span>}
                            </p>
                            <p className="text-[10px] text-slate-500 mt-1">
                              {o.classification.toLowerCase()} · last seen {fmtAge(o.last_seen_at || o.created_at)}
                            </p>
                          </div>
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded border uppercase shrink-0 ${
                              SEVERITY_PILL[o.severity.toLowerCase()] || SEVERITY_PILL.info
                            }`}
                          >
                            {o.severity}
                          </span>
                        </div>
                      </Link>
                    ))
                  )}
                </div>
              )}

              {/* ── Rotation ───────────────────────────────────── */}
              {activeTab === "rotation" && (
                <div className="space-y-4">
                  <div className="rounded border border-white/[0.05] bg-white/[0.02] px-4 py-3">
                    <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1.5">
                      Current rotation status
                    </p>
                    {rotated ? (
                      <>
                        <p className="text-sm text-emerald-400 font-semibold">
                          ✓ Rotated {fmtAge(data.rotated_at)}
                        </p>
                        <p className="text-[11px] text-slate-500 mt-1">
                          All {data.occurrence_count} occurrence(s) covered by this rotation event.
                        </p>
                      </>
                    ) : (
                      <>
                        <p className="text-sm text-amber-400 font-semibold">Not rotated</p>
                        <p className="text-[11px] text-slate-500 mt-1">
                          This credential has not been marked as rotated.  Rotate the secret in the
                          issuing system, then click below to record it.
                        </p>
                      </>
                    )}
                  </div>

                  {!rotated && (
                    <div className="space-y-2">
                      {confirmRotate && (
                        <div className="rounded border border-amber-500/30 bg-amber-500/[0.06] px-3 py-2 text-[11px] text-amber-200 leading-relaxed">
                          About to mark this incident as rotated.  {data.occurrence_count} finding{data.occurrence_count === 1 ? "" : "s"} will be linked to a CredentialRotationEvent for MTTR analytics.  Click <span className="font-semibold">Confirm rotation</span> to commit.
                        </div>
                      )}
                      <div className="flex gap-2">
                        <button
                          onClick={handleMarkRotated}
                          disabled={rotating}
                          className={`flex-1 inline-flex items-center justify-center gap-2 text-xs px-3 py-2 rounded font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                            confirmRotate
                              ? "bg-amber-500/20 text-amber-200 ring-1 ring-amber-500/40 hover:bg-amber-500/30"
                              : "bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25"
                          }`}
                        >
                          {rotating && (
                            <span className="w-3 h-3 border-[1.5px] border-current/30 border-t-current rounded-full animate-spin" />
                          )}
                          {rotating ? "Recording rotation…" : confirmRotate ? "Confirm rotation" : "Mark as rotated"}
                        </button>
                        {confirmRotate && !rotating && (
                          <button
                            onClick={() => setConfirmRotate(false)}
                            className="px-3 py-2 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] border border-white/[0.06] transition-colors"
                          >
                            Cancel
                          </button>
                        )}
                      </div>
                    </div>
                  )}

                  <div className="text-[10px] text-slate-500 leading-relaxed">
                    <p className="font-medium text-slate-400 mb-1">What this does</p>
                    <ul className="space-y-1 list-disc list-inside marker:text-slate-600">
                      <li>Sets the incident's rotation status to <span className="text-emerald-400">rotated</span>.</li>
                      <li>Records a CredentialRotationEvent for MTTR analytics on the Rotation page.</li>
                      <li>Does NOT call your cloud provider to actually rotate the key — that's a manual step.</li>
                    </ul>
                  </div>
                </div>
              )}

              {/* ── History ───────────────────────────────────────
                  Audit timeline mirroring FindingPanel's History
                  tab.  Each row is a coloured dot on a vertical line
                  (continuous between rows) with a card holding the
                  action label, previous→new arrow, actor and an
                  optional italicised comment.  Newest-first. */}
              {activeTab === "history" && (
                <div className="space-y-0">
                  {historyError && (
                    <div className="mb-3 rounded border border-red-500/30 bg-red-500/[0.06] px-3 py-2 text-xs text-red-300">
                      {historyError}
                    </div>
                  )}
                  {historyLoading && history === null ? (
                    <p className="text-xs text-slate-500 text-center py-8">Loading history…</p>
                  ) : !history || history.length === 0 ? (
                    <p className="text-sm text-slate-500 py-8 text-center">No actions taken yet</p>
                  ) : (
                    history.map((h, i) => {
                      const dotClass = HISTORY_DOT_CLASS[h.kind] || HISTORY_DOT_CLASS.other;
                      // Gate the arrow render strictly on the entry's
                      // kind, not on whether the "previous" snapshot
                      // happens to contain a value.  The backend
                      // snapshots all four prev_* fields on EVERY
                      // patch (so we have the option to render any
                      // arrow), but we only want to render the arrow
                      // for the field the entry was actually ABOUT —
                      // otherwise a tag-add row spuriously shows an
                      // assignee arrow because the assignee was set
                      // earlier.  Bug found E2E on 2026-05-17.
                      const isClsKind =
                        h.kind === "mark_tp" || h.kind === "mark_fp"
                        || h.kind === "mark_rotated" || h.kind === "mark_test"
                        || h.kind === "accept_risk" || h.kind === "reopen";
                      const isAssignKind = h.kind === "assigned" || h.kind === "unassigned";
                      const hasClsArrow = isClsKind
                        && h.previous_classification && h.new_classification
                        && h.previous_classification !== h.new_classification;
                      const hasAssignArrow = isAssignKind
                        && h.previous_assigned_to !== h.new_assigned_to
                        && (h.previous_assigned_to || h.new_assigned_to);
                      return (
                        <div key={h.id} className="relative pl-6 pb-3">
                          {i < history.length - 1 && (
                            <div className="absolute left-[7px] top-5 bottom-0 w-px bg-white/[0.06]" />
                          )}
                          <div className={`absolute left-0 top-1 w-[14px] h-[14px] rounded-full border-2 ${dotClass}`} />
                          <div className="bg-white/[0.02] border border-white/[0.04] rounded-lg p-2.5">
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-xs font-medium text-slate-200">{h.label}</span>
                              <span className="text-[9px] text-slate-600">
                                {h.created_at ? new Date(h.created_at).toLocaleString() : ""}
                              </span>
                            </div>
                            {hasClsArrow && (
                              <div className="flex items-center gap-1.5 text-[9px] mt-1">
                                <span className="text-slate-500">{(h.previous_classification || "").replace(/_/g, " ")}</span>
                                <span className="text-slate-600">→</span>
                                <span className="text-red-400">{(h.new_classification || "").replace(/_/g, " ")}</span>
                              </div>
                            )}
                            {hasAssignArrow && (
                              <div className="flex items-center gap-1.5 text-[9px] mt-1">
                                <span className="text-slate-500">{h.previous_assigned_to || "Unassigned"}</span>
                                <span className="text-slate-600">→</span>
                                <span className="text-violet-400">{h.new_assigned_to || "Unassigned"}</span>
                              </div>
                            )}
                            <span className="text-[9px] text-slate-600 block mt-0.5">
                              by {h.user_name || "System"}
                              {h.via && <span className="ml-1 text-slate-700">· {h.via.replace(/_/g, " ")}</span>}
                            </span>
                            {h.comment && (
                              <p className="text-[10px] text-slate-400 mt-1 italic">&ldquo;{h.comment}&rdquo;</p>
                            )}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* ── Action bar (sticky bottom) ─────────────────────────────
            Exact FindingPanel layout: comment textarea + a single row
            holding the status dropdown, Save, and Close. */}
        <div className="px-5 py-3 border-t border-white/[0.06] shrink-0 space-y-2.5" style={{ background: "rgba(8,11,28,0.97)" }}>
          {/* Comment input */}
          <textarea
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => e.stopPropagation()}
            placeholder="Add a note or comment..."
            rows={1}
            onFocus={(e) => { (e.target as HTMLTextAreaElement).rows = 2; }}
            onBlur={(e) => { if (!comment) (e.target as HTMLTextAreaElement).rows = 1; }}
            className="input-dark text-xs w-full resize-none min-h-[32px]"
          />

          <div className="flex items-center gap-2">
            {/* Status dropdown — pending-then-confirm pattern */}
            <div className="relative">
              <button
                onClick={() => setStatusDropdownOpen(!statusDropdownOpen)}
                disabled={saving || !data}
                title={pendingAction
                  ? "Unsaved change — click Save to commit, or pick the same option again to discard"
                  : "Change incident status"
                }
                className={`flex items-center gap-2 px-3 h-[34px] rounded-lg text-xs font-medium border transition-all min-w-[200px] ${triggerBg} ${pendingHint}`}
              >
                <span className={`w-2 h-2 rounded-full shrink-0 ${triggerDot} ${pendingAction ? "animate-pulse" : ""}`} />
                <span className="flex-1 text-left">
                  {pendingAction && <span className="text-amber-400 font-semibold mr-1">Pending →</span>}
                  {triggerLabel}
                </span>
                <svg className={`w-3.5 h-3.5 transition-transform ${statusDropdownOpen ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              {/* Dropdown menu — opens UPWARD so it doesn't get clipped
                  by the bottom of the drawer (same as FindingPanel). */}
              {statusDropdownOpen && data && (
                <>
                  <div className="fixed inset-0 z-10" onClick={() => setStatusDropdownOpen(false)} />
                  <div
                    className="absolute bottom-full left-0 mb-1 z-20 w-52 py-1 rounded-lg border border-white/[0.1] shadow-xl"
                    style={{ background: "rgba(8,11,28,0.95)" }}
                  >
                    {/* Triage decisions only — 5 options, never 6.
                        "Needs Review" was a conditional 6th entry
                        which made the dropdown shape change based
                        on state (confusing UX).  Re-open is now a
                        separate ghost button next to Save in the
                        bottom action bar — only renders when
                        classification ≠ needs_review.  Matches the
                        Findings drawer 1:1. */}
                    {[
                      { action: "mark_tp", label: "True Positive", color: "text-red-400", dot: "bg-red-400", desc: "Confirmed real secret" },
                      { action: "mark_rotated", label: "Rotated / Revoked", color: "text-green-400", dot: "bg-green-400", desc: "Secret has been rotated or revoked" },
                      { action: "mark_fp", label: "False Positive", color: "text-slate-400", dot: "bg-slate-400", desc: "Not a real secret" },
                      { action: "mark_test", label: "Test Credential", color: "text-blue-400", dot: "bg-blue-400", desc: "Intentional test/mock credential" },
                      { action: "accept_risk", label: "Accepted Risk", color: "text-orange-400", dot: "bg-orange-400", desc: "Known exposure, team accepts it" },
                    ].map((opt) => {
                      const isPending = pendingAction === opt.action;
                      // Active = matches the saved state.  needs_review
                      // doesn't appear in the dropdown (it's the
                      // default/inbox state, not a triage decision)
                      // so there's no isSavedActive row for it.
                      const isSavedActive = !pendingAction && (
                        (opt.action === "mark_tp" && data.classification.includes("true_positive"))
                        || (opt.action === "mark_rotated" && (data.classification === "rotated" || data.classification === "revoked" || data.classification === "resolved"))
                        || (opt.action === "mark_fp" && data.classification.includes("false_positive"))
                        || (opt.action === "mark_test" && data.classification === "test_credential")
                        || (opt.action === "accept_risk" && data.classification === "accepted_risk")
                      );

                      return (
                        <button
                          key={opt.action}
                          onClick={() => handleSelectStatus(opt.action)}
                          disabled={saving}
                          className={`w-full text-left px-3 py-2 hover:bg-white/[0.04] transition-colors flex items-center gap-2.5 ${
                            isPending ? "bg-amber-500/[0.08] ring-1 ring-amber-500/30" :
                            isSavedActive ? "bg-white/[0.03]" : ""
                          }`}
                        >
                          <span className={`w-2 h-2 rounded-full shrink-0 ${opt.dot} ${isPending ? "animate-pulse" : ""}`} />
                          <div className="flex-1 min-w-0">
                            <span className={`text-xs font-medium ${opt.color}`}>
                              {opt.label}
                              {isPending && <span className="ml-1 text-[9px] text-amber-400 font-semibold">(unsaved)</span>}
                            </span>
                            <span className="text-[9px] text-slate-600 block">{opt.desc}</span>
                          </div>
                          {(isPending || isSavedActive) && (
                            <svg className={`w-3.5 h-3.5 shrink-0 ${isPending ? "text-amber-400" : opt.color}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                            </svg>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </>
              )}
            </div>

            {/* Re-open — separate ghost button, only visible when
                the incident is NOT already in needs_review.  Stages
                pendingAction="reopen" — the same dropdown trigger
                shows the pending amber state, and Save commits
                action + comment together.  Matches the Findings
                drawer 1:1 (gap #5 from the commercial-grade audit). */}
            {data && data.classification !== "needs_review" && (
              <button
                type="button"
                onClick={() => setPendingAction((prev) => (prev === "reopen" ? null : "reopen"))}
                disabled={saving}
                title="Reset this incident to Needs Review (re-opens for triage)"
                className={`px-2.5 h-[34px] rounded-lg text-xs font-medium border transition-all disabled:opacity-30 disabled:cursor-not-allowed shrink-0 inline-flex items-center gap-1.5 ${
                  pendingAction === "reopen"
                    ? "bg-yellow-500/15 text-yellow-300 border-yellow-500/40 ring-1 ring-yellow-500/30"
                    : "text-yellow-400/80 border-yellow-400/20 hover:bg-yellow-400/10 hover:text-yellow-300"
                }`}
              >
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                {pendingAction === "reopen" ? "Pending Re-open" : "Re-open"}
              </button>
            )}

            {/* Save — same enable rule + amber-glow as FindingPanel.
                Commits pendingAction + comment in one PATCH. */}
            <button
              onClick={handleSave}
              disabled={(!pendingAction && !comment.trim()) || saving || !data}
              title={
                pendingAction && comment.trim() ? `Save status change to "${HUMAN_LABEL[pendingAction]}" with comment` :
                pendingAction ? `Save status change to "${HUMAN_LABEL[pendingAction]}"` :
                comment.trim() ? "Save comment" :
                "Pick a status or write a comment to enable Save"
              }
              className={`px-4 h-[34px] rounded-lg text-xs font-medium border transition-all disabled:opacity-30 disabled:cursor-not-allowed shrink-0 ${
                pendingAction
                  ? "bg-amber-500/15 text-amber-300 border-amber-500/40 hover:bg-amber-500/25 ring-1 ring-amber-500/30"
                  : "text-red-400 border-red-400/20 hover:bg-red-400/10"
              }`}
            >
              {saving
                ? <div className="w-3.5 h-3.5 border-2 border-current/30 border-t-current rounded-full animate-spin" />
                : pendingAction ? "Save Change" : "Save"}
            </button>

            <div className="flex-1" />

            <button
              onClick={handleClose}
              className="px-4 h-[34px] rounded-lg text-xs font-medium text-slate-500 hover:text-slate-300 hover:bg-white/[0.04] border border-white/[0.06] transition-colors"
              title={pendingAction ? "Close (discards unsaved status change)" : "Close"}
            >
              {pendingAction ? "Discard & Close" : "Close"}
            </button>
          </div>
        </div>
      </div>

      {/* Same slide-in keyframe as FindingPanel.  Inlined per-component
          so the drawer's chrome stays drop-in regardless of where it's
          mounted. */}
      <style jsx>{`
        @keyframes slide-in { from { transform: translateX(100%); } to { transform: translateX(0); } }
        .animate-slide-in { animation: slide-in 0.2s ease-out; }
      `}</style>
    </div>
  );
}
