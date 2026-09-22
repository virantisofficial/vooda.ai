"use client";
import { validityOf } from "@/lib/validity";
import { classificationLabel } from "@/lib/findingState";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect } from "react";
import Link from "next/link";
import { triageFinding, addFindingComment, assignFinding, updateFindingTags, getUsers, verifyFinding } from "@/lib/api";
import SuggestionChips from "@/components/suggestions/SuggestionChips";
import { CodeSnippet } from "@/components/findings/CodeSnippet";
import { brandScannerName, getScannerColor, isVoodaEngine } from "@/lib/branding";
import { findingName } from "@/lib/titleUtils";
import { useToast } from "@/components/ui/Toast";
import type { FindingDetail } from "@/types";
import { providerConsole } from "@/lib/providerConsoles";

interface Props {
  finding: FindingDetail;
  onClose: () => void;
  onUpdate: () => void;  // refresh after triage action
}

// Human-friendly label per triage action key — used in the post-
// save toast so the user gets concrete confirmation of what just
// committed. Keep in sync with the dropdown options below.
const _ACTION_LABELS: Record<string, string> = {
  reopen: "Needs Review",
  mark_tp: "True Positive",
  mark_rotated: "Rotated / Revoked",
  mark_fp: "False Positive",
  mark_test: "Test Credential",
  accept_risk: "Accepted Risk",
};
function _humanLabel(action: string): string {
  return _ACTION_LABELS[action] || action;
}

export default function FindingPanel({ finding, onClose, onUpdate }: Props) {
  const [actionLoading, setActionLoading] = useState("");
  const [activeSection, setActiveSection] = useState<"overview" | "code" | "ai" | "next_steps" | "evidence" | "history">("overview");
  const [comment, setComment] = useState("");
  const [statusDropdownOpen, setStatusDropdownOpen] = useState(false);
  const [reverifying, setReverifying] = useState(false);
  // ── Pending-then-confirm status flow (2026-05-04) ──
  // The dropdown used to fire `triageFinding` immediately on click,
  // and the "Save" button only saved comments. Two issues:
  //   1. Save was disabled until the user typed comment text — even
  //      when they had picked a new status. Reported by user as
  //      "Save button not enabled when changing state".
  //   2. No undo on a misclick — picking "False Positive" by mistake
  //      committed instantly to the DB.
  // Fix: dropdown click now QUEUES a pending action; Save commits it
  // (along with any optional comment) in a single API call. Matches
  // GitGuardian / Snyk / Wiz UX. Comment-only save still works the
  // same when pendingAction is null.
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  // Tracks which signal (if any) sourced the pending action.
  // Threaded into the audit `via` field on Save so the History tab
  // can render chip-driven actions distinctly from manual triage.
  // Always cleared when the user manually picks from the dropdown
  // (the source is honestly "manual" at that point).
  const [pendingSource, setPendingSource] = useState<string | null>(null);
  const { toast } = useToast();

  // Discard pending state when the user navigates to a different
  // finding (panel re-used with a new prop). Without this reset, a
  // stale pendingAction from finding A would silently apply to
  // finding B on the next Save click — would be a real footgun.
  useEffect(() => {
    setPendingAction(null);
    setPendingSource(null);
    setComment("");
  }, [finding.id]);

  // Manual re-verify — hits POST /findings/{id}/verify which re-runs
  // the live provider check and updates source_metadata in place.
  // Useful after a credential rotation, or to confirm a previously
  // unverifiable provider is now reachable.
  //
  // Was previously a raw `fetch("/api/findings/...")` call which 404'd
  // because the API is mounted under `/api/v1/findings/...`.  Routing
  // it through the shared axios client (verifyFinding) bakes in the
  // /api/v1 prefix and gets us free auth-header handling + interceptor
  // consistency.  Fixed 2026-05-17 during the commercial-grade audit.
  const handleReverify = async () => {
    setReverifying(true);
    try {
      const res = await verifyFinding(finding.id);
      const data = res.data;
      if (data?.status === "active") {
        toast("error", `LIVE credential confirmed — ${data.details || "rotate immediately"}`);
      } else if (data?.status === "inactive" || data?.status === "revoked") {
        toast("success", `Credential is ${data.status} — ${data.details || "no longer working"}`);
      } else if (data?.status === "unsupported") {
        toast("info", data.message || "No verifier available for this provider");
      } else {
        toast("info", data?.details || data?.message || "Verification returned no decisive result");
      }
      onUpdate();
    } catch (e: any) {
      toast("error", e?.response?.data?.detail || e?.message || "Re-verify failed");
    } finally {
      setReverifying(false);
    }
  };

  // Assignee
  const [assignDropdownOpen, setAssignDropdownOpen] = useState(false);
  const [users, setUsers] = useState<any[]>([]);

  // Tags
  const [tagInput, setTagInput] = useState("");
  const [showTagInput, setShowTagInput] = useState(false);

  useEffect(() => {
    // Load users for assignment dropdown
    getUsers().then((r) => setUsers(r.data || [])).catch(() => {});
  }, []);

  const handleAssign = async (userId: string | null, userName?: string) => {
    setAssignDropdownOpen(false);
    try {
      await assignFinding(finding.id, userId, userName);
      toast("success", userId ? `Assigned to ${userName}` : "Unassigned");
      onUpdate();
    } catch { toast("error", "Assignment failed"); }
  };

  const handleAddTag = async (tag: string) => {
    if (!tag.trim()) return;
    const newTags = [...(finding.tags || []), tag.trim().toLowerCase()];
    try {
      await updateFindingTags(finding.id, newTags);
      setTagInput("");
      setShowTagInput(false);
      onUpdate();
    } catch { toast("error", "Failed to add tag"); }
  };

  const handleRemoveTag = async (tag: string) => {
    const newTags = (finding.tags || []).filter((t: string) => t !== tag);
    try {
      await updateFindingTags(finding.id, newTags);
      onUpdate();
    } catch { toast("error", "Failed to remove tag"); }
  };

  // Dropdown click queues a pending status change. Picking the
  // SAME action twice clears the queue (acts as a discard). Picking
  // a DIFFERENT action replaces the queued one. Nothing hits the
  // API until the user clicks Save below.
  const handleSelectStatus = (action: string) => {
    setPendingAction((prev) => (prev === action ? null : action));
    // Manual dropdown pick — clear any chip-source attribution so the
    // audit log doesn't lie about provenance.
    setPendingSource(null);
    setStatusDropdownOpen(false);
  };

  // SuggestionChip click — stages the suggested action the same way
  // the dropdown does, additionally carries the signal id (for
  // audit) and pre-fills the comment with the chip's reason so the
  // analyst can edit before clicking Save.  Keeps the user in
  // control: nothing commits until Save is pressed.
  const handleSuggest = (action: string, signalId: string, reason: string) => {
    setPendingAction(action);
    setPendingSource(signalId);
    // Only auto-fill comment when the user hasn't already typed
    // something — don't clobber in-progress text.
    if (!comment.trim()) {
      setComment(`Auto-suggested: ${reason}`);
    }
  };

  // Single Save handler — commits whichever combination is pending:
  //   - pendingAction + comment   → triage in one API call
  //   - pendingAction only        → triage with no comment
  //   - comment only              → addFindingComment (legacy path)
  // No-op if neither is set (button is disabled in that case anyway).
  const handleSave = async () => {
    const trimmedComment = comment.trim();
    if (!pendingAction && !trimmedComment) return;
    setActionLoading(pendingAction || "comment");
    try {
      if (pendingAction) {
        await triageFinding(finding.id, {
          action: pendingAction,
          comment: trimmedComment || undefined,
          // pendingSource ⇒ this action originated from a
          // SuggestionChip click.  Threaded into audit metadata so
          // the History tab + compliance queries can distinguish
          // signal-confirmed actions from manual ones.
          source: pendingSource || undefined,
          // Optimistic-lock token: server rejects the write with
          // HTTP 409 if another reviewer beat us to it.  finding.version
          // comes from the GET response and is incremented by the
          // backend on every flush.  Catch handler below renders the
          // 409 as a "reload, your draft is stale" prompt.
          expected_version: (finding as any).version,
        });
        setPendingAction(null);
        setPendingSource(null);
        setComment("");
        toast("success", `Status updated → ${_humanLabel(pendingAction)}`);
      } else if (trimmedComment) {
        await addFindingComment(finding.id, trimmedComment);
        setComment("");
        toast("success", "Comment added");
      }
      onUpdate();
    } catch (e: any) {
      // 409 Conflict means another reviewer saved a change in the
      // window between our load and our save — backend returns the
      // live version so we could merge, but the simplest correct UX
      // is to tell the user to reload.  Calling onUpdate() will
      // refresh the parent list/drawer so they see the new state.
      if (e?.response?.status === 409) {
        toast("error", "This finding was modified by another reviewer. Refresh and try again.");
        onUpdate();
      } else {
        toast("error", e?.message || "Save failed");
      }
    } finally {
      setActionLoading("");
    }
  };

  // Discard any pending change on close so re-opening the panel
  // doesn't carry over a stale status that the user thought they
  // had abandoned. Comment is also cleared (not auto-saved).
  const handleClose = () => {
    setPendingAction(null);
    setPendingSource(null);
    setComment("");
    onClose();
  };

  const sections = [
    { key: "overview", label: "Overview" },
    { key: "code", label: "Code" },
    { key: "ai", label: "AI Analysis", count: finding.evidence.length > 0 ? finding.evidence.length : undefined },
    { key: "next_steps", label: "Next Steps" },
    { key: "history", label: "History", count: finding.decisions.length },
  ] as const;

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      {/* Backdrop — only this div closes the panel */}
      <div className="absolute inset-0 bg-black/40 backdrop-blur-[2px]" onClick={onClose} />

      {/* Panel */}
      <div className="relative w-full max-w-[680px] border-l border-white/[0.08] h-full flex flex-col shadow-2xl animate-slide-in" style={{ background: "rgba(8,11,28,0.95)",  }}>

        {/* Header */}
        <div className="px-5 py-4 border-b border-white/[0.06] shrink-0">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <h3 className="text-base font-semibold text-white leading-snug">{findingName(finding.title, finding.vulnerability_category)}</h3>
              <div className="flex gap-2 mt-2 flex-wrap">
                <span className={`severity-badge severity-${finding.severity}`}>{finding.severity}</span>
                {(finding as any).is_archived_parent && (
                  <span
                    className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full uppercase tracking-wider"
                    style={{ background: "rgba(245, 158, 11, 0.12)", color: "#fbbf24", border: "1px solid rgba(245, 158, 11, 0.3)" }}
                    title="This finding belongs to an archived source — scanning is paused, data is preserved."
                  >
                    <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
                    </svg>
                    Archived source
                  </span>
                )}
                <span className={`inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full ${
                  finding.classification.includes("true_positive") ? "bg-red-500/15 text-red-400 border border-red-500/20" :
                  finding.classification.includes("false_positive") ? "bg-green-500/15 text-green-400 border border-green-500/20" :
                  finding.classification === "accepted_risk" ? "bg-orange-500/15 text-orange-400 border border-orange-500/20" :
                  "bg-yellow-500/15 text-yellow-400 border border-yellow-500/20"
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    finding.classification.includes("true_positive") ? "bg-red-400" :
                    finding.classification.includes("false_positive") ? "bg-green-400" :
                    finding.classification === "accepted_risk" ? "bg-orange-400" : "bg-yellow-400"
                  }`} />
                  {finding.classification.replace(/_/g, " ")}
                </span>
                {(() => { const sm = (finding as any).source_metadata || {}; const p = sm.provider || ""; return p ? <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/20 capitalize">{sm.secret_type?.replace(/_/g, " ") || p}</span> : finding.cwe ? <span className="text-[10px] px-2 py-0.5 rounded-full bg-white/[0.04] text-slate-400 border border-white/[0.06]">{finding.cwe}</span> : null; })()}
              </div>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              {/* Open in full page — was previously a 16px slate-400
                  icon (nearly invisible against the dark panel).
                  Bumped to a cyan badge + label so users actually
                  discover the shareable-URL affordance.  Mirror of
                  the same treatment on IncidentDetailDrawer. */}
              <Link
                href={`/findings/${finding.id}`}
                className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-1 rounded-md bg-cyan-500/15 text-cyan-300 border border-cyan-400/40 hover:bg-cyan-500/25 hover:text-cyan-100 hover:border-cyan-400/70 transition-colors"
                title="Open this finding in a full page (shareable URL)"
              >
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                Open page
              </Link>
              <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/[0.06] transition-colors">
                <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" /></svg>
              </button>
            </div>
          </div>

          {/* Location + Assign + Tags bar */}
          <div className="mt-3 flex items-center gap-2 text-xs flex-wrap">
            <svg className="w-3.5 h-3.5 text-slate-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
            <span className="font-mono text-red-400 truncate">{finding.file_path}:{finding.line_start}</span>

            <span className="text-slate-700">|</span>

            {/* Assignee */}
            <div className="relative">
              <button onClick={() => setAssignDropdownOpen(!assignDropdownOpen)}
                className="flex items-center gap-1 px-2 py-0.5 rounded-md hover:bg-white/[0.06] transition-colors text-slate-400">
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
                {finding.assigned_to ? (
                  <span className="text-red-400">{users.find((u) => u.id === finding.assigned_to)?.full_name || "Assigned"}</span>
                ) : (
                  <span className="text-slate-600">Assign</span>
                )}
                <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
              </button>
              {assignDropdownOpen && (
                <>
                  <div className="fixed inset-0 z-10" onClick={() => setAssignDropdownOpen(false)} />
                  <div className="absolute left-0 top-full mt-1 z-20 w-52 py-1 rounded-lg border border-white/[0.1] shadow-xl max-h-48 overflow-y-auto" style={{ background: "rgba(8,11,28,0.95)",  }}>
                    <button onClick={() => handleAssign(null)} className="w-full text-left px-3 py-2 text-xs text-slate-400 hover:bg-white/[0.04]">
                      <span className="flex items-center gap-2">
                        <svg className="w-3.5 h-3.5 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                        Unassign
                      </span>
                    </button>
                    {users.map((u: any) => (
                      <button key={u.id} onClick={() => handleAssign(u.id, u.full_name)}
                        className={`w-full text-left px-3 py-2 text-xs hover:bg-white/[0.04] flex items-center gap-2 ${u.id === finding.assigned_to ? "text-red-400" : "text-slate-300"}`}>
                        <div className="w-5 h-5 rounded-full bg-gradient-to-br from-red-500/30 to-orange-500/30 flex items-center justify-center text-[8px] font-bold text-red-400 shrink-0">
                          {u.full_name?.split(" ").map((n: string) => n[0]).join("").toUpperCase().slice(0, 2)}
                        </div>
                        {u.full_name}
                        {u.id === finding.assigned_to && <svg className="w-3 h-3 ml-auto text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>}
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>

            <span className="text-slate-700">|</span>

            {/* Tags */}
            <div className="flex items-center gap-1 flex-wrap">
              {(finding.tags || []).map((tag: string) => (
                <span key={tag} className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 text-[9px] border border-purple-500/20">
                  {tag}
                  <button onClick={() => handleRemoveTag(tag)} className="ml-0.5 hover:text-white transition-colors">
                    <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                  </button>
                </span>
              ))}
              {showTagInput ? (
                <input
                  type="text" value={tagInput} onChange={(e) => setTagInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleAddTag(tagInput); if (e.key === "Escape") { setShowTagInput(false); setTagInput(""); } e.stopPropagation(); }}
                  onClick={(e) => e.stopPropagation()}
                  onBlur={() => { if (tagInput) handleAddTag(tagInput); else setShowTagInput(false); }}
                  placeholder="tag name"
                  autoFocus
                  className="w-20 px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.1] text-[9px] text-slate-300 outline-none focus:border-purple-400/40"
                />
              ) : (
                <button onClick={() => setShowTagInput(true)} className="text-[9px] text-slate-600 hover:text-purple-400 transition-colors px-1">+ tag</button>
              )}
            </div>
          </div>

          {/* Suggestion chips — deterministic one-click triage hints
              from is_placeholder / file_context / detection_engine.
              Rendered between the meta bar and the tabs so they're
              visible regardless of which tab is active.  See
              components/suggestions/SuggestionChips.tsx for the
              display-rule logic (chip only appears when AI hasn't
              run, agrees, or is low-confidence). */}
          {(() => {
            const sm = (finding as any).source_metadata || (finding as any).raw_data || {};
            return (
              <div className="mt-3">
                <SuggestionChips
                  signals={{
                    is_placeholder: sm.is_placeholder === true,
                    is_test_file: sm.file_context === "test_file",
                    is_git_history: sm.detection_engine === "secret_scan_history",
                    validation_status: validityOf(finding),
                  }}
                  classification={finding.classification}
                  aiConfidence={finding.ai_confidence ?? null}
                  onSuggest={handleSuggest}
                  disabled={!!actionLoading}
                />
              </div>
            );
          })()}
        </div>

        {/* Section tabs */}
        <div className="px-5 border-b border-white/[0.06] shrink-0">
          <div className="flex gap-0.5 -mb-px">
            {sections.map((s) => (
              <button key={s.key} onClick={() => setActiveSection(s.key as any)}
                className={`px-3 py-2.5 text-xs font-medium border-b-2 transition-colors ${
                  activeSection === s.key
                    ? "border-red-400 text-red-400"
                    : "border-transparent text-slate-500 hover:text-slate-300"
                }`}>
                {s.label}
                {"count" in s && s.count != null && s.count > 0 && <span className="ml-1 text-[9px] text-slate-600">({s.count})</span>}
              </button>
            ))}
          </div>
        </div>

        {/* Content — scrollable */}
        <div className="flex-1 overflow-y-auto px-5 py-4">

          {/* ── Overview ── */}
          {activeSection === "overview" && (() => {
            const sm = (finding as any).source_metadata || {};
            const conf = finding.ai_confidence ?? finding.confidence ?? 0;
            const valStatus = validityOf(finding);
            const valStyles: Record<string, string> = { active: "bg-red-500/15 text-red-400", inactive: "bg-green-500/15 text-green-400", revoked: "bg-green-500/15 text-green-400", unknown: "bg-slate-500/15 text-slate-400", not_validated: "bg-slate-500/10 text-slate-500" };
            const valLabels: Record<string, string> = { active: "Active (Exposed!)", inactive: "Inactive", revoked: "Revoked", unknown: "Unknown", not_validated: "Not Validated" };
            const providerColors: Record<string, string> = { aws: "bg-orange-500", gcp: "bg-blue-500", azure: "bg-blue-600", github: "bg-slate-600", gitlab: "bg-orange-500", stripe: "bg-purple-500", slack: "bg-purple-600", unknown: "bg-slate-600" };
            const provider = sm.provider || "unknown";
            return (
            <div className="space-y-4">
              {/* Secret Identity */}
              <div className="flex items-center gap-3">
                <div className={`w-10 h-10 rounded-xl ${providerColors[provider] || providerColors.unknown} flex items-center justify-center shrink-0`}>
                  <span className="text-sm font-bold text-white">{provider[0]?.toUpperCase()}</span>
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-white capitalize">{sm.secret_type?.replace(/_/g, " ") || finding.vulnerability_category}</p>
                    {sm.detection_engine === "secret_scan_history" && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/20 font-medium">Found in Git History</span>
                    )}
                    {sm.is_placeholder && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-500/10 text-slate-400 border border-slate-500/20 font-medium">Placeholder</span>
                    )}
                    {sm.removed_from_code === true && (
                      <span
                        className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/20 font-medium"
                        title="The file is gone from the current code, but the secret is still in the repository's history and in every existing clone. Rotating the credential is what closes this."
                      >
                        Not in current code
                      </span>
                    )}
                    {sm.file_context === "test_file" && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-medium" title="Finding is in a test/spec file — typically lower production priority">Test</span>
                    )}
                  </div>
                  <p className="text-xs text-slate-500">{finding.description}</p>
                  {sm.removed_from_code === true && (
                    <p className="text-[10px] text-amber-400/70 mt-1">
                      This file was deleted{sm.removed_at_commit ? ` in ${String(sm.removed_at_commit).slice(0, 8)}` : ""} — the secret is no longer in
                      your current code, but it remains in the repository&apos;s history and in every clone already made.
                      Rotate the credential; deleting the file does not revoke it.
                    </p>
                  )}
                  {sm.in_commit_message === true && sm.commit_sha ? (
                    <p className="text-[10px] text-amber-400/70 mt-1">
                      Found in the message of commit {sm.commit_sha?.slice(0, 8)}{sm.commit_author ? ` by ${sm.commit_author}` : ""} — it was never written to a file, so there is nothing to edit: the credential has to be rotated.
                    </p>
                  ) : sm.detection_engine === "secret_scan_history" && sm.commit_sha ? (
                    <p className="text-[10px] text-amber-400/70 mt-1">
                      Deleted from current code but found in commit {sm.commit_sha?.slice(0, 8)}{sm.commit_author ? ` by ${sm.commit_author}` : ""} — credential rotation is still required.
                    </p>
                  ) : null}
                </div>
              </div>

              {/* Masked Value + Validation */}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                  <span className="text-[10px] text-slate-500 uppercase">Masked Value</span>
                  <p className="font-mono text-sm text-red-400 mt-1 bg-black/20 px-2 py-1 rounded">{sm.masked_value || "****"}</p>
                </div>
                <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[10px] text-slate-500 uppercase">Validation Status</span>
                    {/* Manual re-verify — only show if provider is one
                        the verifier dispatcher knows about. The button
                        is always rendered for live findings; if no
                        verifier exists the API returns "unsupported"
                        and we toast that gracefully. */}
                    {/* Re-verify button — colour bumped from slate-on-
                        slate (nearly invisible) to cyan with a filled
                        background so it actually reads as an action on
                        the dark drawer.  Cyan is the conventional
                        "refresh/check" colour and doesn't compete with
                        the red/amber semantics used elsewhere for
                        danger / pending. */}
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
                    {sm.verified_at && (
                      <span className="text-[10px] text-slate-500 ml-2">
                        verified {new Date(sm.verified_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Blast Radius — only when credential is verified-active.
                  Prefers B1 structured data (verification_permissions_detail,
                  verification_risk_level, blast_radius_summary) and falls
                  back to the legacy string fields for verifiers that haven't
                  been upgraded yet. */}
              {validityOf(finding) === "active" && (() => {
                const detail = sm.verification_permissions_detail || {};
                const riskLevel: string =
                  sm.verification_risk_level || detail.risk_level || "";
                const summary: string = sm.blast_radius_summary || "";
                const scopes: string[] = Array.isArray(detail.scopes) ? detail.scopes : [];
                const identity: string = detail.identity || "";
                const accountId: string = detail.account_id || "";
                const isProduction: boolean = detail.is_production === true;

                // Risky scopes to highlight in red (broad blast radius)
                const riskyScopes = new Set([
                  "repo", "admin:org", "admin:enterprise", "delete_repo",
                  "workflow", "admin:gpg_key", "admin:public_key",
                  "admin:repo_hook", "full_access",
                ]);
                const riskPillColor: Record<string, string> = {
                  critical: "bg-red-500/15 text-red-400 border-red-500/30",
                  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
                  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
                  low: "bg-green-500/15 text-green-400 border-green-500/30",
                };

                return (
                  <div className="bg-red-500/[0.04] rounded-lg p-3 border border-red-500/[0.2]">
                    <div className="flex items-center gap-2 mb-2 flex-wrap">
                      <span className="text-xs font-semibold text-red-400">🔴 Blast Radius — Live Credential</span>
                      {riskLevel && (
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-semibold uppercase ${riskPillColor[riskLevel] || "bg-slate-500/15 text-slate-400 border-slate-500/30"}`}>
                          {riskLevel} risk
                        </span>
                      )}
                      {isProduction && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30 font-semibold uppercase">
                          production
                        </span>
                      )}
                    </div>

                    {/* B1 headline: one-line summary of what this key can do */}
                    {summary && (
                      <div className="mb-3 p-2 bg-red-500/[0.06] rounded border border-red-500/[0.15]">
                        <p className="text-[12px] text-red-100 leading-snug">{summary}</p>
                      </div>
                    )}

                    <div className="grid grid-cols-2 gap-3 text-[11px]">
                      {/* Prefer structured identity + account_id when available */}
                      {(identity || accountId) ? (
                        <>
                          {identity && (
                            <div className="col-span-2">
                              <span className="text-slate-500 uppercase text-[9px]">Identity</span>
                              <p className="text-slate-200 mt-0.5 font-mono text-[11px] break-all">{identity}</p>
                            </div>
                          )}
                          {accountId && accountId !== identity && (
                            <div className="col-span-2">
                              <span className="text-slate-500 uppercase text-[9px]">Account ID</span>
                              <p className="text-slate-200 mt-0.5 font-mono text-[11px] break-all">{accountId}</p>
                            </div>
                          )}
                        </>
                      ) : (
                        sm.verification_details && (
                          <div className="col-span-2">
                            <span className="text-slate-500 uppercase text-[9px]">Identity / Account</span>
                            <p className="text-slate-200 mt-0.5 font-mono text-[11px] break-all">{sm.verification_details}</p>
                          </div>
                        )
                      )}

                      {/* Scope chips — color-coded by risky-scope set */}
                      {scopes.length > 0 ? (
                        <div className="col-span-2">
                          <span className="text-slate-500 uppercase text-[9px]">Scopes / Capabilities</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {scopes.map((scope) => (
                              <span
                                key={scope}
                                className={
                                  "text-[10px] px-1.5 py-0.5 rounded font-mono border " +
                                  (riskyScopes.has(scope)
                                    ? "bg-red-500/15 text-red-300 border-red-500/30"
                                    : "bg-slate-500/15 text-slate-300 border-slate-500/20")
                                }
                              >
                                {scope}
                              </span>
                            ))}
                          </div>
                        </div>
                      ) : (
                        sm.verification_permissions && (
                          <div className="col-span-2">
                            <span className="text-slate-500 uppercase text-[9px]">Permissions / Scope</span>
                            <p className="text-slate-200 mt-0.5 font-mono text-[11px] break-all">{sm.verification_permissions}</p>
                          </div>
                        )
                      )}

                      {/* B4: live-enumerated capability counts (resources
                          this credential can actually reach). Rendered
                          only when the backend ran with
                          VOODA_BLAST_RADIUS_ENUMERATE enabled. */}
                      {(() => {
                        const caps = detail.capabilities || {};
                        const rows: Array<[string, number | undefined, string[] | undefined]> = [
                          // GitHub / GitLab (B4 wave 1)
                          ["Repositories", caps.repos_accessible, caps.sample_repos],
                          ["Organizations", caps.orgs_accessible, caps.sample_orgs],
                          ["Projects", caps.projects_accessible, caps.sample_projects],
                          ["Groups", caps.groups_accessible, undefined],
                          ["Emails", caps.email_count, undefined],
                          // AWS (B4 wave 2) — S3 buckets + IAM account alias
                          ["S3 Buckets", caps.buckets_accessible, caps.sample_buckets],
                        ].filter(([, count]) => typeof count === "number") as any;
                        const hasAccountAlias = typeof caps.account_alias === "string" && caps.account_alias;
                        if (rows.length === 0 && !hasAccountAlias) return null;
                        return (
                          <div className="col-span-2 mt-2 pt-2 border-t border-white/[0.05]">
                            <span className="text-slate-500 uppercase text-[9px]">Live Blast Radius — Resources Accessible</span>
                            {/* Account alias row — standalone because it's not a count */}
                            {hasAccountAlias && (
                              <div className="flex items-start gap-2 mt-1">
                                <span className="text-[10px] text-slate-400 uppercase min-w-[5.5rem]">AWS Account</span>
                                <p className="text-[11px] text-red-300 font-mono">{caps.account_alias}</p>
                              </div>
                            )}
                            <div className="grid grid-cols-2 gap-1.5 mt-1">
                              {rows.map(([label, count, samples]) => (
                                <div key={label} className="flex items-start gap-2">
                                  <span className="text-[11px] text-red-300 font-mono font-semibold min-w-[2rem] text-right">{count}</span>
                                  <div className="min-w-0 flex-1">
                                    <span className="text-[10px] text-slate-400 uppercase">{label}</span>
                                    {samples && samples.length > 0 && (
                                      <p className="text-[10px] text-slate-300 font-mono truncate">
                                        {samples.slice(0, 3).join(", ")}
                                        {samples.length > 3 ? "…" : ""}
                                      </p>
                                    )}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        );
                      })()}
                    </div>

                    <p className="text-[10px] text-red-400/80 mt-2">
                      This credential was confirmed active by the provider API. Rotate immediately — exposed keys can be used by anyone who has seen this code.
                    </p>
                  </div>
                );
              })()}

              {/* Paired credential indicator */}
              {sm._pair_key && (
                <div className="bg-purple-500/[0.04] rounded-lg p-3 border border-purple-500/[0.2]">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-semibold text-purple-400">🔗 Multi-Credential Pair</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                      {sm._pair_key.replace(/_paired$/, "")}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    This credential required multiple values to verify. The scanner found its
                    companion credential (secret key, client secret, or private key) in the same file
                    and verified them together against the provider API.
                  </p>
                </div>
              )}

              {/* Detection Details */}
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                  <span className="text-[10px] text-slate-500 uppercase">Detection</span>
                  <p className="text-sm text-slate-300 mt-0.5">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${sm.detection_method === "entropy" ? "bg-purple-500/15 text-purple-400" : "bg-red-500/15 text-red-400"}`}>
                      {sm.detection_method || "regex"}
                    </span>
                  </p>
                </div>
                <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                  <span className="text-[10px] text-slate-500 uppercase">Provider</span>
                  <p className="text-sm text-slate-300 mt-0.5 capitalize">{provider}</p>
                </div>
                <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                  <span className="text-[10px] text-slate-500 uppercase">Confidence</span>
                  <div className="flex items-center gap-2 mt-1">
                    <div className="flex-1 bg-white/[0.06] rounded-full h-1.5">
                      <div className={`h-1.5 rounded-full ${conf > 0.7 ? "bg-green-400" : conf > 0.4 ? "bg-yellow-400" : "bg-red-400"}`}
                        style={{ width: `${conf * 100}%` }} />
                    </div>
                    <span className="text-xs font-semibold text-slate-300">{(conf * 100).toFixed(0)}%</span>
                  </div>
                </div>
              </div>

              {/* Entropy Analysis (if entropy-detected) */}
              {sm.entropy_score && (() => {
                const score = parseFloat(sm.entropy_score);
                const isBase64 = sm.charset === "base64" || score > 4.0;
                const threshold = isBase64 ? 4.5 : 3.0;
                const maxEntropy = isBase64 ? 6.0 : 4.0;
                const overThreshold = score - threshold;
                const randomnessPct = Math.min(99, Math.round((score / maxEntropy) * 100));
                const strength = score >= 5.5 ? "Extremely high" : score >= 5.0 ? "Very high" : score >= 4.5 ? "High" : score >= 3.5 ? "Moderate" : "Low";
                const strengthColor = score >= 5.0 ? "text-red-400" : score >= 4.5 ? "text-orange-400" : score >= 3.5 ? "text-yellow-400" : "text-slate-400";
                return (
                  <div className="bg-purple-500/5 border border-purple-500/10 rounded-lg p-3 space-y-2.5">
                    {/* User-friendly summary */}
                    <div className="flex items-start gap-2">
                      <div className="w-6 h-6 rounded-md bg-purple-500/15 flex items-center justify-center shrink-0 mt-0.5">
                        <svg className="w-3.5 h-3.5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg>
                      </div>
                      <div>
                        <p className="text-xs text-purple-300 font-medium">{strength}-randomness string — likely a secret or credential</p>
                        <p className="text-[10px] text-slate-500 mt-0.5">This string is statistically too random to be normal code</p>
                      </div>
                    </div>

                    {/* Technical details */}
                    <div className="flex items-center gap-3 pt-1 border-t border-purple-500/10">
                      <span className="text-[10px] text-slate-500">Score: <span className="text-purple-400 font-mono font-medium">{sm.entropy_score}</span></span>
                      <span className="text-[10px] text-slate-600">|</span>
                      <span className="text-[10px] text-slate-500">Threshold: <span className="text-slate-400 font-mono">{threshold}</span> ({isBase64 ? "base64" : "hex"})</span>
                      <span className="text-[10px] text-slate-600">|</span>
                      <span className="text-[10px] text-slate-500">Above by: <span className="text-purple-400 font-mono">+{overThreshold.toFixed(3)}</span></span>
                    </div>
                  </div>
                );
              })()}

              {/* Secret Hash */}
              <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                <span className="text-[10px] text-slate-500 uppercase">Secret Hash (SHA256)</span>
                <p className="font-mono text-[10px] text-slate-400 mt-1">{sm.secret_hash || "—"}</p>
              </div>

              {/* ── Vooda Radar (inline in Overview) ── */}
              {(() => {
                const brData = sm.blast_radius;
                if (!brData) return null;
                const impactColors: Record<string, string> = { critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", low: "text-green-400" };
                const impactBg: Record<string, string> = { critical: "bg-red-500/10 border-red-500/15", high: "bg-orange-500/10 border-orange-500/15", medium: "bg-yellow-500/10 border-yellow-500/15", low: "bg-green-500/10 border-green-500/15" };
                const riskColors: Record<string, string> = { critical: "bg-red-500/15 text-red-400", high: "bg-orange-500/15 text-orange-400", medium: "bg-yellow-500/15 text-yellow-400", low: "bg-green-500/15 text-green-400" };
                const accessLabels: Record<string, string> = { admin: "Full control", write: "Can modify", read: "Read only", list: "Can list", member: "Member access", assume: "Can assume", limited: "Restricted", varies: "Mixed" };
                const level = brData.impact_level || "low";
                const resources = brData.resources || [];
                const critCount = resources.filter((r: any) => r.risk === "critical").length;
                const highCount = resources.filter((r: any) => r.risk === "high").length;
                return (
                  <div className="space-y-3">
                    {/* Header */}
                    <div className={`rounded-lg border p-3.5 ${impactBg[level] || impactBg.low}`}>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <svg className={`w-4 h-4 ${impactColors[level]}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                          </svg>
                          <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">Vooda Radar — Blast Radius</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`text-lg font-bold ${impactColors[level]}`}>{brData.impact_score}</span>
                          <span className="text-[9px] text-slate-600">/100</span>
                          <span className={`text-[9px] px-1.5 py-0.5 rounded font-semibold uppercase ${impactColors[level]}`}>{level} risk</span>
                        </div>
                      </div>

                      {/* Human-readable impact summary */}
                      <p className="text-xs text-slate-300 font-medium mt-1">
                        {level === "critical" ? "This credential has catastrophic access — immediate rotation required"
                          : level === "high" ? "This credential can modify production systems — prioritize rotation"
                          : level === "medium" ? "This credential has limited access — schedule rotation"
                          : "This credential has minimal access — low priority"}
                      </p>

                      {/* Quick stats */}
                      <div className="flex gap-3 mt-2">
                        {critCount > 0 && <span className="text-[9px] px-2 py-0.5 rounded bg-red-500/15 text-red-400 font-medium">{critCount} critical</span>}
                        {highCount > 0 && <span className="text-[9px] px-2 py-0.5 rounded bg-orange-500/15 text-orange-400 font-medium">{highCount} high risk</span>}
                        {brData.can_admin && <span className="text-[9px] px-2 py-0.5 rounded bg-red-500/15 text-red-400 font-medium">Has admin access</span>}
                        {brData.can_write && !brData.can_admin && <span className="text-[9px] px-2 py-0.5 rounded bg-orange-500/15 text-orange-400 font-medium">Has write access</span>}
                      </div>
                    </div>

                    {/* Identity */}
                    {brData.identity && (
                      <div className="bg-white/[0.02] border border-white/[0.04] rounded-lg p-2.5">
                        <span className="text-[9px] text-slate-500 uppercase">Credential belongs to</span>
                        <p className="text-xs text-slate-200 font-mono mt-0.5">{brData.identity}</p>
                      </div>
                    )}

                    {/* Resources — collapse after 5 */}
                    {resources.length > 0 && (() => {
                      const COLLAPSE_AT = 5;
                      const needsCollapse = resources.length > COLLAPSE_AT;
                      const showAllId = `radar-show-all-${finding.id}`;
                      return (
                        <div className="space-y-1">
                          <p className="text-[10px] text-slate-500 uppercase tracking-wider">What this credential can access ({resources.length})</p>
                          {resources.slice(0, COLLAPSE_AT).map((r: any, i: number) => (
                            <div key={i} className="py-1.5 px-2.5 rounded bg-white/[0.02] border border-white/[0.04]">
                              <div className="flex items-center gap-2">
                                <span className={`text-[8px] px-1.5 py-0.5 rounded font-medium shrink-0 ${riskColors[r.risk] || riskColors.low}`}>{r.risk}</span>
                                <span className="text-[11px] text-slate-200 truncate flex-1">{r.name}</span>
                                <span className="text-[9px] text-slate-500 shrink-0">{accessLabels[r.access] || r.access}</span>
                              </div>
                              {r.detail && <p className="text-[10px] text-slate-600 mt-0.5 ml-[42px]">{r.detail}</p>}
                            </div>
                          ))}
                          {needsCollapse && (
                            <>
                              <div id={showAllId} className="hidden space-y-1">
                                {resources.slice(COLLAPSE_AT).map((r: any, i: number) => (
                                  <div key={i + COLLAPSE_AT} className="py-1.5 px-2.5 rounded bg-white/[0.02] border border-white/[0.04]">
                                    <div className="flex items-center gap-2">
                                      <span className={`text-[8px] px-1.5 py-0.5 rounded font-medium shrink-0 ${riskColors[r.risk] || riskColors.low}`}>{r.risk}</span>
                                      <span className="text-[11px] text-slate-200 truncate flex-1">{r.name}</span>
                                      <span className="text-[9px] text-slate-500 shrink-0">{accessLabels[r.access] || r.access}</span>
                                    </div>
                                    {r.detail && <p className="text-[10px] text-slate-600 mt-0.5 ml-[42px]">{r.detail}</p>}
                                  </div>
                                ))}
                              </div>
                              <button
                                onClick={(e) => {
                                  const el = document.getElementById(showAllId);
                                  if (el) { el.classList.toggle("hidden"); }
                                  const btn = e.currentTarget;
                                  btn.textContent = el?.classList.contains("hidden")
                                    ? `Show all ${resources.length} resources`
                                    : "Show less";
                                }}
                                className="text-[10px] text-red-400 hover:text-red-300 transition-colors pt-1"
                              >
                                Show all {resources.length} resources
                              </button>
                            </>
                          )}
                        </div>
                      );
                    })()}
                  </div>
                );
              })()}
            </div>
            );
          })()}

          {/* ── Code ── */}
          {activeSection === "code" && (
            <div>
              {finding.code_snippet ? (
                <CodeSnippet snippet={finding.code_snippet} lineStart={finding.line_start} lineEnd={finding.line_end} />
              ) : (
                <p className="text-sm text-slate-500 py-8 text-center">No code snippet available</p>
              )}
            </div>
          )}

          {/* ── AI Analysis ── */}
          {activeSection === "ai" && (
            <div className="space-y-3">
              {finding.ai_explanation ? (
                <>
                  <p className="text-sm text-slate-300 leading-relaxed">{finding.ai_explanation}</p>
                  {finding.true_positive_reasons.length > 0 && (
                    <div className="bg-red-500/5 border border-red-500/10 rounded-lg p-3">
                      <h5 className="text-xs font-medium text-red-400 mb-1.5">Real Secret Indicators</h5>
                      {finding.true_positive_reasons.map((r, i) => (
                        <p key={i} className="text-xs text-slate-400 flex gap-2"><span className="text-red-400 shrink-0">×</span>{r}</p>
                      ))}
                    </div>
                  )}
                  {finding.false_positive_reasons.length > 0 && (
                    <div className="bg-green-500/5 border border-green-500/10 rounded-lg p-3">
                      <h5 className="text-xs font-medium text-green-400 mb-1.5">False Alarm Indicators</h5>
                      {finding.false_positive_reasons.map((r, i) => (
                        <p key={i} className="text-xs text-slate-400 flex gap-2"><span className="text-green-400 shrink-0">✓</span>{r}</p>
                      ))}
                    </div>
                  )}
                  {finding.compensating_controls.length > 0 && (
                    <div className="bg-red-500/5 border border-red-500/10 rounded-lg p-3">
                      <h5 className="text-xs font-medium text-red-400 mb-1.5">Mitigating Factors</h5>
                      {finding.compensating_controls.map((c, i) => (
                        <p key={i} className="text-xs text-slate-400 flex gap-2"><span className="text-red-400 shrink-0">🛡</span>{c}</p>
                      ))}
                    </div>
                  )}

                  {/* Evidence — merged into AI Analysis */}
                  {finding.evidence.length > 0 && (
                    <div className="pt-3 mt-3 border-t border-white/[0.06]">
                      <h5 className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mb-2">Supporting Evidence</h5>
                      <div className="space-y-2">
                        {finding.evidence.map((ev, i) => (
                          <div key={i} className="bg-white/[0.02] border border-white/[0.04] rounded-lg p-2.5">
                            <div className="flex gap-2 items-center mb-1">
                              <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-400 font-medium">{ev.type}</span>
                              {ev.file && <span className="text-[10px] text-slate-600 font-mono truncate">{ev.file}</span>}
                            </div>
                            {ev.summary && <p className="text-[11px] text-slate-400">{ev.summary}</p>}
                            {ev.content && (
                              <pre className="bg-[#0a0e1a] p-2 mt-1.5 rounded text-[10px] text-slate-400 overflow-x-auto font-mono border border-white/[0.04] max-h-32 overflow-y-auto"><code>{ev.content}</code></pre>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <p className="text-sm text-slate-500 py-8 text-center">AI analysis pending or not available</p>
              )}
            </div>
          )}

          {/* ── Next Steps ──
              Vooda finds, triages and verifies; the credential's owner
              rotates it at the provider. This tab says what to do given the
              finding's current state and links to the provider's console. */}
          {activeSection === "next_steps" && (() => {
            const sm = (finding as any).source_metadata || {};
            const rd = (finding as any).raw_data || {};
            const provider = (sm.provider || "").toLowerCase();
            const secretType = (sm.secret_type || rd.secret_type || "").toLowerCase();
            const fixHint: string = rd.fix_hint || "";
            const validation = validityOf(finding);
            const cls = (finding.classification || "").toLowerCase();
            const consoleLink = providerConsole(provider, secretType);
            const inRepo = !!finding.repository_id && !(finding as any).scan_source_id;

            type Tone = "red" | "amber" | "green" | "slate";
            // A deleted file does not disable the credential, so these
            // keep the full rotation steps. Two shapes exist: the current
            // one — an open finding tagged `removed_from_code` — and the
            // legacy `resolved_file_deleted` classification written before
            // scans stopped closing findings on deletion.
            const removedNote = sm.removed_from_code === true
              ? "This file is no longer in your code, but the secret is still in the repository's history and in every clone — that doesn't disable the credential. "
              : cls === "resolved_file_deleted" || cls === "resolved_item_deleted"
              ? `The ${cls === "resolved_file_deleted" ? "file" : "item"} containing this secret was removed, but that doesn't disable the credential. `
              : "";
            const status: { tone: Tone; text: string; showSteps: boolean } =
              ["rotated", "revoked", "resolved"].includes(cls)
                ? { tone: "green", text: "Resolved — this credential was marked rotated / revoked.", showSteps: false }
              : cls === "likely_false_positive"
                ? { tone: "slate", text: "AI assessed this as unlikely to be a real secret. Nobody has reviewed it yet — confirm or dismiss it to close it.", showSteps: false }
              : ["confirmed_false_positive", "test_credential"].includes(cls)
                ? { tone: "slate", text: `No action needed — classified as ${cls.replace(/_/g, " ")}.`, showSteps: false }
              : cls === "accepted_risk"
                ? { tone: "slate", text: "Risk accepted — no rotation is planned for this credential.", showSteps: false }
              : validation === "active"
                ? { tone: "red", text: `${removedNote}Verified live — anyone who can see this ${inRepo ? "code" : "content"} can use it. Revoke it at the provider now.`, showSteps: true }
              : validation === "inactive"
                ? { tone: "green", text: "The provider no longer accepts this credential. Confirm it was revoked on purpose, then mark it Rotated / Revoked.", showSteps: false }
              : { tone: "amber", text: `${removedNote}Not verified live. Treat it as exposed and rotate it as a precaution.`, showSteps: true };
            const toneCls: Record<Tone, string> = {
              red: "bg-red-500/5 border-red-500/15 text-red-300",
              amber: "bg-amber-500/5 border-amber-500/15 text-amber-300",
              green: "bg-green-500/5 border-green-500/15 text-green-300",
              slate: "bg-white/[0.02] border-white/[0.06] text-slate-400",
            };
            return (
              <div className="space-y-3">
                <div className={`rounded-lg border p-3 text-xs leading-relaxed ${toneCls[status.tone]}`}>{status.text}</div>

                {fixHint && (
                  <div className="bg-white/[0.02] border border-white/[0.06] rounded-lg p-3">
                    <p className="text-[10px] text-slate-500 uppercase font-medium mb-1">Detector guidance</p>
                    <p className="text-xs text-slate-300">{fixHint}</p>
                  </div>
                )}

                {status.showSteps && (
                  <div className="bg-white/[0.02] border border-white/[0.06] rounded-lg p-4">
                    <ol className="space-y-2">
                      {[
                        `Issue a new credential ${consoleLink ? `in ${consoleLink.label}` : "at the provider"}.`,
                        "Update everything that uses it — applications, CI/CD pipelines, and secret stores.",
                        "Revoke the old credential.",
                        "Back in Vooda, re-verify this finding — it should report Inactive — then mark it Rotated / Revoked.",
                      ].map((step, i) => (
                        <li key={i} className="flex gap-2 text-xs text-slate-300 leading-relaxed">
                          <span className="text-slate-500 font-mono shrink-0">{i + 1}.</span>
                          <span>{step}</span>
                        </li>
                      ))}
                    </ol>
                    {consoleLink && (
                      <a href={consoleLink.url} target="_blank" rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 mt-3 text-xs text-red-400 hover:text-red-300">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                        Open {consoleLink.label}
                      </a>
                    )}
                  </div>
                )}

                {inRepo && status.tone !== "slate" && (
                  <div className="bg-white/[0.02] border border-white/[0.04] rounded-lg p-3">
                    <p className="text-[10px] text-slate-500 uppercase font-medium mb-1">Git history</p>
                    <p className="text-xs text-slate-400">The old value stays in git history. Once it&apos;s revoked it can&apos;t be used, so purging history (<code className="text-slate-300 text-[10px]">git filter-repo</code> or BFG) is optional — it rewrites shared history and needs coordination with everyone who has cloned the repository.</p>
                  </div>
                )}
              </div>
            );
          })()}

          {/* ── History ── */}
          {activeSection === "history" && (
            <div className="space-y-0">
              {finding.decisions.length === 0 ? (
                <p className="text-sm text-slate-500 py-8 text-center">No actions taken yet</p>
              ) : finding.decisions.map((d: any, i: number) => (
                <div key={i} className="relative pl-6 pb-3">
                  {i < finding.decisions.length - 1 && <div className="absolute left-[7px] top-5 bottom-0 w-px bg-white/[0.06]" />}
                  <div className={`absolute left-0 top-1 w-[14px] h-[14px] rounded-full border-2 ${
                    d.action === "mark_fp" ? "border-green-400 bg-green-400/20" :
                    d.action === "mark_tp" ? "border-red-400 bg-red-400/20" :
                    d.action === "accept_risk" ? "border-orange-400 bg-orange-400/20" :
                    "border-slate-500 bg-slate-500/20"
                  }`} />
                  <div className="bg-white/[0.02] border border-white/[0.04] rounded-lg p-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-slate-200">{d.action.replace(/_/g, " ")}</span>
                      <span className="text-[9px] text-slate-600">{d.created_at ? new Date(d.created_at).toLocaleString() : ""}</span>
                    </div>
                    {d.previous_classification && d.new_classification && (
                      <div className="flex items-center gap-1.5 text-[9px] mt-1">
                        <span className="text-slate-500">{d.previous_classification.replace(/_/g, " ")}</span>
                        <span className="text-slate-600">→</span>
                        <span className="text-red-400">{d.new_classification.replace(/_/g, " ")}</span>
                      </div>
                    )}
                    <span className="text-[9px] text-slate-600">by {d.user_name || "System"}</span>
                    {d.comment && <p className="text-[10px] text-slate-400 mt-1 italic">&ldquo;{d.comment}&rdquo;</p>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Action bar — fixed at bottom */}
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

          {/* Bottom bar: Dropdown + Save + Close — single row */}
          <div className="flex items-center gap-2">

            {/* Status dropdown */}
            {/* When `pendingAction` is set, the trigger shows what
                the status WILL become on Save (with an amber tint +
                "Pending →" prefix), not the current saved value.
                This keeps the user oriented while the change is
                still revertible. */}
            <div className="relative">
              {(() => {
                // Effective classification for display: pending if set,
                // else the saved value. Used by the colour + label
                // logic below.
                const cls = pendingAction
                  ? ({
                      mark_tp: "confirmed_true_positive",
                      mark_rotated: "rotated",
                      mark_fp: "confirmed_false_positive",
                      mark_test: "test_credential",
                      accept_risk: "accepted_risk",
                      reopen: "needs_review",
                    } as Record<string, string>)[pendingAction] || finding.classification
                  : finding.classification;

                const colorBg =
                  cls.includes("true_positive") ? "bg-red-500/10 text-red-400 border-red-500/20" :
                  cls === "rotated" || cls === "revoked" || cls === "resolved" ? "bg-green-500/10 text-green-400 border-green-500/20" :
                  cls.includes("false_positive") ? "bg-slate-500/10 text-slate-400 border-slate-500/20" :
                  cls === "test_credential" ? "bg-blue-500/10 text-blue-400 border-blue-500/20" :
                  cls === "accepted_risk" ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                  "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
                const colorDot =
                  cls.includes("true_positive") ? "bg-red-400" :
                  cls === "rotated" || cls === "revoked" || cls === "resolved" ? "bg-green-400" :
                  cls.includes("false_positive") ? "bg-slate-400" :
                  cls === "test_credential" ? "bg-blue-400" :
                  cls === "accepted_risk" ? "bg-orange-400" :
                  "bg-yellow-400";
                const label =
                  classificationLabel(cls);

                // When pending, override with a dashed border + amber
                // ring so the unsaved state is visually distinct.
                const pendingHint = pendingAction
                  ? "border-amber-500/60 ring-1 ring-amber-500/30 [border-style:dashed]"
                  : "";

                return (
                  <button
                    onClick={() => setStatusDropdownOpen(!statusDropdownOpen)}
                    disabled={!!actionLoading}
                    title={pendingAction ? "Unsaved change — click Save to commit, or pick the same option again to discard" : "Change finding status"}
                    className={`flex items-center gap-2 px-3 h-[34px] rounded-lg text-xs font-medium border transition-all min-w-[200px] ${colorBg} ${pendingHint}`}
                  >
                    <span className={`w-2 h-2 rounded-full shrink-0 ${colorDot} ${pendingAction ? "animate-pulse" : ""}`} />
                    <span className="flex-1 text-left">
                      {pendingAction && <span className="text-amber-400 font-semibold mr-1">Pending →</span>}
                      {label}
                    </span>
                    <svg className={`w-3.5 h-3.5 transition-transform ${statusDropdownOpen ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </button>
                );
              })()}

              {/* Dropdown menu */}
              {statusDropdownOpen && (
                <>
                  <div className="fixed inset-0 z-10" onClick={() => setStatusDropdownOpen(false)} />
                  <div className="absolute bottom-full left-0 mb-1 z-20 w-52 py-1 rounded-lg border border-white/[0.1] shadow-xl" style={{ background: "rgba(8,11,28,0.95)",  }}>
                    {/* Triage decisions only — 5 options, never 6.
                        "Needs Review" used to be a conditional 6th
                        entry which made the dropdown shape change
                        based on current state.  That's confusing UX
                        (every comparable vendor — Snyk, GitHub,
                        GitLab — uses needs_review as the implicit
                        default and exposes Re-open as a separate
                        action elsewhere).  Re-open is now a ghost
                        button next to Save in the bottom action
                        bar — only renders when classification ≠
                        needs_review. */}
                    {[
                      { action: "mark_tp", label: "True Positive", color: "text-red-400", dot: "bg-red-400", desc: "Confirmed real secret" },
                      { action: "mark_rotated", label: "Rotated / Revoked", color: "text-green-400", dot: "bg-green-400", desc: "Secret has been rotated or revoked" },
                      { action: "mark_fp", label: "False Positive", color: "text-slate-400", dot: "bg-slate-400", desc: "Not a real secret" },
                      { action: "mark_test", label: "Test Credential", color: "text-blue-400", dot: "bg-blue-400", desc: "Intentional test/mock credential" },
                      { action: "accept_risk", label: "Accepted Risk", color: "text-orange-400", dot: "bg-orange-400", desc: "Known exposure, team accepts it" },
                    ].map((opt) => {
                      // Two distinct visual states:
                      //   isPending — user just picked this option but
                      //     hasn't clicked Save yet. Amber border.
                      //   isSavedActive — this option matches what's
                      //     currently persisted in the DB. Subtle bg.
                      const isPending = pendingAction === opt.action;
                      const isSavedActive = !pendingAction && (
                        (opt.action === "mark_tp" && finding.classification.includes("true_positive"))
                        || (opt.action === "mark_rotated" && (finding.classification === "rotated" || finding.classification === "revoked" || finding.classification === "resolved"))
                        || (opt.action === "mark_fp" && finding.classification.includes("false_positive"))
                        || (opt.action === "mark_test" && finding.classification === "test_credential")
                        || (opt.action === "accept_risk" && finding.classification === "accepted_risk")
                      );

                      return (
                        <button
                          key={opt.action}
                          onClick={() => handleSelectStatus(opt.action)}
                          disabled={!!actionLoading}
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
                the finding is NOT already in needs_review.  Replaces
                the conditional "Needs Review" dropdown entry that
                used to make the dropdown shape change based on
                state.  Stages pendingAction="reopen" — same pending
                visual + same Save commits both action and comment. */}
            {finding.classification !== "needs_review" && (
              <button
                type="button"
                onClick={() => setPendingAction((prev) => (prev === "reopen" ? null : "reopen"))}
                disabled={!!actionLoading}
                title="Reset this finding to Needs Review (re-opens for triage)"
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

            {/* Save — commits pending status change AND/OR comment.
                Enabled when EITHER a status change is pending OR
                the comment textarea has non-whitespace content.
                When pending, the button glows amber to draw the
                user's eye to the unsaved change. */}
            <button
              onClick={handleSave}
              disabled={(!pendingAction && !comment.trim()) || !!actionLoading}
              title={
                pendingAction && comment.trim() ? `Save status change to "${_humanLabel(pendingAction)}" with comment` :
                pendingAction ? `Save status change to "${_humanLabel(pendingAction)}"` :
                comment.trim() ? "Save comment" :
                "Pick a status or write a comment to enable Save"
              }
              className={`px-4 h-[34px] rounded-lg text-xs font-medium border transition-all disabled:opacity-30 disabled:cursor-not-allowed shrink-0 ${
                pendingAction
                  ? "bg-amber-500/15 text-amber-300 border-amber-500/40 hover:bg-amber-500/25 ring-1 ring-amber-500/30"
                  : "text-red-400 border-red-400/20 hover:bg-red-400/10"
              }`}
            >
              {actionLoading
                ? <div className="w-3.5 h-3.5 border-2 border-current/30 border-t-current rounded-full animate-spin" />
                : pendingAction ? "Save Change" : "Save"}
            </button>

            <div className="flex-1" />

            <button onClick={handleClose}
              className="px-4 h-[34px] rounded-lg text-xs font-medium text-slate-500 hover:text-slate-300 hover:bg-white/[0.04] border border-white/[0.06] transition-colors"
              title={pendingAction ? "Close (discards unsaved status change)" : "Close"}
            >
              {pendingAction ? "Discard & Close" : "Close"}
            </button>
          </div>
        </div>
      </div>

      <style jsx>{`
        @keyframes slide-in { from { transform: translateX(100%); } to { transform: translateX(0); } }
        .animate-slide-in { animation: slide-in 0.2s ease-out; }
      `}</style>
    </div>
  );
}
