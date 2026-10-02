"use client";
import { validityOf } from "@/lib/validity";
import { statusShort, statusDetail, statusTextTone, statusTone, lifecycleOf,
         classificationTextTone, classificationLabel,
         STATUS_CHOICES, REASONS_FOR, REASON_LABELS, RESOLVED_IMPLIES,
         verdictLabel, verdictTone } from "@/lib/findingState";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import AppShell from "@/components/layout/AppShell";
import { CodeSnippet } from "@/components/findings/CodeSnippet";
import { getFinding, triageFinding } from "@/lib/api";
import { brandScannerName, getScannerColor } from "@/lib/branding";
import type { FindingDetail } from "@/types";

export default function FindingDetailPage() {
  const params = useParams();
  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState("");
  // Which closing status has its reason buttons expanded. Closing a
  // finding needs a reason, so the status alone is never submittable.
  const [reasonFor, setReasonFor] = useState<string | null>(null);

  const id = params?.id as string;

  const load = () => {
    getFinding(id).then((r) => setFinding(r.data)).catch(() => {}).finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, [id]);

  const handleTriage = async (action: string) => {
    setActionLoading(action);
    try { await triageFinding(id, { action }); load(); } finally { setActionLoading(""); }
  };

  const handleTriageWithComment = async (action: string, comment?: string, reason?: string) => {
    setActionLoading(reason || action);
    try {
      await triageFinding(id, {
        action,
        comment: comment || undefined,
        // resolve and dismiss require one; every other action rejects it.
        resolution_reason: reason || undefined,
      });
      // Clear the comment input after successful action
      const commentInput = document.getElementById("triage-comment") as HTMLInputElement;
      if (commentInput) commentInput.value = "";
      setReasonFor(null);
      load();
    } finally { setActionLoading(""); }
  };

  if (loading) return <AppShell><div className="flex items-center justify-center py-20"><div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div></AppShell>;
  if (!finding) return <AppShell><div className="text-red-400">Finding not found</div></AppShell>;

  return (
    // pageTitle overrides the auto-derived breadcrumb's last segment
    // (which would otherwise render the raw UUID prefix — "a5974d61…").
    // See Header.tsx::buildBreadcrumbs + the pageTitle override path
    // at line ~161 for the escape-hatch behavior.  Falls back to
    // "Secret detail" if the finding is missing a human-readable
    // title so we never display the UUID stub.
    <AppShell pageTitle={finding.title || "Secret detail"}>
      <div className="space-y-5 max-w-5xl">
        {/* Header */}
        <div>
          <h2 className="text-xl font-bold text-white">{finding.title}</h2>
          <div className="flex gap-2 mt-3 flex-wrap">
            <span className={`severity-badge severity-${finding.severity}`}>{finding.severity}</span>
            <span className={`classification-badge classification-${finding.classification}`}>
              {finding.classification.replace(/_/g, " ")}
            </span>
            {(finding as any).source_metadata?.secret_type && <span className="text-xs px-2.5 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 capitalize">{(finding as any).source_metadata.secret_type.replace(/_/g, " ")}</span>}
            {validityOf(finding) !== "unknown" && <span className={`text-xs px-2.5 py-1 rounded-full border ${(finding as any).source_metadata.validation_status === "active" ? "bg-red-500/10 border-red-500/20 text-red-400" : (finding as any).source_metadata.validation_status === "inactive" ? "bg-green-500/10 border-green-500/20 text-green-400" : "bg-slate-500/10 border-slate-500/20 text-slate-400"}`}>{(finding as any).source_metadata.validation_status}</span>}
            {finding.cwe && !((finding as any).source_metadata?.secret_type) && <span className="text-xs px-2.5 py-1 rounded-full bg-white/[0.04] border border-white/[0.06] text-slate-400">{finding.cwe}</span>}
            <span className={`text-xs px-2.5 py-1 rounded-full border ${getScannerColor(finding.scanner_name)}`}>{brandScannerName(finding.scanner_name)}</span>
          </div>
        </div>

        {/* Location */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Location</h3>
          <div className="font-mono text-sm text-red-400">
            {finding.file_path}:{finding.line_start}{finding.line_end ? `-${finding.line_end}` : ""}
          </div>
          {(finding as any).source_metadata?.masked_value && <div className="text-sm text-slate-500 mt-1">Masked Value: <span className="font-mono text-red-400">{(finding as any).source_metadata.masked_value}</span></div>}
          {(finding as any).source_metadata?.detection_method && <div className="text-sm text-slate-500">Detection: <span className={`text-xs px-2 py-0.5 rounded ${(finding as any).source_metadata.detection_method === "entropy" ? "bg-purple-500/15 text-purple-400" : "bg-red-500/15 text-red-400"}`}>{(finding as any).source_metadata.detection_method}</span></div>}
          {(finding as any).source_metadata?.commit_author && <div className="text-sm text-slate-500">Committed by: <span className="text-slate-400">{(finding as any).source_metadata.commit_author}</span></div>}
          {finding.function_name && <div className="text-sm text-slate-500 mt-1">Function: <span className="text-slate-400">{finding.function_name}</span></div>}
        </div>

        {/* Code Snippet */}
        {finding.code_snippet && (
          <div className="card p-0 overflow-hidden">
            <div className="px-5 py-3 border-b border-white/[0.06]">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Code</h3>
            </div>
            <CodeSnippet snippet={finding.code_snippet} lineStart={finding.line_start} lineEnd={finding.line_end} className="rounded-none border-0" />
          </div>
        )}

        {/* AI Analysis */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">AI Analysis</h3>
          {finding.ai_explanation ? (
            <div className="space-y-4">
              <p className="text-sm text-slate-300 leading-relaxed">{finding.ai_explanation}</p>
              <div className="flex gap-6 text-sm flex-wrap">
                {/* The verdict sits with the confidence that
                    qualifies it, and nowhere near the status control
                    below, which records what a person decided. */}
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">Verdict:</span>
                  <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${verdictTone((finding as any).ai_verdict)}`}>
                    {verdictLabel((finding as any).ai_verdict)}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">Verdict confidence:</span>
                  <span className="font-semibold text-red-400">{finding.ai_confidence != null ? `${(finding.ai_confidence * 100).toFixed(0)}%` : "N/A"}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">Exploitability:</span>
                  <span className="font-semibold text-orange-400">{finding.exploitability_score != null ? `${(finding.exploitability_score * 100).toFixed(0)}%` : "N/A"}</span>
                </div>
              </div>

              {finding.true_positive_reasons.length > 0 && (
                <div className="bg-red-500/5 border border-red-500/10 rounded-lg p-4">
                  <h4 className="text-sm font-medium text-red-400 mb-2">True Positive Indicators</h4>
                  <ul className="space-y-1">{finding.true_positive_reasons.map((r, i) => (
                    <li key={i} className="text-sm text-slate-400 flex items-start gap-2">
                      <svg className="w-4 h-4 text-red-400 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                      {r}
                    </li>
                  ))}</ul>
                </div>
              )}
              {finding.false_positive_reasons.length > 0 && (
                <div className="bg-green-500/5 border border-green-500/10 rounded-lg p-4">
                  <h4 className="text-sm font-medium text-green-400 mb-2">False Positive Indicators</h4>
                  <ul className="space-y-1">{finding.false_positive_reasons.map((r, i) => (
                    <li key={i} className="text-sm text-slate-400 flex items-start gap-2">
                      <svg className="w-4 h-4 text-green-400 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                      {r}
                    </li>
                  ))}</ul>
                </div>
              )}
              {finding.compensating_controls.length > 0 && (
                <div className="bg-red-500/5 border border-red-500/10 rounded-lg p-4">
                  <h4 className="text-sm font-medium text-red-400 mb-2">Compensating Controls</h4>
                  <ul className="space-y-1">{finding.compensating_controls.map((c, i) => (
                    <li key={i} className="text-sm text-slate-400 flex items-start gap-2">
                      <svg className="w-4 h-4 text-red-400 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
                      {c}
                    </li>
                  ))}</ul>
                </div>
              )}
              {/* Evidence — merged into AI Analysis */}
              {finding.evidence.length > 0 && (
                <div className="pt-4 mt-4 border-t border-white/[0.06]">
                  <h4 className="text-sm font-medium text-slate-400 mb-3">Supporting Evidence</h4>
                  <div className="space-y-3">
                    {finding.evidence.map((ev, i) => (
                      <div key={i} className="bg-white/[0.02] border border-white/[0.04] rounded-lg p-4">
                        <div className="flex gap-2 text-sm items-center">
                          <span className="text-xs px-2 py-0.5 rounded bg-purple-500/15 text-purple-400 font-medium">{ev.type}</span>
                          {ev.file && <span className="text-slate-500 font-mono text-xs">{ev.file}</span>}
                        </div>
                        {ev.summary && <p className="text-sm text-slate-400 mt-2">{ev.summary}</p>}
                        {ev.content && (
                          <pre className="bg-[#0d1117] p-3 mt-2 rounded text-xs text-slate-400 overflow-x-auto"><code>{ev.content}</code></pre>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-slate-500">AI analysis pending or not available</p>
          )}
        </div>

        {/* Actions */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Actions</h3>
            <span className="text-[10px] text-slate-600">
              Current: <span className={`font-medium ${statusTextTone(finding)}`}>
                {statusShort(finding)}
                {statusDetail(finding) && ` — ${statusDetail(finding)}`}
              </span>
            </span>
          </div>

          {/* Triage comment input */}
          <div className="mb-3">
            <input
              id="triage-comment"
              type="text"
              placeholder="Add a comment for this action (optional)..."
              className="input-dark text-sm"
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  const target = e.target as HTMLInputElement;
                  // Store for next action
                  (window as any).__voodaTriageComment = target.value;
                }
              }}
            />
          </div>

          {/* Status actions — the same four statuses the sliding
              panel offers, in the same order, so the analyst's
              mental model doesn't fork between the two views. See
              lib/findingState.ts::STATUS_CHOICES for the one list
              both read from.

              These used to be five verdict buttons — True Positive,
              False Positive and so on — which asked the operator to
              record a judgement in the model's vocabulary. A verdict
              is evidence; a status is a decision. The model's own
              verdict is shown with the AI analysis above. */}
          <div className="space-y-2.5">
            <div className="flex gap-2.5 flex-wrap">
              {STATUS_CHOICES.map((opt) => {
                const savedStatus =
                  ((finding as any).status || "").toLowerCase()
                  || lifecycleOf(finding.classification).status;
                const isActive = savedStatus === opt.status;
                const expanded = reasonFor === opt.action;
                const tone = statusTone({ status: opt.status, resolution_reason: null });
                return (
                  <button
                    key={opt.action}
                    onClick={() => {
                      if (opt.needsReason) {
                        setReasonFor(expanded ? null : opt.action);
                        return;
                      }
                      setReasonFor(null);
                      const comment = (document.getElementById("triage-comment") as HTMLInputElement)?.value || undefined;
                      // Resolving sends the implied reason: the column
                      // pairing is a database constraint, not a prompt.
                      handleTriageWithComment(
                        opt.action, comment,
                        opt.action === "resolve" ? RESOLVED_IMPLIES : undefined);
                    }}
                    disabled={!!actionLoading}
                    title={opt.desc}
                    className={`px-3.5 py-2 rounded-lg font-medium text-sm transition-all border inline-flex items-center gap-2 ${
                      expanded
                        ? "bg-white/[0.07] border-white/20 text-white"
                        : isActive
                          ? `${tone.badge} border-white/15`
                          : "text-slate-300 border-white/[0.1] bg-transparent hover:bg-white/[0.04]"
                    }`}
                  >
                    <span className={`w-2 h-2 rounded-full ${tone.dot}`} />
                    {actionLoading === opt.action ? "..." : opt.label}
                    {opt.needsReason && (
                      <svg className={`w-3 h-3 transition-transform ${expanded ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Step two. A close is only submitted once a reason is
                picked, because the pairing is a database constraint
                and not merely a convention. */}
            {reasonFor && (
              <div className="rounded-lg border border-white/[0.08] bg-white/[0.02] p-2.5">
                <p className="text-[10px] text-slate-500 uppercase tracking-wide mb-2">
                  Why dismissed?
                </p>
                <div className="flex gap-2 flex-wrap">
                  {(REASONS_FOR.dismissed || []).map((r) => (
                    <button
                      key={r.reason}
                      onClick={() => {
                        const comment = (document.getElementById("triage-comment") as HTMLInputElement)?.value || undefined;
                        handleTriageWithComment(reasonFor, comment, r.reason);
                      }}
                      disabled={!!actionLoading}
                      title={r.desc}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                        (finding as any).resolution_reason === r.reason
                          ? "bg-white/[0.07] border-white/20 text-white"
                          : "text-slate-300 border-white/[0.1] hover:bg-white/[0.04]"
                      }`}
                    >
                      {actionLoading === r.reason ? "..." : REASON_LABELS[r.reason]}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Decision History (Audit Trail) */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Audit Trail</h3>
            <span className="text-[10px] text-slate-600">{finding.decisions.length} changes</span>
          </div>
          {finding.decisions.length === 0 ? (
            <p className="text-sm text-slate-600 py-4 text-center">No actions taken yet</p>
          ) : (
            <div className="space-y-0">
              {finding.decisions.map((d: any, i: number) => {
                const actionColors: Record<string, string> = {
                  mark_fp: "border-green-500/30 bg-green-500/5",
                  mark_tp: "border-red-500/30 bg-red-500/5",
                  accept_risk: "border-orange-500/30 bg-orange-500/5",
                  reopen: "border-yellow-500/30 bg-yellow-500/5",
                };
                const actionLabels: Record<string, string> = {
                  mark_fp: "Marked as False Positive",
                  mark_tp: "Confirmed as True Positive",
                  accept_risk: "Accepted Risk",
                  reopen: "Reopened for Review",
                  request_review: "Requested Review",
                };
                const borderClass = actionColors[d.action] || "border-slate-700/30 bg-white/[0.01]";

                return (
                  <div key={i} className={`relative pl-8 pb-4 ${i < finding.decisions.length - 1 ? "" : ""}`}>
                    {/* Timeline line */}
                    {i < finding.decisions.length - 1 && (
                      <div className="absolute left-[11px] top-6 bottom-0 w-px bg-white/[0.06]" />
                    )}
                    {/* Timeline dot */}
                    <div className={`absolute left-1 top-1.5 w-[14px] h-[14px] rounded-full border-2 ${
                      d.action === "mark_fp" ? "border-green-400 bg-green-400/20" :
                      d.action === "mark_tp" ? "border-red-400 bg-red-400/20" :
                      d.action === "accept_risk" ? "border-orange-400 bg-orange-400/20" :
                      d.action === "reopen" ? "border-yellow-400 bg-yellow-400/20" :
                      "border-slate-500 bg-slate-500/20"
                    }`} />

                    <div className={`rounded-lg border p-3 ${borderClass}`}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-slate-200">
                          {actionLabels[d.action] || d.action.replace(/_/g, " ")}
                        </span>
                        <span className="text-[10px] text-slate-600">
                          {d.created_at ? new Date(d.created_at).toLocaleString() : ""}
                        </span>
                      </div>

                      {/* Before → After */}
                      {d.previous_classification && d.new_classification && d.previous_classification !== d.new_classification && (
                        <div className="flex items-center gap-2 text-[10px] mb-1">
                          <span className="text-slate-500">{d.previous_classification.replace(/_/g, " ")}</span>
                          <svg className="w-3 h-3 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                          </svg>
                          <span className={`font-medium ${classificationTextTone(d.new_classification)}`}>{classificationLabel(d.new_classification)}</span>
                        </div>
                      )}

                      <div className="flex items-center gap-2 text-[10px]">
                        <span className="text-slate-500">by</span>
                        <span className="text-slate-400 font-medium">{d.user_name || "System"}</span>
                      </div>

                      {d.comment && (
                        <p className="text-xs text-slate-400 mt-1.5 italic">&ldquo;{d.comment}&rdquo;</p>
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
