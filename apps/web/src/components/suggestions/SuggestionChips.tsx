"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * SuggestionChips — one-click triage suggestions derived from
 * deterministic scanner signals (`is_placeholder`, `file_context`,
 * `detection_engine`).  Powers gap #6 of the commercial-grade audit:
 * the scanner already computes these flags, FindingPanel already
 * displays them as passive badges, but the analyst still has to
 * manually navigate the dropdown to triage.  Suggestion chips give
 * them a one-click confirm path.
 *
 * Design: variant B1 of the gap-#6 design discussion.
 *
 * Display rules — chip is only rendered when it's useful:
 *   - already-in-suggested-state                       → HIDE (no-op)
 *   - AI hasn't run (ai_confidence == null)            → SHOW (fast-path)
 *   - AI agrees with the signal                        → SHOW (one-click confirm)
 *   - AI disagrees, confidence < 0.7                   → SHOW with "AI uncertain" pill
 *   - AI disagrees, confidence ≥ 0.7                   → HIDE (respect AI)
 *
 * The hide-on-high-confidence-disagreement rule is the key piece —
 * it prevents the chip from competing with a confident AI verdict
 * (which is what GitGuardian / Snyk / Wiz effectively do).  Showing
 * both when AI is confident would create decision fatigue at scale.
 *
 * Audit trail: clicking a chip calls `onSuggest(action, signal)` —
 * the caller is responsible for adding the signal id to the audit
 * payload (`source: "suggestion_<signal>"`).  The History tab then
 * renders the row with a `via=suggestion_*` tag so compliance can
 * answer "what fraction of TPs were signal-confirmed?".
 *
 * Added 2026-05-18 as part of the gap-#6 implementation.
 */

import { useMemo } from "react";

// Match the same six action names the drawer dropdowns use so a
// SuggestionChip click queues the same pending state.  See
// IncidentDetailDrawer.tsx ACTION_TO_PATCH for the canonical map.
type TriageAction = "mark_tp" | "mark_fp" | "mark_test" | "mark_rotated" | "accept_risk" | "reopen";

interface SignalSpec {
  // Stable identifier used in audit `via` (e.g. "suggestion_placeholder").
  signalId: string;
  // Action this signal recommends.
  action: TriageAction;
  // Pretty label rendered on the chip.
  label: string;
  // Reason text shown in the chip's secondary line + auto-filled
  // into the audit comment when the user clicks.
  reason: string;
  // Classification value the action puts on the record — used for
  // the "already in that state" check.  Lowercase to match the
  // SecretIncident.classification VARCHAR.
  expectedClassification: string;
  // Per-chip colour palette (matches drawer button colours).
  tone: "fp" | "test" | "rotated";
}

/**
 * Source-of-truth shape for the signal inputs.  Both findings
 * (`source_metadata`) and incidents (`signals` derived field) feed
 * through the same shape so the component is surface-agnostic.
 */
export interface SignalInputs {
  is_placeholder?: boolean;
  // For findings: `file_context === "test_file"`.
  // For incidents: the aggregated `is_test_file_only` flag.
  is_test_file?: boolean;
  // For findings: `detection_engine === "secret_scan_history"`.
  // For incidents: the aggregated `is_git_history_only` flag.
  is_git_history?: boolean;
  // Live validation status — needed for the git-history → rotated chip.
  // "inactive" / "revoked" means the credential no longer works, so
  // marking it rotated is a safe deterministic call.
  validation_status?: string | null;
}

interface Props {
  signals: SignalInputs;
  // Current persisted classification (lowercase, e.g.
  // "confirmed_true_positive" / "needs_review").  Used to hide
  // already-in-state chips.
  classification: string;
  // AI confidence from the existing ai_confidence column.  null when
  // AI hasn't run yet (e.g. new finding pre-triage) — chips show
  // immediately in that case.
  aiConfidence: number | null;
  // Click handler.  Caller is responsible for staging pendingAction
  // or committing directly, plus passing `source` to the backend.
  onSuggest: (action: TriageAction, signalId: string, reason: string) => void;
  // Disable all chips during in-flight save.
  disabled?: boolean;
}

// Threshold above which AI confidently disagreeing with a signal
// hides the chip entirely.  0.7 picked as a balance between
// "respect AI when it's pretty sure" and "still surface signals
// when AI is on shakier ground".  Matches the cutoff used in the
// existing analytics in apps/api/app/routers/metrics.py for AI
// confidence buckets.
const AI_CONFIDENT_THRESHOLD = 0.7;

// Maps the suggestion action to the classification(s) that
// represent "AI already agrees".  Used by `aiAgrees()`.
const AGREEMENT_MATCHERS: Record<TriageAction, (cls: string) => boolean> = {
  mark_fp: (cls) => cls.includes("false_positive"),
  mark_tp: (cls) => cls.includes("true_positive"),
  mark_test: (cls) => cls === "test_credential",
  mark_rotated: (cls) => cls === "rotated" || cls === "revoked" || cls === "resolved",
  accept_risk: (cls) => cls === "accepted_risk",
  reopen: (cls) => cls === "needs_review",
};

// Build the per-tone class strings centrally so all chips share a
// consistent visual vocabulary across surfaces (drawer + standalone
// page).  Tone choices mirror the drawer button colours.
const TONE_CLASS: Record<SignalSpec["tone"], { confirm: string; warn: string }> = {
  fp: {
    confirm:
      "bg-slate-500/15 text-slate-200 border-slate-400/40 hover:bg-slate-500/25 hover:border-slate-400/70",
    warn:
      "bg-amber-500/10 text-amber-200 border-amber-500/40 hover:bg-amber-500/20 hover:border-amber-500/70",
  },
  test: {
    confirm:
      "bg-blue-500/15 text-blue-200 border-blue-400/40 hover:bg-blue-500/25 hover:border-blue-400/70",
    warn:
      "bg-amber-500/10 text-amber-200 border-amber-500/40 hover:bg-amber-500/20 hover:border-amber-500/70",
  },
  rotated: {
    confirm:
      "bg-emerald-500/15 text-emerald-200 border-emerald-400/40 hover:bg-emerald-500/25 hover:border-emerald-400/70",
    warn:
      "bg-amber-500/10 text-amber-200 border-amber-500/40 hover:bg-amber-500/20 hover:border-amber-500/70",
  },
};

/**
 * Decide which chips to render given the signals, current
 * classification, and AI confidence.  Pure function — exported so
 * unit tests can call it directly without rendering React.
 */
export function computeSuggestions(
  signals: SignalInputs,
  classification: string,
  aiConfidence: number | null,
): { spec: SignalSpec; warn: boolean }[] {
  const candidates: SignalSpec[] = [];

  if (signals.is_placeholder === true) {
    candidates.push({
      signalId: "suggestion_placeholder",
      action: "mark_fp",
      label: "Mark as False Positive",
      reason: "Matches known placeholder pattern (changeme / xxx / your-key-here)",
      expectedClassification: "confirmed_false_positive",
      tone: "fp",
    });
  }
  if (signals.is_test_file === true) {
    candidates.push({
      signalId: "suggestion_test_file",
      action: "mark_test",
      label: "Mark as Test Credential",
      reason: "Located in test/spec/fixture directory",
      expectedClassification: "test_credential",
      tone: "test",
    });
  }
  // Git-history → Rotated/Revoked is only meaningful when validation
  // also confirms the credential is dead.  An ACTIVE git-history
  // credential is dangerous (leak still works) — don't suggest
  // closing it.  An UNVERIFIED git-history credential is ambiguous —
  // skip to avoid auto-suggesting "rotated" for a possibly-live key.
  if (
    signals.is_git_history === true
    && (signals.validation_status === "inactive" || signals.validation_status === "revoked")
  ) {
    candidates.push({
      signalId: "suggestion_git_history",
      action: "mark_rotated",
      label: "Mark as Rotated / Revoked",
      reason: "Deleted from current code (git history) + verified inactive",
      expectedClassification: "rotated",
      tone: "rotated",
    });
  }

  const cls = (classification || "").toLowerCase();
  const aiHasRun = aiConfidence !== null && aiConfidence !== undefined;
  const aiConfident = aiHasRun && (aiConfidence as number) >= AI_CONFIDENT_THRESHOLD;

  // Treat "needs_review" as "AI hasn't made a decisive call" even
  // when ai_confidence is set — it's the inbox state and the chip
  // should always be available there as a fast-path.  Re-opened
  // findings (user manually reset to needs_review) also land here:
  // chip helps the analyst quickly re-triage.
  const isInboxState = cls === "needs_review";

  return candidates
    .map((spec) => {
      // Already in the target state — chip would be a no-op.
      if (AGREEMENT_MATCHERS[spec.action](cls)) {
        return null;
      }
      // Inbox state — show chip regardless of AI confidence.
      if (isInboxState) {
        return { spec, warn: false };
      }
      // AI hasn't run at all — show as fast-path.
      if (!aiHasRun) {
        return { spec, warn: false };
      }
      // From here on: AI has run AND classification is NOT
      // needs_review AND doesn't match the suggestion.  This means
      // either AI or a human committed to a different verdict.
      //
      // - High-confidence AI verdict → respect it, hide chip.
      // - Low-confidence AI verdict → surface chip with "AI uncertain"
      //   warning styling so analyst sees the alternative perspective.
      if (aiConfident) {
        return null;
      }
      return { spec, warn: true };
    })
    .filter((x): x is { spec: SignalSpec; warn: boolean } => x !== null);
}

export default function SuggestionChips({
  signals,
  classification,
  aiConfidence,
  onSuggest,
  disabled = false,
}: Props) {
  const chips = useMemo(
    () => computeSuggestions(signals, classification, aiConfidence),
    [signals, classification, aiConfidence],
  );

  if (chips.length === 0) return null;

  return (
    <div className="flex flex-wrap items-center gap-2">
      {/* "Suggestions" label so the analyst understands these are
          hints, not committed decisions.  Sparkle icon hints at the
          signal-driven nature without overclaiming "AI". */}
      <span className="inline-flex items-center gap-1 text-[10px] text-slate-500 uppercase tracking-wider shrink-0">
        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
        Suggestions
      </span>
      {chips.map(({ spec, warn }) => {
        const tone = TONE_CLASS[spec.tone];
        return (
          <button
            key={spec.signalId}
            type="button"
            onClick={() => onSuggest(spec.action, spec.signalId, spec.reason)}
            disabled={disabled}
            title={`${spec.reason}${warn ? " · AI verdict is low-confidence — second opinion" : ""}`}
            className={`inline-flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-md border font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
              warn ? tone.warn : tone.confirm
            }`}
          >
            {warn && (
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M5 19h14a2 2 0 001.84-2.75L13.74 4a2 2 0 00-3.48 0l-7.1 12.25A2 2 0 005 19z" />
              </svg>
            )}
            <span className="truncate max-w-[260px]">{spec.label}</span>
            {warn && <span className="text-[9px] text-amber-300/80 normal-case">(AI uncertain)</span>}
          </button>
        );
      })}
    </div>
  );
}
