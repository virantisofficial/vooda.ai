// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * How a model did when Vooda asked it to triage something.
 *
 * TypeScript twin of services/ai_triage/model_probe.py — the Python side
 * owns the vocabulary and a CHECK constraint enforces it in the database.
 * Kept in one file here for the same reason the finding states are: a
 * label invented inline in a component is a label nothing can verify.
 */

export const READY = "ready";
export const NEEDS_SETUP = "needs_setup";
export const UNVERIFIED = "unverified";
export const UNUSABLE = "unusable";

export type ReadinessState =
  | typeof READY | typeof NEEDS_SETUP | typeof UNVERIFIED | typeof UNUSABLE;

export interface AccuracyVerdict {
  total: number;
  correct: number;
  missed_secrets: number;
  unanswered: number;
  headline: string;
  checked_at?: string | null;
  cases?: Array<Record<string, any>>;
}

export interface ProbeVerdict {
  model_id: string;
  state: ReadinessState;
  headline: string;
  remedy: string;
  suggested_config: Record<string, any>;
  detail: Record<string, any>;
  latency_ms: number;
  probed_at?: string | null;
  /** What discovery concluded, kept with the probe verdict. */
  suitability?: string | null;
  suitability_reason?: string | null;
  /** Null until someone runs it — not the same as scoring zero. */
  accuracy?: AccuracyVerdict | null;
}

/** Tone for the accuracy line.
 *
 *  A missed secret is the mistake that matters: raising a harmless
 *  finding costs a reviewer minutes, dismissing a live credential ends
 *  up in an incident report. So any miss reads as a warning however
 *  good the overall count looks. */
export function accuracyTone(a?: AccuracyVerdict | null): string {
  if (!a || a.total === 0) return "text-slate-500";
  if (a.total - a.unanswered === 0) return "text-slate-400";
  if (a.missed_secrets > 0) return "text-amber-400";
  return "text-emerald-400";
}

/** Short word for the badge. Never a token count — that lives in Details.
 *
 * UNVERIFIED reads "Couldn't check", not "Not checked". It means Vooda
 * asked and the provider gave nothing usable back — almost always a
 * 503 — which is a different fact from never having asked. The two
 * were sharing a label while never-checked models showed no badge at
 * all, so the badge said the opposite of what had happened: every card
 * reading "Not checked" was one Vooda had tried and failed to reach.
 */
export function readinessLabel(state?: string): string {
  switch (state) {
    case READY: return "Ready";
    case NEEDS_SETUP: return "Needs Setup";
    case UNVERIFIED: return "Couldn't Check";
    case UNUSABLE: return "Won't Work";
    default: return "Not Checked";
  }
}

/**
 * Badge colours follow the palette already used on this screen:
 * bg-<c>/5 border-<c>/15 text-<c>-400. Written out in full because
 * Tailwind cannot see a class name built by string concatenation.
 */
export function readinessTone(state?: string): string {
  switch (state) {
    case READY: return "bg-emerald-500/5 border-emerald-500/20 text-emerald-400";
    case NEEDS_SETUP: return "bg-amber-500/5 border-amber-500/20 text-amber-400";
    case UNUSABLE: return "bg-rose-500/5 border-rose-500/20 text-rose-400";
    default: return "bg-white/[0.03] border-white/[0.08] text-slate-500";
  }
}

/** Panel tone for the selected model's explanation. */
export function readinessPanelTone(state?: string): string {
  switch (state) {
    case READY: return "bg-emerald-500/5 border-emerald-500/15";
    case NEEDS_SETUP: return "bg-amber-500/5 border-amber-500/15";
    case UNUSABLE: return "bg-rose-500/5 border-rose-500/15";
    default: return "bg-white/[0.02] border-white/[0.06]";
  }
}

/* passesReadyFilter was removed with the "hiding unusable" toggle.
 * One question — can this model triage — is now answered in one place,
 * and everything that cannot goes into a single collapsed section. Two
 * controls and two counts for the same outcome read as a jumble. */

/** A verdict worth explaining under the grid. */
export function needsExplanation(v?: ProbeVerdict): boolean {
  return !!v && v.state !== READY;
}
