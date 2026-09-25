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

export interface ProbeVerdict {
  model_id: string;
  state: ReadinessState;
  headline: string;
  remedy: string;
  suggested_config: Record<string, any>;
  detail: Record<string, any>;
  latency_ms: number;
  probed_at?: string | null;
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
    case NEEDS_SETUP: return "Needs setup";
    case UNVERIFIED: return "Couldn't check";
    case UNUSABLE: return "Won't work";
    default: return "Not checked";
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
