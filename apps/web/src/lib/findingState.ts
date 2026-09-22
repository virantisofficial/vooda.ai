// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
//
// Client-side twin of apps/api/app/core/finding_state.py.
//
// The backend's vocabulary was consolidated first; the dashboard, the
// finding panel and the incident drawer each still carried their own
// copy of "what counts as settled", and all three counted
// likely_false_positive as settled — telling the operator "no action
// needed" on the strength of an AI guess nobody had reviewed.
//
// The rule, same as the backend: only a decision closes a finding. An
// AI verdict is an opinion, shown as such.

/** Settled — somebody decided, or the credential was neutralised. */
export const CLOSED = [
  "confirmed_false_positive",
  "test_credential",
  "accepted_risk",
  "rotated",
  "revoked",
  "resolved_file_deleted",
  "resolved_item_deleted",
  "resolved_repo_removed",
  "resolved_source_removed",
] as const;

/** An AI verdict with nobody behind it. Open, but de-prioritised. */
export const AI_LOW_RISK = ["likely_false_positive"] as const;

/** AI opinion of any kind — advisory, never a resolution. */
export const AI_ADVISORY = ["likely_true_positive", "likely_false_positive"] as const;

const norm = (c?: string | null) => (c || "").toLowerCase();

/** Settled. Mirrors is_closed() server-side, incl. legacy resolved_*. */
export function isClosed(cls?: string | null): boolean {
  const c = norm(cls);
  return (CLOSED as readonly string[]).includes(c) || c.startsWith("resolved");
}

/** Still work to do. */
export function isOpen(cls?: string | null): boolean {
  return !isClosed(cls);
}

/** Open, but the model judged it not a real exposure. */
export function isAiLowRisk(cls?: string | null): boolean {
  return (AI_LOW_RISK as readonly string[]).includes(norm(cls));
}

/** Carries an AI verdict rather than a human decision. */
export function isAiAdvisory(cls?: string | null): boolean {
  return (AI_ADVISORY as readonly string[]).includes(norm(cls));
}

/**
 * Display label. The AI verdicts are deliberately prefixed: calling
 * likely_false_positive "False Positive" asserts a conclusion the
 * system has not reached, and reads identically to the human-confirmed
 * verdict beside it in the same list.
 */
export function classificationLabel(cls?: string | null): string {
  switch (norm(cls)) {
    case "needs_review": return "Needs Review";
    case "not_enough_evidence": return "Needs Review";
    case "likely_true_positive": return "AI: likely real";
    case "likely_false_positive": return "AI: likely not a secret";
    case "confirmed_true_positive": return "Confirmed TP";
    case "confirmed_false_positive": return "Confirmed FP";
    case "accepted_risk": return "Accepted Risk";
    case "test_credential": return "Test Credential";
    case "rotated":
    case "revoked":
    case "resolved": return "Rotated / Revoked";
    default: return norm(cls).replace(/_/g, " ");
  }
}


/** Human label for the lifecycle pair. Prefers the new columns and
 *  falls back to the legacy classification for any stale payload. */
export function statusLabel(obj: any): string {
  const st = (obj?.status || "").toLowerCase();
  const rs = (obj?.resolution_reason || "").toLowerCase();
  const REASONS: Record<string, string> = {
    rotated: "Rotated",
    revoked: "Revoked",
    provider_disabled: "Provider disabled",
    false_positive: "False positive",
    test_credential: "Test credential",
    acceptable_risk: "Acceptable risk",
    mitigating_control: "Mitigating control",
    no_longer_present: "No longer present",
  };
  if (st === "resolved" || st === "dismissed") {
    const head = st === "resolved" ? "Resolved" : "Dismissed";
    return rs ? `${head} — ${REASONS[rs] || rs.replace(/_/g, " ")}` : head;
  }
  if (st === "triaging") return "Triaging";
  if (st === "open") {
    // An open finding shows the model's opinion, clearly marked as one.
    const v = (obj?.ai_verdict || "").toLowerCase();
    if (v === "likely_fp") return "Open — AI: likely not a secret";
    if (v === "likely_tp") return "Open — AI: likely real";
    return "Open";
  }
  return classificationLabel(obj?.classification);
}
