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


/**
 * Badge colour for a finding's lifecycle.
 *
 * Keyed on status — NOT on the legacy classification, which produced
 * two wrong results at once: findings with the same status rendered in
 * different colours, and every `likely_false_positive` rendered green
 * even though it is OPEN and nobody has reviewed it. Green is a claim
 * of safety, and an unreviewed AI guess has not earned it.
 *
 * Green therefore means one thing only: the credential was actually
 * neutralised. Dismissed is neutral — correct, but not an achievement.
 */
export function statusTone(obj: any): { badge: string; dot: string } {
  const st = (obj?.status || "").toLowerCase();
  const verdict = (obj?.ai_verdict || "").toLowerCase();

  if (st === "resolved")
    return { badge: "bg-green-500/10 text-green-400", dot: "bg-green-400" };
  if (st === "dismissed")
    return { badge: "bg-slate-500/10 text-slate-400", dot: "bg-slate-400" };
  if (st === "triaging")
    return { badge: "bg-blue-500/10 text-blue-400", dot: "bg-blue-400" };
  // Open. The model's opinion sets emphasis, never safety.
  if (verdict === "likely_fp")
    return { badge: "bg-slate-500/10 text-slate-400", dot: "bg-slate-500" };
  if (verdict === "likely_tp")
    return { badge: "bg-red-500/10 text-red-400", dot: "bg-red-400" };
  return { badge: "bg-amber-500/10 text-amber-400", dot: "bg-amber-400" };
}

/** Short badge text: the status word. */
export function statusShort(obj: any): string {
  const st = (obj?.status || "").toLowerCase();
  if (st === "resolved") return "Resolved";
  if (st === "dismissed") return "Dismissed";
  if (st === "triaging") return "Triaging";
  if (st === "open") return "Open";
  return classificationLabel(obj?.classification);
}

/** Secondary detail: the reason, or the AI's opinion on an open one. */
export function statusDetail(obj: any): string {
  const st = (obj?.status || "").toLowerCase();
  const rs = (obj?.resolution_reason || "").toLowerCase();
  if (rs) return rs.replace(/_/g, " ").replace(/^./, (c: string) => c.toUpperCase());
  if (st === "open") {
    const v = (obj?.ai_verdict || "").toLowerCase();
    if (v === "likely_fp") return "AI: likely not a secret";
    if (v === "likely_tp") return "AI: likely real";
    if (v === "unsure") return "AI: unsure";
  }
  return "";
}
