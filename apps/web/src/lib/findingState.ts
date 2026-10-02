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


/** Display name for every resolution reason, including the one only
 *  Vooda sets. Exported because the triage control, the filter bar and
 *  the status badges must all spell a reason the same way. */
export const REASON_LABELS: Record<string, string> = {
  rotated: "Rotated",
  revoked: "Revoked",
  provider_disabled: "Provider disabled",
  false_positive: "False positive",
  test_credential: "Test credential",
  acceptable_risk: "Acceptable risk",
  mitigating_control: "Mitigating control",
  no_longer_present: "No longer present",
};


/**
 * The statuses a human may select, and the API action each one sends.
 *
 * This is the whole triage vocabulary the operator sees. It is four
 * statuses, not five verdicts: the model's opinion is rendered beside
 * the confidence score and never appears here, because a verdict is
 * not a decision and offering both in one list invited operators to
 * "set" a finding to something the AI had merely guessed.
 *
 * `needsReason` says whether the operator is ASKED for a reason, which
 * is not the same as whether one is stored. The database rejects any
 * closing status without one, and both closing statuses send one — but
 * only dismissal is worth a question, because its four answers lead to
 * four different outcomes. Resolving sends RESOLVED_IMPLIES without
 * asking, since every way of neutralising a credential lands in the
 * same place.
 */
export const STATUS_CHOICES: {
  status: string;
  action: string;
  label: string;
  desc: string;
  needsReason: boolean;
}[] = [
  { status: "open", action: "reopen", label: "Open", needsReason: false,
    desc: "Back in the queue, nobody has decided" },
  { status: "triaging", action: "mark_tp", label: "Triaging", needsReason: false,
    desc: "Real secret, remediation in progress" },
  { status: "resolved", action: "resolve", label: "Resolved", needsReason: false,
    desc: "The credential can no longer be used" },
  { status: "dismissed", action: "dismiss", label: "Dismissed", needsReason: true,
    desc: "No action needed on this exposure" },
];


/**
 * The reason stored when someone resolves a finding.
 *
 * Resolving used to ask which of three: rotated, revoked, or provider
 * disabled. It no longer does, for two reasons that agree.
 *
 * In this codebase all three collapse onto the same legacy
 * Classification (`_CLOSE_REASON_TO_CLASSIFICATION`), nothing branches
 * on which was chosen, and `REMEDIATED_REASONS` has no production
 * reader at all — so the question cost a click and bought nothing.
 *
 * And no comparable product asks it. GitLab's Resolved takes no
 * reason; GitGuardian's Resolved takes no reason; GitHub has one flat
 * close list where "revoked" is a single entry rather than a category.
 * Every one of them does ask why a finding was DISMISSED, which is the
 * asymmetry kept below.
 *
 * The three values stay in the vocabulary: the database constraint
 * requires a reason on a closing status, rows may already carry any of
 * them, and API clients may still send them.
 */
export const RESOLVED_IMPLIES = "rotated";


/**
 * Reasons a human may pick, per closing status — the client mirror of
 * REASONS_FOR ∩ HUMAN_SELECTABLE_REASONS.
 *
 * Only `dismissed` has an entry: the dismissal reasons each map to a
 * different classification, and those drive the false-positive rate in
 * reports, the suppression rules the pattern learner proposes, and
 * three separate ticketing exclusions. Picking the wrong one changes
 * what the product does, so it is worth asking.
 *
 * `no_longer_present` is deliberately absent: Vooda sets it when it
 * loses sight of the artifact, and the triage endpoint returns 422 if
 * a person sends it. It still appears in REASON_LABELS above, because
 * findings carrying it have to render and be filterable.
 */
/**
 * Every reason a row of each status may carry — what the FILTER offers.
 *
 * Deliberately not REASONS_FOR. Filtering and deciding are different
 * questions: a person can no longer choose how a credential was
 * neutralised, and never could set `no_longer_present`, but findings
 * carry all of these and have to be findable. Narrowing the filter to
 * what the triage control offers would hide rows that exist.
 */
export const FILTERABLE_REASONS_FOR: Record<string, string[]> = {
  resolved: ["rotated", "revoked", "provider_disabled"],
  dismissed: [
    "false_positive", "test_credential", "acceptable_risk",
    "mitigating_control", "no_longer_present",
  ],
};


export const REASONS_FOR: Record<string, { reason: string; desc: string }[]> = {
  dismissed: [
    { reason: "false_positive", desc: "Not a credential at all" },
    { reason: "test_credential", desc: "A fake value, intentionally committed" },
    { reason: "acceptable_risk", desc: "Real, exposed, and signed off anyway" },
    { reason: "mitigating_control", desc: "Reachable only behind another control" },
  ],
};


/**
 * The model's verdict, rendered as its own thing.
 *
 * It is advisory: an AI verdict annotates an open finding and never
 * closes one. Keeping it out of the status vocabulary — and showing it
 * next to the confidence score that qualifies it — is what stops a
 * guess from reading like a decision somebody made.
 */
export const VERDICT_LABELS: Record<string, string> = {
  likely_tp: "Likely Real",
  likely_fp: "Likely Not a Secret",
  unsure: "Unsure",
};

export function verdictLabel(v?: string | null): string {
  return VERDICT_LABELS[(v || "").toLowerCase()] || "Not assessed";
}

/** Badge colours for a verdict. Deliberately dimmer than the status
 *  palette: emphasis, never a claim about safety. */
export function verdictTone(v?: string | null): string {
  switch ((v || "").toLowerCase()) {
    case "likely_tp":
      return "bg-red-500/15 text-red-400";
    case "likely_fp":
      return "bg-slate-500/15 text-slate-400";
    case "unsure":
      return "bg-amber-500/15 text-amber-400";
    default:
      return "bg-slate-500/10 text-slate-500";
  }
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

/**
 * Secondary detail beside a status: the reason it closed, and nothing
 * else.
 *
 * This used to fall back to the model's verdict on an open finding,
 * which is how "Open — AI: Likely Real" kept appearing on the control
 * that records what a person decided. Every caller that wanted the
 * verdict now asks for it by name, next to the confidence score that
 * qualifies it.
 */
export function statusDetail(obj: any): string {
  const rs = (obj?.resolution_reason || "").toLowerCase();
  if (rs) return REASON_LABELS[rs] || rs.replace(/_/g, " ");
  return "";
}


/**
 * Lifecycle for a legacy classification value — the client-side mirror
 * of core/finding_status.py::from_classification.
 *
 * Needed for optimistic UI: when an operator picks an action the panel
 * previews the result before the server answers, and the only thing it
 * has at that moment is the classification the action maps to.
 */
export function lifecycleOf(cls?: string | null): {
  status: string;
  resolution_reason: string | null;
} {
  switch ((cls || "").toLowerCase()) {
    case "confirmed_true_positive":
      return { status: "triaging", resolution_reason: null };
    case "confirmed_false_positive":
      return { status: "dismissed", resolution_reason: "false_positive" };
    case "test_credential":
      return { status: "dismissed", resolution_reason: "test_credential" };
    case "accepted_risk":
      return { status: "dismissed", resolution_reason: "acceptable_risk" };
    case "rotated":
    case "revoked":
    case "resolved":
      return { status: "resolved", resolution_reason: "rotated" };
    case "resolved_file_deleted":
    case "resolved_item_deleted":
    case "resolved_repo_removed":
    case "resolved_source_removed":
      return { status: "dismissed", resolution_reason: "no_longer_present" };
    default:
      return { status: "open", resolution_reason: null };
  }
}

/**
 * A finding as it WOULD look under a pending status + reason.
 *
 * The sibling below previews a legacy classification instead. Both
 * exist because the panel stages a lifecycle pair while the four list
 * screens still stage an action that maps to a classification.
 */
export function previewLifecycle(
  obj: any,
  status?: string | null,
  reason?: string | null,
): any {
  if (!status) return obj;
  return { ...obj, status, resolution_reason: reason || null };
}


/** A finding as it WOULD look under a pending classification change. */
export function previewOf(obj: any, pendingCls?: string | null): any {
  if (!pendingCls) return obj;
  return { ...obj, ...lifecycleOf(pendingCls) };
}


/** Text colour for a lifecycle, for places without a pill. */
export function statusTextTone(obj: any): string {
  const t = statusTone(obj).dot;              // bg-xxx-400 / bg-xxx-500
  return t.replace(/^bg-/, "text-");
}

/** Text colour for a bare legacy classification (decision history). */
export function classificationTextTone(cls?: string | null): string {
  return statusTextTone(lifecycleOf(cls));
}
