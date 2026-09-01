# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Who established a finding's classification.

`Classification` separates `LIKELY_*` from `CONFIRMED_*` on purpose.
`LIKELY_*` is the scanner's or the model's opinion. `CONFIRMED_*` is the
stronger claim that somebody established this — and an auditor reading
`CONFIRMED_FALSE_POSITIVE` reasonably concludes a person signed off.

Nothing enforced that. Two paths wrote `CONFIRMED_*` without a human:

  * org-wide learning marked findings `CONFIRMED_FALSE_POSITIVE` off
    three FP decisions elsewhere, leaving no rule and no audit row.
    That path is gone.
  * the triage cache replays a stored decision onto a *new* finding.
    That one is legitimate and worth keeping — re-asking a human about
    identical code in the same place is how a queue becomes unusable —
    but the new finding was left claiming a confirmation that nothing
    on it pointed back to.

So this module does not ban automation from writing `CONFIRMED_*`. It
requires that every such write names its mechanism and its actor, and
refuses the write when it cannot. A replayed decision is as auditable
as the original because it carries the original decider forward.

Provenance is recorded on the finding rather than derived from
`FindingDecision`, because a replay legitimately has no decision row of
its own — the decision belongs to a different finding, and pointing at
it is exactly what makes the replay reviewable.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import event, inspect as sa_inspect
from sqlalchemy.orm import Session

from apps.api.app.models.finding import Classification


class UnprovenancedClassification(RuntimeError):
    """Raised when a CONFIRMED_* value is written with no actor.

    Deliberately fatal. A silent fallback to LIKELY_* would quietly
    change a triage verdict, and a warning would be a compliance hole
    that logs itself.
    """


#: Values that assert somebody established the verdict. Only these
#: require provenance — LIKELY_*, NEEDS_REVIEW and the closure states
#: are self-describing as machine or workflow output.
ESTABLISHED_CLASSIFICATIONS: frozenset = frozenset({
    Classification.CONFIRMED_TRUE_POSITIVE.value,
    Classification.CONFIRMED_FALSE_POSITIVE.value,
})

#: How a classification came to be.
MECHANISM_HUMAN_TRIAGE = "human_triage"      # a person, in the UI or API
MECHANISM_BULK_TRIAGE = "bulk_triage"        # a person, over a selection
MECHANISM_CACHE_REPLAY = "cache_replay"      # a stored decision re-applied
MECHANISM_IMPORT = "import"                  # carried in from another tool

VALID_MECHANISMS: frozenset = frozenset({
    MECHANISM_HUMAN_TRIAGE, MECHANISM_BULK_TRIAGE,
    MECHANISM_CACHE_REPLAY, MECHANISM_IMPORT,
})


def _value(classification: Any) -> Optional[str]:
    """Normalise an enum or raw string to its stored value."""
    if classification is None:
        return None
    return getattr(classification, "value", classification)


def requires_provenance(classification: Any) -> bool:
    return _value(classification) in ESTABLISHED_CLASSIFICATIONS


def build(
    *,
    mechanism: str,
    actor: Any,
    decision_id: Any = None,
    source_finding_id: Any = None,
    note: Optional[str] = None,
) -> dict:
    """Assemble a provenance record.

    `actor` is whoever the confirmation is attributable to — a user id
    for direct triage, and for a replay the user who made the ORIGINAL
    decision, not the scan that copied it. Attributing a replay to the
    system would launder a human decision into a machine one and lose
    the only name an auditor can follow.
    """
    if mechanism not in VALID_MECHANISMS:
        raise ValueError(f"unknown classification mechanism: {mechanism!r}")
    if actor in (None, "", "system"):
        raise ValueError(
            f"mechanism {mechanism!r} needs an actor a confirmation can be "
            f"attributed to; 'system' is not one"
        )

    record = {
        "mechanism": mechanism,
        "actor": str(actor),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    if decision_id is not None:
        record["decision_id"] = str(decision_id)
    if source_finding_id is not None:
        record["source_finding_id"] = str(source_finding_id)
    if note:
        record["note"] = note
    return record


def set_classification(
    finding,
    classification: Any,
    *,
    mechanism: str,
    actor: Any = None,
    decision_id: Any = None,
    source_finding_id: Any = None,
    note: Optional[str] = None,
) -> None:
    """Set a classification and, when it is an established one, its
    provenance. The single supported way to write `CONFIRMED_*`."""
    if requires_provenance(classification):
        finding.classification_provenance = build(
            mechanism=mechanism, actor=actor, decision_id=decision_id,
            source_finding_id=source_finding_id, note=note,
        )
    finding.classification = classification


def _changed_to_established(obj, is_new: bool) -> bool:
    if not requires_provenance(getattr(obj, "classification", None)):
        return False
    if is_new:
        return True
    # An unrelated edit to a row that was already confirmed is not a new
    # claim, so only an actual change to the column is checked.
    try:
        return sa_inspect(obj).attrs.classification.history.has_changes()
    except Exception:
        return False


def _guard(session: Session, flush_context, instances) -> None:
    from apps.api.app.models.finding import NormalizedFinding

    for is_new, bucket in ((True, session.new), (False, session.dirty)):
        for obj in bucket:
            if not isinstance(obj, NormalizedFinding):
                continue
            if not _changed_to_established(obj, is_new):
                continue
            prov = getattr(obj, "classification_provenance", None) or {}
            if prov.get("mechanism") in VALID_MECHANISMS and prov.get("actor"):
                continue
            raise UnprovenancedClassification(
                f"finding {getattr(obj, 'id', '?')} was set to "
                f"{_value(obj.classification)!r} with no provenance. "
                f"A confirmed verdict must name who established it — use "
                f"core.classification_provenance.set_classification()."
            )


def install() -> None:
    """Register the guard. Idempotent."""
    if not event.contains(Session, "before_flush", _guard):
        event.listen(Session, "before_flush", _guard)


install()
