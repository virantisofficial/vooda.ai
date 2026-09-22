# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Single source of truth for what a finding's ``classification`` MEANS.

Before this module every caller hand-rolled its own tuple of
classifications, and they disagreed. ``LIKELY_FALSE_POSITIVE`` counted as
CLOSED in the metrics router and as UNDECIDED in the occurrence
propagator — a contradiction covering ~90% of all findings, which meant
the dashboard reported an unconfirmed AI guess as settled work.

The rule this module encodes: **only a decision closes a finding.** An
AI verdict is an opinion. ``LIKELY_*`` is therefore open — the AI's
opinion is carried by ``ai_confidence``, not by the closure state. That
is also why GitHub, GitGuardian and GitLab all require an explicit
resolution reason to leave the open state.

Adding a value to ``Classification`` without adding it to exactly one of
``CLOSED`` / ``OPEN`` raises at import time (see ``_assert_total``), so
the taxonomy cannot silently drift again.
"""

from typing import Iterable

from apps.api.app.models.finding import Classification

# ── The primary axis: is there still work to do? ─────────────────────

#: Settled. Somebody decided, or the credential was provably neutralised.
#: Nothing here is the product of an AI verdict alone.
CLOSED: tuple[Classification, ...] = (
    Classification.CONFIRMED_FALSE_POSITIVE,
    Classification.TEST_CREDENTIAL,
    Classification.ACCEPTED_RISK,
    Classification.ROTATED,
    Classification.RESOLVED_FILE_DELETED,
    Classification.RESOLVED_ITEM_DELETED,
    Classification.RESOLVED_REPO_REMOVED,
    Classification.RESOLVED_SOURCE_REMOVED,
)

#: Open work. Note CONFIRMED_TRUE_POSITIVE is open: a confirmed real
#: secret is the most open thing in the system until it is rotated.
OPEN: tuple[Classification, ...] = (
    Classification.NEEDS_REVIEW,
    Classification.NOT_ENOUGH_EVIDENCE,
    Classification.LIKELY_TRUE_POSITIVE,
    Classification.LIKELY_FALSE_POSITIVE,
    Classification.CONFIRMED_TRUE_POSITIVE,
)

# ── Secondary axes. Orthogonal to open/closed; never a substitute. ───

#: Nobody has ruled on these yet, so a verdict may propagate into them.
#: A superset of AI_ADVISORY: it also covers "no opinion at all".
UNDECIDED: tuple[Classification, ...] = (
    Classification.NEEDS_REVIEW,
    Classification.NOT_ENOUGH_EVIDENCE,
    Classification.LIKELY_TRUE_POSITIVE,
    Classification.LIKELY_FALSE_POSITIVE,
)

#: An AI opinion with no human behind it. Safe to present as a
#: low-priority bucket; never safe to present as resolved.
AI_ADVISORY: tuple[Classification, ...] = (
    Classification.LIKELY_TRUE_POSITIVE,
    Classification.LIKELY_FALSE_POSITIVE,
)

#: Open, but the AI judged it not a real exposure. These are what a
#: findings list should collapse by default — hidden from the front
#: page, still counted as open.
AI_LOW_RISK: tuple[Classification, ...] = (
    Classification.LIKELY_FALSE_POSITIVE,
)

#: A human decided. Requires classification_provenance.
CONFIRMED: tuple[Classification, ...] = (
    Classification.CONFIRMED_TRUE_POSITIVE,
    Classification.CONFIRMED_FALSE_POSITIVE,
)

#: "Judged not a real exposure", at any confidence. For FP-rate
#: reporting only — do NOT use as a closure test.
FALSE_POSITIVE_VERDICTS: tuple[Classification, ...] = (
    Classification.LIKELY_FALSE_POSITIVE,
    Classification.CONFIRMED_FALSE_POSITIVE,
)

#: "Judged a real exposure", at any confidence.
TRUE_POSITIVE_VERDICTS: tuple[Classification, ...] = (
    Classification.LIKELY_TRUE_POSITIVE,
    Classification.CONFIRMED_TRUE_POSITIVE,
)

#: Carries an AI verdict of any kind. Used to answer "has triage run
#: on this finding yet?" — not "is it settled".
ANY_VERDICT: tuple[Classification, ...] = (
    FALSE_POSITIVE_VERDICTS + TRUE_POSITIVE_VERDICTS
)

#: The leak was actually cleaned up — the only states MTTR may count.
#: Admin deletions (RESOLVED_REPO_REMOVED / RESOLVED_SOURCE_REMOVED) are
#: deliberately absent: they mean "Vooda lost visibility", not "fixed".
#: Counting them would let deleting a repository read as an instant fix.
REMEDIATED: tuple[Classification, ...] = (
    Classification.ROTATED,
    Classification.RESOLVED_FILE_DELETED,
    Classification.RESOLVED_ITEM_DELETED,
)


def _assert_total() -> None:
    """Every classification must be exactly one of CLOSED / OPEN."""
    covered = set(CLOSED) | set(OPEN)
    missing = set(Classification) - covered
    if missing:
        raise RuntimeError(
            "finding_state: unclassified Classification value(s): "
            f"{sorted(m.value for m in missing)}. Add each to CLOSED or "
            "OPEN in apps/api/app/core/finding_state.py."
        )
    overlap = set(CLOSED) & set(OPEN)
    if overlap:
        raise RuntimeError(
            "finding_state: value(s) in both CLOSED and OPEN: "
            f"{sorted(o.value for o in overlap)}."
        )


_assert_total()


# ── SQLAlchemy helpers. Use these instead of inlining a set. ─────────

def is_open(model) -> "object":
    """Clause: this finding still represents work to do."""
    return model.classification.notin_(CLOSED)


def is_closed(model) -> "object":
    """Clause: this finding is settled."""
    return model.classification.in_(CLOSED)


def in_states(model, states: Iterable[Classification]) -> "object":
    """Clause: classification is one of ``states``."""
    return model.classification.in_(tuple(states))
