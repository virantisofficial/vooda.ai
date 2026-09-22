# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""The finding lifecycle: one short status, plus a reason for leaving it.

``Classification`` grew to thirteen values because it was doing four
jobs at once — the verdict, who reached it, why the finding closed, and
how. Each new reason multiplied the list instead of adding a row, which
is why four separate ``RESOLVED_*_DELETED`` values existed that differ
only in *what kind of thing disappeared*.

Split along the axes that were fused:

    status             where the finding is in its lifecycle      (4)
    resolution_reason  why it left the open states                (8)
    ai_verdict         what the model thinks — advisory only      (3)
    resolved_by/at     who decided and when                       (audit)

Confidence lives in ``ai_confidence`` and provenance in
``classification_provenance``; neither belongs in a status name, which
is what the ``LIKELY_``/``CONFIRMED_`` prefixes were doing.

Shaped so every incumbent maps in without loss — see
``from_incumbent`` — because a customer migrating off GitHub Advanced
Security, GitGuardian or GitLab must not lose triage history at the
door.
"""

import enum
from typing import NamedTuple, Optional

from apps.api.app.models.finding import Classification


class FindingStatus(str, enum.Enum):
    #: Needs attention. The default, and where an AI verdict leaves it.
    OPEN = "open"
    #: A human picked it up — assigned, investigating, or confirmed real
    #: and awaiting rotation.
    TRIAGING = "triaging"
    #: It was a real exposure and the credential is now neutralised.
    RESOLVED = "resolved"
    #: Not a real exposure, or accepted. Nothing to neutralise.
    DISMISSED = "dismissed"


class ResolutionReason(str, enum.Enum):
    # ── valid with RESOLVED ──
    ROTATED = "rotated"
    REVOKED = "revoked"
    PROVIDER_DISABLED = "provider_disabled"
    # ── valid with DISMISSED ──
    FALSE_POSITIVE = "false_positive"
    TEST_CREDENTIAL = "test_credential"
    ACCEPTABLE_RISK = "acceptable_risk"
    MITIGATING_CONTROL = "mitigating_control"
    #: The file, item, repository or source carrying the finding is gone.
    #: Deliberately NOT a RESOLVED reason: losing sight of a credential
    #: is not the same as revoking it, and the value survives in every
    #: clone and every commit that carried it. This one value replaces
    #: the four legacy RESOLVED_*_DELETED classifications.
    NO_LONGER_PRESENT = "no_longer_present"


class AiVerdict(str, enum.Enum):
    LIKELY_TRUE_POSITIVE = "likely_tp"
    LIKELY_FALSE_POSITIVE = "likely_fp"
    UNSURE = "unsure"


#: Which reasons each closing status accepts. A rotated credential is
#: RESOLVED; a false positive is DISMISSED. Crossing them would make
#: MTTR and compliance reporting meaningless.
REASONS_FOR: dict[FindingStatus, tuple[ResolutionReason, ...]] = {
    FindingStatus.RESOLVED: (
        ResolutionReason.ROTATED,
        ResolutionReason.REVOKED,
        ResolutionReason.PROVIDER_DISABLED,
    ),
    FindingStatus.DISMISSED: (
        ResolutionReason.FALSE_POSITIVE,
        ResolutionReason.TEST_CREDENTIAL,
        ResolutionReason.ACCEPTABLE_RISK,
        ResolutionReason.MITIGATING_CONTROL,
        ResolutionReason.NO_LONGER_PRESENT,
    ),
}

#: Statuses that still represent work. Mirrors finding_state.OPEN.
ACTIVE_STATUSES: tuple[FindingStatus, ...] = (
    FindingStatus.OPEN,
    FindingStatus.TRIAGING,
)

#: Statuses that require a reason to enter.
CLOSING_STATUSES: tuple[FindingStatus, ...] = (
    FindingStatus.RESOLVED,
    FindingStatus.DISMISSED,
)

#: Reasons a person may choose. NO_LONGER_PRESENT is excluded: it means
#: Vooda lost sight of the artifact — set by the repository- and
#: source-delete sweeps — and is a statement about our visibility, not a
#: judgement anyone can make about the credential. Offering it in a
#: triage menu invites someone to assert it while the secret is still
#: live in every clone that carried it.
HUMAN_SELECTABLE_REASONS: tuple[ResolutionReason, ...] = tuple(
    r for rs in REASONS_FOR.values() for r in rs
    if r is not ResolutionReason.NO_LONGER_PRESENT
)

#: The leak was actually cleaned up. Only these may count toward MTTR —
#: NO_LONGER_PRESENT is excluded on purpose, so deleting a repository
#: can never read as an instant fix.
REMEDIATED_REASONS: tuple[ResolutionReason, ...] = (
    ResolutionReason.ROTATED,
    ResolutionReason.REVOKED,
    ResolutionReason.PROVIDER_DISABLED,
)


class Mapped(NamedTuple):
    status: FindingStatus
    reason: Optional[ResolutionReason]
    ai_verdict: Optional[AiVerdict]


#: Every legacy Classification, decomposed. Nothing is lost: the four
#: RESOLVED_* variants collapse into one reason plus a note naming what
#: disappeared, which is where that detail always belonged.
FROM_CLASSIFICATION: dict[Classification, Mapped] = {
    Classification.NEEDS_REVIEW: Mapped(FindingStatus.OPEN, None, None),
    Classification.NOT_ENOUGH_EVIDENCE: Mapped(
        FindingStatus.OPEN, None, AiVerdict.UNSURE),
    # An AI verdict never closes a finding — it annotates an open one.
    Classification.LIKELY_TRUE_POSITIVE: Mapped(
        FindingStatus.OPEN, None, AiVerdict.LIKELY_TRUE_POSITIVE),
    Classification.LIKELY_FALSE_POSITIVE: Mapped(
        FindingStatus.OPEN, None, AiVerdict.LIKELY_FALSE_POSITIVE),
    # A confirmed real secret is the most open thing in the system until
    # somebody rotates it.
    Classification.CONFIRMED_TRUE_POSITIVE: Mapped(
        FindingStatus.TRIAGING, None, None),
    Classification.CONFIRMED_FALSE_POSITIVE: Mapped(
        FindingStatus.DISMISSED, ResolutionReason.FALSE_POSITIVE, None),
    Classification.TEST_CREDENTIAL: Mapped(
        FindingStatus.DISMISSED, ResolutionReason.TEST_CREDENTIAL, None),
    Classification.ACCEPTED_RISK: Mapped(
        FindingStatus.DISMISSED, ResolutionReason.ACCEPTABLE_RISK, None),
    Classification.ROTATED: Mapped(
        FindingStatus.RESOLVED, ResolutionReason.ROTATED, None),
    Classification.RESOLVED_FILE_DELETED: Mapped(
        FindingStatus.DISMISSED, ResolutionReason.NO_LONGER_PRESENT, None),
    Classification.RESOLVED_ITEM_DELETED: Mapped(
        FindingStatus.DISMISSED, ResolutionReason.NO_LONGER_PRESENT, None),
    Classification.RESOLVED_REPO_REMOVED: Mapped(
        FindingStatus.DISMISSED, ResolutionReason.NO_LONGER_PRESENT, None),
    Classification.RESOLVED_SOURCE_REMOVED: Mapped(
        FindingStatus.DISMISSED, ResolutionReason.NO_LONGER_PRESENT, None),
}

#: Incumbent vocabularies, for importing a customer's triage history.
#: Keys are ``(product, their_state, their_reason_or_None)``.
_INCUMBENT: dict[tuple[str, str, Optional[str]], Mapped] = {
    # GitHub Advanced Security — state + required resolution
    ("github", "open", None): Mapped(FindingStatus.OPEN, None, None),
    ("github", "resolved", "revoked"): Mapped(
        FindingStatus.RESOLVED, ResolutionReason.REVOKED, None),
    ("github", "resolved", "false_positive"): Mapped(
        FindingStatus.DISMISSED, ResolutionReason.FALSE_POSITIVE, None),
    ("github", "resolved", "used_in_tests"): Mapped(
        FindingStatus.DISMISSED, ResolutionReason.TEST_CREDENTIAL, None),
    ("github", "resolved", "wont_fix"): Mapped(
        FindingStatus.DISMISSED, ResolutionReason.ACCEPTABLE_RISK, None),
    # GitGuardian — status + ignore reason
    ("gitguardian", "triggered", None): Mapped(FindingStatus.OPEN, None, None),
    ("gitguardian", "assigned", None): Mapped(FindingStatus.TRIAGING, None, None),
    ("gitguardian", "resolved", None): Mapped(
        FindingStatus.RESOLVED, ResolutionReason.ROTATED, None),
    ("gitguardian", "ignored", "test_credential"): Mapped(
        FindingStatus.DISMISSED, ResolutionReason.TEST_CREDENTIAL, None),
    ("gitguardian", "ignored", "false_positive"): Mapped(
        FindingStatus.DISMISSED, ResolutionReason.FALSE_POSITIVE, None),
    ("gitguardian", "ignored", "low_risk"): Mapped(
        FindingStatus.DISMISSED, ResolutionReason.ACCEPTABLE_RISK, None),
    ("gitguardian", "ignored", None): Mapped(
        FindingStatus.DISMISSED, ResolutionReason.ACCEPTABLE_RISK, None),
    # GitLab — state + dismissal reason
    ("gitlab", "detected", None): Mapped(FindingStatus.OPEN, None, None),
    ("gitlab", "confirmed", None): Mapped(FindingStatus.TRIAGING, None, None),
    ("gitlab", "resolved", None): Mapped(
        FindingStatus.RESOLVED, ResolutionReason.ROTATED, None),
    ("gitlab", "dismissed", "acceptable_risk"): Mapped(
        FindingStatus.DISMISSED, ResolutionReason.ACCEPTABLE_RISK, None),
    ("gitlab", "dismissed", "false_positive"): Mapped(
        FindingStatus.DISMISSED, ResolutionReason.FALSE_POSITIVE, None),
    ("gitlab", "dismissed", "mitigating_control"): Mapped(
        FindingStatus.DISMISSED, ResolutionReason.MITIGATING_CONTROL, None),
    ("gitlab", "dismissed", "used_in_tests"): Mapped(
        FindingStatus.DISMISSED, ResolutionReason.TEST_CREDENTIAL, None),
    ("gitlab", "dismissed", "not_applicable"): Mapped(
        FindingStatus.DISMISSED, ResolutionReason.NO_LONGER_PRESENT, None),
}


def from_classification(cls) -> Mapped:
    """Decompose a legacy Classification. Unknown values stay OPEN —
    never silently closed."""
    if isinstance(cls, str):
        try:
            cls = Classification(cls.lower())
        except ValueError:
            return Mapped(FindingStatus.OPEN, None, None)
    return FROM_CLASSIFICATION.get(cls, Mapped(FindingStatus.OPEN, None, None))


def from_incumbent(product: str, state: str,
                   reason: Optional[str] = None) -> Optional[Mapped]:
    """Map another scanner's triage state. Returns None when the pair is
    unrecognised, so an importer can report it rather than guess."""
    key = (product.lower(), (state or "").lower(),
           reason.lower() if reason else None)
    hit = _INCUMBENT.get(key)
    if hit is None and reason is not None:
        hit = _INCUMBENT.get((key[0], key[1], None))
    return hit


def validate(status: FindingStatus,
             reason: Optional[ResolutionReason]) -> None:
    """Enforce the contract the database also enforces.

    Closing without a reason is how the old model lost the *why* — the
    single thing an auditor always asks for.
    """
    if status in CLOSING_STATUSES:
        if reason is None:
            raise ValueError(
                f"status {status.value!r} requires a resolution_reason"
            )
        if reason not in REASONS_FOR[status]:
            raise ValueError(
                f"reason {reason.value!r} is not valid for status "
                f"{status.value!r}; allowed: "
                f"{[r.value for r in REASONS_FOR[status]]}"
            )
    elif reason is not None:
        raise ValueError(
            f"status {status.value!r} is not a closing status and must "
            f"not carry a resolution_reason"
        )


def _assert_total() -> None:
    missing = set(Classification) - set(FROM_CLASSIFICATION)
    if missing:
        raise RuntimeError(
            "finding_status: unmapped Classification value(s): "
            f"{sorted(m.value for m in missing)} — add each to "
            "FROM_CLASSIFICATION."
        )
    assigned = {r for rs in REASONS_FOR.values() for r in rs}
    unplaced = set(ResolutionReason) - assigned
    if unplaced:
        raise RuntimeError(
            "finding_status: reason(s) valid for no status: "
            f"{sorted(r.value for r in unplaced)}"
        )
    overlap = set(REASONS_FOR[FindingStatus.RESOLVED]) & set(
        REASONS_FOR[FindingStatus.DISMISSED])
    if overlap:
        raise RuntimeError(
            f"finding_status: reason(s) valid for both closing statuses: "
            f"{sorted(r.value for r in overlap)}"
        )
    for m in FROM_CLASSIFICATION.values():
        validate(m.status, m.reason)


_assert_total()
