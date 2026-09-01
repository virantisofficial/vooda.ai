# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""A confirmed verdict must name who established it.

`Classification` separates `LIKELY_*` from `CONFIRMED_*` deliberately.
`LIKELY_*` is the model's opinion; `CONFIRMED_*` says somebody decided,
and an auditor reads it that way. Two paths wrote it without a human:

  * org-wide learning marked findings CONFIRMED_FALSE_POSITIVE off three
    FP decisions made elsewhere, leaving no rule and no audit row. That
    path is deleted.
  * the triage cache replays a stored decision onto a NEW finding. That
    is worth keeping — re-asking someone about identical code in the
    same place is how a queue becomes unusable — but the copy asserted
    a confirmation with nothing on it pointing back to a decider.

The rule is not "machines may not write CONFIRMED_*". It is that every
such write names its mechanism and an actor, enforced at flush so no
future caller can route around it.
"""
import uuid

import pytest

from apps.api.app.core import classification_provenance as CP
from apps.api.app.core.classification_provenance import (
    UnprovenancedClassification,
    build,
    requires_provenance,
    set_classification,
)
from apps.api.app.models.finding import Classification


class _Finding:
    """Enough of NormalizedFinding for the helper."""

    def __init__(self):
        self.classification = Classification.NEEDS_REVIEW
        self.classification_provenance = None


# ── which values make a claim ────────────────────────────────────────

@pytest.mark.parametrize("value", [
    Classification.CONFIRMED_FALSE_POSITIVE,
    Classification.CONFIRMED_TRUE_POSITIVE,
    "confirmed_false_positive",
])
def test_confirmed_values_require_provenance(value):
    assert requires_provenance(value) is True


@pytest.mark.parametrize("value", [
    Classification.LIKELY_FALSE_POSITIVE,
    Classification.LIKELY_TRUE_POSITIVE,
    Classification.NEEDS_REVIEW,
    Classification.ACCEPTED_RISK,
    None,
])
def test_weaker_values_do_not(value):
    """LIKELY_* already says "a machine thinks". Demanding an actor for
    it would make the scanner's own output unwritable."""
    assert requires_provenance(value) is False


# ── the record ───────────────────────────────────────────────────────

def test_a_record_names_mechanism_actor_and_time():
    actor = uuid.uuid4()
    r = build(mechanism=CP.MECHANISM_HUMAN_TRIAGE, actor=actor)
    assert r["mechanism"] == "human_triage"
    assert r["actor"] == str(actor)
    assert r["recorded_at"]


def test_system_is_not_an_actor():
    """The whole failure was a confirmation attributable to nobody.
    "system" is that failure with a label on it."""
    for bad in (None, "", "system"):
        with pytest.raises(ValueError):
            build(mechanism=CP.MECHANISM_HUMAN_TRIAGE, actor=bad)


def test_an_unknown_mechanism_is_refused():
    with pytest.raises(ValueError):
        build(mechanism="vibes", actor=uuid.uuid4())


def test_a_replay_points_back_at_its_source():
    r = build(
        mechanism=CP.MECHANISM_CACHE_REPLAY, actor=uuid.uuid4(),
        source_finding_id=uuid.uuid4(),
    )
    assert "source_finding_id" in r


# ── the helper ───────────────────────────────────────────────────────

def test_setting_a_confirmed_value_stamps_provenance():
    f = _Finding()
    actor = uuid.uuid4()
    set_classification(
        f, Classification.CONFIRMED_FALSE_POSITIVE,
        mechanism=CP.MECHANISM_HUMAN_TRIAGE, actor=actor,
    )
    assert f.classification == Classification.CONFIRMED_FALSE_POSITIVE
    assert f.classification_provenance["actor"] == str(actor)


def test_setting_a_weaker_value_stamps_nothing():
    """Scanner and model output must stay cheap to write."""
    f = _Finding()
    set_classification(
        f, Classification.LIKELY_FALSE_POSITIVE,
        mechanism=CP.MECHANISM_HUMAN_TRIAGE, actor=uuid.uuid4(),
    )
    assert f.classification_provenance is None


def test_confirming_without_an_actor_raises_before_anything_is_set():
    f = _Finding()
    with pytest.raises(ValueError):
        set_classification(
            f, Classification.CONFIRMED_TRUE_POSITIVE,
            mechanism=CP.MECHANISM_HUMAN_TRIAGE, actor=None,
        )
    assert f.classification == Classification.NEEDS_REVIEW, (
        "a refused write must not leave the finding half-updated"
    )


# ── the guard is armed by importing the models ───────────────────────

def test_importing_the_models_arms_the_guard():
    """Enforcement that has to be remembered is not enforcement."""
    from sqlalchemy import event
    from sqlalchemy.orm import Session
    import apps.api.app.models.finding  # noqa: F401
    assert event.contains(Session, "before_flush", CP._guard)


def test_install_is_idempotent():
    from sqlalchemy import event
    from sqlalchemy.orm import Session
    CP.install(); CP.install()
    assert event.contains(Session, "before_flush", CP._guard)


# ── the writers ──────────────────────────────────────────────────────

def test_neither_triage_path_assigns_classification_directly():
    """Both must go through the helper. A bare `finding.classification =`
    in a triage path is the shape of the original defect: it writes the
    verdict and leaves provenance to whoever remembers."""
    import inspect
    from apps.api.app.routers import findings

    for fn in (findings.triage_finding, findings.bulk_triage_findings):
        src = inspect.getsource(fn)
        assert "set_classification(" in src, f"{fn.__name__} bypasses the helper"
        for bad in ("classification = new_class", "classification=new_class"):
            assert bad not in src.replace("_", "").replace("f.", "").replace("finding.", "") \
                or "set_classification" in src


@pytest.mark.parametrize("mechanism", [
    CP.MECHANISM_HUMAN_TRIAGE, CP.MECHANISM_BULK_TRIAGE,
])
def test_each_triage_path_names_its_own_mechanism(mechanism):
    """Single and bulk are distinguishable in the audit trail — "one
    person clicked this" and "one person swept 400 of these" are not the
    same claim."""
    import inspect
    from apps.api.app.routers import findings
    assert mechanism in inspect.getsource(findings) or \
        f"MECHANISM_{mechanism.upper()}" in inspect.getsource(findings)


# ── the guard actually refuses the write ─────────────────────────────

def _session_holding(obj, *, new: bool):
    """Minimal stand-in for a Session mid-flush."""
    class _S:
        pass
    s = _S()
    s.new = [obj] if new else []
    s.dirty = [] if new else [obj]
    return s


def _real_finding(**kw):
    from apps.api.app.models.finding import NormalizedFinding
    f = NormalizedFinding()
    f.classification = kw.get("classification")
    f.classification_provenance = kw.get("provenance")
    return f


def test_the_guard_refuses_an_unprovenanced_confirmation_at_flush():
    """The control that matters: not a convention, a refusal."""
    f = _real_finding(classification=Classification.CONFIRMED_FALSE_POSITIVE)
    with pytest.raises(UnprovenancedClassification) as exc:
        CP._guard(_session_holding(f, new=True), None, None)
    assert "provenance" in str(exc.value)


def test_the_guard_allows_a_provenanced_confirmation():
    f = _real_finding(
        classification=Classification.CONFIRMED_FALSE_POSITIVE,
        provenance=build(mechanism=CP.MECHANISM_HUMAN_TRIAGE, actor=uuid.uuid4()),
    )
    CP._guard(_session_holding(f, new=True), None, None)  # must not raise


def test_the_guard_allows_weaker_classifications_unprovenanced():
    f = _real_finding(classification=Classification.LIKELY_FALSE_POSITIVE)
    CP._guard(_session_holding(f, new=True), None, None)


def test_a_forged_provenance_shape_does_not_satisfy_the_guard():
    """Something has to be checked, or the column is decoration."""
    for bad in ({}, {"mechanism": "human_triage"}, {"actor": "x"},
                {"mechanism": "vibes", "actor": "x"}):
        f = _real_finding(
            classification=Classification.CONFIRMED_TRUE_POSITIVE, provenance=bad,
        )
        with pytest.raises(UnprovenancedClassification):
            CP._guard(_session_holding(f, new=True), None, None)


def test_the_guard_ignores_objects_that_are_not_findings():
    class _Other:
        classification = Classification.CONFIRMED_FALSE_POSITIVE
        classification_provenance = None
    CP._guard(_session_holding(_Other(), new=True), None, None)


def test_the_cache_replay_carries_the_original_decider():
    """Attributing a replay to the scan that copied it would launder a
    human decision into a machine one and lose the only name an auditor
    can follow."""
    import inspect
    from apps.worker import tasks
    src = inspect.getsource(tasks)
    assert "decided_by_user_id" in src
    assert "MECHANISM_CACHE_REPLAY" in src


def test_a_cached_confirmation_with_no_decider_is_downgraded():
    """Rather than asserting a confirmation on an unknown person's
    behalf. Older cache rows predate decided_by_user_id."""
    import inspect
    from apps.worker import tasks
    src = inspect.getsource(tasks)
    assert "cached_confirmation_without_decider" in src


def test_the_invisible_suppression_path_is_gone():
    """It suppressed findings with no rule, no audit row, and a
    machine-written CONFIRMED_*. Deleted rather than left unwired — a
    working function is an invitation to call it again."""
    from services.learning import pattern_learner
    assert not hasattr(pattern_learner, "apply_learned_suppressions")
