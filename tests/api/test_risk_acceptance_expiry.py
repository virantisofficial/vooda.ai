# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""An accepted risk has a name on it and an end date.

Dismissing a finding as an acceptable risk used to record who clicked
and nothing else, which made every acceptance permanent by default —
the one thing a risk acceptance is never meant to be. The credential
stayed live, the finding stayed closed, and nothing asked again.

Enforcement is read-side, like the rule-override snooze it mirrors.
Nothing flips the row when the date passes; the scan pipeline stops
replaying a lapsed acceptance, so the finding comes back on its own at
the next scan and the row survives its own expiry for the audit trail.

That last part is what these tests mostly guard. An expiry nothing
checks is decoration, and the only thing standing between the stored
date and a finding that stays closed forever is the cache lookup.
"""
import pathlib
import types
from datetime import datetime, timedelta, timezone

import pytest

ROUTER = pathlib.Path("apps/api/app/routers/findings.py")
CACHE = pathlib.Path("services/normalization/decision_cache.py")


# ── The columns exist and are readable ──────────────────────────────

def test_both_tables_carry_the_owner_and_the_end_date():
    from apps.api.app.models.finding import NormalizedFinding, SecretIncident
    for model in (NormalizedFinding, SecretIncident):
        cols = set(model.__table__.columns.keys())
        assert "risk_owner" in cols, model.__name__
        assert "risk_accepted_until" in cols, model.__name__


def test_the_api_returns_them():
    """A reader that cannot see the date cannot tell a live acceptance
    from one that expired months ago."""
    from apps.api.app.schemas.finding import FindingListItem, FindingDetail
    for schema in (FindingListItem, FindingDetail):
        assert "risk_owner" in schema.model_fields, schema.__name__
        assert "risk_accepted_until" in schema.model_fields, schema.__name__


def test_the_request_accepts_them():
    from apps.api.app.schemas.finding import TriageRequest
    assert "risk_owner" in TriageRequest.model_fields
    assert "risk_accepted_until" in TriageRequest.model_fields


# ── The acceptance belongs to the dismissal that recorded it ────────

class _Row:
    """Minimal stand-in for a finding row, carrying only the columns
    mirror_lifecycle writes."""

    def __init__(self, **kw):
        self.status = None
        self.resolution_reason = None
        self.resolution_note = None
        self.resolved_at = None
        self.resolved_by = None
        self.ai_verdict = None
        self.risk_owner = None
        self.risk_accepted_until = None
        self.__dict__.update(kw)


def test_an_acceptance_survives_its_own_dismissal():
    from apps.api.app.core.classification_provenance import mirror_lifecycle
    from apps.api.app.models.finding import Classification
    import uuid

    row = _Row(risk_owner=uuid.uuid4(),
               risk_accepted_until=datetime(2027, 1, 1, tzinfo=timezone.utc))
    mirror_lifecycle(row, Classification.ACCEPTED_RISK)
    assert row.resolution_reason == "acceptable_risk"
    assert row.risk_owner is not None
    assert row.risk_accepted_until is not None


@pytest.mark.parametrize("cls_name", [
    "NEEDS_REVIEW",            # re-opened
    "CONFIRMED_TRUE_POSITIVE",  # moved to triaging
    "ROTATED",                 # resolved for a different reason
    "CONFIRMED_FALSE_POSITIVE",  # dismissed for a different reason
])
def test_leaving_the_acceptance_clears_who_owned_it(cls_name):
    """An owner left standing behind a decision nobody is making any
    more is worse than no owner: it reads as a live sign-off."""
    from apps.api.app.core.classification_provenance import mirror_lifecycle
    from apps.api.app.models.finding import Classification
    import uuid

    row = _Row(status="dismissed",
               resolution_reason="acceptable_risk",
               risk_owner=uuid.uuid4(),
               risk_accepted_until=datetime(2027, 1, 1, tzinfo=timezone.utc))
    mirror_lifecycle(row, getattr(Classification, cls_name))
    assert row.risk_owner is None, cls_name
    assert row.risk_accepted_until is None, cls_name


# ── The expiry actually stops the replay ────────────────────────────

class _Result:
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class _Db:
    def __init__(self, row):
        self._row = row
        self.flushed = False

    async def execute(self, *_a, **_kw):
        return _Result(self._row)

    async def flush(self):
        self.flushed = True


def _cached(**kw):
    row = types.SimpleNamespace(
        classification="accepted_risk",
        risk_accepted_until=None,
        code_hash="deadbeef",
        ai_confidence=0.9,
        ai_explanation="",
        exploitability_score=0.0,
        true_positive_reasons=[],
        false_positive_reasons=[],
        compensating_controls=[],
        ai_evidence_refs=[],
        decided_by="user",
        decided_by_user_id=None,
        hit_count=1,
        last_hit_at=None,
    )
    row.__dict__.update(kw)
    return row


async def _lookup(row):
    from services.normalization.decision_cache import lookup_cache
    import uuid
    return await lookup_cache(
        db=_Db(row),
        tenant_id=uuid.uuid4(),
        repository_id=uuid.uuid4(),
        stability_id="s1",
        code_hash="deadbeef",
    )


@pytest.mark.asyncio
async def test_a_lapsed_acceptance_is_not_replayed():
    """The regression this guards: without the check, the cache
    re-closes the finding on every scan and the end date means
    nothing."""
    past = datetime.now(timezone.utc) - timedelta(days=1)
    result = await _lookup(_cached(risk_accepted_until=past))
    assert result.hit is False
    assert result.invalidated is True
    assert "lapsed" in (result.invalidation_reason or "").lower()


@pytest.mark.asyncio
async def test_an_acceptance_still_in_force_is_replayed():
    future = datetime.now(timezone.utc) + timedelta(days=30)
    result = await _lookup(_cached(risk_accepted_until=future))
    assert result.hit is True
    assert result.classification == "accepted_risk"


@pytest.mark.asyncio
async def test_an_acceptance_with_no_end_date_is_replayed():
    """NULL means the acceptance does not expire on its own, not that
    it expired at the epoch."""
    result = await _lookup(_cached(risk_accepted_until=None))
    assert result.hit is True


@pytest.mark.asyncio
async def test_the_expiry_only_gates_an_acceptance():
    """A past date on any other classification is not an expiry — it
    would be a stale column, and silently dropping those hits would
    send unrelated findings back through AI triage."""
    past = datetime.now(timezone.utc) - timedelta(days=1)
    result = await _lookup(_cached(
        classification="confirmed_false_positive", risk_accepted_until=past))
    assert result.hit is True


def test_the_date_reaches_the_cache_at_all():
    """The replay check can only work if the store copied the date
    across in the first place."""
    src = CACHE.read_text(encoding="utf-8")
    assert 'risk_accepted_until=getattr(finding, "risk_accepted_until", None)' in src
    assert "existing.risk_accepted_until = risk_accepted_until" in src
    assert "risk_accepted_until=risk_accepted_until," in src


# ── The write path refuses nonsense ─────────────────────────────────

def test_the_fields_are_refused_on_any_other_action():
    src = ROUTER.read_text(encoding="utf-8")
    assert "apply only to an" in src
    assert '"acceptable_risk" dismissal.' in src or "acceptable_risk dismissal." in src


def test_an_expiry_in_the_past_is_refused():
    """An acceptance that lapsed before it was recorded would close the
    finding and stop applying in the same request."""
    src = ROUTER.read_text(encoding="utf-8")
    assert "risk_accepted_until must be in the future" in src


def test_the_owner_must_be_a_user_in_this_workspace():
    src = ROUTER.read_text(encoding="utf-8")
    assert "risk_owner is not a user in this workspace." in src


def test_a_lapsed_acceptance_is_findable_before_the_next_scan():
    """Nothing re-opens these on the date, so an operator needs a way
    to see them in the meantime."""
    src = ROUTER.read_text(encoding="utf-8")
    assert "risk_expired" in src
    assert 'NormalizedFinding.resolution_reason == "acceptable_risk"' in src
