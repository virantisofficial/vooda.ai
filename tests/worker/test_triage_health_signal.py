# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""The triage health badge fires on failures, not on held verdicts.

A verdict below the tenant's confidence threshold is held at
NEEDS_REVIEW on purpose: the model's reasoning is stored, a human
decides. That is triage working. The health signal used to define
failure as "triaged minus (FP + TP)", which counts every NEEDS_REVIEW
outcome — held verdicts and honest needs_review verdicts alike — as a
parse failure. On a one-finding scan, one held verdict meant a 100%
failure rate, a "broken" badge on the provider card, and
failure_type=unknown because the failure summary was rightly empty.

Failure is what the engine stamped `_parse_failure` on. Nothing else.
"""
import inspect
import uuid

import pytest
from unittest.mock import AsyncMock, MagicMock

from apps.worker.tasks import (
    _TRIAGE_PARSE_FAILURE_THRESHOLD,
    _emit_triage_health_signal,
    _pick_failure_copy,
)


# ── the failure definition ───────────────────────────────────────────

def test_call_site_counts_failures_from_the_summary():
    """`triaged - (FP+TP)` treats held-for-review as broken. The rate
    must come from the buckets the engine actually recorded."""
    from apps.worker import tasks
    src = inspect.getsource(tasks)
    assert "failed_calls = sum((failure_summary or {}).values())" in src
    assert "failed_calls / triaged" in src


def test_pick_copy_empty_summary_is_unknown():
    dominant, summary, _ = _pick_failure_copy({})
    assert dominant == "unknown"
    dominant, _, _ = _pick_failure_copy(None)
    assert dominant == "unknown"


def test_pick_copy_dominant_bucket_wins():
    dominant, summary, _ = _pick_failure_copy(
        {"invalid_json": 3, "empty_response": 1}
    )
    assert dominant == "invalid_json"
    assert "JSON" in summary


# ── the signal itself ────────────────────────────────────────────────

def _db_with_primary(last_error=None):
    primary = MagicMock()
    primary.last_error = last_error
    primary.name = "qwen"
    primary.model_id = "qwen/x"
    primary.id = uuid.uuid4()

    db = MagicMock()
    model_res = MagicMock()
    model_res.scalars = MagicMock(
        return_value=MagicMock(first=MagicMock(return_value=primary))
    )
    user_res = MagicMock()
    user_res.scalar_one_or_none = MagicMock(return_value=uuid.uuid4())
    db.execute = AsyncMock(side_effect=[model_res, user_res])
    db.flush = AsyncMock()
    db.add = MagicMock()
    return db, primary


@pytest.mark.asyncio
async def test_a_held_verdict_does_not_light_the_badge():
    """The exact production case: one finding, verdict held below the
    confidence threshold, nothing failed. Rate is 0, and a stale badge
    from the old arithmetic gets cleared."""
    db, primary = _db_with_primary(
        last_error="triage_parse_failure: 1/1 findings — stale",
    )
    await _emit_triage_health_signal(
        db=db, tenant_id=uuid.uuid4(), scan_job_id=uuid.uuid4(),
        triaged=1, classified=0,
        parse_failure_rate=0.0,          # sum({}) / 1
        failure_summary={},
    )
    assert primary.last_error is None, "stale false-alarm badge must clear"
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_real_failures_still_badge_with_their_type():
    db, primary = _db_with_primary()
    await _emit_triage_health_signal(
        db=db, tenant_id=uuid.uuid4(), scan_job_id=uuid.uuid4(),
        triaged=2, classified=0,
        parse_failure_rate=1.0,
        failure_summary={"invalid_json": 2},
    )
    assert primary.last_error is not None
    assert "failure_type=invalid_json" in primary.last_error
    assert "2/2" in primary.last_error
    db.add.assert_called_once()          # bell notification


@pytest.mark.asyncio
async def test_failed_count_in_the_badge_comes_from_the_summary():
    """triaged=3 with 1 real failure and 2 held verdicts must read
    1/3, not 3/3 — over-reporting is how trust in the badge dies."""
    db, primary = _db_with_primary()
    await _emit_triage_health_signal(
        db=db, tenant_id=uuid.uuid4(), scan_job_id=uuid.uuid4(),
        triaged=3, classified=0,
        parse_failure_rate=1.0 / 3,      # only counts if >= threshold
        failure_summary={"truncated_response": 1},
    )
    if 1.0 / 3 >= _TRIAGE_PARSE_FAILURE_THRESHOLD:
        assert "1/3" in primary.last_error
    else:
        assert primary.last_error is None


@pytest.mark.asyncio
async def test_below_threshold_rate_never_badges():
    db, primary = _db_with_primary()
    await _emit_triage_health_signal(
        db=db, tenant_id=uuid.uuid4(), scan_job_id=uuid.uuid4(),
        triaged=10, classified=6,
        parse_failure_rate=0.1,
        failure_summary={"invalid_json": 1},
    )
    assert primary.last_error is None
    db.add.assert_not_called()


# ── trend baseline honesty (same bug family, other endpoint) ─────────

def test_trend_change_pct_is_null_without_a_baseline():
    """max(prev,1) fabricated e.g. 14700% for a tenant whose scanning
    began inside the window — capped by the UI to a shouting 999%+
    while the KPI tiles honestly showed an em-dash for the very same
    empty baseline."""
    import inspect
    from apps.api.app.routers import metrics
    src = inspect.getsource(metrics)
    assert "if prev_count > 0 else None" in src
    assert "max(prev_count, 1)" not in src
    assert '"no_baseline" if change_pct is None' in src
