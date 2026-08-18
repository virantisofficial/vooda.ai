"""Notification retry queue — state machine + retry-eligibility tests.

Track-A P1.5 (2026-05-22): the notification dispatcher (services/
notifications/dispatcher.py) was fire-and-forget — a Slack 503 or
Jira blip silently lost the alert.  This file pins the contract for
the retry queue that fixes that:

  • _is_retryable_error() classifies failure strings into transient
    vs. permanent buckets (transient → retry, permanent → DLQ).
  • _persist_failed_dispatches_for_retry() writes NotificationDelivery
    rows for failed channel attempts, with status / backoff / config
    linkage set correctly.
  • The retry-backoff constants (1m → 5m → 15m → 1h → 6h, max 5
    attempts) are part of the public contract.

DB-level retry-task tests live in test_notification_retry_queue_e2e.py
(if/when wired up).  This file is pure unit-level so it runs in <1s.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from apps.api.app.models.notification_delivery import (
    MAX_RETRY_ATTEMPTS,
    NOTIFICATION_DELIVERY_STATUSES,
    NotificationDelivery,
    RETRY_BACKOFF_SECONDS,
)
from services.notifications.dispatcher import (
    DispatchResult,
    NotificationDispatcher,
    NotificationPayload,
    _is_retryable_error,
)


pytestmark = pytest.mark.asyncio


# ── _is_retryable_error: transient vs. permanent classifier ────


@pytest.mark.parametrize("err,expected", [
    # Transient (retry):
    ("503 Service Unavailable", True),
    ("502 Bad Gateway", True),
    ("connection refused", True),
    ("timeout after 10s", True),
    ("temporary failure", True),
    (None, True),                  # unknown → retry (conservative)
    ("", True),                    # empty → retry
    ("HTTPSConnectionPool: read timed out", True),
])
async def test_transient_errors_are_retryable(err, expected):
    assert _is_retryable_error(err) is expected


@pytest.mark.parametrize("err", [
    "401 Unauthorized",
    "403 Forbidden — invalid_auth",
    "404 channel not found",
    "400 Bad Request: malformed payload",
    "Invalid token",
    "invalid api key for slack",
    "authentication failed",
    "not_authed",
    "Unsupported channel: nonsense",
    "Unknown channel: xyz",
])
async def test_permanent_errors_are_not_retryable(err):
    assert _is_retryable_error(err) is False


# ── _persist_failed_dispatches_for_retry: row construction ─────


async def _fake_channel(provider="slack", config_id=None):
    """Stand-in for an IntegrationConfig row."""
    c = SimpleNamespace()
    c.id = config_id or uuid4()
    c.provider = provider
    return c


def _fake_payload(**overrides):
    defaults = dict(
        title="Critical secret found",
        body="AWS access key leaked in app.py:42",
        severity="critical",
        event_type="critical_finding",
        resource_type="finding",
        resource_id=str(uuid4()),
        url="https://vooda.local/findings/abc",
        metadata={"k": "v"},
    )
    defaults.update(overrides)
    return NotificationPayload(**defaults)


async def test_persist_skips_successful_results():
    """Successful dispatches must NOT create retry rows — the table
    is for failures only."""
    d = NotificationDispatcher()
    channel = await _fake_channel("slack")
    db = MagicMock()
    db.add = MagicMock()
    results = [DispatchResult(channel="slack", success=True)]

    count = await d._persist_failed_dispatches_for_retry(
        db, uuid4(), _fake_payload(), [channel], results,
    )
    assert count == 0
    db.add.assert_not_called()


async def test_persist_creates_pending_retry_row_for_transient():
    """A transient failure should create a row with status=pending_retry
    and next_retry_at set to ~1 minute out."""
    d = NotificationDispatcher()
    channel = await _fake_channel("slack")
    tenant = uuid4()
    payload = _fake_payload()
    db = MagicMock()
    added = []
    db.add = lambda row: added.append(row)
    results = [DispatchResult(channel="slack", success=False, error="503 Service Unavailable")]

    count = await d._persist_failed_dispatches_for_retry(db, tenant, payload, [channel], results)
    assert count == 1
    assert len(added) == 1
    row = added[0]
    assert row.status == "pending_retry"
    assert row.attempt_count == 1
    assert row.channel == "slack"
    assert row.tenant_id == tenant
    assert row.integration_config_id == channel.id
    assert row.last_error == "503 Service Unavailable"
    # next_retry_at should be ~60s in the future (first backoff step)
    assert row.next_retry_at is not None
    delta = (row.next_retry_at - datetime.now(timezone.utc)).total_seconds()
    assert 55 < delta < 70


async def test_persist_creates_permanent_failure_row_for_4xx():
    """A 401/403 should land as status=permanent_failure with no
    next_retry_at — visible in audit, never re-attempted."""
    d = NotificationDispatcher()
    channel = await _fake_channel("slack")
    db = MagicMock()
    added = []
    db.add = lambda row: added.append(row)
    results = [DispatchResult(channel="slack", success=False, error="401 invalid_auth")]

    await d._persist_failed_dispatches_for_retry(db, uuid4(), _fake_payload(), [channel], results)

    assert len(added) == 1
    row = added[0]
    assert row.status == "permanent_failure"
    assert row.next_retry_at is None
    assert row.dead_lettered_at is not None


async def test_persist_handles_mixed_success_and_failure():
    """When one channel succeeds and another fails, only the failure
    creates a retry row.  Order preserved via zip()."""
    d = NotificationDispatcher()
    ch_slack = await _fake_channel("slack")
    ch_teams = await _fake_channel("teams")
    db = MagicMock()
    added = []
    db.add = lambda row: added.append(row)
    results = [
        DispatchResult(channel="slack", success=True),
        DispatchResult(channel="teams", success=False, error="503"),
    ]

    count = await d._persist_failed_dispatches_for_retry(
        db, uuid4(), _fake_payload(), [ch_slack, ch_teams], results,
    )
    assert count == 1
    assert added[0].channel == "teams"
    assert added[0].integration_config_id == ch_teams.id


async def test_persist_bails_on_results_channels_length_mismatch():
    """Defensive: if results and channels are out of sync (caller bug),
    fall back to no persistence rather than write wrong channel→config
    pairings."""
    d = NotificationDispatcher()
    ch = await _fake_channel("slack")
    db = MagicMock()
    db.add = MagicMock()
    results = [
        DispatchResult(channel="slack", success=False, error="503"),
        DispatchResult(channel="teams", success=False, error="503"),
    ]
    count = await d._persist_failed_dispatches_for_retry(db, uuid4(), _fake_payload(), [ch], results)
    assert count == 0
    db.add.assert_not_called()


async def test_persist_serialises_uuid_resource_id_to_string():
    """Payload may contain UUIDs (resource_id, business_unit_id).
    JSONB doesn't accept UUID objects — must serialise to str."""
    d = NotificationDispatcher()
    ch = await _fake_channel("slack")
    db = MagicMock()
    added = []
    db.add = lambda row: added.append(row)
    rid = uuid4()
    payload = _fake_payload(resource_id=str(rid))  # resource_id is str on the dataclass
    payload.business_unit_id = uuid4()  # but BU id might be UUID

    results = [DispatchResult(channel="slack", success=False, error="503")]
    await d._persist_failed_dispatches_for_retry(db, uuid4(), payload, [ch], results)

    assert len(added) == 1
    # The serialised payload dict on the row should be JSON-safe
    import json
    encoded = json.dumps(added[0].payload)
    assert encoded  # round-trips without TypeError


# ── Backoff schedule contract ──────────────────────────────────


def test_backoff_schedule_is_exponential():
    """The 5-step backoff sequence must be monotonically increasing
    and reach hours-scale by the end (so transient blips have time
    to clear before we declare DLQ)."""
    assert len(RETRY_BACKOFF_SECONDS) == 5
    for i in range(1, len(RETRY_BACKOFF_SECONDS)):
        assert RETRY_BACKOFF_SECONDS[i] > RETRY_BACKOFF_SECONDS[i - 1], \
            "backoff must be monotonically increasing"
    assert RETRY_BACKOFF_SECONDS[0] == 60          # 1 minute first retry
    assert RETRY_BACKOFF_SECONDS[-1] >= 3600       # ≥1 hour final wait


def test_max_retry_attempts_matches_backoff_length():
    """MAX_RETRY_ATTEMPTS and the backoff array must stay in sync —
    a mismatch would cause off-by-one indexing in the retry task."""
    assert MAX_RETRY_ATTEMPTS == len(RETRY_BACKOFF_SECONDS) == 5


def test_status_enum_contains_all_required_states():
    """The retry state machine has exactly 4 states.  Pinned here so
    a future addition forces an explicit decision."""
    assert set(NOTIFICATION_DELIVERY_STATUSES) == {
        "pending_retry",
        "succeeded",
        "dead_lettered",
        "permanent_failure",
    }


# ── Model wiring ───────────────────────────────────────────────


def test_notification_delivery_has_version_column_for_concurrency():
    """NotificationDelivery uses optimistic locking (same pattern as
    P0 #1) to prevent two retry workers from clobbering each other."""
    assert "version" in NotificationDelivery.__table__.columns
    assert NotificationDelivery.__table__.columns["version"].nullable is False
    # version_id_col mapper hint is what makes SQLAlchemy enforce it
    mapper_args = NotificationDelivery.__mapper_args__
    assert "version_id_col" in mapper_args
    assert mapper_args["version_id_col"].name == "version"
