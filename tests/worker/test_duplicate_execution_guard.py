# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""A redelivered scan task must not run alongside the live original.

At-least-once delivery is a property of every distributed queue, not a
bug to be tuned away: the broker can reclaim a slow message, a SIGKILLed
worker requeues via ``task_reject_on_worker_lost``, a redeploy restarts
in-flight work, or an operator retries by hand.

The guard compares the row's heartbeat against the stale-scan threshold
and makes the second copy a no-op while the first is still live.
"""
from datetime import datetime, timedelta, timezone

import pytest

from apps.api.app.models.scan import ScanStatus
from apps.worker.tasks import (
    _is_duplicate_live_execution,
    _triage_coverage_warning,
)

THRESHOLD = 5400  # 90 min, the watchdog's default stall threshold
NOW = datetime(2026, 8, 22, 3, 0, 0, tzinfo=timezone.utc)


def _hb(seconds_ago: int) -> datetime:
    return NOW - timedelta(seconds=seconds_ago)


# ── the incident itself ──────────────────────────────────────────────

def test_redelivery_at_60_minutes_is_skipped_while_original_is_alive():
    """Heartbeat is seconds old and the task is redelivered."""
    is_dup, age = _is_duplicate_live_execution(
        status=ScanStatus.ANALYZING, heartbeat_at=_hb(12),
        threshold_seconds=THRESHOLD, now=NOW,
    )
    assert is_dup is True
    assert age == 12


def test_running_status_is_guarded_too_not_just_analyzing():
    is_dup, _ = _is_duplicate_live_execution(
        status=ScanStatus.RUNNING, heartbeat_at=_hb(30),
        threshold_seconds=THRESHOLD, now=NOW,
    )
    assert is_dup is True


# ── legitimate retries must NOT be blocked ───────────────────────────

def test_dead_original_lets_the_retry_proceed():
    """Worker died; heartbeat went stale. This delivery is the real retry."""
    is_dup, age = _is_duplicate_live_execution(
        status=ScanStatus.ANALYZING, heartbeat_at=_hb(THRESHOLD + 60),
        threshold_seconds=THRESHOLD, now=NOW,
    )
    assert is_dup is False
    assert age == THRESHOLD + 60


def test_no_heartbeat_yet_proceeds_rather_than_deadlocking():
    """A redelivery that beats the first heartbeat must not wedge the scan
    permanently — better a rare duplicate than a scan that never runs."""
    is_dup, age = _is_duplicate_live_execution(
        status=ScanStatus.RUNNING, heartbeat_at=None,
        threshold_seconds=THRESHOLD, now=NOW,
    )
    assert is_dup is False
    assert age is None


@pytest.mark.parametrize(
    "status",
    [ScanStatus.PENDING, ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED],
)
def test_non_running_states_are_never_treated_as_duplicates(status):
    """A queued scan must start; a finished one is out of scope here."""
    is_dup, _ = _is_duplicate_live_execution(
        status=status, heartbeat_at=_hb(5),
        threshold_seconds=THRESHOLD, now=NOW,
    )
    assert is_dup is False


# ── boundary + robustness ────────────────────────────────────────────

def test_exactly_at_threshold_is_treated_as_dead():
    is_dup, _ = _is_duplicate_live_execution(
        status=ScanStatus.ANALYZING, heartbeat_at=_hb(THRESHOLD),
        threshold_seconds=THRESHOLD, now=NOW,
    )
    assert is_dup is False


def test_one_second_inside_threshold_is_a_duplicate():
    is_dup, _ = _is_duplicate_live_execution(
        status=ScanStatus.ANALYZING, heartbeat_at=_hb(THRESHOLD - 1),
        threshold_seconds=THRESHOLD, now=NOW,
    )
    assert is_dup is True


def test_naive_heartbeat_is_handled_as_utc_not_crashed_on():
    """Postgres can hand back a naive datetime; subtracting it from an
    aware `now` would raise TypeError and take the whole scan down."""
    naive = NOW.replace(tzinfo=None) - timedelta(seconds=20)
    is_dup, age = _is_duplicate_live_execution(
        status=ScanStatus.ANALYZING, heartbeat_at=naive,
        threshold_seconds=THRESHOLD, now=NOW,
    )
    assert is_dup is True
    assert age == 20


# ── triage-coverage assertion (fix C) ────────────────────────────────

def test_partial_triage_produces_a_visible_warning():
    warning = _triage_coverage_warning(185)
    assert warning is not None
    assert "185" in warning
    assert "not triaged" in warning


def test_full_coverage_produces_no_warning():
    assert _triage_coverage_warning(0) is None


def test_none_is_treated_as_no_warning():
    assert _triage_coverage_warning(None) is None


def test_the_incident_scan_would_have_been_flagged():
    """A large shortfall between detected and triaged must warn."""
    assert _triage_coverage_warning(185) is not None
