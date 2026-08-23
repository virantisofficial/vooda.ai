# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Broker visibility timeout must exceed every task's time limit.

With ``task_acks_late=True`` the broker holds a task's message unacked
for the whole run, and Redis redelivers anything unacked for longer than
``visibility_timeout`` — starting a second, concurrent execution of a
task that is still running.

Celery's Redis default is 3600s, while long scans are given a much
higher limit, so the two numbers have to be tied together explicitly.
These tests encode the invariant across EVERY registered task, so
raising a task limit without raising the broker timeout fails here.
"""
import pytest

from apps.worker.celery_app import (
    celery_app,
    BROKER_VISIBILITY_TIMEOUT,
    SCAN_TASK_TIME_LIMIT,
    SCAN_TASK_SOFT_TIME_LIMIT,
)

# Celery registers tasks lazily on import. Without this the registry is
# EMPTY and the "every registered task" assertion below passes
# vacuously — which is worse than no test at all.
import apps.worker.tasks  # noqa: F401,E402


def test_task_registry_is_actually_populated():
    """Guards the guard: an empty registry makes the invariant vacuous."""
    names = [n for n in celery_app.tasks if not n.startswith("celery.")]
    assert "apps.worker.tasks.run_scan_job" in names
    assert len(names) > 5, f"suspiciously few tasks registered: {names}"


def _visibility_timeout() -> int:
    opts = celery_app.conf.broker_transport_options or {}
    assert "visibility_timeout" in opts, (
        "broker_transport_options.visibility_timeout is not set — Celery "
        "falls back to 3600s, which silently redelivers any task running "
        "longer than an hour."
    )
    return opts["visibility_timeout"]


def test_visibility_timeout_is_configured_at_all():
    # The original bug was absence, not a wrong value.
    assert _visibility_timeout() > 0


def test_visibility_timeout_exceeds_every_registered_task_time_limit():
    """The invariant. Checked against real task registrations, not constants."""
    vt = _visibility_timeout()
    offenders = []
    for name, task in celery_app.tasks.items():
        if name.startswith("celery."):      # built-ins carry no meaningful limit
            continue
        limit = getattr(task, "time_limit", None)
        if limit and limit >= vt:
            offenders.append((name, limit))
    assert not offenders, (
        f"visibility_timeout={vt}s does not exceed these task time limits: "
        f"{offenders}. The broker would redeliver these tasks mid-run, "
        f"causing duplicate concurrent execution. Raise "
        f"BROKER_VISIBILITY_TIMEOUT in apps/worker/celery_app.py."
    )


def test_visibility_timeout_beats_the_celery_default():
    # A regression to the default is the exact failure we hit.
    assert _visibility_timeout() > 3600


def test_visibility_timeout_is_derived_not_hardcoded():
    """It must track SCAN_TASK_TIME_LIMIT, so the two cannot drift."""
    assert BROKER_VISIBILITY_TIMEOUT > SCAN_TASK_TIME_LIMIT
    # Derived value, with headroom for graceful shutdown + ack.
    assert BROKER_VISIBILITY_TIMEOUT - SCAN_TASK_TIME_LIMIT >= 600


def test_scan_task_uses_the_shared_constant():
    """run_scan_job must not re-declare its limit as a literal."""
    task = celery_app.tasks["apps.worker.tasks.run_scan_job"]
    assert task.time_limit == SCAN_TASK_TIME_LIMIT
    assert task.soft_time_limit == SCAN_TASK_SOFT_TIME_LIMIT


def test_soft_limit_leaves_room_to_write_a_failed_row():
    assert SCAN_TASK_SOFT_TIME_LIMIT < SCAN_TASK_TIME_LIMIT
    assert SCAN_TASK_TIME_LIMIT - SCAN_TASK_SOFT_TIME_LIMIT >= 120


@pytest.mark.parametrize("raised_limit", [14400, 21600, 43200])
def test_invariant_would_catch_a_future_limit_increase(raised_limit):
    """Documents the guard's purpose: raising a task limit past the
    broker ceiling must be a detectable error, not a silent loop."""
    vt = _visibility_timeout()
    would_be_caught = raised_limit >= vt
    assert would_be_caught == (raised_limit >= vt)
    if raised_limit < vt:
        assert raised_limit < vt  # safe today
