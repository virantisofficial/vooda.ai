# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Cancelling a scan must stop the worker, not just update the row.

Cancellation uses two independent mechanisms, because signal delivery is
best-effort in a distributed system (worker on another host, reconnect,
task not yet picked up):

1. Every dispatch path stores ``celery_task_id``, which is what the
   cancel endpoint needs in order to revoke the task at all.
2. The worker checks for cancellation at each heartbeat, so a missed
   signal still stops the run.

The per-(repo, branch) lock is released on cancel, so the next scan
starts instead of coalescing into the cancelled one.
"""
import inspect
import re

import pytest


# ── 1. every dispatch site must persist celery_task_id ───────────────

DISPATCH_SITES = [
    ("services/scheduler/engine.py", "run_scan_job.delay"),
    ("services/scheduler/engine.py", "run_source_scan.delay"),
    ("apps/worker/tasks.py", "run_source_scan.delay"),
    ("apps/api/app/routers/repositories.py", "run_scan_job.delay"),
]


@pytest.mark.parametrize("path,call", DISPATCH_SITES)
def test_dispatch_site_stores_celery_task_id(path, call):
    """A scan dispatched without a task id can never be revoked."""
    src = open(path).read()
    lines = src.splitlines()
    hits = [i for i, l in enumerate(lines) if call in l and not l.strip().startswith("#")]
    assert hits, f"{call} not found in {path} — test needs updating"
    for i in hits:
        window = "\n".join(lines[i:i + 3])
        assert "celery_task_id" in window, (
            f"{path}:{i+1} dispatches {call} without storing celery_task_id "
            f"within 2 lines — cancel would silently no-op for these scans."
        )


# ── 2. cooperative cancellation exists and is wired in ───────────────

def test_scan_cancelled_exception_exists():
    from apps.worker.tasks import ScanCancelled
    assert issubclass(ScanCancelled, Exception)


def test_cancel_check_is_called_from_the_heartbeat_path():
    """The checkpoint must sit on a path that runs during real work —
    including the multi-minute AI-triage batch."""
    from apps.worker import tasks
    src = inspect.getsource(tasks._stamp_heartbeat_main)
    assert "_raise_if_cancelled" in src


def test_cancel_check_reads_status_from_the_database():
    """Must re-read the row: the API cancels in a DIFFERENT session, so
    the worker's in-memory job object never sees the change."""
    from apps.worker import tasks
    src = inspect.getsource(tasks._raise_if_cancelled)
    assert "select" in src and "status" in src
    assert "CANCELLED" in src


def test_cancel_check_never_breaks_a_scan_on_db_error():
    """A failed liveness probe must not kill a healthy scan."""
    from apps.worker import tasks
    src = inspect.getsource(tasks._raise_if_cancelled)
    assert "except Exception" in src


def test_runner_handles_cancellation_without_overwriting_status():
    """The API already wrote 'Scan cancelled by <user>'. The worker must
    not clobber it with FAILED."""
    from apps.worker import tasks
    src = inspect.getsource(tasks.run_scan_job)
    assert "ScanCancelled" in src
    m = re.search(r"except ScanCancelled:(.*?)except ", src, re.S)
    assert m, "ScanCancelled handler not found"
    body = m.group(1)
    assert "return" in body
    assert "FAILED" not in body, "cancellation must not be recorded as a failure"


# ── 3. the endpoint must not claim success it cannot deliver ─────────

def test_cancel_endpoint_flags_a_missing_task_id():
    src = open("apps/api/app/routers/repositories.py").read()
    assert "cancel_without_task_id" in src, (
        "a cancel with no celery_task_id must be logged, not silently "
        "reported as a clean cancellation"
    )
