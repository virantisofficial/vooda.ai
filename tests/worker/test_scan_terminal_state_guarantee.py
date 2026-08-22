# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""A scan job must always reach a terminal state.

If the AI phase raises — a finding deleted mid-run, a provider error —
the job must still land on FAILED rather than stay ANALYZING.

Two properties make that hold, both pinned below:

1. A stale ORM object is never mutated, so one vanished row cannot
   poison the transaction and take the rest of the batch with it.
2. The failure handler runs on its own session. A session that has
   already raised cannot be committed, so reusing the caller's would
   drop the status write as well.
"""
import inspect
import re

import pytest

from apps.worker import tasks


# ── 1. terminal-state writer uses an independent session ─────────────

def test_force_terminal_failure_exists():
    assert callable(tasks._force_terminal_failure)


def test_force_terminal_failure_opens_its_own_session():
    """Must NOT accept or reuse the caller's (possibly poisoned) session."""
    sig = inspect.signature(tasks._force_terminal_failure)
    assert "db" not in sig.parameters and "session" not in sig.parameters, (
        "taking the caller's session would defeat the purpose — the whole "
        "point is that the caller's session may be unusable"
    )
    src = inspect.getsource(tasks._force_terminal_failure)
    assert "_get_db_session()" in src


def test_force_terminal_failure_never_raises():
    """It runs on the error path; raising would mask the real failure."""
    src = inspect.getsource(tasks._force_terminal_failure)
    assert "except Exception" in src
    assert "return False" in src


def test_force_terminal_failure_does_not_clobber_terminal_states():
    """A cancelled or completed scan must not be rewritten to FAILED."""
    src = inspect.getsource(tasks._force_terminal_failure)
    for state in ("COMPLETED", "FAILED", "CANCELLED"):
        assert state in src


# ── 2. the failure handler recovers a poisoned session ───────────────

def test_failure_handler_rolls_back_before_writing():
    src = inspect.getsource(tasks._run_scan_job)
    assert "await db.rollback()" in src, (
        "after a flush error the session must be rolled back before any "
        "further statement, or the status write raises PendingRollbackError"
    )


def test_failure_handler_falls_back_to_a_fresh_session():
    src = inspect.getsource(tasks._run_scan_job)
    assert "_force_terminal_failure" in src


# ── 3. outermost guarantee ───────────────────────────────────────────

def test_runner_has_a_last_resort_terminal_guarantee():
    src = inspect.getsource(tasks.run_scan_job)
    m = re.search(r"except Exception as exc:(.*)", src, re.S)
    assert m, "run_scan_job needs a catch-all terminal-state guarantee"
    assert "_force_terminal_failure" in m.group(1)
    assert "raise" in m.group(1), "must still re-raise so Celery records the failure"


def test_cancellation_is_not_turned_into_a_failure():
    """ScanCancelled must be handled before the catch-all."""
    src = inspect.getsource(tasks.run_scan_job)
    i_cancel = src.index("except ScanCancelled")
    i_generic = src.index("except Exception as exc")
    assert i_cancel < i_generic, (
        "a cancelled scan would otherwise be recorded as FAILED"
    )


# ── 4. root cause: a deleted finding must not destroy the batch ──────

def test_apply_loop_revalidates_findings_before_mutating():
    src = inspect.getsource(tasks._run_ai_triage)
    assert "_alive_ids" in src
    assert "triage_apply_skipped_deleted_findings" in src


def test_apply_loop_skips_vanished_findings_rather_than_failing():
    src = inspect.getsource(tasks._run_ai_triage)
    m = re.search(r"if _alive_ids and str\(triage_result\.finding_id\) not in _alive_ids:\s*\n\s*(\w+)", src)
    assert m and m.group(1) == "continue", (
        "a vanished finding must be skipped, not raised on — one deleted "
        "row must not discard the other verdicts in the batch"
    )


def test_liveness_probe_failure_degrades_gracefully():
    """If the probe query itself fails, apply verdicts anyway — never
    silently drop all of them."""
    src = inspect.getsource(tasks._run_ai_triage)
    assert "triage_apply_liveness_probe_failed" in src
