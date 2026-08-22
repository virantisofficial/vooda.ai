# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""No handler between the AI phase and the task entry may absorb a cancel.

Cooperative cancellation only works if ScanCancelled travels the whole
way up. The scan pipeline is defensive by design — broad
``except Exception`` handlers keep a scan alive through provider errors,
metric failures and flaky sub-steps — and any one of them will equally
happily absorb a cancellation and let the run finish.

Each handler on that path is pinned below. Also pinned: completion never
claims COMPLETED for a row an operator has already cancelled, which is
the last line of defence if a checkpoint is somehow missed.
"""
import inspect
import re

from apps.worker import tasks
from packages.common.cancellation import ScanCancelled


SCAN_SRC = inspect.getsource(tasks._run_scan_job)
ENTRY_SRC = inspect.getsource(tasks.run_scan_job)


def test_cancellation_type_is_shared_not_worker_local():
    """services/ must be able to re-raise it without importing the worker."""
    assert tasks.ScanCancelled is ScanCancelled
    assert ScanCancelled.__module__ == "packages.common.cancellation"


def test_ai_triage_handler_reraises_cancel():
    """`ai_triage_failed_continuing` must not treat a cancel as an error."""
    m = re.search(r"except ScanCancelled:(.*?)except Exception as ai_err:", SCAN_SRC, re.S)
    assert m, "the AI-triage handler does not special-case ScanCancelled"
    assert "raise" in m.group(1)


def test_outer_failure_handler_reraises_cancel():
    """A cancelled scan must not be recorded as FAILED."""
    idx = SCAN_SRC.find("except Exception as e:")
    assert idx > 0
    before = SCAN_SRC[:idx]
    assert "except ScanCancelled:" in before, (
        "the generic failure handler would mark a cancelled scan FAILED"
    )


def test_completion_does_not_overwrite_a_cancelled_row():
    assert "scan_completion_suppressed_by_cancel" in SCAN_SRC
    m = re.search(
        r"_final_status = await db\.scalar\((.*?)\)\s*\n\s*if _final_status == ScanStatus\.CANCELLED:",
        SCAN_SRC, re.S,
    )
    assert m, "completion does not re-read status before claiming COMPLETED"


def test_completion_status_is_read_from_the_database_not_memory():
    """The in-memory job object predates the operator's cancel."""
    m = re.search(r"_final_status = await db\.scalar\((.*?)\)", SCAN_SRC, re.S)
    assert m and "ScanJob.status" in m.group(1)


def test_entry_point_treats_cancel_as_success_not_failure():
    m = re.search(r"except ScanCancelled:(.*?)except SoftTimeLimitExceeded:", ENTRY_SRC, re.S)
    assert m, "run_scan_job does not handle ScanCancelled"
    body = m.group(1)
    assert "return" in body
    assert "FAILED" not in body, "a cancel must not be stamped as a failure"


def test_batch_dispatch_reraises_cancel():
    """The completion-order loop must not swallow it in either handler."""
    from services.ai_triage import batch
    src = inspect.getsource(batch.BatchTriageProcessor.process_batch)
    # Three: the await-result handler, the on_progress handler, and the
    # outer wrapper that cancels pending calls. Dropping any one of them
    # re-opens the swallow.
    assert src.count("except ScanCancelled:") >= 3, (
        "the await-result handler, the on_progress handler and the outer "
        "wrapper must each handle ScanCancelled"
    )
    assert "_t.cancel()" in src, "pending calls must be cancelled on abort"
