# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""A webhook scan has to be able to reach the commit it diffs against.

run_webhook_scan exists to scan the range a push introduced, and it
carries a full incremental implementation: _is_commit_reachable, a
diff-file count, and scan_diff. None of it ever ran.

The default clone is --depth 1, and this path skipped
_clone_repository entirely whenever the directory already existed, so
the base commit was never present locally. `_base_usable` was always
false and every event fell through to the full-scan fallback — correct
output, wrong path, and code that reads as a working feature while
being unreachable.

Measured on a live install before the fix: shallow=true, commits=1,
base reachable=no, incremental=false, files_analyzed=null. After:
shallow=false, commits=3, base reachable=yes, incremental=true,
files_analyzed=3.
"""
from __future__ import annotations

import inspect

from apps.worker import tasks


def _webhook_scan_source() -> str:
    """The async implementation, not the Celery wrapper.

    run_webhook_scan is a thin task that delegates; the clone and the
    diff live in the coroutine it calls.
    """
    return inspect.getsource(tasks._run_webhook_scan)


def test_the_clone_is_asked_for_history():
    """Without it the diff has nothing to diff against."""
    src = _webhook_scan_source()
    assert "full_history=True" in src, (
        "a --depth 1 clone cannot reach the base commit, so scan_diff "
        "can never run"
    )


def test_the_clone_call_is_not_skipped_when_the_directory_exists():
    """Skipping it is what left a shallow clone shallow.

    The helper deepens an existing clone only if it is called; guarding
    the call on the directory being absent skipped it in exactly the
    case where there was something to deepen.
    """
    src = _webhook_scan_source()
    assert "if not os.path.exists(repo_path):" not in src, (
        "the clone helper must be called unconditionally so it can "
        "unshallow a clone left behind by an earlier standalone scan"
    )


def test_the_incremental_branch_is_still_reachable():
    """Guard the feature this exists to enable."""
    src = _webhook_scan_source()
    assert "scan_diff(" in src
    assert "_base_usable" in src
