# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""PATCH_GENERATED may only be stamped alongside a persisted patch.

The status is a claim that a draft fix exists. A plan-only result
(root cause and rationale, no patch) must not read as "patch
generated": a finding in that state never re-enters the generation
queue because it looks done, and any coverage number built on the
status counts a patch that is not there.

Both generation paths are pinned here, plus the data-repair migration
that downgrades historical rows.
"""
import inspect
import re

import pytest


def _sites():
    from apps.worker import tasks
    from services.batch_remediation import engine
    worker_src = inspect.getsource(tasks)
    batch_src = inspect.getsource(engine.BatchRemediationEngine)
    return {"worker": worker_src, "batch_engine": batch_src}


@pytest.mark.parametrize("site", ["worker", "batch_engine"])
def test_status_is_stamped_only_with_a_real_diff(site):
    src = _sites()[site]
    for m in re.finditer(r'remediation_status = "patch_generated"', src):
        # The 500 characters before each stamp must contain the guarded
        # diff check — an unconditional stamp is the bug.
        window = src[max(0, m.start() - 700):m.start()]
        assert 'if len(_diff) > 20:' in window, (
            f"{site}: PATCH_GENERATED is stamped without verifying a "
            f"non-trivial patch diff was persisted"
        )


@pytest.mark.parametrize("site", ["worker", "batch_engine"])
def test_plan_only_results_stay_pending(site):
    """A finding with a plan but no patch still needs generation — it
    must re-enter the queue, not be parked as covered."""
    src = _sites()[site]
    assert 'remediation_status = "pending"' in src
    assert "remediation_plan_only" in src, (
        f"{site}: the plan-only path must be observable in logs"
    )


@pytest.mark.parametrize("site", ["worker", "batch_engine"])
def test_empty_and_whitespace_diffs_do_not_count(site):
    src = _sites()[site]
    assert '(rem_result.get("patch_diff") or "").strip()' in src, (
        f"{site}: a whitespace-only diff must not count as a patch"
    )


def test_batch_result_counts_only_real_patches():
    """`result.remediated` feeds the batch summary — a plan-only finding
    was counted as remediated too."""
    from services.batch_remediation import engine
    src = inspect.getsource(engine.BatchRemediationEngine)
    m = src.find("result.remediated += 1")
    assert m > 0
    window = src[max(0, m - 900):m]
    assert "if len(_diff) > 20:" in window


def test_repair_migration_downgrades_patchless_rows():
    import importlib.util, pathlib
    path = pathlib.Path(__file__).parents[2] / (
        "apps/api/alembic/versions/c9d0e1f2a3b4_repair_patchless_patch_generated.py"
    )
    assert path.exists(), "data-repair migration missing"
    src = path.read_text()
    assert "SET remediation_status = 'PENDING'" in src
    assert "NOT EXISTS" in src
    assert "length(coalesce(rp.patch_diff, '')) > 20" in src
    # The repaired state is the truthful one — restoring the false
    # status on downgrade would re-create the lie.
    assert re.search(r"def downgrade\(\) -> None:\s*\n(\s*#[^\n]*\n)*\s*pass", src)
