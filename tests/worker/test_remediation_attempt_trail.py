# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Every remediation attempt leaves a settled record.

47 findings sat with a plan and no patch, and 3 more claimed PENDING
with no plan at all — failures with no status, no error, no retry
path, indistinguishable in the UI from work in progress. The plan row
is now the attempt record: created before anything that can fail, and
every exit settles it ('patched' | 'no_patch' | 'failed' + error).
"""
import inspect

from apps.worker import tasks


def _src():
    return inspect.getsource(tasks._generate_remediation)


def test_the_plan_is_created_before_the_model_is_called():
    """A crash mid-call must still leave a row that says so."""
    src = _src()
    assert src.index('status="generating"') < src.index("generate_remediation(finding_data")


def test_every_failure_path_settles_the_attempt():
    src = _src()
    assert 'await _settle("failed", "no AI provider configured' in src
    assert 'await _settle("failed", f"context extraction' in src
    assert 'await _settle("failed", str(gen_err))' in src


def test_success_and_plan_only_settle_too():
    src = _src()
    assert 'plan.status = "patched"' in src
    assert 'plan.status = "no_patch"' in src


def test_no_outcome_leaves_a_finding_claiming_pending():
    """PENDING is 'queued/in-flight'. Settled outcomes go to NONE (or
    PATCH_GENERATED), so nothing failed reads as forever in-progress
    and everything failed stays eligible for re-queue."""
    src = _src()
    assert 'finding.remediation_status = "pending"' not in src


def test_the_shadowed_batch_task_is_gone():
    """Two same-name Celery tasks: the later registration silently
    replaced the earlier one, leaving dead code that read as live."""
    src_all = inspect.getsource(tasks)
    assert src_all.count("def batch_remediate(") == 1
    assert src_all.count("async def _batch_remediate(") == 1


def test_backfill_selection_matches_the_dashboard_metric():
    """'Queued' by the backfill and 'missing' on the tile must be the
    same set, or the button can never close the gap it advertises."""
    from apps.api.app.routers import findings
    src = inspect.getsource(findings.backfill_remediation)
    assert "patch_diff" in src and "> 20" in src, "same real-diff bar as metrics"
    assert "LIKELY_TRUE_POSITIVE" in src, "same eligibility as the scan pipeline"
    assert "repository_id.is_not(None)" in src, "nothing to patch without a snapshot"
