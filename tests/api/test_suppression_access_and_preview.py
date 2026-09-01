# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Suppression writes are tenant-admin actions; previews are free.

A suppression rule is tenant-wide policy — it moves findings out of
every member's queue — not a per-finding triage call, so writes carry
the same admin gate the sibling rule-overrides surface has. Reads stay
open: seeing which rules exist reveals nothing the findings list
doesn't.

The preview endpoint is the inverse case: it must be reachable before
a rule exists, because "how many findings would this hide" is the
question to answer BEFORE saving, not after.
"""
import uuid

import pytest
from unittest.mock import AsyncMock, MagicMock

from fastapi import HTTPException
from pydantic import ValidationError

from apps.api.app.routers import suppressions as mod
from apps.api.app.routers.suppressions import (
    SuppressionPreviewRequest,
    _require_admin,
)


def _db_where_user_has_no_admin_role():
    db = MagicMock()
    res = MagicMock()
    res.scalar_one_or_none = MagicMock(return_value=None)
    db.execute = AsyncMock(return_value=res)
    return db


def _db_where_user_is_admin():
    db = MagicMock()
    res = MagicMock()
    res.scalar_one_or_none = MagicMock(return_value=object())
    db.execute = AsyncMock(return_value=res)
    return db


# ── the gate itself ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_non_admin_is_refused_with_403():
    user = MagicMock(); user.id = uuid.uuid4()
    with pytest.raises(HTTPException) as exc:
        await _require_admin(_db_where_user_has_no_admin_role(), user)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_an_admin_passes():
    user = MagicMock(); user.id = uuid.uuid4()
    await _require_admin(_db_where_user_is_admin(), user)  # must not raise


# ── every write endpoint carries it ──────────────────────────────────

@pytest.mark.parametrize("endpoint", [
    "create_suppression_rule",
    "update_suppression_rule",
    "delete_suppression_rule",
    "trigger_learning",
    "review_proposal",
])
def test_every_write_endpoint_checks_admin(endpoint):
    import inspect
    src = inspect.getsource(getattr(mod, endpoint))
    assert "_require_admin(db, user)" in src, (
        f"{endpoint} writes tenant-wide suppression policy and must "
        f"carry the admin gate"
    )


@pytest.mark.parametrize("endpoint", [
    "list_suppression_rules",
    "suppression_stats",
    "preview_suppression_rule",
])
def test_reads_and_previews_stay_open(endpoint):
    """Gating reads would break the page for every non-admin member
    while protecting nothing they can't already see."""
    import inspect
    src = inspect.getsource(getattr(mod, endpoint))
    assert "_require_admin" not in src


# ── the preview contract ─────────────────────────────────────────────

def test_preview_needs_at_least_one_criterion():
    with pytest.raises(ValidationError):
        SuppressionPreviewRequest()


def test_preview_rejects_unknown_fields():
    """Same strictness as create: a misspelled criterion silently
    matching everything-minus-that-field would preview the wrong rule."""
    with pytest.raises(ValidationError):
        SuppressionPreviewRequest(scanner_rule_id="AWS-001", rule="typo")


def test_preview_counts_only_unsuppressed():
    """The number answers "what changes when I save this" — findings a
    rule already hides won't change."""
    import inspect
    src = inspect.getsource(mod.preview_suppression_rule)
    assert "is_suppressed == False" in src


# ── the prefilter must narrow, never decide ──────────────────────────

def test_prefilter_covers_exactly_the_equality_criteria():
    from services.suppressions.engine import _exact_criteria_clauses

    class _R:
        scanner_rule_id = "AWS-001"
        vulnerability_category = "Hardcoded Secret"
        cwe = "CWE-798"
        file_path_pattern = "tests/**"   # must NOT become SQL
        pattern_hash = "abc"             # must NOT become SQL

    clauses = _exact_criteria_clauses(_R)
    assert len(clauses) == 3, (
        "glob and hash semantics live in Python; pushing them into SQL "
        "as LIKE/equality would change what the rule matches"
    )


def test_scans_still_finish_with_rule_matches():
    """The prefilter is an optimisation. Rows it returns must still be
    judged by the real matcher, or SQL becomes a second, drifting
    definition of what a rule means."""
    import inspect
    from services.suppressions import engine
    for fn in (engine.apply_rule_to_existing,):
        src = inspect.getsource(fn)
        assert "_exact_criteria_clauses" in src
    assert "rule_matches" in inspect.getsource(engine.count_matching)
