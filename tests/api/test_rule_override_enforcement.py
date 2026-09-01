# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Rule overrides must actually stop findings — and only in their scope.

The CRUD surface was well tested; the enforcement layer had no tests at
all. That layer is the feature: an override that stores perfectly and
skips nothing is the suppressions bug all over again, one storey down.

Scope is the sharp edge. An org-wide row has BOTH target columns NULL,
and a repo-scoped row must not leak into another repo's scan. Scope is
decided by which optional field survives parsing, which is why these
schemas forbid unknown fields: a dropped typo would silently broaden a
repo-scoped mute to the whole org.
"""
import uuid

import pytest
from unittest.mock import AsyncMock, MagicMock

from pydantic import ValidationError

from apps.api.app.schemas.rule_override import RuleOverrideCreate, RuleOverrideUpdate


# ── the typo that broadened scope ────────────────────────────────────

def test_an_unknown_field_is_rejected_not_dropped():
    """A dropped unknown field would leave the scope columns NULL and
    the override org-wide — a repo mute applied to every repository."""
    with pytest.raises(ValidationError):
        RuleOverrideCreate(
            scanner_rule_id="AWS-001",
            repositoryId=str(uuid.uuid4()),   # camelCase typo
            reason="meant to be repo-scoped",
        )


def test_update_rejects_unknown_fields_too():
    """A misspelled is_active would silently no-op the un-mute."""
    with pytest.raises(ValidationError):
        RuleOverrideUpdate(isActive=False)


def test_the_documented_examples_are_accepted_values():
    """An example that 422s when copied is documentation lying."""
    for ex in RuleOverrideCreate.model_fields["mode"].examples:
        assert RuleOverrideCreate(
            scanner_rule_id="AWS-001", mode=ex, reason="x",
        ).mode == ex
    for ex in RuleOverrideCreate.model_fields["scanner_rule_id"].examples:
        assert RuleOverrideCreate(scanner_rule_id=ex, reason="x")


def test_scope_xor_still_enforced():
    with pytest.raises(ValidationError):
        RuleOverrideCreate(
            scanner_rule_id="AWS-001",
            repository_id=uuid.uuid4(),
            scan_source_id=uuid.uuid4(),
            reason="x",
        )


# ── the loader: which rules a scan target sees ───────────────────────

def _db_returning(rows):
    db = MagicMock()
    res = MagicMock()
    res.all = MagicMock(return_value=rows)
    db.execute = AsyncMock(return_value=res)
    return db


@pytest.mark.asyncio
async def test_loader_returns_the_rule_ids_as_a_set():
    from apps.worker.rule_overrides import load_active_rule_ids
    db = _db_returning([("AWS-001",), ("JWT-001",), (None,)])
    got = await load_active_rule_ids(db, uuid.uuid4(), uuid.uuid4())
    assert got == {"AWS-001", "JWT-001"}, "None ids must be dropped"


@pytest.mark.asyncio
async def test_loader_fails_open_on_db_error():
    """Documented trade-off: a missed override is a noisy finding an
    admin can clean up; a killed scan loses signal. The loader must
    swallow and return empty, never raise into the scan."""
    from apps.worker.rule_overrides import load_active_rule_ids
    db = MagicMock()
    db.execute = AsyncMock(side_effect=RuntimeError("db down"))
    got = await load_active_rule_ids(db, uuid.uuid4(), uuid.uuid4())
    assert got == set()


def test_loader_scopes_org_wide_with_both_columns_null():
    """An org-wide row is (NULL, NULL). Testing repository_id alone
    would let a source-scoped row leak into every repo scan."""
    import inspect
    from apps.worker import rule_overrides as mod
    src = inspect.getsource(mod.load_active_rule_ids)
    assert "repository_id.is_(None)" in src
    assert "scan_source_id.is_(None)" in src


# ── the skip is wired into every scan path ───────────────────────────

def test_all_three_scan_paths_consult_overrides_and_skip():
    """Repo scans, source scans and webhook scans each load the muted
    set and branch on membership. A path that loads but never checks —
    or checks but never loads — mutes nothing silently."""
    import inspect
    from apps.worker import tasks
    src = inspect.getsource(tasks)
    for loaded, checked in [
        ("muted_rule_ids: set[str] = await load_active_rule_ids", "in muted_rule_ids"),
        ("src_muted_rule_ids", "in src_muted_rule_ids"),
        ("wh_muted_rule_ids", "in wh_muted_rule_ids"),
    ]:
        assert loaded in src, f"a scan path no longer loads overrides: {loaded}"
        assert checked in src, f"a scan path loads but never checks: {checked}"


def test_the_skip_compares_branded_ids():
    """Overrides store the branded form (AWS-001). The raw detector id
    (VOODA-SEC-AWS-001) would never match, so every comparison must go
    through brand_rule_id first — that mismatch is documented as the
    exact bug the create-endpoint normalisation exists to prevent."""
    import inspect
    from apps.worker import tasks
    src = inspect.getsource(tasks)
    assert src.count("brand_rule_id") >= 3


# ── counting blocks stays inside the scan's scope ────────────────────

@pytest.mark.asyncio
async def test_record_blocks_is_a_noop_when_nothing_was_blocked():
    """The common case must not issue an UPDATE per scan."""
    from apps.worker.rule_overrides import record_blocks
    db = MagicMock()
    db.execute = AsyncMock()
    await record_blocks(db, uuid.uuid4(), {})
    db.execute.assert_not_called()


def test_record_blocks_uses_the_same_scope_shape_as_the_loader():
    """If the two drift, a Slack-source scan increments counters on a
    repo-scoped override — the docstring names this exact hazard."""
    import inspect
    from apps.worker import rule_overrides as mod
    for fn in (mod.load_active_rule_ids, mod.record_blocks):
        src = inspect.getsource(fn)
        assert "repository_id.is_(None)" in src
        assert "scan_source_id.is_(None)" in src


# ── expiry: mutes that lift themselves ───────────────────────────────

def test_a_past_expiry_is_refused_on_create():
    """An override born expired was never in force — almost certainly a
    timezone slip, and better refused than silently inert."""
    from datetime import datetime, timezone
    with pytest.raises(ValidationError):
        RuleOverrideCreate(
            scanner_rule_id="AWS-001", reason="x",
            expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )


def test_a_past_expiry_is_refused_on_update_but_null_clears():
    from datetime import datetime, timezone
    with pytest.raises(ValidationError):
        RuleOverrideUpdate(expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    assert RuleOverrideUpdate(expires_at=None).expires_at is None


def test_the_loader_excludes_expired_rows():
    """Enforcement is read-side only: the next scan simply no longer
    sees the rule, so findings resurface with no cron and no state
    flip. NULL keeps meaning 'until someone turns it off'."""
    import inspect
    from apps.worker import rule_overrides as mod
    src = inspect.getsource(mod.load_active_rule_ids)
    assert "expires_at.is_(None)" in src
    assert "expires_at > func.now()" in src


def test_stats_do_not_count_expired_rows_as_active():
    """A tile that says Active for a mute that scans ignore makes the
    dashboard disagree with behaviour."""
    import inspect
    from apps.api.app.routers import rule_overrides as router
    src = inspect.getsource(router.rule_override_stats)
    assert src.count("expires_at.is_(None)") >= 4


# ── one owner per blocked count ──────────────────────────────────────

def test_block_attribution_picks_the_most_specific_override():
    """When a repo-scoped and an org-wide override cover the same rule,
    the scoped one is doing the muting for that repo, so it alone owns
    the number. Incrementing both would over-count the Findings
    Blocked tile."""
    import inspect
    from apps.worker import rule_overrides as mod
    src = inspect.getsource(mod.record_blocks)
    assert "owner_for" in src
    assert "is_scoped" in src


def test_record_blocks_also_excludes_expired_rows():
    """An expired override cannot have caused a skip, so it must not
    absorb the count either."""
    import inspect
    from apps.worker import rule_overrides as mod
    src = inspect.getsource(mod.record_blocks)
    assert "expires_at.is_(None)" in src


# ── fail-open is no longer silent ────────────────────────────────────

@pytest.mark.asyncio
async def test_a_load_failure_is_stamped_onto_the_scan_job():
    """Fail-open stays right (a killed scan loses signal), but the scan
    that ran WITHOUT the configured mutes must say so somewhere the
    product can show — not only in worker logs."""
    from apps.worker.rule_overrides import load_active_rule_ids

    class _Job:
        stats = {"findings_count": 3}

    db = MagicMock()
    db.execute = AsyncMock(side_effect=RuntimeError("db down"))
    got = await load_active_rule_ids(db, uuid.uuid4(), uuid.uuid4(), scan_job=_Job)
    assert got == set(), "must still fail open"
    assert _Job.stats["rule_overrides_load_failed"] is True
    assert _Job.stats["findings_count"] == 3, "existing stats preserved"


def test_every_scan_path_passes_its_job_for_stamping():
    import inspect
    from apps.worker import tasks
    src = inspect.getsource(tasks)
    assert src.count("scan_job=job,") >= 3
