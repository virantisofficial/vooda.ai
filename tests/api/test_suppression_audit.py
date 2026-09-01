"""Suppression audit-trail regression tests.

Covers the scenarios from Track-A P0 #2:

  A. Creating a suppression emits ``suppression_created`` audit event
  B. Updating a non-active field emits ``suppression_updated``
  C. Flipping is_active=False emits ``suppression_deactivated``
  D. Flipping is_active=True emits ``suppression_reactivated``
  E. Deleting a suppression emits ``suppression_deleted``
  F. Pattern learning that creates new rules emits ``suppressions_learned``

Compliance context: Settings → Suppressions is the surface where a
security/eng lead mutes a noisy scanner rule.  Without an audit row,
SOC 2 / ISO 27001 auditors have no way to answer "who muted what,
when, and why" — the only signal was a silent ``is_active=False`` on
a DB column with no actor and no narrative.

These tests exercise the actual log_audit() call through a stubbed
session so they don't need a live DB.  The point is to lock the
*contract* (action name + the metadata fields each one carries) so a
future refactor can't silently strip the audit.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest


pytestmark = pytest.mark.asyncio


class _FakeSuppressionRule:
    """Stand-in row that doesn't need a real DB session."""
    def __init__(self, **kw):
        self.id = uuid4()
        self.name = kw.get("name", "test-rule")
        self.description = kw.get("description")
        self.suppression_type = kw.get("suppression_type", "manual")
        self.scanner_rule_id = kw.get("scanner_rule_id")
        self.pattern_hash = kw.get("pattern_hash")
        self.vulnerability_category = kw.get("vulnerability_category")
        self.cwe = kw.get("cwe")
        self.file_path_pattern = kw.get("file_path_pattern")
        # Mirrors the model: NULL on an ordinary rule, "pending"
        # while a learning proposal awaits review.
        self.review_status = kw.get("review_status")
        self.evidence_count = kw.get("evidence_count", 0)
        self.evidence_repo_count = kw.get("evidence_repo_count", 0)
        self.confidence = kw.get("confidence", 0.85)
        self.sample_code = kw.get("sample_code")
        self.is_active = kw.get("is_active", True)
        self.created_by = kw.get("created_by", "user@example.com")
        self.times_applied = kw.get("times_applied", 0)
        self.tenant_id = uuid4()
        from datetime import datetime, timezone
        self.created_at = datetime.now(timezone.utc)
        # Mock __table__.columns iteration used by response builder
        self.__table__ = MagicMock()
        cols = []
        for attr_name in [
            "id", "name", "description", "suppression_type",
            "scanner_rule_id", "pattern_hash", "vulnerability_category",
            "cwe", "file_path_pattern", "evidence_count",
            "evidence_repo_count", "confidence", "sample_code",
            "is_active", "created_by", "times_applied",
        ]:
            c = MagicMock()
            c.name = attr_name
            cols.append(c)
        self.__table__.columns = cols


@pytest.fixture
def fake_user():
    u = MagicMock()
    u.tenant_id = uuid4()
    u.id = uuid4()
    u.email = "reviewer@vooda.ai"
    return u


@pytest.fixture
def captured_audits():
    """Collects log_audit() calls so tests can assert on action + metadata."""
    return []


@pytest.fixture
def mock_log_audit(captured_audits):
    async def _spy(db, user, action, resource_type, resource_id=None, detail=None, metadata=None, **_):
        captured_audits.append({
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "detail": detail,
            "metadata": metadata,
            "user_id": getattr(user, "id", None),
            "tenant_id": getattr(user, "tenant_id", None),
        })
    return _spy


# ── A: create emits suppression_created ──────────────────────


async def test_create_suppression_emits_audit(fake_user, captured_audits, mock_log_audit):
    from apps.api.app.routers import suppressions as suppressions_mod
    from apps.api.app.routers.suppressions import SuppressionRuleCreate, create_suppression_rule

    body = SuppressionRuleCreate(
        name="Mute Java class-decl FPs",
        description="Class decl matches AKIA-shape; never real",
        scanner_rule_id="VOODA-SEC-AWS-001",
        file_path_pattern="**/*.java",
    )

    # The router does: db.add(rule); await db.flush(); await db.refresh(rule)
    # We just need flush/refresh to be no-ops; add() to register the row
    # against our fake session so we can hand it back from refresh.
    added: list = []
    db = MagicMock()
    db.add = lambda x: added.append(x)
    db.flush = AsyncMock()
    # The admin gate SELECTs the user's role row before anything else;
    # a truthy scalar means "is an admin", which this test's actor is.
    _role_row = MagicMock()
    _role_row.scalar_one_or_none = MagicMock(return_value=object())
    db.execute = AsyncMock(return_value=_role_row)

    async def _refresh(obj):
        # Populate the row id + created_at like a real flush would
        from datetime import datetime, timezone
        obj.id = obj.id or uuid4()
        obj.created_at = obj.created_at or datetime.now(timezone.utc)
    db.refresh = _refresh

    with patch.object(suppressions_mod, "log_audit", side_effect=mock_log_audit), \
         patch.object(suppressions_mod, "SuppressionRule", _FakeSuppressionRule):
        resp = await create_suppression_rule(body=body, db=db, user=fake_user)

    assert resp is not None
    assert len(captured_audits) == 1, "expected exactly one audit row"
    ev = captured_audits[0]
    assert ev["action"] == "suppression_created"
    assert ev["resource_type"] == "suppression_rule"
    md = ev["metadata"]
    assert md["name"] == "Mute Java class-decl FPs"
    assert md["scanner_rule_id"] == "VOODA-SEC-AWS-001"
    assert md["file_path_pattern"] == "**/*.java"


# ── B/C/D: update emits the right action + diff ──────────────


async def _run_update(initial_state, patch_body, captured_audits, mock_log_audit, fake_user):
    """Helper — drive update_suppression_rule with a fake DB."""
    from apps.api.app.routers import suppressions as suppressions_mod
    from apps.api.app.routers.suppressions import SuppressionRuleUpdate, update_suppression_rule

    rule = _FakeSuppressionRule(**initial_state)

    db = MagicMock()
    # SELECT returns our fake rule
    select_result = MagicMock()
    select_result.scalar_one_or_none = MagicMock(return_value=rule)
    db.execute = AsyncMock(return_value=select_result)
    db.flush = AsyncMock()

    async def _refresh(obj):
        return None
    db.refresh = _refresh

    body = SuppressionRuleUpdate(**patch_body)
    with patch.object(suppressions_mod, "log_audit", side_effect=mock_log_audit):
        await update_suppression_rule(rule_id=rule.id, body=body, db=db, user=fake_user)
    return rule


async def test_update_field_emits_suppression_updated(captured_audits, mock_log_audit, fake_user):
    """Scenario B: rename a rule — action is 'suppression_updated'."""
    await _run_update(
        initial_state={"name": "old name", "is_active": True},
        patch_body={"name": "new name"},
        captured_audits=captured_audits,
        mock_log_audit=mock_log_audit,
        fake_user=fake_user,
    )
    assert len(captured_audits) == 1
    ev = captured_audits[0]
    assert ev["action"] == "suppression_updated"
    diff = ev["metadata"]["diff"]
    assert "name" in diff
    assert diff["name"]["from"] == "old name"
    assert diff["name"]["to"] == "new name"


async def test_update_is_active_false_emits_deactivated(captured_audits, mock_log_audit, fake_user):
    """Scenario C: muting flip — action is 'suppression_deactivated'."""
    await _run_update(
        initial_state={"name": "muted-rule", "is_active": True},
        patch_body={"is_active": False},
        captured_audits=captured_audits,
        mock_log_audit=mock_log_audit,
        fake_user=fake_user,
    )
    assert len(captured_audits) == 1
    assert captured_audits[0]["action"] == "suppression_deactivated"


async def test_update_is_active_true_emits_reactivated(captured_audits, mock_log_audit, fake_user):
    """Scenario D: unmuting flip — action is 'suppression_reactivated'."""
    await _run_update(
        initial_state={"name": "re-muted-rule", "is_active": False},
        patch_body={"is_active": True},
        captured_audits=captured_audits,
        mock_log_audit=mock_log_audit,
        fake_user=fake_user,
    )
    assert len(captured_audits) == 1
    assert captured_audits[0]["action"] == "suppression_reactivated"


async def test_mixed_update_with_is_active_uses_generic_action(captured_audits, mock_log_audit, fake_user):
    """When the update bundles is_active with other fields, prefer the
    generic 'suppression_updated' action so the audit row reflects the
    multi-field nature — the diff metadata still carries the is_active
    flip for forensic queries."""
    await _run_update(
        initial_state={"name": "rule", "is_active": True},
        patch_body={"is_active": False, "name": "new-rule"},
        captured_audits=captured_audits,
        mock_log_audit=mock_log_audit,
        fake_user=fake_user,
    )
    assert len(captured_audits) == 1
    ev = captured_audits[0]
    assert ev["action"] == "suppression_updated"
    diff = ev["metadata"]["diff"]
    assert "is_active" in diff
    assert "name" in diff


# ── E: delete emits suppression_deleted ──────────────────────


async def test_delete_suppression_emits_audit(captured_audits, mock_log_audit, fake_user):
    from apps.api.app.routers import suppressions as suppressions_mod
    from apps.api.app.routers.suppressions import delete_suppression_rule

    rule = _FakeSuppressionRule(
        name="Java class-decl FPs",
        scanner_rule_id="VOODA-SEC-AWS-001",
        file_path_pattern="**/*.java",
        times_applied=42,
    )

    db = MagicMock()
    select_result = MagicMock()
    select_result.scalar_one_or_none = MagicMock(return_value=rule)
    db.execute = AsyncMock(return_value=select_result)
    db.delete = AsyncMock()

    with patch.object(suppressions_mod, "log_audit", side_effect=mock_log_audit):
        await delete_suppression_rule(rule_id=rule.id, db=db, user=fake_user)

    assert len(captured_audits) == 1
    ev = captured_audits[0]
    assert ev["action"] == "suppression_deleted"
    md = ev["metadata"]
    # CRITICAL: metadata must preserve scope info AFTER row deletion,
    # because the row itself is gone — audit metadata is the only
    # surviving record.
    assert md["name"] == "Java class-decl FPs"
    assert md["scanner_rule_id"] == "VOODA-SEC-AWS-001"
    assert md["file_path_pattern"] == "**/*.java"
    assert md["times_applied"] == 42


# ── F: pattern-learning emits suppressions_learned ───────────


async def test_learning_with_no_new_rules_skips_audit(captured_audits, mock_log_audit, fake_user):
    """No-op learning runs (no new rules created) should NOT spam the
    audit log.  Routine background passes that found nothing are not
    a compliance event."""
    from apps.api.app.routers import suppressions as suppressions_mod
    from apps.api.app.routers.suppressions import trigger_learning

    # Learning now goes through one writer, which reports what it made:
    # rules from confirmed decisions, proposals from AI triage.
    async def _nothing_new(*a, **k):
        return {"created_active": 0, "created_pending": 0}
    mod = MagicMock()
    mod.sync_learned_rules = _nothing_new

    db = MagicMock()
    db.execute = AsyncMock()
    db.flush = AsyncMock()
    db.add = MagicMock()

    with patch.dict("sys.modules", {"services.learning.pattern_learner": mod}), \
         patch.object(suppressions_mod, "log_audit", side_effect=mock_log_audit):
        result = await trigger_learning(db=db, user=fake_user)

    assert result == {"rules_created": 0, "proposals_created": 0}
    assert len(captured_audits) == 0, "no-op learning runs must not audit"


async def test_learning_audits_rules_and_proposals_separately(
    captured_audits, mock_log_audit, fake_user,
):
    """A proposal is not a suppression. An auditor reading "learning
    created 6 rules" must not be counting 6 things that suppress nothing
    and are still waiting on a human."""
    from apps.api.app.routers import suppressions as suppressions_mod
    from apps.api.app.routers.suppressions import trigger_learning

    async def _some(*a, **k):
        return {"created_active": 2, "created_pending": 4}
    mod = MagicMock()
    mod.sync_learned_rules = _some

    db = MagicMock()
    db.execute = AsyncMock()
    db.flush = AsyncMock()

    with patch.dict("sys.modules", {"services.learning.pattern_learner": mod}), \
         patch.object(suppressions_mod, "log_audit", side_effect=mock_log_audit):
        result = await trigger_learning(db=db, user=fake_user)

    assert result == {"rules_created": 2, "proposals_created": 4}
    assert len(captured_audits) == 1
    md = captured_audits[0]["metadata"]
    assert md["rules_created"] == 2
    assert md["proposals_created"] == 4
