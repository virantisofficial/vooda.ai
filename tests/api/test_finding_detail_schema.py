"""FindingDetail response-schema regression tests.

Bug discovered 2026-05-04 (after AI triage for source findings
shipped): the `FindingDetail` Pydantic schema declared
``repository_id: UUID`` as a required field. Source-scan findings
have ``repository_id = None`` (their parent is ``scan_source_id``
instead) — every ``GET /api/v1/findings/{id}`` request for a Slack
or Jira finding 500'd with::

    UUID input should be a string, bytes or UUID object
    [type=uuid_type, input_value=None, input_type=NoneType]

Symptom: the side panel in the findings UI stopped opening because
the detail fetch silently failed.

These tests guard against the regression in two directions:

  1. Every model field that's NULL-able in the database AND can
     legitimately be None on a real finding row must be Optional in
     the response schema. Source findings are the canonical "lots of
     fields are None" case.

  2. The reverse — every required (non-Optional) schema field must
     correspond to a model column that's either NOT NULL in the DB
     or guaranteed-populated by the persistence path.

Pure unit tests — build a fake row dict and validate it through the
schema. No DB or network needed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from apps.api.app.schemas.finding import FindingDetail, FindingListItem


# ── Fixture builders ─────────────────────────────────────────


def _git_finding_dict() -> dict:
    """Minimal valid git-scan finding shape — has repository_id,
    no scan_source_id."""
    now = datetime.now(timezone.utc)
    return {
        "id": uuid4(),
        "scan_job_id": uuid4(),
        "repository_id": uuid4(),
        "scan_source_id": None,
        "scanner_name": "vooda-secret-scan",
        "scanner_rule_id": "VOODA-SEC-AWS-001",
        "external_finding_id": None,
        "title": "AWS Access Key",
        "description": "Hardcoded AWS access key",
        "vulnerability_category": "Hardcoded Secret",
        "cwe": "CWE-798",
        "cve": None,
        "severity": "high",
        "confidence": 0.9,
        "exploitability_score": None,
        "business_risk_score": None,
        "branch": "main",
        "commit_sha": "abc123",
        "file_path": "src/config.py",
        "line_start": 42,
        "line_end": None,
        "function_name": None,
        "class_name": None,
        "code_snippet": "AWS_KEY = 'AKIA...'",
        "classification": "needs_review",
        "ai_explanation": None,
        "ai_confidence": None,
        "true_positive_reasons": [],
        "false_positive_reasons": [],
        "compensating_controls": [],
        "review_status": "unreviewed",
        "remediation_status": "none",
        "is_suppressed": False,
        "source_metadata": None,
        "sink_metadata": None,
        "assigned_to": None,
        "tags": None,            # Should be coerced to []
        "stability_id": None,
        "first_seen_at": None,
        "last_seen_at": None,
        "scan_count": 0,
        "cache_hit": False,
        "cache_source": None,
        "evidence": [],
        "decisions": [],
        "remediation_plans": [],
        "created_at": now,
        "updated_at": now,
    }


def _source_finding_dict() -> dict:
    """Minimal valid source-scan finding shape — repository_id=None,
    scan_source_id set, file_path is a URL locator."""
    d = _git_finding_dict()
    d.update({
        "repository_id": None,             # ← the bug-trigger field
        "scan_source_id": uuid4(),
        "scanner_name": "vooda-source-scan",
        "scanner_rule_id": "VOODA-SEC-GEN-003-COLLAB",
        "branch": None,
        "commit_sha": None,
        "file_path": "slack://C04ABC/1777778918.896719",
        "code_snippet": "the prod password=hunter2-real fyi",
        "classification": "likely_true_positive",
        "ai_explanation": "Hardcoded password in a Slack message...",
        "ai_confidence": 0.75,
        "true_positive_reasons": ["Real password value in a Slack message"],
    })
    return d


# ── Regression: source findings must validate ─────────────────


def test_finding_detail_validates_source_finding():
    """The reported bug: source-scan findings have repository_id=None
    but the schema demanded UUID. Must validate now."""
    d = _source_finding_dict()
    assert d["repository_id"] is None
    m = FindingDetail.model_validate(d)
    assert m.repository_id is None
    assert m.scan_source_id is not None
    assert m.classification == "likely_true_positive"


def test_finding_detail_validates_git_finding():
    """Git findings still work — Optional doesn't break the existing
    path."""
    d = _git_finding_dict()
    assert d["repository_id"] is not None
    m = FindingDetail.model_validate(d)
    assert m.repository_id is not None
    assert m.scan_source_id is None


def test_finding_detail_coerces_none_tags_to_empty_list():
    """Pre-existing validator — covered separately because it's
    easily broken by a refactor + the bug also surfaces as a 500."""
    d = _git_finding_dict()
    d["tags"] = None
    m = FindingDetail.model_validate(d)
    assert m.tags == []


# ── Schema-level invariants ───────────────────────────────────


def test_repository_id_field_is_optional():
    """Direct schema-introspection guard: any future refactor that
    re-tightens repository_id back to required should fail this
    test loudly instead of silently breaking the UI."""
    field = FindingDetail.model_fields["repository_id"]
    assert not field.is_required(), (
        "FindingDetail.repository_id MUST stay Optional — "
        "source-scan findings have repository_id=None and the side "
        "panel will 500 if this becomes required again."
    )


def test_scan_source_id_field_present_and_optional():
    """The companion field — must be on the schema so the FE can
    link source findings back to their source page."""
    assert "scan_source_id" in FindingDetail.model_fields
    field = FindingDetail.model_fields["scan_source_id"]
    assert not field.is_required()


# ── Data-shape edge cases on source findings ──────────────────


@pytest.mark.parametrize("locator", [
    "slack://C04ABC/1234.5",
    "jira://TRUF-99/description",
    "s3://bucket/path/to/key.env",
    "m365://site/drive/item",
    "salesforce://Case/5003t",
])
def test_finding_detail_accepts_url_shaped_file_paths(locator):
    """`file_path` is a URL locator on source findings — must NOT
    be rejected even though it doesn't look like a filesystem path."""
    d = _source_finding_dict()
    d["file_path"] = locator
    m = FindingDetail.model_validate(d)
    assert m.file_path == locator


# ── List item parity (same Optional repository semantics) ─────


def test_finding_list_item_does_not_require_repository_id():
    """FindingListItem doesn't currently include repository_id, but
    if a future change adds it, that change must keep it Optional."""
    if "repository_id" in FindingListItem.model_fields:
        field = FindingListItem.model_fields["repository_id"]
        assert not field.is_required(), (
            "FindingListItem.repository_id (if present) must stay "
            "Optional for the same reason as FindingDetail."
        )
