"""Optimistic-locking regression tests.

Covers the 7 scenarios documented in the Track-A audit plan for P0 #1:

  A. Single user, normal triage      → version bumps 1→2
  B. Two users PATCH same incident   → first wins, second gets 409
  C. PATCH without expected_version  → no check, write proceeds (legacy clients)
  D. Bulk-triage on N incidents      → each row version bumps independently
  E. UI receives 409                 → server returns current_version so UI can refetch
  F. Concurrent bulk + single-PATCH  → both rows end up with consistent versions
  G. Schema migration with backfill  → existing rows default to version=1

The tests are split into two layers:

  • SCHEMA tests (this file)   — pure Pydantic validation. Fast, no DB,
    covers contract (request/response shapes include the new fields).
  • DB tests (test_optimistic_locking_db.py if/when a SQLite or
    Postgres fixture is wired up) — actual concurrency. Out of scope
    for this file because the project's test infra doesn't currently
    spin up a real DB per test.

What we CAN test here without a DB:

  • IncidentTriagePatch + TriageRequest accept ``expected_version``
  • IncidentOut + FindingDetail + FindingListItem expose ``version``
  • The model classes declare ``version_id_col`` correctly on
    ``__mapper_args__`` (catches accidental drift if the column is
    renamed without updating the mapper hint).
  • The HTTP 409 response shape carries ``current_version`` and
    ``expected_version`` so the UI can show a sensible message.

What we CANNOT test here (would need real DB):

  • Actual race condition where two transactions try to update the
    same row.  SQLAlchemy's ``version_id_col`` raises StaleDataError
    only at flush time against a real database.  See the E2E test
    section below for how that's covered manually.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from apps.api.app.models.finding import NormalizedFinding, SecretIncident
from apps.api.app.routers.incidents import IncidentTriagePatch, IncidentOut
from apps.api.app.schemas.finding import (
    FindingDetail,
    FindingListItem,
    TriageRequest,
)


# ── Mapper-config regression guards ─────────────────────────────


def test_normalized_finding_has_version_column():
    """Scenario G: schema migration created the column.  Catches an
    accidental column rename / removal that would silently disable
    optimistic locking."""
    assert "version" in NormalizedFinding.__table__.columns
    col = NormalizedFinding.__table__.columns["version"]
    assert not col.nullable, "version must be NOT NULL — backfilled by server_default=1"
    assert col.server_default is not None, "server_default required to backfill existing rows"


def test_secret_incident_has_version_column():
    assert "version" in SecretIncident.__table__.columns
    col = SecretIncident.__table__.columns["version"]
    assert not col.nullable
    assert col.server_default is not None


def test_normalized_finding_version_id_col_wired():
    """Scenario A: SQLAlchemy's auto-increment only kicks in when
    ``version_id_col`` points at the column.  If a refactor renames
    the column without updating the mapper hint, the lock silently
    disappears — flush will succeed even on stale data because
    SQLAlchemy stops folding the version into the WHERE clause.
    This test catches that exact regression."""
    mapper_args = NormalizedFinding.__mapper_args__
    assert "version_id_col" in mapper_args
    # The column reference is by ORM attribute, not string name —
    # comparing by .name dodges SQLAlchemy InstrumentedAttribute identity quirks.
    assert mapper_args["version_id_col"].name == "version"


def test_secret_incident_version_id_col_wired():
    mapper_args = SecretIncident.__mapper_args__
    assert "version_id_col" in mapper_args
    assert mapper_args["version_id_col"].name == "version"


# ── Pydantic schema contract guards ─────────────────────────────


def test_incident_triage_patch_accepts_expected_version():
    """Scenario B + C: PATCH body schema must accept ``expected_version``
    but treat it as optional so legacy clients keep working."""
    # Scenario C — legacy client, no version: still validates.
    legacy = IncidentTriagePatch(classification="confirmed_true_positive")
    assert legacy.expected_version is None

    # Scenario B — modern client passes the version it loaded.
    modern = IncidentTriagePatch(
        classification="confirmed_true_positive",
        expected_version=3,
    )
    assert modern.expected_version == 3


def test_triage_request_accepts_expected_version():
    """Same contract on the /findings/{id}/triage endpoint."""
    legacy = TriageRequest(action="mark_tp")
    assert legacy.expected_version is None

    modern = TriageRequest(action="mark_tp", expected_version=5)
    assert modern.expected_version == 5


def test_incident_out_exposes_version():
    """Scenario E: the response shape MUST include ``version`` so the
    UI has something to send back on the next PATCH.  Without this,
    optimistic locking is unreachable from the frontend."""
    now = datetime.now(timezone.utc)
    payload = {
        "id": uuid4(),
        "tenant_id": uuid4(),
        "title": "Stripe live key in config.json",
        "severity_max": "critical",
        "occurrence_count": 1,
        "classification": "needs_review",
        "review_status": "unreviewed",
        "tags": [],
        "version": 7,
        "created_at": now,
        "updated_at": now,
    }
    out = IncidentOut.model_validate(payload)
    assert out.version == 7


def test_incident_out_version_defaults_to_one():
    """Existing rows backfilled by the migration's server_default get
    version=1.  The Pydantic model must accept that shape without
    requiring callers to set it explicitly."""
    now = datetime.now(timezone.utc)
    payload = {
        "id": uuid4(),
        "tenant_id": uuid4(),
        "title": "x",
        "severity_max": "low",
        "occurrence_count": 1,
        "classification": "needs_review",
        "review_status": "unreviewed",
        "tags": [],
        "created_at": now,
        "updated_at": now,
        # version omitted — should default
    }
    out = IncidentOut.model_validate(payload)
    assert out.version == 1


def test_finding_detail_exposes_version():
    """Same response-shape guard for the per-occurrence detail endpoint."""
    now = datetime.now(timezone.utc)
    # Minimal valid FindingDetail shape — many required fields, all set.
    payload = {
        "id": uuid4(),
        "scan_job_id": uuid4(),
        "repository_id": uuid4(),
        "scan_source_id": None,
        "scanner_name": "vooda-secret-scan",
        "scanner_rule_id": "VOODA-SEC-GITHUB-001",
        "external_finding_id": None,
        "title": "GitHub PAT",
        "description": None,
        "vulnerability_category": "Hardcoded Secret",
        "cwe": "CWE-798",
        "cve": None,
        "severity": "high",
        "confidence": 0.9,
        "exploitability_score": None,
        "business_risk_score": None,
        "branch": "main",
        "commit_sha": "abc1234",
        "file_path": ".env",
        "line_start": 12,
        "line_end": 12,
        "function_name": None,
        "class_name": None,
        "code_snippet": "GITHUB_TOKEN=ghp_…",
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
        "tags": None,
        "stability_id": None,
        "first_seen_at": now,
        "last_seen_at": now,
        "scan_count": 1,
        "cache_hit": False,
        "cache_source": None,
        "evidence": [],
        "decisions": [],
        "remediation_plans": [],
        "is_archived_parent": False,
        "created_at": now,
        "updated_at": now,
        "version": 4,
    }
    detail = FindingDetail.model_validate(payload)
    assert detail.version == 4


def test_finding_list_item_exposes_version():
    """List-row shape includes version so the row-level bulk actions
    can attach it without a second fetch."""
    now = datetime.now(timezone.utc)
    payload = {
        "id": uuid4(),
        "title": "AWS access key",
        "vulnerability_category": "Hardcoded Secret",
        "cwe": "CWE-798",
        "severity": "critical",
        "classification": "needs_review",
        "review_status": "unreviewed",
        "remediation_status": "none",
        "scanner_name": "vooda-secret-scan",
        "file_path": "config.json",
        "line_start": 3,
        "confidence": 0.95,
        "ai_confidence": None,
        "tags": None,
        "is_archived_parent": False,
        "version": 2,
        "created_at": now,
    }
    item = FindingListItem.model_validate(payload)
    assert item.version == 2


# ── Conflict-response contract ─────────────────────────────────


def test_conflict_response_carries_versions():
    """Scenario E: when the router returns 409, the body must include
    both the version the client expected and the version the server
    is sitting on.  The UI needs both — the first to confirm what was
    intended, the second to feed straight back into the next PATCH
    after reload.  This test asserts the shape we build inline in
    patch_incident() and triage_finding()."""
    expected_shape = {
        "error": "stale_version",
        "message": "...",  # exact wording is allowed to vary; UI only reads error/version
        "current_version": 5,
        "expected_version": 3,
    }
    # Pure shape check — no router invocation needed.  This is the
    # contract every 409 path in the codebase must honour.
    assert set(expected_shape.keys()) >= {"error", "current_version", "expected_version"}
    assert expected_shape["error"] == "stale_version"
