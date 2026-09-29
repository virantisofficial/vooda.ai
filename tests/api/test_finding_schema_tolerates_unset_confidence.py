"""A nullable column must not be able to 500 the findings list.

`normalized_findings.confidence` is nullable, but the response model
declared it a required float — so one row without a scanner confidence
made GET /findings fail entirely rather than returning that row with
the field absent. An endpoint that lists findings should not be one
unset value away from returning nothing.
"""
import pytest
from pydantic import ValidationError

from apps.api.app.schemas.finding import FindingListItem


def _row(**over):
    base = dict(
        id="11111111-1111-1111-1111-111111111111",
        title="PostgreSQL Connection with Password",
        vulnerability_category="secrets",
        severity="high",
        classification="LIKELY_TRUE_POSITIVE",
        review_status="pending",
        remediation_status="open",
        scanner_name="vooda",
        file_path="dvwa/includes/DBMS/PGSQL.php",
        line_start=12,
        confidence=0.8,
        ai_confidence=None,
        created_at="2026-09-25T00:00:00Z",
    )
    base.update(over)
    return base


def test_a_row_without_scanner_confidence_still_serialises():
    item = FindingListItem.model_validate(_row(confidence=None))
    assert item.confidence is None


def test_the_nullable_columns_agree_with_the_schema():
    """Both confidence columns are nullable in the database; neither
    may be required here, or a legitimate NULL becomes a 500."""
    for field in ("confidence", "ai_confidence"):
        assert not FindingListItem.model_fields[field].is_required(), field


def test_a_real_value_is_still_carried_through():
    assert FindingListItem.model_validate(_row(confidence=0.75)).confidence == 0.75
