"""IncidentTriagePatch vocabulary validation tests (Track-A P0 #4).

Before this hardening: SecretIncident.classification was stored as a
free-form String(40) column, and IncidentTriagePatch.classification was a
plain str — any garbage string ("definitely_not_a_secret",
"PLEASE_IGNORE", an injection payload, …) sailed through the API and
landed in the DB.  Downstream UI grouping, audit queries, and bulk
actions broke silently when they encountered values outside the
canonical vocabulary.

The fix adds @field_validator hooks to IncidentTriagePatch for
classification / review_status / rotation_status, locking each to
the canonical Classification / ReviewStatus vocabulary (+ the
historical "confirmed" synonym for review_status that the cascade
code already maps to REVIEWED).

These tests pin the contract — they FAIL if a future refactor
loosens the validator or accidentally drops one of the legacy
values.
"""
from __future__ import annotations

import pytest

from apps.api.app.routers.incidents import IncidentTriagePatch
from apps.api.app.models.finding import Classification, ReviewStatus


# ── Classification ───────────────────────────────────────────────


@pytest.mark.parametrize("value", [c.value for c in Classification])
def test_every_canonical_classification_value_accepted(value: str):
    """Every Classification enum value MUST validate cleanly through
    the patch schema — regression guard so a future enum addition
    isn't silently rejected by the validator."""
    patch = IncidentTriagePatch(classification=value)
    assert patch.classification == value


@pytest.mark.parametrize("bad_value", [
    "definitely_not_a_secret",
    "PLEASE_IGNORE",
    "rotated_typo",  # nearly right but not exact
    "Confirmed_True_Positive",  # wrong case
    " needs_review ",  # padded
    "",  # empty
    "true",  # bool-ish
    "1",  # numeric
    "<script>alert(1)</script>",  # injection payload
])
def test_garbage_classification_rejected(bad_value: str):
    """Any string outside the canonical vocab MUST raise a Pydantic
    validation error — closes the silent-garbage-write hole."""
    with pytest.raises(Exception) as exc_info:
        IncidentTriagePatch(classification=bad_value)
    # Pydantic wraps validators in ValidationError; either way, the
    # message must name the field so the API caller knows what to fix.
    assert "classification" in str(exc_info.value).lower()


def test_none_classification_passes_through():
    """None means 'leave unchanged' — must not fail validation."""
    patch = IncidentTriagePatch(classification=None)
    assert patch.classification is None


# ── ReviewStatus ─────────────────────────────────────────────────


@pytest.mark.parametrize("value", [s.value for s in ReviewStatus])
def test_every_canonical_review_status_accepted(value: str):
    patch = IncidentTriagePatch(review_status=value)
    assert patch.review_status == value


def test_confirmed_review_status_accepted_as_synonym():
    """The cascade code in patch_incident maps incident 'confirmed' →
    finding REVIEWED.  The validator must keep accepting 'confirmed'
    or the cascade contract breaks."""
    patch = IncidentTriagePatch(review_status="confirmed")
    assert patch.review_status == "confirmed"


@pytest.mark.parametrize("bad_value", [
    "FOOBAR",
    "approved",  # not in our vocab
    "Confirmed",  # wrong case
    "in-review",  # wrong separator
    "",
    "1",
])
def test_garbage_review_status_rejected(bad_value: str):
    with pytest.raises(Exception) as exc_info:
        IncidentTriagePatch(review_status=bad_value)
    assert "review_status" in str(exc_info.value).lower()


def test_none_review_status_passes_through():
    patch = IncidentTriagePatch(review_status=None)
    assert patch.review_status is None


# ── RotationStatus ───────────────────────────────────────────────


@pytest.mark.parametrize("value", ["rotated", "pending", "in_progress", "failed", "overdue"])
def test_every_canonical_rotation_status_accepted(value: str):
    patch = IncidentTriagePatch(rotation_status=value)
    assert patch.rotation_status == value


@pytest.mark.parametrize("bad_value", [
    "ROTATED",  # wrong case
    "rotated_",  # trailing junk
    "in progress",  # space instead of underscore
    "queued",  # not a real status
    "",
])
def test_garbage_rotation_status_rejected(bad_value: str):
    with pytest.raises(Exception) as exc_info:
        IncidentTriagePatch(rotation_status=bad_value)
    assert "rotation_status" in str(exc_info.value).lower()


# ── Composite (real-world payload) ──────────────────────────────


def test_full_realistic_patch_accepted():
    """End-to-end realistic patch — multiple fields set, all valid."""
    patch = IncidentTriagePatch(
        classification="confirmed_true_positive",
        review_status="confirmed",
        rotation_status="rotated",
        comment="Verified live in prod; rotating now",
        source="manual",
        expected_version=3,
    )
    assert patch.classification == "confirmed_true_positive"
    assert patch.review_status == "confirmed"
    assert patch.rotation_status == "rotated"


def test_patch_with_one_garbage_field_fails_whole_payload():
    """Pydantic validates all fields up front — one bad value MUST
    fail the whole patch, otherwise the half-applied state would
    leave inconsistent data."""
    with pytest.raises(Exception):
        IncidentTriagePatch(
            classification="confirmed_true_positive",  # valid
            review_status="garbage_status",  # invalid
        )
