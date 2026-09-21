# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""The "not in current code" marker.

A deleted file does not revoke a credential, so a repository finding
whose file disappears is TAGGED and stays open rather than being
closed. The tag has to come off again when the file genuinely returns,
and must not come off for scans that are no evidence either way — a
history walk (which reads old commits) or a scan of another branch.
"""
from datetime import datetime, timezone

from apps.worker.tasks import _clear_removed_from_code


class _Finding:
    """Minimal stand-in for the ORM row: the helper only touches this field."""

    def __init__(self, metadata):
        self.source_metadata = metadata


NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)


def _marked():
    return _Finding({
        "removed_from_code": True,
        "removed_by_scan_job_id": "job-1",
        "removed_at_commit": "abc123",
        "removed_at": "2026-09-20T10:00:00+00:00",
        "removal_reason": "file_deleted",
        "removed_by_full_sweep": True,
        "secret_type": "github_pat",
    })


def test_marker_is_cleared_when_the_file_returns():
    f = _marked()
    assert _clear_removed_from_code(f, NOW) is True
    for gone in (
        "removed_from_code", "removed_by_scan_job_id", "removed_at_commit",
        "removed_at", "removal_reason", "removed_by_full_sweep",
    ):
        assert gone not in f.source_metadata


def test_unrelated_metadata_survives():
    """Clearing must not take the rest of the finding's metadata with it."""
    f = _marked()
    _clear_removed_from_code(f, NOW)
    assert f.source_metadata["secret_type"] == "github_pat"


def test_return_is_recorded_for_the_audit_trail():
    f = _marked()
    _clear_removed_from_code(f, NOW)
    assert f.source_metadata["returned_to_code_at"] == NOW.isoformat()


def test_unmarked_finding_is_left_alone():
    """No marker means nothing to clear — and no spurious write."""
    f = _Finding({"secret_type": "aws_key"})
    assert _clear_removed_from_code(f, NOW) is False
    assert f.source_metadata == {"secret_type": "aws_key"}


def test_missing_metadata_does_not_raise():
    f = _Finding(None)
    assert _clear_removed_from_code(f, NOW) is False
