"""S3 — verified-inactive suppression: decision logic + allowlist safety.

The suppression decision is the safety-critical part: a finding is only
auto-suppressed when its credential was verified DEAD (status="inactive") by a
provider on the curated allowlist (whose verifier returns "inactive" only on a
definitive 401/403/revoked rejection). These tests lock that contract down.
"""
from __future__ import annotations

import pytest

import apps.worker.tasks as tasks
from apps.worker.tasks import (
    SUPPRESSION_ALLOWLIST, SUPPRESSION_DENYLIST, _should_suppress_inactive,
)
from services.secret_verification.verifier import SUPPORTED_PROVIDERS


def _rd(status, provider):
    return {"validation_status": status, "provider": provider}


# ── allowlist integrity ──────────────────────────────────────────────

def test_allowlist_entries_are_real_verifier_keys():
    bad = sorted(p for p in SUPPRESSION_ALLOWLIST if p not in SUPPORTED_PROVIDERS)
    assert not bad, f"allowlist references non-existent verifier keys: {bad}"


def test_ambiguous_providers_denied_and_disjoint():
    # azure_devops / servicenow map 404 → inactive (could be wrong org/endpoint).
    assert "azure_devops" in SUPPRESSION_DENYLIST
    assert "servicenow" in SUPPRESSION_DENYLIST
    assert SUPPRESSION_ALLOWLIST.isdisjoint(SUPPRESSION_DENYLIST)


# ── suppress only on a definitive dead verdict from an allowlisted provider ──

@pytest.mark.parametrize("provider", ["github", "stripe", "gitlab", "slack", "cloudflare"])
def test_suppress_inactive_allowlisted(provider):
    assert _should_suppress_inactive(_rd("inactive", provider)) is True


def test_case_insensitive_provider():
    assert _should_suppress_inactive(_rd("inactive", "GitHub")) is True


@pytest.mark.parametrize("status", ["active", "error", "unsupported", "unknown", "not_validated", None, ""])
def test_no_suppress_for_non_inactive_status(status):
    assert _should_suppress_inactive(_rd(status, "github")) is False


@pytest.mark.parametrize("provider", ["azure_devops", "servicenow", "telegram", "monday", "finnhub", "", "unknown"])
def test_no_suppress_for_non_allowlisted_or_denied(provider):
    # Even a definitive "inactive" must NOT suppress outside the audited allowlist.
    assert _should_suppress_inactive(_rd("inactive", provider)) is False


def test_empty_or_missing_rd():
    assert _should_suppress_inactive({}) is False
    assert _should_suppress_inactive(None) is False


def test_global_flag_off_disables_all_suppression(monkeypatch):
    monkeypatch.setattr(tasks.settings, "VERIFICATION_SUPPRESS_INACTIVE", False, raising=False)
    assert _should_suppress_inactive(_rd("inactive", "github")) is False
    assert _should_suppress_inactive(_rd("inactive", "stripe")) is False
