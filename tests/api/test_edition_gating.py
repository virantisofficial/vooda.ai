# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Enterprise features are gated on the API, not only in the UI.

A greyed tile is a suggestion — the endpoints behind it are reachable
directly with curl. So the same list drives both: the UI reads it from
`/edition` to draw the badge, and the routers refuse the call. One
constant, so the badge and the refusal cannot describe different sets.

402 rather than 403 is deliberate. The caller's permissions are fine and
no different login would help, so this is not an authorisation failure;
Payment Required is the status that describes it, and it lets the UI
tell "you may not" apart from "this edition does not include it".

The default is Community. An install that sets nothing must not
accidentally ship Enterprise features.
"""
import inspect

import pytest
from fastapi import HTTPException

from apps.api.app.core import edition as E
from apps.api.app.core.config import settings


class _Req:
    """Minimal stand-in for starlette's Request — the guard reads only
    the method, to honour the access-control escape hatch."""

    def __init__(self, method: str = "POST"):
        self.method = method


@pytest.fixture(autouse=True)
def _restore_edition():
    original = settings.EDITION
    yield
    settings.EDITION = original


# ── what is gated ────────────────────────────────────────────────────

@pytest.mark.parametrize("feature", [
    "access_control", "audit", "custom_detectors", "schedules",
])
def test_feature_is_gated_in_community(feature):
    settings.EDITION = "community"
    assert feature in E.ENTERPRISE_FEATURES
    assert E.feature_enabled(feature) is False


def test_default_edition_is_community():
    """An install that configures nothing must not get Enterprise."""
    field = type(settings).model_fields["EDITION"]
    assert field.default == "community"


@pytest.mark.parametrize("feature", ["users", "roles", "api_keys", "reports", "integrations"])
def test_core_features_are_never_gated(feature):
    settings.EDITION = "community"
    assert E.feature_enabled(feature) is True


@pytest.mark.parametrize("feature", ["suppressions", "rule_overrides"])
def test_noise_control_is_never_gated(feature):
    """AI triage is good, not perfect. When it calls a real credential a
    false positive — or the reverse — these are the only remedy. Gating
    them would leave the same finding reappearing on every scan with no
    recourse, contradicting the noise reduction the product is sold on."""
    settings.EDITION = "community"
    assert feature not in E.ENTERPRISE_FEATURES
    assert E.feature_enabled(feature) is True


def test_scan_engine_is_not_gated():
    """The README promises the whole scan engine in Community. Detection,
    verification and triage must never appear in the gated set."""
    for key in ("findings", "repositories", "scan", "ai_models", "verification", "triage"):
        assert key not in E.ENTERPRISE_FEATURES


# ── the guard ────────────────────────────────────────────────────────

def test_guard_raises_402_not_403():
    settings.EDITION = "community"
    with pytest.raises(HTTPException) as exc:
        E.require_enterprise("audit")(_Req())
    assert exc.value.status_code == 402, (
        "403 would say the caller lacks permission; no login fixes this"
    )


def test_guard_names_the_feature_and_points_somewhere():
    settings.EDITION = "community"
    with pytest.raises(HTTPException) as exc:
        E.require_enterprise("custom_detectors")(_Req())
    detail = str(exc.value.detail)
    assert "Custom Detectors" in detail
    assert "vooda.ai" in detail


def test_enterprise_unlocks_everything():
    settings.EDITION = "enterprise"
    for feature in E.ENTERPRISE_FEATURES:
        E.require_enterprise(feature)(_Req())  # must not raise
    assert E.is_enterprise() is True


@pytest.mark.parametrize("value", ["Enterprise", "ENTERPRISE", " enterprise "])
def test_edition_value_is_forgiving(value):
    """An operator typing Enterprise in a .env should get Enterprise."""
    settings.EDITION = value
    assert E.is_enterprise() is True


@pytest.mark.parametrize("value", ["", "free", "pro", "community"])
def test_anything_else_is_community(value):
    settings.EDITION = value
    assert E.is_enterprise() is False


# ── access control must never strand a tenant ────────────────────────

def test_creating_scope_is_gated():
    settings.EDITION = "community"
    for method in ("POST", "PUT", "PATCH"):
        assert E.method_exempt("access_control", method) is False, (
            f"{method} creates or changes scope — that is the Enterprise part"
        )


@pytest.mark.parametrize("method", ["GET", "DELETE", "get", "delete"])
def test_reading_and_removing_scope_stay_open(method):
    """Grants keep enforcing after a downgrade. Without a way to see and
    remove them, a scoped user is locked out of repositories with no
    route back — and no support call could fix it from inside."""
    settings.EDITION = "community"
    assert E.method_exempt("access_control", method) is True


def test_other_gates_have_no_escape_hatch():
    """Only access control can strand someone; the rest fully gate."""
    for feature in E.ENTERPRISE_FEATURES:
        if feature == "access_control":
            continue
        for method in ("GET", "POST", "DELETE"):
            assert E.method_exempt(feature, method) is False


def test_users_and_roles_are_never_gated():
    """Disabling access control must not touch authentication or RBAC —
    they are separate tables with separate enforcement."""
    settings.EDITION = "community"
    assert E.feature_enabled("users") is True
    assert E.feature_enabled("roles") is True


def test_reading_the_audit_log_is_not_gated():
    """The dashboard's Recent Activity panel reads this router. Gating it
    would empty a panel that has nothing to do with compliance, and an
    operator who cannot see their own audit trail cannot answer "what
    happened?" — which is the point of keeping a log. Export and
    retention, the compliance tooling, are gated per-endpoint instead."""
    from apps.api.app import main
    src = inspect.getsource(main)
    m = src.find('audit.router')
    assert m > 0
    assert 'require_enterprise("audit")' not in src[m:m + 220], (
        "a router-level guard here empties the dashboard activity feed"
    )


def test_audit_export_and_retention_are_gated():
    from apps.api.app.routers import audit
    src = inspect.getsource(audit)
    assert src.count('require_enterprise("audit_export")') >= 2, (
        "export and retention are the compliance half and should be gated"
    )


# ── the routers actually carry the guard ─────────────────────────────

def test_gated_routers_are_mounted_with_the_guard():
    """UI-only gating is cosmetic — the endpoints answer curl."""
    from apps.api.app import main
    src = inspect.getsource(main)
    # audit is gated per-endpoint (export/retention) and schedules at the
    # field, so only these two carry a router-level guard.
    for feature in ("access_control", "custom_detectors"):
        assert f'require_enterprise("{feature}")' in src, (
            f"the {feature} router is mounted without the edition guard, so "
            f"the tile is greyed but the API still answers"
        )


def test_scan_schedule_is_gated_at_the_field():
    """Schedules has no router of its own — it is a repository field, so
    the guard lives in the update path instead of on a mount."""
    from apps.api.app.routers import repositories
    src = inspect.getsource(repositories.update_repository)
    assert 'feature_enabled("schedules")' in src


def test_unchanged_schedule_is_not_refused():
    """A tenant that downgrades keeps working: only a CHANGE is blocked,
    so re-saving a repository with its existing schedule still succeeds."""
    from apps.api.app.routers import repositories
    src = inspect.getsource(repositories.update_repository)
    assert '!= _current' in src, (
        "blocking every save that merely echoes the stored schedule would "
        "break editing any repository that already had one"
    )
