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


# ── a gate on writing something that still runs is not a gate ────────
#
# Three holes, found by surveying the whole application against this
# list. Each had the same shape: the capability was refused at one
# door and granted at another, or refused on write while the thing
# written went on executing.


def test_scheduling_is_gated_on_scan_sources_too():
    """Repositories were not the only way to get a recurring scan.

    `scan_sources` owns its own `scan_schedule` column, and the whole
    capability could be had by pointing a source at S3 instead of a
    git repository.
    """
    from apps.api.app.routers import scan_sources
    for fn in (scan_sources.create_scan_source, scan_sources.update_scan_source):
        assert 'feature_enabled("schedules")' in inspect.getsource(fn), fn.__name__


def test_a_smart_default_does_not_hand_out_a_gated_feature():
    """Every new source was given a recurring schedule automatically.

    jira landed on daily, s3 on weekly, from DEFAULT_SCHEDULE_BY_SOURCE_TYPE
    — so Community got scheduled scanning without asking for it. An
    explicit request is refused because it is a request; a default the
    customer never typed resolves to on_demand instead, because
    refusing there would block source creation over a value they did
    not choose.
    """
    from apps.api.app.routers import scan_sources
    src = inspect.getsource(scan_sources.create_scan_source)
    assert 'resolved_schedule = "on_demand"' in src
    assert "if data.scan_schedule:" in src, (
        "an explicit ask and an implicit default must not be treated alike"
    )


def test_stored_schedules_stop_firing_in_community():
    """Refusing the write is not enough.

    Rows written under an Enterprise licence, or before the gate
    existed, kept being dispatched by the beat loop forever. The
    scheduler is one of only two edition checks outside the API layer.
    """
    import asyncio

    from services.scheduler.engine import run_scheduled_scans

    settings.EDITION = "community"
    # A None session is deliberate: if it returns 0 without raising,
    # it refused before touching the database.
    assert asyncio.run(run_scheduled_scans(None)) == 0


@pytest.mark.parametrize("edition,expected", [("community", []), ("enterprise", None)])
def test_custom_detectors_do_not_execute_in_community(edition, expected):
    """CRUD was gated; execution was not.

    `get_all_rules_with_custom` runs on every scan, so any enabled
    detector row kept matching after a downgrade. Checked in the two
    loaders rather than their callers, so a new caller cannot
    reintroduce it — which is why a None session is safe here.
    """
    import asyncio

    from services.secret_scan.detectors import registry

    settings.EDITION = edition
    if expected == []:
        assert registry.get_custom_rules_sync("t", None) == []
        assert asyncio.run(registry.get_custom_rules_async("t", None)) == []
    else:
        # Enterprise must actually reach the database — with no session
        # to reach it with, that is an error rather than a quiet [].
        with pytest.raises(Exception):
            registry.get_custom_rules_sync("t", None)
    settings.EDITION = "community"


# ── inbound webhooks: Vooda listening on your behalf ─────────────────


def test_configuring_an_inbound_webhook_is_gated():
    """Schedules and inbound webhooks are one capability in two hats.

    Both are Vooda starting a scan nobody asked for at that moment, so
    gating one and not the other made the boundary arbitrary. Community
    still automates through the CLI, a CI pipeline key and the pre-push
    hook — what it does not get is Vooda listening for pushes.
    """
    from apps.api.app.routers import webhooks
    src = inspect.getsource(webhooks)
    assert src.count('require_enterprise("webhooks")') >= 2, (
        "both the config write and the test-ping should carry the guard"
    )


def test_the_receiver_itself_is_never_gated():
    """A 402 to GitHub is a silent outage.

    The receiver authenticates by HMAC signature, not a bearer token,
    so a guard there would answer the provider with 402 until it
    disabled the hook — and nobody would be told. Already-connected
    repositories keep being scanned; only NEW configuration is refused.
    """
    from apps.api.app.routers import webhooks
    src = inspect.getsource(webhooks.receive_webhook)
    assert "require_enterprise" not in src


def test_reading_webhook_config_stays_open():
    """An operator has to be able to see what is still in force."""
    from apps.api.app.routers import webhooks
    src = inspect.getsource(webhooks.get_webhook_config)
    assert "require_enterprise" not in src


# ── ticketing: the whole category ────────────────────────────────────


@pytest.mark.parametrize("provider",
                         ["jira", "servicenow", "custom_ticketing", "linear"])
def test_every_ticketing_provider_is_gated(provider):
    """Filing into a tracker is workflow automation, not detection.

    Started as a split with Jira left in Community. Seen on screen, one
    unbadged tile in a row of three read as a missing badge rather than
    a decision, and the boundary was hard to state. Taken whole it is
    one sentence: Community finds, verifies and triages; Enterprise
    pushes the result into the tools a team already runs.
    """
    settings.EDITION = "community"
    assert E.ticketing_provider_enabled(provider) is False
    settings.EDITION = "enterprise"
    assert E.ticketing_provider_enabled(provider) is True
    settings.EDITION = "community"


def test_linear_is_covered_even_though_it_is_not_advertised():
    """It is absent from PROVIDER_SCHEMAS but the dispatcher routes it.

    A provider gated everywhere except the one path that actually
    sends is not gated.
    """
    settings.EDITION = "community"
    assert "linear" in E.ENTERPRISE_TICKETING_PROVIDERS
    assert E.ticketing_provider_enabled("linear") is False


@pytest.mark.parametrize("provider", ["slack", "teams", "email", "webhook", "pagerduty"])
def test_notification_channels_are_untouched_by_the_ticketing_gate(provider):
    """Being told about a finding is not the same as filing it.

    Gating the channels would leave a scanner that cannot tell anyone
    what it found, which is a different product.
    """
    settings.EDITION = "community"
    assert E.ticketing_provider_enabled(provider) is True


def test_gated_ticketing_cannot_be_configured_or_dispatched():
    """A gate on configuring something that still sends is not a gate.

    Rows written under an Enterprise licence, or before the gate
    existed, would otherwise keep filing tickets — the same hole the
    custom-detector registry had.
    """
    from apps.api.app.routers import integrations
    assert "provider_enabled" in inspect.getsource(
        integrations.create_integration)

    from services.notifications import dispatcher
    src = inspect.getsource(dispatcher.NotificationDispatcher)
    assert "provider_enabled" in src, (
        "the dispatcher must refuse a gated provider at send time too"
    )


# ── notification channels: telling a system outside Vooda ────────────


@pytest.mark.parametrize("provider", ["slack", "teams", "email", "webhook",
                                      "pagerduty", "splunk", "sentinel", "datadog"])
def test_notification_channels_are_gated(provider):
    settings.EDITION = "community"
    assert E.provider_enabled(provider) is False
    settings.EDITION = "enterprise"
    assert E.provider_enabled(provider) is True
    settings.EDITION = "community"


def test_the_in_app_bell_is_never_a_channel():
    """A licence must not be able to silence "triage could not run".

    In-app notifications are written straight to the notifications
    table, not dispatched through a channel, so gating the channels
    cannot reach them. That matters: the health signal that tells a
    customer their findings are untriaged rather than low risk arrives
    that way, and a scan that stops silently is the failure this
    product exists to prevent.
    """
    assert "in_app" not in E.ENTERPRISE_PROVIDER_FEATURES
    assert "notification" not in E.ENTERPRISE_PROVIDER_FEATURES

    from services.notifications import dispatcher
    import inspect as _i
    src = _i.getsource(dispatcher.NotificationDispatcher._send_to_channel)
    assert "provider_enabled" in src
    # The in-app path is a different method, so the guard above cannot
    # reach it.
    assert "_send_to_channel" not in _i.getsource(
        dispatcher.NotificationDispatcher._create_in_app_notifications
    ) if hasattr(dispatcher.NotificationDispatcher,
                 "_create_in_app_notifications") else True


def test_a_provider_outside_both_sets_is_untouched():
    """Scanners, sources and vaults are not notification channels."""
    settings.EDITION = "community"
    for provider in ("github", "s3", "jira_source", "container_registry"):
        assert E.provider_enabled(provider) is True


def test_every_gated_provider_names_a_real_feature():
    """A provider mapped to a key nobody declares would never be gated."""
    for provider, feature in E.ENTERPRISE_PROVIDER_FEATURES.items():
        assert feature in E.ENTERPRISE_FEATURES, (provider, feature)
