"""Smoke tests for the 6 verifiers added 2026-05-03.

Closes the loop on the source-catalog work: every source we built a
SCANNER for now also has a VERIFIER (so credentials of those types
detected anywhere — git scan, Slack, S3 — get live-checked).

For each new verifier we test three shapes:
  1. Missing tenant URL → "unsupported" (clean rejection, not crash)
  2. Provider returns 401/403 → "inactive"
  3. Provider returns 200 → "active" with permissions_detail populated

Plus dispatcher integrity: all VERIFIERS entries are callable and the
new providers are registered + reachable via SUPPORTED_PROVIDERS.

Mocks `verification_client` directly so no network calls are made and
the tests run fast (<200ms total).
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.secret_verification import verifier as v


# ── Helpers ───────────────────────────────────────────────────


def _fake_response(status_code: int, json_body: dict | None = None, text: str = ""):
    """Build a mock httpx.Response stand-in that the verifier code can
    use exactly like the real thing."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-type": "application/json"} if json_body else {"content-type": "text/plain"}
    resp.json = MagicMock(return_value=json_body or {})
    resp.text = text or (str(json_body) if json_body else "")
    return resp


def _patch_client(get_response=None, post_response=None):
    """Returns an asynccontextmanager that yields an AsyncClient mock
    pre-wired to return `get_response` for `.get()` calls and
    `post_response` for `.post()` calls."""

    @asynccontextmanager
    async def _cm(*args, **kwargs):
        client = AsyncMock()
        client.get = AsyncMock(return_value=get_response)
        client.post = AsyncMock(return_value=post_response)
        yield client

    return _cm


# ── Salesforce ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_salesforce_unsupported_without_instance_url():
    result = await v.verify_salesforce_token("token-no-url")
    assert result.status == "unsupported"
    assert "instance URL" in result.details
    assert result.provider == "salesforce"


@pytest.mark.asyncio
async def test_salesforce_inactive_on_401():
    cm = _patch_client(get_response=_fake_response(401))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_salesforce_token(
            "bad-token", "https://acme.my.salesforce.com",
        )
    assert result.status == "inactive"
    assert result.provider == "salesforce"


@pytest.mark.asyncio
async def test_salesforce_active_on_200_with_limits():
    body = {"DailyApiRequests": {"Max": 100000, "Remaining": 99500}}
    cm = _patch_client(get_response=_fake_response(200, body))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_salesforce_token(
            "good-token", "https://acme.my.salesforce.com",
        )
    assert result.status == "active"
    assert result.provider == "salesforce"
    assert result.permissions_detail["risk_level"] == "high"
    assert "99500" in result.details


# ── Box ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_box_inactive_on_401():
    cm = _patch_client(get_response=_fake_response(401))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_box_token("expired-developer-token")
    assert result.status == "inactive"
    assert result.provider == "box"


@pytest.mark.asyncio
async def test_box_active_enterprise_promotes_to_critical():
    body = {
        "id": "12345", "login": "admin@acme.com", "name": "Admin User",
        "enterprise": {"id": "ent_1", "name": "Acme Corp"},
    }
    cm = _patch_client(get_response=_fake_response(200, body))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_box_token("good-enterprise-token")
    assert result.status == "active"
    assert result.permissions_detail["risk_level"] == "critical"
    assert "Acme Corp" in result.details


@pytest.mark.asyncio
async def test_box_active_personal_stays_high():
    body = {"id": "67890", "login": "user@example.com", "name": "User"}
    cm = _patch_client(get_response=_fake_response(200, body))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_box_token("personal-token")
    assert result.status == "active"
    assert result.permissions_detail["risk_level"] == "high"


# ── Mattermost ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mattermost_unsupported_without_server_url():
    result = await v.verify_mattermost_token("token-no-url")
    assert result.status == "unsupported"
    assert "server URL" in result.details


@pytest.mark.asyncio
async def test_mattermost_active_admin_is_critical():
    body = {
        "id": "u_1", "email": "admin@chat.acme.com", "username": "admin",
        "roles": "system_user system_admin",
    }
    cm = _patch_client(get_response=_fake_response(200, body))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_mattermost_token("admin-pat", "https://chat.acme.com")
    assert result.status == "active"
    assert result.permissions_detail["risk_level"] == "critical"
    assert result.permissions_detail["extra"]["is_system_admin"] is True


@pytest.mark.asyncio
async def test_mattermost_active_user_is_high():
    body = {"id": "u_2", "email": "user@chat.acme.com", "username": "user", "roles": "system_user"}
    cm = _patch_client(get_response=_fake_response(200, body))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_mattermost_token("user-pat", "https://chat.acme.com")
    assert result.status == "active"
    assert result.permissions_detail["risk_level"] == "high"


# ── Azure DevOps ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_azure_devops_unsupported_without_org():
    result = await v.verify_azure_devops_pat("pat-no-org")
    assert result.status == "unsupported"


@pytest.mark.asyncio
async def test_azure_devops_inactive_on_401():
    cm = _patch_client(get_response=_fake_response(401))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_azure_devops_pat("bad-pat", "https://dev.azure.com/acme")
    assert result.status == "inactive"


@pytest.mark.asyncio
async def test_azure_devops_active_on_200():
    body = {
        "authenticatedUser": {
            "providerDisplayName": "Engineer User",
            "properties": {"Account": {"$value": "engineer@acme.com"}},
        },
        "instanceId": "abc-instance-uuid",
    }
    cm = _patch_client(get_response=_fake_response(200, body))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_azure_devops_pat("good-pat", "acme")  # bare slug
    assert result.status == "active"
    assert "engineer@acme.com" in result.details or "Engineer User" in result.details
    # Bare slug should expand to dev.azure.com URL
    assert "dev.azure.com/acme" in result.permissions_detail["extra"]["org_url"]


# ── ServiceNow ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_servicenow_unsupported_without_password():
    result = await v.verify_servicenow_creds("user", "", "https://acme.service-now.com")
    assert result.status == "unsupported"


@pytest.mark.asyncio
async def test_servicenow_inactive_on_401():
    cm = _patch_client(get_response=_fake_response(401))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_servicenow_creds(
            "user", "wrong-pwd", "https://acme.service-now.com",
        )
    assert result.status == "inactive"


@pytest.mark.asyncio
async def test_servicenow_active_on_200():
    body = {"result": [{"user_name": "admin", "email": "admin@acme.com"}]}
    cm = _patch_client(get_response=_fake_response(200, body))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_servicenow_creds(
            "admin", "good-pwd", "https://acme.service-now.com",
        )
    assert result.status == "active"
    assert result.permissions_detail["risk_level"] == "high"


# ── Webhook URL (GEN-010-COLLAB) ──────────────────────────────


@pytest.mark.asyncio
async def test_webhook_unsupported_for_non_https():
    result = await v.verify_webhook_url("http://insecure-webhook.example.com/abc")
    assert result.status == "unsupported"


@pytest.mark.asyncio
async def test_webhook_slack_live_returns_active():
    """Slack returns 200 + `no_payload` JSON on GET of a live webhook."""
    cm = _patch_client(get_response=_fake_response(
        200, json_body=None, text='{"ok":false,"error":"no_payload"}',
    ))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_webhook_url(
            "https://hooks.slack.com/services/T01ABC/B02DEF/XYZ123abc",
        )
    assert result.status == "active"
    assert result.permissions_detail["extra"]["flavor"] == "slack"
    assert "post access" in (result.blast_radius_summary or "").lower()


@pytest.mark.asyncio
async def test_webhook_teams_405_means_live():
    """Teams webhooks are POST-only — a GET returns 405 Method Not
    Allowed which CONFIRMS the webhook exists."""
    cm = _patch_client(get_response=_fake_response(
        405, text="Method Not Allowed",
    ))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_webhook_url(
            "https://acme.webhook.office.com/webhookb2/abc/IncomingWebhook/123/abc",
        )
    assert result.status == "active"
    assert result.permissions_detail["extra"]["flavor"] == "teams"


@pytest.mark.asyncio
async def test_webhook_revoked_returns_inactive():
    cm = _patch_client(get_response=_fake_response(404, text="no_service"))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_webhook_url(
            "https://hooks.slack.com/services/T01ABC/B02DEF/REVOKED-OLD",
        )
    assert result.status == "inactive"


# ── Dispatcher integrity ──────────────────────────────────────


def test_new_providers_in_supported_set():
    """All 6 new providers must be in SUPPORTED_PROVIDERS so the
    worker's verification routing actually finds them."""
    expected = {"salesforce", "box", "mattermost", "azure_devops", "servicenow", "webhook"}
    missing = expected - v.SUPPORTED_PROVIDERS
    assert not missing, f"New verifiers not registered: {missing}"


def test_all_verifier_lambdas_callable():
    """Every entry in VERIFIERS must be a callable that accepts a
    source_metadata dict. Catches typos in the lambda signature
    (e.g. forgetting `sm.get(...)`) at collection time."""
    sm_stub = {"_raw_value": "x", "instance_url": "https://example.com",
               "tenant_domain": "example.com", "server_url": "https://example.com",
               "org_url": "example", "username": "u", "password": "p"}
    for name, fn in v.VERIFIERS.items():
        assert callable(fn), f"{name} entry is not callable"
        try:
            coro = fn(sm_stub)
            # Lambdas should return a coroutine — close it without awaiting
            # (we don't actually want to make 246 HTTP calls in this test).
            if hasattr(coro, "close"):
                coro.close()
        except TypeError as e:
            pytest.fail(f"{name} dispatcher lambda failed: {e}")


def test_verifier_count_did_not_decrease():
    """Guards against a refactor accidentally dropping verifier coverage.

    History:
      Original baseline (pre-Fauna/Xata removal): 252
      Track-A P0 #6 (2026-05-22): -2 (Fauna + Xata providers sunset)
      Current floor:                              250
    """
    assert len(v.VERIFIERS) >= 250, (
        f"Verifier dispatcher dropped from baseline; got {len(v.VERIFIERS)}"
    )
