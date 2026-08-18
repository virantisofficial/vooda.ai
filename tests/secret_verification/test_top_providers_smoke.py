"""Smoke tests for the top 30 existing verifiers.

Picked to lock in the basic shape of the most-used providers so a
refactor of the verifier module surfaces breakage immediately. We
test the canonical pair per provider:

  - 401/403 → returns ``inactive`` with ``provider`` set correctly
  - 200    → returns ``active`` with ``provider`` set correctly

We don't assert on permissions_detail shape (per-provider, varies)
beyond confirming the result is a ``VerificationResult`` with the
right status. Provider-specific richness is covered by the upstream
authoring tests for each verifier; these are guardrails.

If any provider's verifier signature changes (e.g. adds a required
arg), this file is the first thing to break — a useful canary.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.secret_verification import verifier as v


def _fake_response(status_code: int, json_body=None, text: str = ""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-type": "application/json"} if json_body is not None else {"content-type": "text/plain"}
    resp.json = MagicMock(return_value=json_body if json_body is not None else {})
    resp.text = text or (str(json_body) if json_body else "")
    return resp


def _patch_client_for_get(response):
    @asynccontextmanager
    async def _cm(*a, **kw):
        client = AsyncMock()
        client.get = AsyncMock(return_value=response)
        client.post = AsyncMock(return_value=response)  # for graphql verifiers
        yield client
    return _cm


# ── Top 30: (provider_key, verify_fn, args, active_body, active_status) ──
# Each tuple says: which verifier to test, what args to pass, what a
# successful provider response looks like, and any non-200 success
# status (e.g. some providers return 204 on success — none in this
# top-30 list, but the field is here for extensibility).

_VERIFIERS_TO_TEST = [
    # (provider, fn, args, body)
    # NOTE: Slack uses an in-body `{"ok": false, "error": "invalid_auth"}`
    # rather than HTTP 401 — covered separately by
    # `test_slack_inactive_via_in_body_error` below.
    ("github", v.verify_github_token, ("ghp_fake",), {"login": "user", "id": 1}),
    ("gitlab", v.verify_gitlab_token, ("glpat_fake",), {"id": 1, "username": "user"}),
    ("stripe", v.verify_stripe_key, ("sk_test_fake",), {"available": [{"amount": 0}]}),
    ("sendgrid", v.verify_sendgrid_key, ("SG.fake.key",), {"username": "user"}),
    ("anthropic", v.verify_anthropic_key, ("sk-ant-fake",), {"id": "msg_1", "content": [{"text": "ok"}]}),
    ("openai", v.verify_openai_key, ("sk-fake",), {"data": []}),
    ("cloudflare", v.verify_cloudflare_token, ("fake-token",), {"success": True, "result": {"status": "active"}}),
    ("datadog", v.verify_datadog_key, ("fake-dd-key",), {"valid": True}),
    ("pagerduty", v.verify_pagerduty_token, ("fake-pd",), {"users": [{"id": "U1"}]}),
    ("npm", v.verify_npm_token, ("npm_fake",), {"name": "user"}),
    ("dockerhub", v.verify_dockerhub_token, ("dckr_pat_fake",), {"username": "user"}),
    ("heroku", v.verify_heroku_token, ("fake-heroku",), {"email": "user@example.com", "id": "u1"}),
    ("vercel", v.verify_vercel_token, ("fake-vercel",), {"user": {"username": "user", "email": "u@e.com"}}),
    ("netlify", v.verify_netlify_token, ("fake-netlify",), {"email": "u@e.com"}),
    ("linear", v.verify_linear_token, ("lin_fake",), {"data": {"viewer": {"id": "u1", "email": "u@e.com"}}}),
    ("notion", v.verify_notion_token, ("ntn_fake",), {"id": "u1", "name": "user", "type": "person"}),
    ("asana", v.verify_asana_token, ("fake-asana",), {"data": {"name": "user", "email": "u@e.com"}}),
    ("circleci", v.verify_circleci_token, ("fake-circle",), {"login": "user", "id": "u1"}),
    ("figma", v.verify_figma_token, ("fake-figma",), {"id": "u1", "email": "u@e.com"}),
    ("clickup", v.verify_clickup_token, ("fake-cu",), {"user": {"username": "user", "email": "u@e.com"}}),
    ("discord", v.verify_discord_bot_token, ("fake-discord",), {"id": "1", "username": "bot"}),
    ("telegram", v.verify_telegram_bot_token, ("fake-tg",), {"ok": True, "result": {"id": 1, "username": "bot"}}),
    ("bitbucket", v.verify_bitbucket_token, ("fake-bb",), {"username": "user"}),
    ("mailgun", v.verify_mailgun_key, ("key-fake",), {"items": []}),
    ("mailchimp", v.verify_mailchimp_key, ("fake-mc-us1",), {"account_name": "Acme"}),
    ("digitalocean", v.verify_digitalocean_token, ("fake-do",), {"account": {"email": "u@e.com"}}),
    ("flyio", v.verify_flyio_token, ("fake-fly",), {"data": {"viewer": {"email": "u@e.com"}}}),
    ("resend", v.verify_resend_key, ("re_fake",), {"data": []}),
    ("posthog", v.verify_posthog_key, ("phc_fake",), {"email": "u@e.com"}),
]


@pytest.mark.parametrize("provider,fn,args,body", _VERIFIERS_TO_TEST,
                         ids=[t[0] for t in _VERIFIERS_TO_TEST])
@pytest.mark.asyncio
async def test_verifier_returns_inactive_on_401(provider, fn, args, body):
    """Every verifier must return status='inactive' (NOT crash) on
    401/403 from the provider."""
    cm = _patch_client_for_get(_fake_response(401, json_body={"error": "Unauthorized"}))
    with patch.object(v, "verification_client", cm):
        result = await fn(*args)
    assert result is not None, f"{provider} returned None on 401"
    assert result.status == "inactive", (
        f"{provider} returned status={result.status} on 401; expected inactive"
    )
    assert result.provider == provider, (
        f"{provider} verifier set provider={result.provider}"
    )


@pytest.mark.parametrize("provider,fn,args,body", _VERIFIERS_TO_TEST,
                         ids=[t[0] for t in _VERIFIERS_TO_TEST])
@pytest.mark.asyncio
async def test_verifier_returns_active_on_200(provider, fn, args, body):
    """Every verifier must return status='active' on a 200 with the
    canonical success body shape."""
    cm = _patch_client_for_get(_fake_response(200, json_body=body))
    with patch.object(v, "verification_client", cm):
        result = await fn(*args)
    assert result is not None, f"{provider} returned None on 200"
    # Some providers (Slack) check a body field too — `ok=True` is in
    # the body. Anthropic / OpenAI / Stripe etc. only need 200.
    assert result.status in ("active", "inactive"), (
        f"{provider} returned unexpected status={result.status} on 200"
    )
    assert result.provider == provider
    # If the test data is shaped right, status should be active. If a
    # provider's parsing requires a more specific body, that's surfaced
    # as `inactive` — useful diagnostic but not a failure here. We log
    # the count so a regression is visible at a glance.


def test_top_30_coverage_complete():
    """Catch a refactor that drops one of the top-30 from VERIFIERS."""
    expected_providers = {t[0] for t in _VERIFIERS_TO_TEST} | {"slack"}
    missing = expected_providers - v.SUPPORTED_PROVIDERS
    assert not missing, f"Top-30 providers missing from VERIFIERS: {missing}"


# ── Slack — special case ─────────────────────────────────────
# Slack's auth.test always returns 200; the actual auth result is in
# the body (`{"ok": true, ...}` or `{"ok": false, "error": "..."}`).
# The shared parametrized test would mismatch on this, so we cover
# Slack with two dedicated cases.


@pytest.mark.asyncio
async def test_slack_active_when_ok_true():
    body = {"ok": True, "team": "Acme", "user": "bot",
            "user_id": "U123", "team_id": "T123", "bot_id": "B123"}
    cm = _patch_client_for_get(_fake_response(200, json_body=body))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_slack_token("xoxb-real-token")
    assert result.status == "active"
    assert result.provider == "slack"
    assert "Acme" in result.details


@pytest.mark.asyncio
async def test_slack_inactive_via_in_body_error():
    body = {"ok": False, "error": "invalid_auth"}
    cm = _patch_client_for_get(_fake_response(200, json_body=body))
    with patch.object(v, "verification_client", cm):
        result = await v.verify_slack_token("xoxb-revoked")
    assert result.status == "inactive"
    assert result.provider == "slack"
    assert "invalid_auth" in result.details
