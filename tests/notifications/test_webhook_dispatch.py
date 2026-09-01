# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""The generic notification webhook must honour its own contract.

Three properties are pinned here, each of which failed silently: a
webhook that returns 200 looks healthy from the sender's side no matter
what it actually sent, so none of these produced an error anywhere.

1. Custom headers reach the request. The connect form collects
   "Custom Headers (JSON)" and the value was stored and never read, so
   an endpoint requiring an API-key header received unauthenticated
   deliveries while the Test button reported success.

2. The signature covers the bytes that are sent. The digest was computed
   over the dataclass while a separately built dict was posted, so it
   could not match and any receiver verifying it rejected everything.

3. A malformed destination is permanent. A bad port or host cannot
   become valid on retry, so it belongs in the dead-letter path rather
   than the retry queue.
"""
import hashlib
import hmac
import json

import pytest

from services.notifications.dispatcher import (
    NotificationDispatcher, NotificationPayload, _is_retryable_error,
)


def _payload():
    return NotificationPayload(
        title="Critical secret detected",
        body="AWS key committed to main",
        severity="critical",
        event_type="critical_finding",
        resource_type="repository",
        resource_id=None,
        url="https://vooda.example/findings/1",
    )


class _Capture:
    """Stand-in httpx client that records the outgoing request."""

    def __init__(self, status=200):
        self.status = status
        self.sent = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, content=None, json=None, headers=None, **kw):
        self.sent = {"url": url, "content": content, "json": json, "headers": headers or {}}

        class _R:
            status_code = self.status
        return _R()


@pytest.fixture
def capture(monkeypatch):
    cap = _Capture()
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: cap)
    return cap


# ── 1. custom headers ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_custom_headers_are_sent(capture):
    cfg = {"endpoint_url": "https://h.example/hook",
           "headers": '{"X-Api-Key": "abc123", "X-Tenant": "acme"}'}
    r = await NotificationDispatcher()._send_webhook(cfg, _payload())
    assert r.success
    assert capture.sent["headers"].get("X-Api-Key") == "abc123", (
        "the operator's custom header never reached the request"
    )
    assert capture.sent["headers"].get("X-Tenant") == "acme"


@pytest.mark.asyncio
async def test_custom_headers_accept_a_dict_too(capture):
    cfg = {"endpoint_url": "https://h.example/hook", "headers": {"X-Api-Key": "k"}}
    await NotificationDispatcher()._send_webhook(cfg, _payload())
    assert capture.sent["headers"].get("X-Api-Key") == "k"


@pytest.mark.asyncio
async def test_malformed_header_json_does_not_break_delivery(capture):
    """A typo in the JSON must not cost the notification."""
    cfg = {"endpoint_url": "https://h.example/hook", "headers": "{not json"}
    r = await NotificationDispatcher()._send_webhook(cfg, _payload())
    assert r.success
    assert capture.sent["headers"]["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_custom_headers_cannot_override_the_signature(capture):
    """Otherwise a stray config entry silently disables verification."""
    cfg = {"endpoint_url": "https://h.example/hook", "secret": "s3cret",
           "headers": '{"X-Vooda-Signature": "forged", "Content-Type": "text/plain"}'}
    await NotificationDispatcher()._send_webhook(cfg, _payload())
    assert capture.sent["headers"]["X-Vooda-Signature"] != "forged"
    assert capture.sent["headers"]["Content-Type"] == "application/json"


# ── 2. signature covers the delivered bytes ──────────────────────────

@pytest.mark.asyncio
async def test_signature_verifies_against_the_sent_body(capture):
    secret = "s3cret"
    cfg = {"endpoint_url": "https://h.example/hook", "secret": secret}
    await NotificationDispatcher()._send_webhook(cfg, _payload())

    raw = capture.sent["content"]
    assert raw is not None, "body must be sent as bytes the signature can cover"
    got = capture.sent["headers"]["X-Vooda-Signature"]
    expect = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    assert got == expect, (
        "signature does not verify against the delivered body — a receiver "
        "checking it would reject every notification"
    )


@pytest.mark.asyncio
async def test_signature_uses_the_sha256_prefix(capture):
    """Same convention as the ticketing webhook, GitHub and Stripe, so one
    verification routine works for every webhook Vooda sends."""
    cfg = {"endpoint_url": "https://h.example/hook", "secret": "k"}
    await NotificationDispatcher()._send_webhook(cfg, _payload())
    assert capture.sent["headers"]["X-Vooda-Signature"].startswith("sha256=")


@pytest.mark.asyncio
async def test_body_still_carries_the_documented_fields(capture):
    cfg = {"endpoint_url": "https://h.example/hook"}
    await NotificationDispatcher()._send_webhook(cfg, _payload())
    body = json.loads(capture.sent["content"])
    for key in ("title", "body", "severity", "event_type", "url", "source"):
        assert key in body
    assert body["source"] == "vooda_ai"


@pytest.mark.asyncio
async def test_no_secret_means_no_signature_header(capture):
    cfg = {"endpoint_url": "https://h.example/hook"}
    await NotificationDispatcher()._send_webhook(cfg, _payload())
    assert "X-Vooda-Signature" not in capture.sent["headers"]


# ── 3. permanent vs transient failures ───────────────────────────────

@pytest.mark.parametrize("err", [
    "Invalid port: '9099-DEAD'",
    "Invalid URL: no host supplied",
    "Missing URL",
    "unsupported protocol: gopher",
])
def test_malformed_destination_is_permanent(err):
    assert _is_retryable_error(err) is False, (
        f"{err!r} cannot succeed on retry — it must dead-letter"
    )


@pytest.mark.parametrize("err", [
    "Connection timed out",
    "502 Bad Gateway",
    "Temporary failure in name resolution",
    "429 Too Many Requests",
])
def test_transient_failures_still_retry(err):
    assert _is_retryable_error(err) is True


def test_auth_failures_remain_permanent():
    assert _is_retryable_error("401 Unauthorized") is False


@pytest.mark.asyncio
async def test_non_2xx_reports_the_status(capture):
    capture.status = 500
    cfg = {"endpoint_url": "https://h.example/hook"}
    r = await NotificationDispatcher()._send_webhook(cfg, _payload())
    assert r.success is False
    assert "500" in (r.error or ""), "the status must survive into the retry record"
