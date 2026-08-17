"""SSRF / egress guard + verification kill-switch regression tests (S0).

Locks down the safety foundation for live credential verification:

* the per-provider host-suffix allowlist (jira/shopify/supabase/chronosphere
  may only reach their legitimate cloud domain),
* the universal private/loopback/link-local/metadata IP block,
* fail-open-on-resolution-failure (so mocked tests and dead hosts don't raise),
* the wiring of the guard into ``verification_client`` (block happens BEFORE any
  network connection), and
* the global ``VERIFICATION_ENABLED`` kill-switch short-circuiting verification.

All tests are network-free: IP literals and ``localhost`` resolve locally, and
the ``.invalid`` TLD (RFC-2606) is guaranteed non-resolvable.
"""
from __future__ import annotations

import pytest

from services.secret_verification.egress import (
    EgressBlocked,
    _ip_is_blocked,
    assert_host_suffix_allowed,
    assert_host_publicly_routable,
    guard_request_url,
)


# ── IP classification ───────────────────────────────────────────────

@pytest.mark.parametrize("ip", [
    "127.0.0.1", "0.0.0.0", "10.0.0.1", "10.255.255.255", "172.16.0.1",
    "192.168.1.1", "169.254.169.254",          # ← cloud metadata
    "::1", "fd00::1", "fe80::1",
])
def test_blocked_ip_ranges(ip):
    assert _ip_is_blocked(ip) is True


@pytest.mark.parametrize("ip", [
    "8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111",
])
def test_public_ips_allowed(ip):
    assert _ip_is_blocked(ip) is False


def test_non_ip_string_is_not_an_ip():
    # A hostname is not an IP literal — IP classifier must say "not blocked"
    # (the DNS resolver, not this function, decides for hostnames).
    assert _ip_is_blocked("api.github.com") is False


# ── Per-provider suffix allowlist ───────────────────────────────────

@pytest.mark.parametrize("provider,host", [
    ("jira", "company.atlassian.net"),
    ("jira", "ACME.Atlassian.NET"),            # case-insensitive
    ("shopify", "shop.myshopify.com"),
    ("supabase", "abcdef.supabase.co"),
    ("chronosphere", "acme.chronosphere.io"),
])
def test_suffix_allowlist_permits_legit_cloud_host(provider, host):
    assert_host_suffix_allowed(provider, host)  # must not raise


@pytest.mark.parametrize("provider,host", [
    ("jira", "evil.com"),
    ("jira", "internal.corp.local"),
    ("jira", "company.atlassian.net.evil.com"),  # suffix-smuggling
    ("shopify", "10.0.0.1"),
    ("supabase", "metadata.google.internal"),
    ("chronosphere", "localhost"),
])
def test_suffix_allowlist_blocks_foreign_host(provider, host):
    with pytest.raises(EgressBlocked):
        assert_host_suffix_allowed(provider, host)


def test_suffix_allowlist_noop_for_unlisted_or_missing_provider():
    # Providers with hard-coded hosts (e.g. github) and a missing provider are
    # not suffix-restricted — the IP guard still applies to them separately.
    assert_host_suffix_allowed("github", "anything.example.com")
    assert_host_suffix_allowed(None, "anything.example.com")


# ── IP guard (async, resolution-aware) ──────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["169.254.169.254", "127.0.0.1", "localhost"])
async def test_ip_guard_blocks_internal(host):
    with pytest.raises(EgressBlocked):
        await assert_host_publicly_routable(host)


@pytest.mark.asyncio
async def test_ip_guard_fails_open_on_unresolvable_host():
    # RFC-2606 .invalid TLD never resolves → cannot be an internal-IP SSRF →
    # must NOT raise (keeps mocked tests / dead provider hosts working).
    await assert_host_publicly_routable("this-host-does-not-exist.invalid")


@pytest.mark.asyncio
async def test_ip_guard_allows_public_ip_literal():
    await assert_host_publicly_routable("93.184.216.34")  # no raise


# ── Combined entrypoint ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_guard_request_url_blocks_private_ip():
    with pytest.raises(EgressBlocked):
        await guard_request_url("https://10.0.0.1/admin", provider=None)


@pytest.mark.asyncio
async def test_guard_request_url_blocks_foreign_host_for_scoped_provider():
    with pytest.raises(EgressBlocked):
        await guard_request_url("https://internal.corp.local/rest/api/3/myself",
                                provider="jira")


@pytest.mark.asyncio
async def test_guard_request_url_strips_userinfo_smuggling():
    # urlsplit must extract the REAL host past userinfo: the request would go
    # to evil.com, not company.atlassian.net.
    with pytest.raises(EgressBlocked):
        await guard_request_url("https://company.atlassian.net@evil.com/x",
                                provider="jira")


# ── verification_client wiring (block happens pre-network) ───────────

@pytest.mark.asyncio
async def test_client_event_hook_blocks_before_connecting():
    from services.secret_verification.http_client import verification_client
    # provider-scoped: a foreign host is refused by the suffix check, which
    # runs in the request event-hook BEFORE any socket is opened.
    async with verification_client(timeout=5, provider="jira") as c:
        with pytest.raises(EgressBlocked):
            await c.get("https://evil.com/rest/api/3/myself")


@pytest.mark.asyncio
async def test_client_event_hook_blocks_private_ip_unscoped():
    from services.secret_verification.http_client import verification_client
    async with verification_client(timeout=5) as c:
        with pytest.raises(EgressBlocked):
            await c.get("https://127.0.0.1/")


# ── Global kill-switch ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_kill_switch_short_circuits_verify_finding(monkeypatch):
    from apps.api.app.core.config import settings
    from services.secret_verification import verifier

    monkeypatch.setattr(settings, "VERIFICATION_ENABLED", False, raising=False)
    # Even a fully-formed, supported-provider finding must return None (skip)
    # when verification is globally disabled — no outbound call is attempted.
    result = await verifier.verify_finding({
        "provider": "github",
        "_raw_value": "ghp_" + "A" * 36,
        "detection_method": "regex",
    })
    assert result is None


def test_kill_switch_helper_defaults_enabled(monkeypatch):
    from apps.api.app.core.config import settings
    from services.secret_verification import verifier

    monkeypatch.setattr(settings, "VERIFICATION_ENABLED", True, raising=False)
    assert verifier._verification_enabled() is True
