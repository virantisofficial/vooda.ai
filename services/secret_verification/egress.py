# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""
SSRF / egress guard for credential verification.

Most of the ~250 verifiers call hard-coded provider hosts (api.github.com,
api.stripe.com, …) — those are inherently safe. A handful interpolate a host
derived from FINDING CONTENT (a Jira cloud domain, a Supabase project URL, a
Shopify shop domain, a Chronosphere tenant domain). When Vooda scans an
*untrusted* repository, an attacker can plant a crafted "secret" whose host
points at an internal service or the cloud-metadata endpoint, turning a
verification request into SSRF.

This module is the single chokepoint that makes verification egress safe. It is
wired into ``http_client.verification_client`` as an httpx request event-hook,
so EVERY verifier is protected with no per-verifier change.

1. IP guard (universal): before any verification request is sent, resolve the
   target host and BLOCK if it resolves to a private / loopback / link-local /
   reserved / multicast / unspecified address (covers 127.0.0.1, ::1, 10/8,
   192.168/16, 169.254.0.0/16 incl. the 169.254.169.254 cloud-metadata
   address, etc.).

   * Fail-OPEN on resolution FAILURE — an unresolvable host cannot be an
     internal-IP SSRF, and this keeps mocked tests / genuinely-dead hosts
     working (they just fail to connect later).
   * Fail-CLOSED if the host resolves to a blocked range — catches
     ``localhost``, literal metadata IPs, and DNS-rebinding names that resolve
     to RFC-1918 space.

2. Suffix allowlist (per-provider): the host-from-content verifiers may ONLY
   talk to their legitimate cloud domain (``.atlassian.net``, ``.myshopify.com``,
   ``.supabase.co``, ``.chronosphere.io``). A planted ``internal.corp.local``
   fails the suffix check and is blocked outright (no DNS needed).

Any block raises :class:`EgressBlocked`. Verifiers already wrap their HTTP call
in try/except returning ``status="error"`` on any exception, so a blocked
request surfaces as a (non-suppressing) verification error — never as a dead
key and never as a crashed scan.

Residual: the IP check and the actual connect resolve independently, so a
sub-second DNS-rebinding window exists for the IP layer. The suffix allowlist
closes it for the host-from-content providers (the only attacker-influenced
hosts); a full pinned-IP transport is a noted hardening follow-up.

Stdlib-only (asyncio, ipaddress, socket, urllib) — no dependency on ``apps`` so
it stays importable in the trimmed CLI image.
"""

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit


class EgressBlocked(Exception):
    """Raised when a verification request target is disallowed."""


# Per-provider allowed host suffixes for verifiers that build the target host
# from finding content. Providers NOT listed here are unrestricted by suffix
# (but still subject to the universal IP guard below).
HOST_SUFFIX_ALLOWLIST: dict[str, tuple[str, ...]] = {
    "jira": (".atlassian.net",),
    "shopify": (".myshopify.com",),
    "supabase": (".supabase.co",),
    "chronosphere": (".chronosphere.io",),
}


def _host_from_url(url: str) -> str:
    """Extract the lowercased hostname from a URL (drops userinfo/port/path)."""
    return (urlsplit(url).hostname or "").strip().rstrip(".").lower()


def assert_host_suffix_allowed(provider: str | None, host: str) -> None:
    """Enforce the per-provider host-suffix allowlist (pure string check, no DNS).

    No-op when ``provider`` is falsy or has no allowlist entry.
    """
    if not provider:
        return
    suffixes = HOST_SUFFIX_ALLOWLIST.get(provider.lower())
    if not suffixes:
        return
    h = (host or "").lower().rstrip(".")
    if not any(h == s.lstrip(".") or h.endswith(s) for s in suffixes):
        raise EgressBlocked(
            f"host {host!r} not in allowlist for provider {provider!r} "
            f"(allowed suffixes: {', '.join(suffixes)})"
        )


def _ip_is_blocked(ip_str: str) -> bool:
    """True when ``ip_str`` is a literal IP in a non-publicly-routable range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


async def assert_host_publicly_routable(host: str) -> None:
    """Raise :class:`EgressBlocked` if ``host`` resolves to a non-public IP.

    Fail-OPEN on resolution failure; fail-CLOSED if ANY resolved address is in
    a blocked range. A bare IP literal is checked directly without DNS.
    """
    if not host:
        return
    # IP literal → check directly, no DNS round-trip.
    if _ip_is_blocked(host):
        raise EgressBlocked(f"host {host!r} is a non-public address")
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        # Resolution failed — cannot be an internal-IP SSRF. Allow; the real
        # connection (if any) will simply fail. Keeps mocked tests working.
        return
    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0] if sockaddr else ""
        if _ip_is_blocked(ip_str):
            raise EgressBlocked(
                f"host {host!r} resolves to blocked address {ip_str}"
            )


async def guard_request_url(url: str, provider: str | None = None) -> None:
    """Single entrypoint: enforce the suffix allowlist (if any) + the IP guard.

    Suffix check runs first (cheap, no DNS) so an obviously-wrong host is
    rejected before we spend a resolution on it.
    """
    host = _host_from_url(url)
    assert_host_suffix_allowed(provider, host)
    await assert_host_publicly_routable(host)
