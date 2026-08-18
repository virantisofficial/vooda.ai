# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""
Shared HTTP Client for Secret Verification.

A thin factory around ``httpx.AsyncClient`` that every verifier calls into.
It exists so the ~200 verifier functions don't each invent their own client
with inconsistent timeouts, no retries, no User-Agent, and no connection
pooling discipline.

What it gives us over a raw ``httpx.AsyncClient(timeout=10)``:

1. **Connection-level retries.** ``AsyncHTTPTransport(retries=2)`` means a
   transient DNS / TCP reset / refused-connection doesn't immediately mark
   a valid credential as ``status="error"``. Retries happen BEFORE the
   request is sent, so they're safe for non-idempotent methods too.

2. **Shared connection pool limits.** When the worker verifies 100+
   findings in a burst, we cap concurrent host connections so we don't
   trigger provider rate limits with accidental parallelism.

3. **Consistent User-Agent.** Providers inspect UAs for rate-limit
   bucketing and abuse triage; identifying ourselves honestly gives us a
   named bucket instead of being lumped into "unidentified" traffic.

4. **Centralised error classification.** ``classify_http_error()`` tells
   the caller whether an exception is transient (network blip, timeout)
   vs definitive (TLS failure, invalid URL). The worker can use this to
   decide whether to re-verify later instead of marking a key dead.

Migration pattern:

    # before
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url, headers=h)

    # after
    async with verification_client() as client:
        r = await client.get(url, headers=h)

Everything else in the call site stays the same — same ``r.status_code``,
same ``r.json()``, same try/except — so migration is mechanical.
"""

import httpx

from services.secret_verification.egress import guard_request_url


# ── Defaults ─────────────────────────────────────────────────

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_UA = "Vooda-Verifier/1.0 (+https://vooda.io; secret-scan-validator)"

# Per-host pool limits. These cap the damage if a verification loop
# accidentally fans out against one host. httpx pools are per-client, so
# since we construct a new client per call we also keep per-client caps low.
_LIMITS = httpx.Limits(
    max_connections=20,
    max_keepalive_connections=10,
    keepalive_expiry=30.0,
)

# Transport with built-in connection-level retries. Note: httpx retries
# only apply to connection errors (DNS, TCP reset, refused), NOT to HTTP
# status codes like 429 / 503. Status-code retry is deliberately out of
# scope for this layer — the call site knows what a 429 means for its
# provider and can choose to back off.
_TRANSPORT_RETRIES = 2


# ── Factories ────────────────────────────────────────────────


def verification_client(
    timeout: float = _DEFAULT_TIMEOUT,
    user_agent: str = _DEFAULT_UA,
    follow_redirects: bool = False,
    provider: str | None = None,
) -> httpx.AsyncClient:
    """Construct a pre-configured ``httpx.AsyncClient`` for verifier use.

    Callers use it exactly like a raw AsyncClient:

        async with verification_client() as c:
            r = await c.get(url, headers=headers)

    Parameters
    ----------
    timeout:
        Total request timeout in seconds. Most verifiers use 10s; a few
        slower ones pass 12 or 15 explicitly.
    user_agent:
        UA header sent on every request. Callers can override per-request
        if the provider requires a specific UA.
    follow_redirects:
        Off by default — verifiers expect to see 301/302 directly rather
        than silently follow into HTML login pages that would return 200.
    provider:
        When set, the SSRF/egress guard additionally enforces this
        provider's host-suffix allowlist (see ``egress.HOST_SUFFIX_ALLOWLIST``).
        Verifiers that build the target host from FINDING CONTENT
        (jira/shopify/supabase/chronosphere) pass their provider so a
        planted internal/arbitrary host is refused. Verifiers calling a
        hard-coded host can leave it ``None`` — the universal IP guard
        still applies either way.

    Egress safety
    -------------
    Every outgoing request runs through ``egress.guard_request_url`` via an
    httpx request event-hook BEFORE it is sent: the host must resolve to a
    publicly-routable IP (no RFC-1918 / loopback / link-local / metadata),
    and — when ``provider`` is given — match that provider's allowed cloud
    suffix. A blocked request raises ``EgressBlocked``, which verifiers'
    existing try/except turns into ``status="error"`` (never a dead key,
    never a crashed scan).
    """
    async def _egress_guard(request: httpx.Request) -> None:
        await guard_request_url(str(request.url), provider)

    return httpx.AsyncClient(
        timeout=timeout,
        transport=httpx.AsyncHTTPTransport(retries=_TRANSPORT_RETRIES),
        limits=_LIMITS,
        headers={"User-Agent": user_agent},
        follow_redirects=follow_redirects,
        event_hooks={"request": [_egress_guard]},
    )


# ── Error classification ─────────────────────────────────────


# Exception types that are transient: we should mark the verification as
# ``error`` (not ``inactive``) and re-try in a later pass.
_TRANSIENT_EXC_TYPES = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
    httpx.NetworkError,
)


def is_transient_http_error(exc: BaseException) -> bool:
    """Return True when ``exc`` looks like a transient network blip.

    Verifiers default to ``status="error"`` on any exception, but callers
    that want smarter re-verification semantics can use this to tag the
    result (e.g. with a ``retryable=True`` flag in ``details``).
    """
    return isinstance(exc, _TRANSIENT_EXC_TYPES)
