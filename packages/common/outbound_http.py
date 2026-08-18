# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Outbound HTTP client with auto-correlation headers.

Wraps ``httpx.AsyncClient`` so every outbound request carries the
inbound ``request_id`` as correlation headers — letting a support
engineer trace a single user action across Vooda's logs *and* the
upstream provider's audit log.

The headers we set (only when an inbound request_id is present in
structlog contextvars):

  X-Request-ID
        Universal pattern. Recognized by Atlassian, Heroku, Cloudflare,
        GitHub, GitLab, most application gateways. Atlassian forwards
        it into their internal traces.

  traceparent
        W3C Trace Context (RFC 9110 — ratified standard). Format:
        ``00-<32-hex-trace-id>-<16-hex-span-id>-01``. Any OpenTelemetry-
        aware downstream service will join the same trace.  Picked
        because it's vendor-neutral — works with Datadog, Honeycomb,
        Tempo, AWS X-Ray, Azure App Insights, GCP Cloud Trace.

  client-request-id
        Microsoft Graph / Azure AD specific.  Echoed in Entra sign-in
        logs and Graph audit logs, which means a customer's Azure
        admin can correlate back to a Vooda incident by pasting the
        same ID into Microsoft's portal.

Why a factory and not a global monkey-patch?  Patching httpx globally
breaks tests that rely on the unmodified client and surprises anyone
inspecting the call site.  An explicit factory is one extra import
per adapter — small price for code that's clear about what it does.

Patterns matched
----------------
The dual-header approach (vendor-neutral + provider-specific) is
how mature SDKs handle this:

  - Microsoft Azure SDK  — ``x-ms-client-request-id`` + ``traceparent``
  - Google Cloud SDK     — ``X-Goog-Trace-Id`` + ``traceparent``
  - AWS SDK              — ``amz-sdk-invocation-id`` + ``traceparent``
  - Stripe Python SDK    — ``Idempotency-Key`` + W3C trace context

We do the same thing with the universal ``X-Request-ID`` instead of
a vendor prefix — same signal, no client-side library hint about who
the client is.

Usage
-----
Adapter authors swap ``httpx.AsyncClient(...)`` for
``make_async_client(...)``::

    async with make_async_client(timeout=15) as client:
        r = await client.get(...)

All kwargs pass through unchanged.  Behavior is identical except for
the added headers.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import structlog


async def _inject_correlation_headers(request: httpx.Request) -> None:
    """httpx event hook — runs once per outbound request, before send.

    Pulls the inbound ``request_id`` from structlog's contextvars
    (bound by ``RequestContextMiddleware`` for HTTP requests, or
    explicitly by background-task entrypoints).  When no inbound
    context is present (Celery boot, scheduled task without a parent
    request), we skip — tagging an unrelated outbound call with a
    bogus correlation ID would be worse than no header at all.

    Must be ``async def`` — httpx.AsyncClient's event hooks require
    awaitables.  Sync hooks pass type-check but raise at request time.
    """
    rid = structlog.contextvars.get_contextvars().get("request_id")
    if not rid:
        return

    # 1) Universal correlation header — works with everyone.
    #    setdefault so callers who set their own X-Request-ID
    #    (e.g. for retries with idempotency) are not overwritten.
    request.headers.setdefault("X-Request-ID", rid)

    # 2) W3C Trace Context.  Compose deterministically from the
    #    request_id so the same trace ID surfaces consistently in
    #    OpenTelemetry-aware backends, with a fresh span_id per
    #    outbound call (one span per upstream API request).
    #
    #    Format: ``00-<32-hex-trace-id>-<16-hex-span-id>-01``
    #    The trailing 01 is the "sampled" flag — telling downstream
    #    OTEL collectors this trace should be recorded.
    if "traceparent" not in request.headers:
        trace_id = rid.replace("-", "").lower()[:32].ljust(32, "0")
        span_id = uuid.uuid4().hex[:16]
        request.headers["traceparent"] = f"00-{trace_id}-{span_id}-01"

    # 3) Provider-specific header for Microsoft Graph / Azure AD.
    #    Microsoft echoes this in Entra sign-in logs and Graph audit
    #    logs — meaning a customer's Azure admin can correlate a
    #    failed Vooda action to the exact Microsoft-side log entry.
    #    Other providers don't have a documented "we echo this in
    #    our audit log" header, so we don't add anything provider-
    #    specific for them.
    host = (request.url.host or "").lower()
    if "graph.microsoft.com" in host or "login.microsoftonline.com" in host:
        request.headers.setdefault("client-request-id", rid)


def make_async_client(**kwargs: Any) -> httpx.AsyncClient:
    """Drop-in replacement for ``httpx.AsyncClient`` with correlation.

    Identical kwargs to ``httpx.AsyncClient``.  Only difference:
    every outbound request gets ``X-Request-ID``, ``traceparent``,
    and (for MS Graph / Entra) ``client-request-id`` injected from
    the inbound request's structlog context.

    Caller-supplied ``event_hooks`` are preserved — our injector
    runs first, then the caller's hooks.
    """
    incoming_hooks = kwargs.pop("event_hooks", None) or {}
    request_hooks = list(incoming_hooks.get("request", []))
    response_hooks = list(incoming_hooks.get("response", []))

    # Prepend our hook so it runs before any caller-supplied request
    # hook (which may want to log the final headers).
    request_hooks.insert(0, _inject_correlation_headers)

    return httpx.AsyncClient(
        event_hooks={"request": request_hooks, "response": response_hooks},
        **kwargs,
    )
