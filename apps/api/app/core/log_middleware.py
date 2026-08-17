# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""FastAPI middleware that binds per-request fields to structlog context.

For every HTTP request:

  1. Generate a UUID4 ``request_id``, or accept one from the inbound
     ``X-Request-ID`` header (so callers / load-balancers can supply
     their own correlation ID and have it flow through Vooda).

  2. Bind ``{request_id, method, path}`` to structlog's contextvars so
     every ``logger.info(...)`` call inside this request's task picks
     them up automatically.

  3. After the response is built, log a single access line at INFO
     (or DEBUG for health endpoints — handled by the noise filter in
     ``logging_config.py``) with ``{status_code, duration_ms}``.

  4. Echo the request_id back to the client via ``X-Request-ID``
     header so users can include it in support tickets.

  5. Always clear the contextvars in ``finally`` so the next task
     scheduled on this asyncio loop doesn't inherit stale fields.

Notes
-----
- ``user_id`` and ``tenant_id`` are bound by the auth dependency,
  not here — at this point in the request the user hasn't been
  authenticated yet.  This middleware lays the foundation; the
  ``get_current_user`` dependency adds onto it once the token is
  decoded.
- Body / headers are NOT logged here (PII / secret risk).  Adapter-
  level logging is the right place for that, with the centralized
  redaction processor stripping anything credential-shaped.
"""

from __future__ import annotations

import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from packages.common.logging_config import bind_request_context, clear_request_context


_REQUEST_ID_HEADER = "X-Request-ID"

# Paths where the per-request access log lands at DEBUG instead of
# INFO.  Health probes and openapi polls fire every few seconds and
# would otherwise dominate the log stream — same approach Google
# Cloud Run / Azure App Service use for their internal probe paths.
_QUIET_PATHS = (
    "/api/health",
    "/healthz",
    "/api/openapi.json",
    "/openapi.json",
)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Per-request context-var binding + access log emission."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Accept inbound correlation IDs from upstream (load balancer,
        # API gateway, customer-side caller).  Validate length to
        # bound the field size — accept anything that "looks like an
        # ID" but cap at 128 chars to defend against header-bomb DoS.
        inbound_id = request.headers.get(_REQUEST_ID_HEADER, "")
        request_id = inbound_id.strip()[:128] if inbound_id else uuid.uuid4().hex

        bind_request_context(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )

        logger = structlog.get_logger("vooda.request")
        started = time.perf_counter()
        status_code = 500  # default in case of mid-handler crash

        try:
            response: Response = await call_next(request)
            status_code = response.status_code
            response.headers[_REQUEST_ID_HEADER] = request_id
            return response
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 1)
            path = request.url.path
            # Health / openapi probes go to DEBUG so they don't
            # dominate INFO-level streams.  Everything else stays at
            # INFO (or ERROR if the response was 5xx).
            if path in _QUIET_PATHS:
                logger.debug("http.request", status=status_code, duration_ms=duration_ms)
            elif status_code >= 500:
                logger.error("http.request", status=status_code, duration_ms=duration_ms)
            else:
                logger.info("http.request", status=status_code, duration_ms=duration_ms)
            clear_request_context()
