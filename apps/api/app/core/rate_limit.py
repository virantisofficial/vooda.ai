# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Per-principal rate limiting (Sprint 1 / Stage B of the API-key audit).

slowapi is used as the FastAPI integration; the underlying storage is
Redis so all uvicorn workers share one bucket per principal — without
the shared backend, two workers running side-by-side would each grant
the full burst before any throttling kicked in.

Key function priority:
    1. ``api_key_id`` (most specific — set by ``_authenticate_api_key``
       via ``request.state.api_key`` after Sprint 0).
    2. Authenticated user id (JWT path).
    3. Remote IP (anonymous / pre-auth requests).

This ordering lets us:
    * Throttle a leaked CI/CD key without affecting other keys from the
      same tenant.
    * Throttle an abusive logged-in user without affecting their team.
    * Still apply a sane per-IP cap on the login endpoint so brute-force
      attempts can be blunted before they ever reach a 401-counting
      layer.

Limits are intentionally generous defaults.  Tighten per-endpoint with
``@limiter.limit("N/minute")`` decorators where business reasons exist.

429 responses include a ``Retry-After`` header (seconds) and a JSON body
that names the limit so CI logs can self-diagnose.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from apps.api.app.core.config import settings


def _principal_key(request: Request) -> str:
    """Identify the request principal for rate-limit bucket selection.

    Order of preference matches the docstring above.  Falls back to the
    remote IP so anonymous endpoints still get throttled rather than
    sharing one global bucket.
    """
    # API-key request — most specific, exactly the per-key throttle the
    # audit asked for.  Set by ``_authenticate_api_key``.
    api_key = getattr(request.state, "api_key", None)
    if api_key is not None and getattr(api_key, "id", None):
        return f"apikey:{api_key.id}"

    # JWT-authenticated session.
    user = getattr(request.state, "auth_user", None)
    if user is not None and getattr(user, "id", None):
        return f"user:{user.id}"

    # Anonymous — respects X-Forwarded-For via slowapi's built-in helper.
    return f"ip:{get_remote_address(request)}"


# Global limiter instance.  ``default_limits`` is the per-principal
# default applied when an endpoint doesn't carry a more specific
# ``@limiter.limit(...)``.  Tuned to be generous: a busy CI pipeline
# scanning a monorepo every push will sit comfortably under 600 req/min,
# while a credential-stuffing or scraping attempt against a single key
# blows through it well before causing real load.
limiter = Limiter(
    key_func=_principal_key,
    default_limits=["600/minute", "10000/hour"],
    storage_uri=settings.REDIS_URL,
    headers_enabled=True,  # X-RateLimit-{Limit,Remaining,Reset} on every response
    strategy="fixed-window",  # cheapest, sufficient for abuse-prevention
)


async def rate_limit_exceeded_handler(
    request: Request, exc: RateLimitExceeded
) -> JSONResponse:
    """Pretty-print 429s.  slowapi's default handler returns plain text;
    CI tooling wants JSON + a clear ``Retry-After``.

    Always sets the standard ``Retry-After`` header (seconds) so well-
    behaved clients back off.  ``X-RateLimit-*`` headers come from
    slowapi's middleware so we don't duplicate them.
    """
    retry_after = getattr(exc, "retry_after", None) or 60
    return JSONResponse(
        status_code=429,
        headers={"Retry-After": str(int(retry_after))},
        content={
            "detail": (
                f"Rate limit exceeded: {exc.detail}. "
                f"Retry after {int(retry_after)}s."
            ),
            "limit": str(exc.detail),
            "retry_after_seconds": int(retry_after),
        },
    )
