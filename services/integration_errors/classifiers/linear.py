# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Linear GraphQL error classifier.

Linear is GraphQL-only.  Like all GraphQL APIs, errors come back at
HTTP 200 inside an ``errors`` array::

    {
      "data": null,
      "errors": [
        {
          "message": "Authentication required, not authenticated",
          "extensions": {
            "code": "AUTHENTICATION_ERROR",
            "type": "authentication error",
            "userPresentableMessage": "..."
          }
        }
      ]
    }

The ``extensions.code`` field is small, stable, and machine-readable.
We use it as the primary classification key.

HTTP-level errors (401 from auth pre-flight, 429 from rate-limit) ARE
also possible and we route them through the same function — adapters
just call ``classify_linear_error(response)`` regardless of whether
the error surfaced as HTTP or GraphQL.

Diagnostic header / field:

  - ``X-Request-ID`` (header) carries Linear's per-request trace id;
    GraphQL errors echo additional context under ``extensions.requestId``
    on some plans.

Error classes covered:

  linear.auth.invalid_token             AUTHENTICATION_ERROR / 401
  linear.permission.insufficient        FORBIDDEN / NOT_AUTHORISED
  linear.rate_limited                   RATELIMITED / 429
  linear.not_found                      NOT_FOUND
  linear.validation_error               INVALID_INPUT / GRAPHQL_VALIDATION_FAILED
  linear.provider_fault                 INTERNAL_SERVER_ERROR / 5xx
  linear.unknown                        catch-all
"""

from __future__ import annotations

from typing import Any

import httpx

from ..model import ErrorCategory, ErrorSeverity, IntegrationError
from ..redact import redact_secrets


def _trace(r: httpx.Response, body: dict[str, Any] | None) -> str | None:
    if isinstance(body, dict):
        errs = body.get("errors")
        if isinstance(errs, list) and errs:
            ext = (errs[0] or {}).get("extensions") or {}
            if isinstance(ext, dict) and ext.get("requestId"):
                return str(ext["requestId"])
    return r.headers.get("X-Request-Id") or r.headers.get("x-request-id")


def _raw(r: httpx.Response, body: Any) -> dict[str, Any]:
    return redact_secrets(
        {
            "headers": dict(r.headers),
            "status": r.status_code,
            "body": body if not isinstance(body, str) else body[:1000],
            "request_url": str(r.request.url) if r.request else None,
        }
    )  # type: ignore[return-value]


def _parse(r: httpx.Response) -> tuple[str, str, dict[str, Any] | None]:
    """Return (extensions.code, message, body)."""
    try:
        body = r.json()
    except ValueError:
        return "", r.text[:500], None
    if not isinstance(body, dict):
        return "", "", None
    errs = body.get("errors")
    if not isinstance(errs, list) or not errs:
        return "", "", body
    first = errs[0] or {}
    if not isinstance(first, dict):
        return "", "", body
    message = str(first.get("message") or "")
    ext = first.get("extensions") or {}
    code = ""
    if isinstance(ext, dict):
        code = str(ext.get("code") or ext.get("type") or "")
    return code.upper(), message, body


def classify_linear_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    ctx = dict(context or {})
    code, message, body = _parse(response)
    http_status = response.status_code
    trace = _trace(response, body)

    # ── Rate limit (429 OR ratelimited code) ───────────────────────
    if http_status == 429 or code in ("RATELIMITED", "RATE_LIMITED"):
        ra = response.headers.get("Retry-After") or response.headers.get("retry-after")
        try:
            retry = int(ra) if ra else None
        except ValueError:
            retry = None
        return IntegrationError(
            code="linear.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="Linear rate-limited the request",
            summary="Linear caps API key usage to ~1500 requests / hour by default.",
            fix_steps=[
                f"Wait {retry}s and retry" if retry else "Wait at least 60s and retry",
                "Lower the page size in the scan settings if this happens often",
                "Linear's ratelimit headers (X-RateLimit-Requests-Remaining) show your current budget",
            ],
            doc_anchor="/docs?section=sources&provider=linear#rate-limit",
            http_status=http_status,
            provider_code=code or "ratelimited",
            retry_after_s=retry,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── Auth ───────────────────────────────────────────────────────
    if http_status == 401 or code in ("AUTHENTICATION_ERROR", "AUTHENTICATION_REQUIRED"):
        return IntegrationError(
            code="linear.auth.invalid_token",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Linear rejected the API key",
            summary="Linear returned an authentication error. The API key is wrong, revoked, or the workspace was deleted.",
            fix_steps=[
                "Open linear.app → Settings → API → Personal API keys",
                "Confirm the key listed matches the one in Vooda; if not, regenerate and update",
                "Linear API keys do NOT use the `Bearer` prefix — Vooda already handles this; if you copy-paste manually, send the raw key",
            ],
            doc_anchor="/docs?section=sources&provider=linear#token",
            http_status=http_status,
            provider_code=code or "AUTHENTICATION_ERROR",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── Permission ─────────────────────────────────────────────────
    if code in ("FORBIDDEN", "NOT_AUTHORISED", "NOT_AUTHORIZED"):
        return IntegrationError(
            code="linear.permission.insufficient",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="API key lacks permission",
            summary="The Linear key authenticated but doesn't have permission for this resource.",
            fix_steps=[
                "Confirm the key was generated by an admin (workspace-wide keys can read all teams)",
                "Member-scoped keys only see teams the member belongs to — switch to a workspace key or invite the key's owner to the team",
            ],
            doc_anchor="/docs?section=sources&provider=linear#permissions",
            http_status=http_status,
            provider_code=code,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── Not found ──────────────────────────────────────────────────
    if code == "NOT_FOUND":
        return IntegrationError(
            code="linear.not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Linear couldn't find the resource",
            summary=message or "Linear returned NOT_FOUND for the requested entity.",
            fix_steps=[
                "Verify the team key / issue identifier matches what's in Linear",
                "Confirm the API key's user can see the team",
            ],
            http_status=http_status,
            provider_code=code,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── Validation ─────────────────────────────────────────────────
    if code in ("INVALID_INPUT", "GRAPHQL_VALIDATION_FAILED", "BAD_USER_INPUT"):
        return IntegrationError(
            code="linear.validation_error",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Linear rejected the query",
            summary=message or "Linear returned a validation error on the request shape.",
            fix_steps=[
                "Check the GraphQL query against Linear's schema",
                "If this only happens on specific items, file a bug — Vooda may be sending an invalid query",
            ],
            http_status=http_status,
            provider_code=code,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── Server fault ───────────────────────────────────────────────
    if 500 <= http_status < 600 or code in ("INTERNAL_SERVER_ERROR", "INTERNAL_ERROR"):
        return IntegrationError(
            code="linear.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Linear server error",
            summary=f"Linear returned a server error ({http_status} / {code or 'INTERNAL_SERVER_ERROR'}).",
            fix_steps=[
                "Retry — most Linear server errors are transient",
                "If persistent, check linearstatus.com",
            ],
            http_status=http_status,
            provider_code=code or "INTERNAL_SERVER_ERROR",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    return IntegrationError(
        code="linear.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title="Linear error",
        summary=message or f"Linear returned an unrecognised error ({code or http_status}).",
        fix_steps=["Check the Linear API reference for this code", "Retry once"],
        http_status=http_status,
        provider_code=code,
        trace_id=trace,
        raw=_raw(response, body),
        context=ctx,
    )
