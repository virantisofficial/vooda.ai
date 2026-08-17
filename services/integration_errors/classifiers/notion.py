# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Notion API error classifier.

Notion is REST-based with a stable JSON error envelope::

    {
      "object": "error",
      "status": 401,
      "code": "unauthorized",
      "message": "API token is invalid.",
      "request_id": "..."
    }

The ``code`` field is small, stable, and stripe-style — preferred for
sub-classification.  ``message`` is the user-facing string Notion
recommends rendering.

Diagnostic header / field:

  - ``request_id`` (in body) and ``X-Request-Id`` (header) — both carry
    Notion's per-request correlation id.

Most common causes in the wild:

  - "API token is invalid"          → token wrong / revoked
  - "object_not_found"              → integration not shared with the page
  - "restricted_resource"           → integration shared but with insufficient capability
  - "rate_limited"                  → 429
  - "validation_error"              → request payload bad

Notion's distinguishing feature is its sharing model: the integration
must be EXPLICITLY shared on every page/database it can see.  Most
"can't read this page" failures resolve to "share the page with the
integration in the Notion UI."  The classifier surfaces that fix.

Error classes covered:

  notion.auth.invalid_token             401 + "unauthorized" / "invalid_token"
  notion.auth.token_revoked             401 + "restricted_resource" on /search
  notion.permission.not_shared          404 + "object_not_found"
  notion.permission.insufficient        403 + "restricted_resource"
  notion.rate_limited                   429
  notion.validation_error               400 + "validation_error"
  notion.payload_too_large              413
  notion.provider_fault                 5xx
  notion.unknown                        catch-all
"""

from __future__ import annotations

from typing import Any

import httpx

from ..model import ErrorCategory, ErrorSeverity, IntegrationError
from ..redact import redact_secrets


def _trace(r: httpx.Response, body: dict[str, Any] | None) -> str | None:
    if isinstance(body, dict) and body.get("request_id"):
        return str(body["request_id"])
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
    """Return (code, message, full_body_or_none) from a Notion response."""
    try:
        body = r.json()
    except ValueError:
        return "", r.text[:500], None
    if not isinstance(body, dict):
        return "", "", None
    return str(body.get("code") or ""), str(body.get("message") or ""), body


def classify_notion_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    ctx = dict(context or {})
    code, message, body = _parse(response)
    http_status = response.status_code
    trace = _trace(response, body)

    # ── 429: rate limited ──────────────────────────────────────────
    if http_status == 429 or code == "rate_limited":
        ra = response.headers.get("Retry-After") or response.headers.get("retry-after")
        try:
            retry = int(ra) if ra else None
        except ValueError:
            retry = None
        return IntegrationError(
            code="notion.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="Notion rate-limited the request",
            summary="Notion limits each integration to ~3 requests per second on average.",
            fix_steps=[
                f"Wait {retry}s and retry" if retry else "Wait at least 1s and retry",
                "If this happens often, lower scan concurrency for this Notion source",
            ],
            doc_anchor="/docs?section=sources&provider=notion#rate-limit",
            http_status=http_status,
            provider_code=code or "rate_limited",
            retry_after_s=retry,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 401: token invalid / revoked ───────────────────────────────
    if http_status == 401 or code in ("unauthorized", "invalid_token"):
        return IntegrationError(
            code="notion.auth.invalid_token",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Notion rejected the integration token",
            summary=(
                "Notion returned 401. The token is wrong, revoked, or the "
                "integration was deleted from the workspace."
            ),
            fix_steps=[
                "Open notion.so/my-integrations → your integration → Internal integration secret",
                "Copy the current secret (it starts with `secret_` or `ntn_`) and paste it into Vooda",
                "If the integration was deleted, create a new one and re-share the pages with it",
            ],
            doc_anchor="/docs?section=sources&provider=notion#token",
            http_status=http_status,
            provider_code=code or "unauthorized",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 404: page/database not shared with integration ─────────────
    # Notion deliberately returns 404 when the integration can't see
    # the resource (rather than 403) — privacy by design. The fix is
    # always "share the page with the integration in the Notion UI."
    if http_status == 404 or code == "object_not_found":
        return IntegrationError(
            code="notion.permission.not_shared",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Page or database not shared with Vooda",
            summary=(
                "Notion couldn't find the resource. The most common cause is that "
                "the page/database hasn't been shared with the Vooda integration — "
                "Notion treats those cases as 404 by design."
            ),
            fix_steps=[
                "Open the page or database in Notion",
                "Click '...' → 'Connections' → 'Add connections' → select your Vooda integration",
                "If you want workspace-wide access, share the workspace's top-level page",
            ],
            doc_anchor="/docs?section=sources&provider=notion#sharing",
            http_status=http_status,
            provider_code=code or "object_not_found",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 403: insufficient capability ───────────────────────────────
    if http_status == 403 or code == "restricted_resource":
        return IntegrationError(
            code="notion.permission.insufficient",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Integration lacks the required capability",
            summary=(
                "The integration is shared on this resource but doesn't have the "
                "right capability (Read content / Read comments / etc.) to perform "
                "this call."
            ),
            fix_steps=[
                "Open notion.so/my-integrations → your integration → Capabilities",
                "Enable 'Read content' (and 'Read comments' if you want to scan comments)",
                "Save and retry — the change is effective immediately",
            ],
            doc_anchor="/docs?section=sources&provider=notion#capabilities",
            http_status=http_status,
            provider_code=code or "restricted_resource",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 400: validation error ──────────────────────────────────────
    if http_status == 400 or code == "validation_error":
        return IntegrationError(
            code="notion.validation_error",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Notion rejected the request payload",
            summary=message or "Notion returned 400 — the request body failed validation.",
            fix_steps=[
                "Check the request body shape against Notion's API reference",
                "If this only happens on specific items, file a bug — Vooda may be malforming the payload",
            ],
            http_status=http_status,
            provider_code=code or "validation_error",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 413: payload too large ─────────────────────────────────────
    if http_status == 413:
        return IntegrationError(
            code="notion.payload_too_large",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Request payload too large",
            summary="Notion rejected the request body for exceeding the size cap.",
            fix_steps=[
                "Reduce per-page result count in the scan settings",
                "Skip blocks with very large embeds",
            ],
            http_status=http_status,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 5xx: provider fault ────────────────────────────────────────
    if 500 <= http_status < 600:
        return IntegrationError(
            code="notion.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Notion returned a server error",
            summary=f"Notion server returned HTTP {http_status}. This is on Notion's side.",
            fix_steps=[
                "Retry — most 5xx responses are transient",
                "If persistent, check status.notion.so",
            ],
            http_status=http_status,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── Catch-all ──────────────────────────────────────────────────
    return IntegrationError(
        code="notion.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title="Notion error",
        summary=f"Notion returned HTTP {http_status} ({code or 'no code'}).",
        fix_steps=["Check the Notion API reference", "Retry once"],
        http_status=http_status,
        provider_code=code,
        trace_id=trace,
        raw=_raw(response, body),
        context=ctx,
    )
