# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""ServiceNow REST error classifier.

ServiceNow uses a stable error envelope::

    {
      "error": {
        "message": "User Not Authenticated",
        "detail": "Required to provide Auth information"
      },
      "status": "failure"
    }

Auth modes: HTTP Basic with username + password, or OAuth password
grant.  Vooda's adapter uses Basic.

Per-instance gotchas:

  - Most-frequent failure mode is the user account being locked out
    after Vooda makes too many requests with a wrong password — it
    looks like 401 + "User Not Authenticated" but the underlying
    cause is "your user is locked".  ServiceNow doesn't surface that
    distinction — the admin has to unlock in Setup → Users.

  - ACL (table-level access) failures return 403 with a body
    referencing "Operation against table X" — distinct from a
    plain auth failure.

Diagnostic header:

  - ``X-ServiceNow-Sysparm-Display-Value`` and similar headers carry
    contextual info but no per-request trace id is documented.

Error classes covered:

  servicenow.auth.invalid_credentials   401
  servicenow.auth.account_locked        401 + locked hint (best-effort detection)
  servicenow.permission.no_acl          403
  servicenow.not_found                  404 (table/record)
  servicenow.rate_limited               429
  servicenow.validation_error           400
  servicenow.provider_fault             5xx
  servicenow.unknown                    catch-all
"""

from __future__ import annotations

from typing import Any

import httpx

from ..model import ErrorCategory, ErrorSeverity, IntegrationError
from ..redact import redact_secrets


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
    """Return (message, detail, body)."""
    try:
        body = r.json()
    except ValueError:
        return r.text[:500], "", None
    if not isinstance(body, dict):
        return "", "", None
    err = body.get("error")
    if isinstance(err, dict):
        return str(err.get("message") or ""), str(err.get("detail") or ""), body
    return str(body.get("message") or ""), "", body


def classify_servicenow_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    ctx = dict(context or {})
    message, detail, body = _parse(response)
    http_status = response.status_code
    detail_lower = (detail or "").lower()
    msg_lower = (message or "").lower()

    # ── Rate limit ─────────────────────────────────────────────────
    if http_status == 429:
        ra = response.headers.get("Retry-After") or response.headers.get("retry-after")
        try:
            retry = int(ra) if ra else None
        except ValueError:
            retry = None
        return IntegrationError(
            code="servicenow.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="ServiceNow rate-limited the request",
            summary="ServiceNow's rate limiter caps per-user transactions per second based on the instance's tier.",
            fix_steps=[
                f"Wait {retry}s and retry" if retry else "Wait at least 60s and retry",
                "Lower scan concurrency for this ServiceNow source",
                "Ask the admin to bump the user's rate-limit rule in System Administration → Rate Limit Rules",
            ],
            doc_anchor="/docs?section=sources&provider=servicenow#rate-limit",
            http_status=http_status,
            provider_code="rate_limited",
            retry_after_s=retry,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 401: auth (with best-effort lock detection) ────────────────
    if http_status == 401:
        if "locked" in detail_lower or "locked" in msg_lower:
            return IntegrationError(
                code="servicenow.auth.account_locked",
                category=ErrorCategory.AUTHENTICATION,
                severity=ErrorSeverity.ERROR,
                title="ServiceNow user is locked",
                summary=(
                    "The integration user has been locked out, usually after too "
                    "many failed login attempts."
                ),
                fix_steps=[
                    "Open ServiceNow → User Administration → Users → find the integration user",
                    "Untick 'Locked out' and save",
                    "Update Vooda's password to the correct one before retrying",
                ],
                doc_anchor="/docs?section=sources&provider=servicenow#account-locked",
                http_status=http_status,
                provider_code="account_locked",
                raw=_raw(response, body),
                context=ctx,
            )
        return IntegrationError(
            code="servicenow.auth.invalid_credentials",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="ServiceNow rejected the credentials",
            summary="ServiceNow returned 401. The username or password is wrong, or the account doesn't have web-service access.",
            fix_steps=[
                "Verify the username (often a service account, e.g. `vooda.svc`)",
                "Confirm the password is current — ServiceNow accounts can have rotation policies",
                "Check the user has the `web_service_admin` role (or equivalent) — REST API access is gated on it",
            ],
            doc_anchor="/docs?section=sources&provider=servicenow#auth",
            http_status=http_status,
            provider_code="invalid_credentials",
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 403: ACL ───────────────────────────────────────────────────
    if http_status == 403:
        return IntegrationError(
            code="servicenow.permission.no_acl",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="User lacks ACL for this table",
            summary=(
                "ServiceNow authenticated the user but the table-level ACL "
                "doesn't permit read."
            ),
            fix_steps=[
                "Confirm the user has a role that grants read on the target table (e.g. `itil` for Incident, `change_manager` for change_request)",
                "Open ServiceNow → System Security → Access Control (ACL) and verify the rule",
            ],
            doc_anchor="/docs?section=sources&provider=servicenow#acl",
            http_status=http_status,
            provider_code="forbidden",
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 404 ────────────────────────────────────────────────────────
    if http_status == 404:
        return IntegrationError(
            code="servicenow.not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="ServiceNow returned 404",
            summary="The instance URL or table name is wrong.",
            fix_steps=[
                "Verify instance URL is `https://<your-instance>.service-now.com` (no trailing path)",
                "Verify the table names in your scan config exist in the org (e.g. incident, change_request)",
            ],
            http_status=http_status,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 400 ────────────────────────────────────────────────────────
    if http_status == 400:
        return IntegrationError(
            code="servicenow.validation_error",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="ServiceNow rejected the request",
            summary=message or "ServiceNow returned 400 — the query parameters were malformed.",
            fix_steps=[
                "Check the sysparm_query / sysparm_fields shape in ServiceNow's REST API docs",
                "If this only happens for specific items, file a bug",
            ],
            http_status=http_status,
            raw=_raw(response, body),
            context=ctx,
        )

    if 500 <= http_status < 600:
        return IntegrationError(
            code="servicenow.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="ServiceNow server error",
            summary=f"ServiceNow returned {http_status}.",
            fix_steps=["Retry — most 5xx are transient", "If persistent, contact your ServiceNow admin"],
            http_status=http_status,
            raw=_raw(response, body),
            context=ctx,
        )

    return IntegrationError(
        code="servicenow.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title="ServiceNow error",
        summary=message or f"ServiceNow returned {http_status}.",
        fix_steps=["Retry once", "Check the instance status"],
        http_status=http_status,
        raw=_raw(response, body),
        context=ctx,
    )
