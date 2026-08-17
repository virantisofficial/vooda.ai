# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Salesforce REST + OAuth error classifier.

Salesforce has TWO error envelopes:

  1. OAuth token endpoint (POST /services/oauth2/token)::

         { "error": "invalid_client", "error_description": "..." }

     Form-encoded fields, lowercase error codes (RFC 6749 + Salesforce
     extensions).  Distinct because token failures need different fix
     steps from REST failures (Connected App config vs. permission).

  2. REST API (GET/POST /services/data/...)::

         [
           { "errorCode": "INVALID_SESSION_ID",
             "message": "Session expired or invalid" }
         ]

     ARRAY at the top level (uncommon shape) — Salesforce always
     returns an array even for a single error.

Auth-flow gotcha: Salesforce username-password flow requires the
*security token* concatenated to the password.  When customers
forget that, the token endpoint returns
``invalid_grant: authentication failure``.  We surface this as
the top fix step.

Diagnostic header:

  - Salesforce uses Sforce-Limit-Info on data API responses (per-org
    daily limits).  No per-request trace ID is documented for cloud
    REST — the org's Setup → Logs is the closest equivalent.

Error classes covered:

  salesforce.auth.invalid_client          OAuth invalid_client
  salesforce.auth.invalid_grant_creds     OAuth invalid_grant + auth-failure
  salesforce.auth.invalid_grant_security  invalid_grant — security token forgotten / IP not whitelisted
  salesforce.auth.session_expired         REST INVALID_SESSION_ID
  salesforce.permission.insufficient      REST INSUFFICIENT_ACCESS / API_DISABLED_FOR_ORG
  salesforce.not_found                    REST NOT_FOUND / 404
  salesforce.rate_limited                 REQUEST_LIMIT_EXCEEDED / 429
  salesforce.invalid_query                REST INVALID_QUERY_LOCATOR / MALFORMED_QUERY
  salesforce.provider_fault               5xx
  salesforce.unknown                      catch-all
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


def _parse_oauth(r: httpx.Response) -> tuple[str, str, dict[str, Any] | None]:
    """Token endpoint returns {error, error_description}."""
    try:
        body = r.json()
    except ValueError:
        return "", r.text[:500], None
    if not isinstance(body, dict):
        return "", "", None
    return str(body.get("error") or ""), str(body.get("error_description") or ""), body


def _parse_rest(r: httpx.Response) -> tuple[str, str, list[dict[str, Any]] | None]:
    """REST endpoint returns [{errorCode, message}, ...]."""
    try:
        body = r.json()
    except ValueError:
        return "", r.text[:500], None
    if isinstance(body, list) and body:
        first = body[0] or {}
        if isinstance(first, dict):
            return str(first.get("errorCode") or ""), str(first.get("message") or ""), body
    if isinstance(body, dict):
        # Some endpoints wrap differently
        return str(body.get("errorCode") or ""), str(body.get("message") or ""), [body]
    return "", "", None


def classify_salesforce_token_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    """Classify a failure from /services/oauth2/token (token endpoint)."""
    ctx = dict(context or {})
    err, desc, body = _parse_oauth(response)
    desc_lower = desc.lower()
    http_status = response.status_code

    if err == "invalid_client":
        return IntegrationError(
            code="salesforce.auth.invalid_client",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Connected App credentials wrong",
            summary=(
                "Salesforce returned `invalid_client`. The Connected App's "
                "consumer key or consumer secret doesn't match what Vooda sent."
            ),
            fix_steps=[
                "Open Salesforce → Setup → App Manager → your Connected App → View",
                "Copy the Consumer Key and Consumer Secret EXACTLY (no trailing whitespace)",
                "Paste them into Vooda's source config",
            ],
            doc_anchor="/docs?section=sources&provider=salesforce#connected-app",
            http_status=http_status,
            provider_code=err,
            raw=_raw(response, body),
            context=ctx,
        )

    if err == "invalid_grant" and ("security token" in desc_lower or "ip" in desc_lower):
        return IntegrationError(
            code="salesforce.auth.invalid_grant_security",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Security token / IP problem",
            summary=(
                "Salesforce rejected the login. Either the password is missing "
                "the security token, or the user's profile is enforcing IP allow-listing "
                "and the Vooda host isn't on the list."
            ),
            fix_steps=[
                "Reset the user's security token: Salesforce → Personal Settings → Reset My Security Token",
                "Append the new token to the password (e.g. `mypassXXXXXX`) and retry",
                "If your org enforces IP allow-listing, add the Vooda host's egress IP to the user's profile login range",
            ],
            doc_anchor="/docs?section=sources&provider=salesforce#security-token",
            http_status=http_status,
            provider_code=err,
            raw=_raw(response, body),
            context=ctx,
        )

    if err == "invalid_grant":
        return IntegrationError(
            code="salesforce.auth.invalid_grant_creds",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Salesforce login failed",
            summary=desc or "Salesforce returned `invalid_grant`. The username or password is wrong.",
            fix_steps=[
                "Verify the username (it's an email address)",
                "If the password recently changed, update Vooda with the new password + appended security token",
                "Confirm the user is not locked out — try logging in via the Salesforce UI to clear any prompts",
            ],
            doc_anchor="/docs?section=sources&provider=salesforce#login",
            http_status=http_status,
            provider_code=err,
            raw=_raw(response, body),
            context=ctx,
        )

    if err == "inactive_user":
        return IntegrationError(
            code="salesforce.auth.inactive_user",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Salesforce user deactivated",
            summary="The user this credential belongs to is deactivated in Salesforce.",
            fix_steps=[
                "Activate the user in Salesforce → Setup → Users",
                "Or switch Vooda to a different active integration user",
            ],
            http_status=http_status,
            provider_code=err,
            raw=_raw(response, body),
            context=ctx,
        )

    if 500 <= http_status < 600:
        return IntegrationError(
            code="salesforce.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Salesforce token endpoint error",
            summary=f"Salesforce returned {http_status} from the token endpoint.",
            fix_steps=["Retry", "If persistent, check status.salesforce.com"],
            http_status=http_status,
            raw=_raw(response, body),
            context=ctx,
        )

    return IntegrationError(
        code="salesforce.auth.unknown",
        category=ErrorCategory.AUTHENTICATION,
        severity=ErrorSeverity.ERROR,
        title="Salesforce login failed",
        summary=desc or f"Salesforce returned {err or http_status} during login.",
        fix_steps=["Re-check Connected App config", "Verify the user's password + security token"],
        http_status=http_status,
        provider_code=err,
        raw=_raw(response, body),
        context=ctx,
    )


def classify_salesforce_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    """Classify a REST API failure (post-token)."""
    ctx = dict(context or {})
    code, message, body = _parse_rest(response)
    http_status = response.status_code

    if code == "INVALID_SESSION_ID" or http_status == 401:
        return IntegrationError(
            code="salesforce.auth.session_expired",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Salesforce session expired",
            summary=(
                "The access token expired or was revoked. Vooda will normally "
                "refresh automatically — if you see this in the UI, the worker's "
                "refresh failed."
            ),
            fix_steps=[
                "Re-test the connection; Vooda will mint a new token",
                "If it keeps happening, confirm the Connected App still has API enabled",
            ],
            doc_anchor="/docs?section=sources&provider=salesforce#session",
            http_status=http_status,
            provider_code=code or "INVALID_SESSION_ID",
            raw=_raw(response, body),
            context=ctx,
        )

    if code in ("INSUFFICIENT_ACCESS", "INSUFFICIENT_ACCESS_OR_READONLY", "API_DISABLED_FOR_ORG"):
        return IntegrationError(
            code="salesforce.permission.insufficient",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Profile lacks the required access",
            summary=(
                "The user's profile doesn't grant access to this object/field, OR "
                "API access is disabled at the org level."
            ),
            fix_steps=[
                "Open Salesforce → Setup → Profiles → the user's profile → Object Settings",
                "Confirm Read access on Case / Knowledge / FeedItem (whichever is being scanned)",
                "If API_DISABLED_FOR_ORG, ask an admin to enable API access on the org",
            ],
            doc_anchor="/docs?section=sources&provider=salesforce#permissions",
            http_status=http_status,
            provider_code=code,
            raw=_raw(response, body),
            context=ctx,
        )

    if code == "REQUEST_LIMIT_EXCEEDED" or http_status == 429:
        return IntegrationError(
            code="salesforce.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="Salesforce daily API limit exhausted",
            summary="The org's daily API call quota is gone.",
            fix_steps=[
                "Wait until the daily reset (midnight org timezone)",
                "Open Salesforce → Setup → System Overview to see current API usage",
                "Consider scheduling Vooda scans during off-peak hours",
            ],
            doc_anchor="/docs?section=sources&provider=salesforce#api-limits",
            http_status=http_status,
            provider_code=code or "REQUEST_LIMIT_EXCEEDED",
            raw=_raw(response, body),
            context=ctx,
        )

    if code in ("MALFORMED_QUERY", "INVALID_QUERY_LOCATOR", "INVALID_TYPE"):
        return IntegrationError(
            code="salesforce.invalid_query",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.WARN,
            title="SOQL query rejected",
            summary=message or "Salesforce rejected the SOQL query — usually because an object isn't enabled in this org (e.g. Knowledge__kav).",
            fix_steps=[
                "If the error names Knowledge__kav, the org doesn't have Knowledge enabled — disable scan_knowledge in this source",
                "If a custom object is named, verify it exists and the user has read access",
            ],
            http_status=http_status,
            provider_code=code,
            raw=_raw(response, body),
            context=ctx,
        )

    if http_status == 404 or code == "NOT_FOUND":
        return IntegrationError(
            code="salesforce.not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Salesforce returned 404",
            summary="The record / endpoint Vooda asked for doesn't exist in this org.",
            fix_steps=["Verify the record id", "Verify the API version exists for this org"],
            http_status=http_status,
            provider_code=code,
            raw=_raw(response, body),
            context=ctx,
        )

    if 500 <= http_status < 600:
        return IntegrationError(
            code="salesforce.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Salesforce server error",
            summary=f"Salesforce returned {http_status}. This is on Salesforce's side.",
            fix_steps=["Retry", "If persistent, check status.salesforce.com"],
            http_status=http_status,
            raw=_raw(response, body),
            context=ctx,
        )

    return IntegrationError(
        code="salesforce.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title="Salesforce error",
        summary=message or f"Salesforce returned {http_status} ({code or 'no code'}).",
        fix_steps=["Check status.salesforce.com", "Retry once"],
        http_status=http_status,
        provider_code=code,
        raw=_raw(response, body),
        context=ctx,
    )
