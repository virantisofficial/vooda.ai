# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""GitHub REST API error classifier.

Used by every adapter that talks to api.github.com (github_issues,
cicd_logs.github_actions, plus repository scanning paths that route
through the GitHub API rather than git over SSH).

Diagnostic headers we rely on:

  - ``X-GitHub-Request-Id: <id>``
        Per-request correlation ID. Echoed in GitHub's internal logs
        — copyable for support tickets and exact-issue lookup.

  - ``X-RateLimit-Remaining: 0`` + ``X-RateLimit-Reset: <epoch>``
        GitHub's rate-limit signal.  Distinct from "abuse-detection"
        rate-limit which uses ``Retry-After`` instead.

  - ``X-RateLimit-Resource: <bucket>``
        Names the specific quota bucket that was exhausted (core,
        search, graphql, …) — useful for diagnosing which call type
        is the noisy one.

GitHub error envelope (when present)::

    {
      "message": "Bad credentials",
      "documentation_url": "https://docs.github.com/...",
      "status": "401"
    }

The ``message`` field is short and stable enough to use for
sub-classification — GitHub doesn't change these strings often, and
when they do they ship the change with a changelog entry.

Error classes covered:

  github.auth.token_invalid                401 + "Bad credentials"
  github.auth.token_expired                401 + "expired" hint
  github.permission.missing_scope          403 + "Resource not accessible"
  github.permission.sso_required           403 + "saml-consumer-pending" hint
  github.not_found                         404
  github.rate_limited                      403/429 + X-RateLimit-Remaining: 0
  github.abuse_detection                   403 + "abuse" hint + Retry-After
  github.payload_too_large                 413
  github.validation_failed                 422 (request payload rejected)
  github.provider_fault                    5xx
  github.unknown                           catch-all
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from ..model import ErrorCategory, ErrorSeverity, IntegrationError
from ..redact import redact_secrets


def _trace(r: httpx.Response) -> str | None:
    return r.headers.get("X-GitHub-Request-Id") or r.headers.get("x-github-request-id")


def _raw(r: httpx.Response) -> dict[str, Any]:
    """Redacted-response snapshot, mirrors the atlassian classifier shape."""
    body: Any
    try:
        body = r.json()
    except ValueError:
        body = r.text[:1000]
    return redact_secrets(
        {
            "headers": dict(r.headers),
            "status": r.status_code,
            "body": body,
            "request_url": str(r.request.url) if r.request else None,
        }
    )  # type: ignore[return-value]


def _msg(r: httpx.Response) -> str:
    """Pull GitHub's `message` field from a JSON envelope when present."""
    try:
        body = r.json()
    except ValueError:
        return ""
    if isinstance(body, dict):
        return str(body.get("message") or "")
    return ""


def _retry_after_seconds(r: httpx.Response) -> int | None:
    """Compute back-off seconds from Retry-After OR X-RateLimit-Reset.

    GitHub puts the reset on a different header for primary rate
    limits.  We accept both so callers don't have to special-case.
    """
    ra = r.headers.get("Retry-After") or r.headers.get("retry-after")
    if ra:
        try:
            return int(ra)
        except ValueError:
            return None
    reset = r.headers.get("X-RateLimit-Reset") or r.headers.get("x-ratelimit-reset")
    if reset:
        try:
            wait = int(reset) - int(time.time())
            return max(wait, 0)
        except ValueError:
            return None
    return None


def classify_github_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    """Convert a GitHub error response into an :class:`IntegrationError`.

    Order of checks matters: rate-limit / abuse before generic 403,
    SSO before generic 403, scope before generic 403; specific 401
    flavours before the catch-all.
    """
    ctx = dict(context or {})
    code = response.status_code
    msg = _msg(response).lower()
    trace = _trace(response)

    # ── Rate limit (primary): 403 + X-RateLimit-Remaining: 0 ───────
    # GitHub returns 403 (not 429) for primary rate limit hits.  The
    # X-RateLimit-Remaining: 0 + X-RateLimit-Reset header pair is the
    # signal — distinct from a permission-denied 403 which has the
    # remaining count > 0.
    remaining = response.headers.get("X-RateLimit-Remaining") or response.headers.get("x-ratelimit-remaining")
    if code in (403, 429) and remaining == "0":
        retry = _retry_after_seconds(response)
        bucket = response.headers.get("X-RateLimit-Resource") or response.headers.get("x-ratelimit-resource") or "core"
        return IntegrationError(
            code="github.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="GitHub rate-limited the request",
            summary=(
                f"The '{bucket}' quota for this token is exhausted. "
                "GitHub will accept new requests once the window resets."
            ),
            fix_steps=[
                f"Wait {retry}s and retry" if retry else "Wait until the X-RateLimit-Reset timestamp and retry",
                "If this is hitting often, generate a separate token for Vooda so it has its own per-token bucket",
                "Confirm Vooda isn't sharing a token with another tool — shared tokens share quota",
            ],
            doc_anchor="/docs?section=sources&provider=github#rate-limit",
            http_status=code,
            provider_code=f"rate_limit:{bucket}",
            retry_after_s=retry,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── Abuse / secondary rate limit: 403 + "abuse" / "secondary" ──
    # Triggered by very high request bursts even when primary quota
    # is fine.  Retry-After is mandatory on this path per GitHub docs.
    if code == 403 and ("abuse" in msg or "secondary rate limit" in msg):
        retry = _retry_after_seconds(response)
        return IntegrationError(
            code="github.abuse_detection",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="GitHub abuse-detection limit hit",
            summary=(
                "GitHub's abuse-detection system flagged the call rate as too high. "
                "This is a secondary limit — separate from the per-hour quota."
            ),
            fix_steps=[
                f"Wait {retry}s before retrying" if retry else "Wait at least 60s before retrying",
                "Reduce per-second concurrency on this scan source",
                "If this happens repeatedly, GitHub recommends contacting them to whitelist the integration",
            ],
            doc_anchor="/docs?section=sources&provider=github#abuse",
            http_status=403,
            provider_code="abuse",
            retry_after_s=retry,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 401: bad credentials ───────────────────────────────────────
    if code == 401:
        if "expired" in msg:
            return IntegrationError(
                code="github.auth.token_expired",
                category=ErrorCategory.AUTHENTICATION,
                severity=ErrorSeverity.ERROR,
                title="GitHub token expired",
                summary="The personal access token has expired. GitHub fine-grained tokens have a hard expiry; classic tokens expire if you set one.",
                fix_steps=[
                    "Open github.com → Settings → Developer settings → Personal access tokens",
                    "Regenerate the token (or create a new one) and update the credentials in Vooda",
                    "Consider extending the expiry window if your security policy permits",
                ],
                doc_anchor="/docs?section=sources&provider=github#token",
                http_status=401,
                provider_code="bad_credentials",
                trace_id=trace,
                raw=_raw(response),
                context=ctx,
            )
        return IntegrationError(
            code="github.auth.token_invalid",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="GitHub rejected the token",
            summary=(
                "GitHub returned 401 Bad Credentials. Either the token is wrong, "
                "revoked, or doesn't belong to the org/user it's being used against."
            ),
            fix_steps=[
                "Confirm the token is still listed at github.com → Settings → Developer settings → Personal access tokens",
                "If using a fine-grained token, confirm it was issued for the org / repo you're scanning",
                "If you're unsure of the token state, generate a new one and paste it into Vooda",
            ],
            doc_anchor="/docs?section=sources&provider=github#token",
            http_status=401,
            provider_code="bad_credentials",
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 403: SSO required ──────────────────────────────────────────
    # Org has SAML SSO enforced and the token hasn't been authorized
    # for that org.  Specific fix is one click in the token settings.
    if code == 403 and ("saml" in msg or "sso" in msg or "single sign-on" in msg):
        return IntegrationError(
            code="github.permission.sso_required",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Token needs SSO authorization",
            summary=(
                "The org enforces SAML SSO and this token hasn't been authorized "
                "for it. GitHub blocks the call until you click 'Authorize' in the "
                "token settings."
            ),
            fix_steps=[
                "Open github.com → Settings → Developer settings → Personal access tokens",
                "Click the token name → 'Configure SSO' → 'Authorize' for the target org",
                "Retry the scan",
            ],
            doc_anchor="/docs?section=sources&provider=github#sso",
            http_status=403,
            provider_code="saml_sso",
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 403: missing scope / resource not accessible ───────────────
    if code == 403:
        return IntegrationError(
            code="github.permission.missing_scope",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Token lacks the required scope",
            summary=(
                "GitHub authenticated the token but it doesn't carry the scopes "
                "needed for this call. Most common cause for issue scanning: missing "
                "`repo` (private repos) or `read:org`."
            ),
            fix_steps=[
                "Open github.com → Settings → Developer settings → Personal access tokens",
                "Edit the token and add `repo` (and `read:org` if scanning org-private repos)",
                "If using a fine-grained token, edit Repository access + Permissions → Issues: Read",
            ],
            doc_anchor="/docs?section=sources&provider=github#scopes",
            http_status=403,
            provider_code="missing_scope",
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 404: not found / hidden by permissions ─────────────────────
    if code == 404:
        return IntegrationError(
            code="github.not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="GitHub returned 404 for this resource",
            summary=(
                "Either the repo / user / org doesn't exist, or the token can't see "
                "it.  GitHub deliberately returns 404 instead of 403 for private "
                "resources it doesn't think you should know about."
            ),
            fix_steps=[
                "Verify the repo path is `owner/repo` exactly as it appears in the URL",
                "If the repo is private, confirm the token has `repo` scope and (for org repos) is SSO-authorized",
                "If you're using a fine-grained token, confirm the repo is in its allowed list",
            ],
            doc_anchor="/docs?section=sources&provider=github#404",
            http_status=404,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 413: payload too large ─────────────────────────────────────
    if code == 413:
        return IntegrationError(
            code="github.payload_too_large",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Request payload too large",
            summary="GitHub rejected the request body for exceeding the size cap.",
            fix_steps=[
                "Reduce the per-page size in your scan settings",
                "If sending a comment / issue body, trim to under 65 KB",
            ],
            http_status=413,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 422: validation failed ─────────────────────────────────────
    if code == 422:
        return IntegrationError(
            code="github.validation_failed",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="GitHub rejected the request body",
            summary="The request payload was syntactically OK but failed GitHub's validation rules.",
            fix_steps=[
                "Check the request body against GitHub's API docs",
                "If this only happens for specific items, file a bug — Vooda may be sending a malformed payload",
            ],
            http_status=422,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 5xx: provider fault ────────────────────────────────────────
    if 500 <= code < 600:
        return IntegrationError(
            code="github.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="GitHub error",
            summary=f"GitHub returned {code}. This is on GitHub's side.",
            fix_steps=[
                "Retry — most 5xx errors are transient",
                "If persistent, check the GitHub status page at githubstatus.com",
            ],
            http_status=code,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── Catch-all ──────────────────────────────────────────────────
    return IntegrationError(
        code="github.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title="GitHub error",
        summary=f"GitHub returned {code}.",
        fix_steps=["Check the GitHub status page", "Retry once"],
        http_status=code,
        trace_id=trace,
        raw=_raw(response),
        context=ctx,
    )
