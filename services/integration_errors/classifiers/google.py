# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Google APIs error classifier (Drive, Workspace, GCP).

Every Google API uses the same JSON error envelope::

    {
      "error": {
        "code": 403,
        "message": "Insufficient permission",
        "errors": [
          { "domain": "global", "reason": "insufficientPermissions",
            "message": "..." }
        ],
        "status": "PERMISSION_DENIED"
      }
    }

The ``error.errors[0].reason`` field is the most useful classifier
input — it's a short, stable, machine-readable code (Google has
documented the full set in the Cloud-side error reference).

Diagnostic header:

  - ``X-GUploader-UploadID`` / ``X-Goog-Trace-Id`` — request trace
    correlation; rendered in Google's own logs.

Most actionable distinct cases for credential-style scanning:

  - ``authError``                 token wrong / expired
  - ``insufficientPermissions``   token OK, scope missing
  - ``forbidden``                 admin-disabled API or quota project denied
  - ``notFound``                  fileId / driveId doesn't exist
  - ``rateLimitExceeded``         per-second user-rate quota
  - ``userRateLimitExceeded``     per-second user-quota
  - ``quotaExceeded``             daily quota gone
  - ``invalid``                   request payload bad
  - ``backendError``              Google-side 5xx
  - ``serviceDisabled``           project hasn't enabled the API

Most common service-account-flow gotcha: the SA hasn't had
domain-wide delegation set up, so it can read its own files but not
files in user drives.  Surfaced as a specific fix.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..model import ErrorCategory, ErrorSeverity, IntegrationError
from ..redact import redact_secrets


def _trace(r: httpx.Response) -> str | None:
    return (
        r.headers.get("X-Goog-Trace-Id")
        or r.headers.get("x-goog-trace-id")
        or r.headers.get("X-GUploader-UploadID")
    )


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
    """Return (reason, message, body) — reason from errors[0], message from top-level."""
    try:
        body = r.json()
    except ValueError:
        return "", r.text[:500], None
    if not isinstance(body, dict):
        return "", "", None
    err = body.get("error")
    if not isinstance(err, dict):
        return "", "", body
    message = str(err.get("message") or "")
    reason = ""
    errs = err.get("errors")
    if isinstance(errs, list) and errs:
        first = errs[0]
        if isinstance(first, dict):
            reason = str(first.get("reason") or "")
    return reason, message, body


def classify_google_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    ctx = dict(context or {})
    reason, message, body = _parse(response)
    http_status = response.status_code
    trace = _trace(response)

    # ── 401 + authError: token rejected ────────────────────────────
    if http_status == 401 or reason == "authError":
        return IntegrationError(
            code="google.auth.invalid_token",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Google rejected the credentials",
            summary=(
                "Google returned 401. Either the access token expired, the service "
                "account key is wrong/revoked, or the OAuth client is misconfigured."
            ),
            fix_steps=[
                "If using a service account, regenerate the JSON key in Google Cloud → IAM → Service Accounts → Keys",
                "If using OAuth, refresh the access token (Vooda's worker should do this automatically)",
                "Confirm the service-account email is the one shared with the resource",
            ],
            doc_anchor="/docs?section=sources&provider=google#auth",
            http_status=http_status,
            provider_code=reason or "auth_error",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 429 / rate / quota errors ──────────────────────────────────
    if http_status == 429 or reason in ("rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded"):
        ra = response.headers.get("Retry-After") or response.headers.get("retry-after")
        try:
            retry = int(ra) if ra else None
        except ValueError:
            retry = None
        is_daily = reason == "quotaExceeded"
        return IntegrationError(
            code="google.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="Google quota exhausted" if is_daily else "Google rate-limited the request",
            summary=(
                "The daily quota for this Cloud project is gone — wait until midnight Pacific time."
                if is_daily else
                "Google's per-second user quota was hit. Vooda will back off and retry."
            ),
            fix_steps=(
                [
                    "Open Google Cloud Console → APIs & Services → Quotas",
                    "Find the quota that's at 100% and request an increase, or",
                    "Wait until the daily reset (00:00 Pacific time)",
                ] if is_daily else [
                    f"Wait {retry}s and retry" if retry else "Vooda will back off automatically",
                    "If this happens repeatedly, lower scan concurrency for this source",
                ]
            ),
            doc_anchor="/docs?section=sources&provider=google#quota",
            http_status=http_status,
            provider_code=reason or "rate_limited",
            retry_after_s=retry,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 403: scope / admin / SA delegation ─────────────────────────
    if reason == "insufficientPermissions":
        return IntegrationError(
            code="google.permission.missing_scope",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Service account lacks the required scope",
            summary=(
                "The credentials authenticated, but the OAuth scope (or domain-wide "
                "delegation grant) doesn't permit this call."
            ),
            fix_steps=[
                "If using a service account, confirm domain-wide delegation is configured at admin.google.com → Security → API controls → Domain-wide delegation",
                "Add the required scope (e.g. https://www.googleapis.com/auth/drive.readonly) to the SA's delegation entry",
                "Wait a few minutes for the change to propagate, then retry",
            ],
            doc_anchor="/docs?section=sources&provider=google#scopes",
            http_status=http_status,
            provider_code=reason,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if reason == "serviceDisabled":
        return IntegrationError(
            code="google.permission.api_disabled",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="API not enabled for this project",
            summary=(
                "The Google Cloud project hasn't enabled the API this call uses "
                "(e.g. Drive API, Admin SDK)."
            ),
            fix_steps=[
                "Open Google Cloud Console → APIs & Services → Library",
                "Search for the API named in the error message and click Enable",
                "Retry — it can take 1-2 minutes to propagate",
            ],
            doc_anchor="/docs?section=sources&provider=google#enable-api",
            http_status=http_status,
            provider_code=reason,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if http_status == 403 or reason in ("forbidden", "domainPolicy"):
        return IntegrationError(
            code="google.permission.forbidden",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Google denied access",
            summary=message or "Google returned 403. Either the resource isn't shared with this service account, or admin policy blocks it.",
            fix_steps=[
                "Confirm the resource is shared with the service-account email",
                "If admin policy blocks third-party apps, ask the workspace admin to allow-list Vooda's app",
            ],
            http_status=http_status,
            provider_code=reason or "forbidden",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 404: not found ─────────────────────────────────────────────
    if http_status == 404 or reason == "notFound":
        return IntegrationError(
            code="google.not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Google returned 404",
            summary=(
                "The fileId / folderId / driveId Vooda used doesn't exist or isn't "
                "visible to this service account."
            ),
            fix_steps=[
                "Verify the ID was copied correctly from the resource's URL",
                "Confirm the resource is shared with the service-account email",
            ],
            http_status=http_status,
            provider_code=reason or "not_found",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 400: invalid / validation ──────────────────────────────────
    if http_status == 400 or reason == "invalid":
        return IntegrationError(
            code="google.validation_error",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Google rejected the request body",
            summary=message or "Google returned 400. The query, body, or parameter shape is wrong.",
            fix_steps=[
                "Check the request shape against the Google API reference",
                "If this only happens on specific items, file a bug — Vooda may be malforming the request",
            ],
            http_status=http_status,
            provider_code=reason or "invalid",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 5xx ────────────────────────────────────────────────────────
    if 500 <= http_status < 600 or reason == "backendError":
        return IntegrationError(
            code="google.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Google server error",
            summary=f"Google returned {http_status}. This is on Google's side.",
            fix_steps=[
                "Retry — Google 5xx responses are usually transient",
                "If persistent, check status.cloud.google.com",
            ],
            http_status=http_status,
            provider_code=reason or "backend_error",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    return IntegrationError(
        code="google.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title="Google error",
        summary=message or f"Google returned {http_status}.",
        fix_steps=["Check the Google API reference for this status", "Retry once"],
        http_status=http_status,
        provider_code=reason,
        trace_id=trace,
        raw=_raw(response, body),
        context=ctx,
    )
