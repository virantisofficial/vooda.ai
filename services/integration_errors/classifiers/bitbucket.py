# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Bitbucket Cloud (api.bitbucket.org) error classifier.

Atlassian-owned but with a DIFFERENT API surface from Confluence /
Jira — different domain, different error envelope.  We keep this
classifier separate so Bitbucket-specific fix steps (app passwords,
workspace permissions, repo issues feature toggle) don't pollute
the Atlassian-cloud classifier.

Bitbucket error envelope::

    {
      "type": "error",
      "error": {
        "message": "App password authentication failed",
        "detail": "...",
        "id": "..."
      }
    }

Auth model: HTTP Basic with username + app-password (Bitbucket Cloud)
or PAT (Bitbucket Server).  App passwords are a separate concept
from regular passwords and have their own UI in Atlassian account
settings.

Diagnostic header:

  - ``X-Request-Id`` carries Bitbucket's per-request correlation id

Common gotcha: Bitbucket Cloud's per-repository "Issues" feature is
OFF by default. Repos without it return 404 on /repositories/{repo}/
issues — that's a configuration issue, not an auth issue.

Error classes covered:

  bitbucket.auth.invalid_app_password    401
  bitbucket.permission.insufficient      403
  bitbucket.repo.issues_disabled         404 on /issues path with body hint
  bitbucket.not_found                    404 (generic)
  bitbucket.rate_limited                 429
  bitbucket.validation_error             400
  bitbucket.provider_fault               5xx
  bitbucket.unknown                      catch-all
"""

from __future__ import annotations

from typing import Any

import httpx

from ..model import ErrorCategory, ErrorSeverity, IntegrationError
from ..redact import redact_secrets


def _trace(r: httpx.Response) -> str | None:
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


def _parse(r: httpx.Response) -> tuple[str, dict[str, Any] | None]:
    """Return (message, body)."""
    try:
        body = r.json()
    except ValueError:
        return r.text[:500], None
    if not isinstance(body, dict):
        return "", None
    err = body.get("error")
    if isinstance(err, dict):
        return str(err.get("message") or ""), body
    return str(body.get("message") or ""), body


def classify_bitbucket_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    ctx = dict(context or {})
    message, body = _parse(response)
    http_status = response.status_code
    trace = _trace(response)
    url = str(response.request.url) if response.request else ""

    # ── Rate limit ─────────────────────────────────────────────────
    if http_status == 429:
        ra = response.headers.get("Retry-After") or response.headers.get("retry-after")
        try:
            retry = int(ra) if ra else None
        except ValueError:
            retry = None
        return IntegrationError(
            code="bitbucket.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="Bitbucket rate-limited the request",
            summary="Bitbucket Cloud caps anonymous calls at 60/hr and authenticated calls at 1000/hr per hour.",
            fix_steps=[
                f"Wait {retry}s and retry" if retry else "Wait at least 60s and retry",
                "If this happens often, narrow the repo filter so fewer repos are scanned per cycle",
            ],
            doc_anchor="/docs?section=sources&provider=bitbucket#rate-limit",
            http_status=http_status,
            provider_code="rate_limited",
            retry_after_s=retry,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 401: bad credentials ───────────────────────────────────────
    if http_status == 401:
        return IntegrationError(
            code="bitbucket.auth.invalid_app_password",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Bitbucket rejected the credentials",
            summary=(
                "Bitbucket returned 401. Make sure you're using an *app password* "
                "(not your Atlassian account password) — they're a separate concept."
            ),
            fix_steps=[
                "Open id.atlassian.com → Profile → App passwords",
                "Click 'Create app password' and give it Repositories: Read + Issues: Read scopes",
                "Use your Atlassian *username* (not your email) and the new app password in Vooda",
            ],
            doc_anchor="/docs?section=sources&provider=bitbucket#app-password",
            http_status=http_status,
            provider_code="invalid_credentials",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 403: missing scope / permission ────────────────────────────
    if http_status == 403:
        return IntegrationError(
            code="bitbucket.permission.insufficient",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="App password lacks permission",
            summary=(
                "The credentials authenticated, but the app password doesn't carry "
                "the scope this call needs (typically Repositories: Read or Issues: Read)."
            ),
            fix_steps=[
                "Open id.atlassian.com → Profile → App passwords",
                "Edit the app password used here and tick Repositories: Read + Issues: Read",
                "If the workspace has IP allow-listing on, add the Vooda host to it",
            ],
            doc_anchor="/docs?section=sources&provider=bitbucket#scopes",
            http_status=http_status,
            provider_code="forbidden",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 404: special-case the Issues-disabled repo ─────────────────
    # Bitbucket repos have an opt-in Issues feature. Hitting
    # /repositories/{repo}/issues on a repo where it's off returns
    # 404 with a body hinting at the disabled state.
    if http_status == 404 and "/issues" in url:
        return IntegrationError(
            code="bitbucket.repo.issues_disabled",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.WARN,
            title="Issues feature not enabled on this repo",
            summary=(
                "Bitbucket repos have an opt-in Issues feature.  When it's off, "
                "the API returns 404 — there are no issues to scan."
            ),
            fix_steps=[
                "Open the repo in Bitbucket → Settings → General → Issue tracker",
                "Toggle 'This repository has issues' on if you want this repo scanned",
                "Otherwise, exclude it from the repo filter in the scan source",
            ],
            doc_anchor="/docs?section=sources&provider=bitbucket#issues-toggle",
            http_status=http_status,
            provider_code="issues_disabled",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 404: not found ─────────────────────────────────────────────
    if http_status == 404:
        return IntegrationError(
            code="bitbucket.not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Bitbucket returned 404",
            summary=(
                "The workspace, repo, or PR id doesn't exist or isn't visible to "
                "this app password."
            ),
            fix_steps=[
                "Verify the repo path is `workspace/repo` exactly as it appears in the URL",
                "If the repo is private, confirm the app password's owner is a workspace member",
            ],
            http_status=http_status,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 400: validation ────────────────────────────────────────────
    if http_status == 400:
        return IntegrationError(
            code="bitbucket.validation_error",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Bitbucket rejected the request",
            summary=message or "Bitbucket returned 400 — the request body / query was malformed.",
            fix_steps=[
                "Check the request shape against Bitbucket's API reference",
                "If this only happens on specific items, file a bug",
            ],
            http_status=http_status,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 5xx ────────────────────────────────────────────────────────
    if 500 <= http_status < 600:
        return IntegrationError(
            code="bitbucket.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Bitbucket server error",
            summary=f"Bitbucket returned {http_status}. This is on Atlassian's side.",
            fix_steps=[
                "Retry — most 5xx are transient",
                "If persistent, check status.atlassian.com",
            ],
            http_status=http_status,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    return IntegrationError(
        code="bitbucket.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title="Bitbucket error",
        summary=message or f"Bitbucket returned {http_status}.",
        fix_steps=["Check status.atlassian.com", "Retry once"],
        http_status=http_status,
        trace_id=trace,
        raw=_raw(response, body),
        context=ctx,
    )
