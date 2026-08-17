# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Atlassian Cloud (Jira + Confluence) error classifier.

Maps the responses we've actually observed from Atlassian to the
shared :class:`IntegrationError` shape.  Diagnostic headers we rely on:

  - ``x-seraph-loginreason: AUTHENTICATED_FAILED``
        Returned on Basic-auth rejection — credentials wrong or revoked.

  - ``x-failure-category: FAILURE_CLIENT_AUTH_MISMATCH``
        Returned on the global ``api.atlassian.com`` and on
        site endpoints when a *scoped* API token is used against
        Basic auth (or a classic token is used with the wrong auth
        scheme).  Distinct from a wrong-credential rejection.

  - ``atl-traceid: <uuid>``
        Per-request correlation ID — copyable so support can find the
        request in Atlassian's own logs.

The set of error classes covered (in order of frequency observed):

  atlassian.auth.token_invalid              401 + AUTHENTICATED_FAILED
  atlassian.auth.scoped_token_unsupported   401 + FAILURE_CLIENT_AUTH_MISMATCH
  atlassian.permission.user_lacks_access    403 with body
  atlassian.not_found                       404 (wrong site / wrong path)
  atlassian.rate_limited                    429 + Retry-After
  atlassian.provider_fault                  5xx
  atlassian.bad_request                     400 (catch-all for malformed
                                                  request — e.g. the
                                                  pre-fix space-key bug)
  atlassian.unknown                         everything else
"""

from __future__ import annotations

from typing import Any

import httpx

from ..model import ErrorCategory, ErrorSeverity, IntegrationError
from ..redact import redact_secrets


def _trace(r: httpx.Response) -> str | None:
    return r.headers.get("atl-traceid")


def _raw(r: httpx.Response) -> dict[str, Any]:
    """Capture the verbatim provider response, redacted of secrets.

    Body is included up to 1 KB — enough for an Atlassian JSON error
    envelope, small enough to keep audit log entries lightweight.
    """
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


def classify_atlassian_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    """Convert any Atlassian error response into a structured error.

    ``context`` is propagated verbatim into the error's ``context``
    field — adapters typically pass ``{"scan_source_id": "...",
    "tenant_id": "..."}`` so the log entry has enough scope to find
    the row.
    """
    ctx = dict(context or {})
    code = response.status_code
    seraph = response.headers.get("x-seraph-loginreason", "")
    fail_cat = response.headers.get("x-failure-category", "")
    trace = _trace(response)

    # ── 401 / AUTHENTICATED_FAILED ─────────────────────────────────
    # Credentials rejected by Atlassian's auth layer.  The user-facing
    # path is "make sure the email + token are right and current"; we
    # deliberately don't speculate about *why* the token might be
    # invalid (revoked, never existed, expired) — that's between the
    # user and Atlassian, and the fix steps are the same regardless.
    if code == 401 and seraph == "AUTHENTICATED_FAILED":
        return IntegrationError(
            code="atlassian.auth.token_invalid",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Authentication failed",
            summary="Atlassian rejected the email + token combination Vooda sent.",
            fix_steps=[
                "Open id.atlassian.com → Security → API tokens and confirm the token Vooda is using is still listed",
                "If it's missing or you're unsure, click 'Create API token' (NOT 'with scopes') and paste the new value into Vooda",
                "Verify the email here matches the user's primary Atlassian profile email exactly",
            ],
            doc_anchor="/docs?section=sources#6.4.5",
            http_status=401,
            provider_code=seraph,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 401 / FAILURE_CLIENT_AUTH_MISMATCH ─────────────────────────
    # Scoped token used directly with Basic auth (or wrong auth
    # scheme).  Vooda doesn't support scoped tokens today.
    if code == 401 and fail_cat == "FAILURE_CLIENT_AUTH_MISMATCH":
        return IntegrationError(
            code="atlassian.auth.scoped_token_unsupported",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Token type not supported",
            summary=(
                "This looks like a scoped Atlassian API token. Vooda only accepts "
                "classic tokens — scoped tokens require the OAuth 2.0 (3LO) flow we "
                "don't support yet."
            ),
            fix_steps=[
                "At id.atlassian.com → Security → API tokens, revoke the scoped token",
                "Click 'Create API token' (the simpler button, not 'with scopes')",
                "Paste the new classic token here — it should look like ATATT3xFf…=XXXXXXXX",
            ],
            doc_anchor="/docs?section=sources#6.4",
            http_status=401,
            provider_code=fail_cat,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 401 / AUTHENTICATION_DENIED (CAPTCHA / login lock) ───────
    # Triggered when the same account fails Atlassian's web login
    # repeatedly enough that the security layer trips a CAPTCHA.
    # API calls from that account are blocked until a human signs in
    # via the web UI and clears the prompt — Vooda can't retry past
    # this on its own.
    if code == 401 and seraph in ("AUTHENTICATION_DENIED", "LOGIN_BLOCKED"):
        return IntegrationError(
            code="atlassian.auth.captcha_locked",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Account locked by Atlassian",
            summary=(
                "Atlassian is blocking API access for this account because of "
                "repeated failed logins (CAPTCHA / login-lock). Vooda can't bypass "
                "this; a human has to clear it via the web UI."
            ),
            fix_steps=[
                "Open id.atlassian.com or your Atlassian site in a browser",
                "Sign in as the locked account and complete any CAPTCHA / 2FA prompts",
                "Once the web session works, retry Test Connection here",
            ],
            doc_anchor="/docs?section=sources#6.4.5",
            http_status=401,
            provider_code=seraph,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 401 / OUT_OF_SERVICE (account disabled) ──────────────────
    # Distinct from "credentials wrong" — the user account itself
    # has been deactivated by an Atlassian admin.  Token regeneration
    # won't help; an admin has to re-enable the account.
    if code == 401 and seraph == "OUT_OF_SERVICE":
        return IntegrationError(
            code="atlassian.auth.user_disabled",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Atlassian account disabled",
            summary=(
                "The Atlassian user that issued this token has been deactivated. "
                "Generating a new token won't help — only an Atlassian admin can "
                "re-enable the account."
            ),
            fix_steps=[
                "Ask an Atlassian admin to re-activate the user at admin.atlassian.com → Directory → Users",
                "Or switch to a different service-account user that's still active",
                "Once re-activated, generate a fresh classic API token and update Vooda",
            ],
            doc_anchor="/docs?section=sources#6.4.1",
            http_status=401,
            provider_code=seraph,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 401 / generic ──────────────────────────────────────────────
    if code == 401:
        return IntegrationError(
            code="atlassian.auth.unknown",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Authentication failed",
            summary="Atlassian rejected the credentials but didn't say why specifically.",
            fix_steps=[
                "Verify the email and token are correct and belong to the same user",
                "Generate a fresh classic API token and try again",
            ],
            doc_anchor="/docs?section=sources#6.4.5",
            http_status=401,
            provider_code=seraph or fail_cat or None,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 403 — permission missing on the resource ──────────────────
    if code == 403:
        # Try to surface Atlassian's specific message ("You don't
        # have permission to view this space") if present in body.
        provider_msg = ""
        try:
            j = response.json()
            provider_msg = (j.get("message") or "").strip()
        except ValueError:
            pass
        return IntegrationError(
            code="atlassian.permission.user_lacks_access",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Permission denied",
            summary=(
                "Authentication worked, but the Atlassian user lacks permission for "
                "the requested resource."
                + (f" Provider says: {provider_msg[:200]}" if provider_msg else "")
            ),
            fix_steps=[
                "For Confluence: ask a space admin to add the user as a Viewer on the target space",
                "For Jira: ask a project admin to grant 'Browse Projects' permission on the target project",
                "Confirm the user has the 'Use Confluence' / 'Use Jira' global permission",
            ],
            doc_anchor="/docs?section=sources#6.4.2",
            http_status=403,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 404 — wrong site URL or wrong path ────────────────────────
    if code == 404:
        return IntegrationError(
            code="atlassian.not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Atlassian returned 404",
            summary="Atlassian returned 404 for the workspace + token combination Vooda used.",
            fix_steps=[
                "Verify the workspace URL: it should look like https://acme.atlassian.net (no trailing slash, no /wiki path, no /jira path)",
                "If the URL is correct, generate a fresh classic API token at id.atlassian.com → Security → API tokens and retry",
                "If a fresh token still returns 404, confirm the Atlassian account has Confluence access — Jira-only accounts can't read Confluence",
            ],
            doc_anchor="/docs?section=sources#6.4.3",
            http_status=404,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 410 Gone — archived space / deleted project ──────────────
    # Atlassian returns 410 for resources that existed but have been
    # archived (Confluence space → archive, Jira project → trash).
    # The credential is fine; the *target* doesn't exist any more.
    # Generic 404 guidance ("check your URL") would be misleading.
    if code == 410:
        return IntegrationError(
            code="atlassian.archived_space",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.WARN,
            title="Resource archived",
            summary=(
                "The Confluence space or Jira project you're trying to scan has "
                "been archived or deleted. Auth is fine — there's just nothing "
                "to scan at that path any more."
            ),
            fix_steps=[
                "If this is a single archived space, remove it from the source's space filter",
                "If you genuinely need to scan it, ask an Atlassian admin to restore the space first",
            ],
            doc_anchor="/docs?section=sources#6.4",
            http_status=410,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 413 Payload Too Large — oversized attachment ─────────────
    # Confluence/Jira will sometimes serve attachments larger than
    # Atlassian's per-response cap.  Affects only the attachment
    # download path (page-body fetches stay small).
    if code == 413:
        return IntegrationError(
            code="atlassian.payload_too_large",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.WARN,
            title="Atlassian response too large",
            summary=(
                "Atlassian rejected the request because the response would exceed "
                "their per-call size cap. Almost always an oversized attachment."
            ),
            fix_steps=[
                "Lower the per-attachment scan size cap, or",
                "Add a path-glob exclude for the attachment that triggered this",
                "Vooda continues scanning the rest of the source; this is only the one item",
            ],
            doc_anchor="/docs?section=sources#6.4",
            http_status=413,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 422 Validation — malformed body on a write endpoint ──────
    # Vooda's Atlassian adapter is read-only today, so 422s are a
    # symptom of a Vooda bug rather than a customer-fixable issue.
    # Future write-paths (auto-PR, ticket creation) will hit this
    # legitimately, so we classify it now.
    if code == 422:
        provider_msg = ""
        try:
            j = response.json()
            provider_msg = (j.get("message") or "").strip()
        except ValueError:
            pass
        return IntegrationError(
            code="atlassian.validation_error",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Atlassian rejected the request body",
            summary=(
                "Atlassian returned 422 — the request body failed validation. "
                "This is almost always a Vooda issue, not a customer one."
                + (f" Provider says: {provider_msg[:200]}" if provider_msg else "")
            ),
            fix_steps=[
                "Retry — if it persists, this is a Vooda bug",
                "Copy the trace ID from the details and contact support",
            ],
            doc_anchor="/docs?section=sources#6.4.5",
            http_status=422,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 429 — rate limited ────────────────────────────────────────
    if code == 429:
        retry = response.headers.get("retry-after")
        retry_s = int(retry) if retry and retry.isdigit() else None
        return IntegrationError(
            code="atlassian.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="Rate limited",
            summary="Atlassian returned 429. Vooda will retry automatically.",
            fix_steps=[
                "No action required — Vooda backs off and retries",
                "If this persists, lower the source's scan schedule (e.g. daily → weekly)",
            ],
            doc_anchor="/docs?section=sources",
            http_status=429,
            trace_id=trace,
            retry_after_s=retry_s,
            raw=_raw(response),
            context=ctx,
        )

    # ── 5xx — provider fault ──────────────────────────────────────
    if 500 <= code < 600:
        return IntegrationError(
            code="atlassian.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.WARN,
            title="Atlassian is having trouble",
            summary=f"Atlassian returned {code}. This is on their side, not yours.",
            fix_steps=[
                "Check status.atlassian.com",
                "Retry in a few minutes",
            ],
            http_status=code,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 400 — bad request (e.g. our pre-fix space-key bug) ────────
    if code == 400:
        return IntegrationError(
            code="atlassian.bad_request",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Atlassian rejected the request",
            summary="Atlassian returned 400. Likely an internal Vooda issue (malformed request).",
            fix_steps=[
                "Retry — if it persists, this is a Vooda bug",
                "Copy the trace ID from the details and contact support",
            ],
            doc_anchor="/docs?section=sources#6.4.5",
            http_status=400,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── Catch-all ────────────────────────────────────────────────
    return IntegrationError(
        code="atlassian.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title="Atlassian error",
        summary=f"Atlassian returned {code}.",
        fix_steps=[
            "Retry — if it persists, copy the trace ID and contact support",
        ],
        http_status=code,
        trace_id=trace,
        raw=_raw(response),
        context=ctx,
    )
