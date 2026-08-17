# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Slack Web API error classifier.

Slack is the awkward one in the lineup — every Web API call returns
HTTP 200, even on logical errors.  The success/failure signal lives
in the body::

    { "ok": true, "result": ... }                  # success
    { "ok": false, "error": "invalid_auth", ... }  # failure

So adapters can't classify by status code alone; they parse the body
first and then call this classifier with the parsed dict.

The dispatch interface is therefore different from the HTTP-based
classifiers — we accept a parsed dict (or a httpx.Response) and the
Slack ``error`` string.

Diagnostic header we rely on:

  - ``X-Slack-Req-Id: <id>``   per-request correlation, copyable for support
  - ``Retry-After``            on rate-limit responses (429 — Slack DOES
                                 use 429 for ratelimited, the one place
                                 a real status code carries the signal)

Slack error strings we cover (most common ones from production
observation across Slack-Bolt and other major SDKs):

  slack.auth.invalid_token             "invalid_auth" / "token_revoked"
  slack.auth.token_expired             "token_expired"
  slack.auth.account_inactive          "account_inactive"
  slack.permission.missing_scope       "missing_scope" / "no_permission"
  slack.permission.not_in_channel      "not_in_channel" / "channel_not_found"
  slack.permission.is_archived         "is_archived"
  slack.rate_limited                   429 OR "ratelimited"
  slack.user_not_found                 "user_not_found"
  slack.invalid_arguments              "invalid_arguments" / "method_not_supported_for_channel_type"
  slack.provider_fault                 "fatal_error" / "internal_error"
  slack.unknown                        catch-all for anything we haven't seen
"""

from __future__ import annotations

from typing import Any

import httpx

from ..model import ErrorCategory, ErrorSeverity, IntegrationError
from ..redact import redact_secrets


def _trace(r: httpx.Response | None) -> str | None:
    if r is None:
        return None
    return r.headers.get("X-Slack-Req-Id") or r.headers.get("x-slack-req-id")


def _raw(r: httpx.Response | None, body: dict[str, Any] | None) -> dict[str, Any]:
    headers = dict(r.headers) if r is not None else {}
    return redact_secrets(
        {
            "headers": headers,
            "status": r.status_code if r is not None else 200,
            "body": body,
            "request_url": str(r.request.url) if r is not None and r.request else None,
        }
    )  # type: ignore[return-value]


def classify_slack_error(
    body: dict[str, Any] | None,
    response: httpx.Response | None = None,
    context: dict[str, Any] | None = None,
) -> IntegrationError:
    """Convert a Slack non-OK body (or 429/5xx response) to a structured error.

    Adapters call this AFTER they've checked ``body.get("ok") is False``
    or after observing a non-200 HTTP status (Slack's only non-200
    response is 429).
    """
    ctx = dict(context or {})
    body = body or {}
    err = str(body.get("error") or "").lower()
    trace = _trace(response)
    http_status = response.status_code if response is not None else 200

    # ── Real HTTP 429 (the one place Slack uses status codes) ──────
    if http_status == 429 or err == "ratelimited":
        retry = None
        if response is not None:
            ra = response.headers.get("Retry-After") or response.headers.get("retry-after")
            try:
                retry = int(ra) if ra else None
            except ValueError:
                retry = None
        return IntegrationError(
            code="slack.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="Slack rate-limited the request",
            summary=(
                "Slack throttled this token. Slack's per-method rate limits are "
                "tier-based — search calls are stricter than message reads."
            ),
            fix_steps=[
                f"Wait {retry}s and retry" if retry else "Wait at least 60s and retry",
                "If this happens repeatedly, lower the per-channel scan concurrency",
                "Consider scoping the channel filter so fewer parallel reads run per scan",
            ],
            doc_anchor="/docs?section=sources&provider=slack#rate-limit",
            http_status=http_status,
            provider_code="ratelimited",
            retry_after_s=retry,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── Auth failures ──────────────────────────────────────────────
    if err in ("invalid_auth", "not_authed", "token_revoked"):
        return IntegrationError(
            code="slack.auth.invalid_token",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Slack rejected the bot token",
            summary=(
                "Slack returned `invalid_auth`. The token is wrong, revoked, or "
                "the app it belongs to was uninstalled from the workspace."
            ),
            fix_steps=[
                "Open api.slack.com/apps → your app → OAuth & Permissions",
                "Confirm the bot token matches the value pasted into Vooda (it starts with `xoxb-`)",
                "If the app was uninstalled, reinstall it to the workspace and use the new bot token",
            ],
            doc_anchor="/docs?section=sources&provider=slack#token",
            http_status=http_status,
            provider_code=err,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if err == "token_expired":
        return IntegrationError(
            code="slack.auth.token_expired",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Slack token expired",
            summary="The bot token has expired (Slack now supports rotating tokens; this one's window is up).",
            fix_steps=[
                "If you're using rotating tokens, the worker should refresh — file a bug if it didn't",
                "Otherwise, regenerate the bot token in api.slack.com/apps and update Vooda",
            ],
            doc_anchor="/docs?section=sources&provider=slack#token",
            http_status=http_status,
            provider_code=err,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if err == "account_inactive":
        return IntegrationError(
            code="slack.auth.account_inactive",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Slack workspace deactivated",
            summary="The workspace this token belongs to was deactivated or deleted.",
            fix_steps=[
                "Confirm the workspace is still active",
                "If the workspace was migrated, reinstall the Vooda app to the new workspace",
            ],
            http_status=http_status,
            provider_code=err,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── Permission / scope failures ────────────────────────────────
    if err in ("missing_scope", "no_permission", "not_allowed_token_type"):
        needed = body.get("needed") or ""
        provided = body.get("provided") or ""
        return IntegrationError(
            code="slack.permission.missing_scope",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Slack token lacks the required scope",
            summary=(
                f"The bot token doesn't carry the scope this call needs"
                f"{f' (needs `{needed}`, has `{provided}`)' if needed else ''}."
            ),
            fix_steps=[
                "Open api.slack.com/apps → your app → OAuth & Permissions → Scopes",
                f"Add the `{needed}` bot scope" if needed else "Add the missing scope shown in the error details",
                "Reinstall the app to the workspace so the new scopes take effect, then update Vooda with the fresh token",
            ],
            doc_anchor="/docs?section=sources&provider=slack#scopes",
            http_status=http_status,
            provider_code=err,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if err == "not_in_channel":
        channel = body.get("channel") or ""
        return IntegrationError(
            code="slack.permission.not_in_channel",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Bot is not a member of the channel",
            summary=(
                "Slack returned `not_in_channel`. Reading channel history requires "
                "the bot to be a member."
            ),
            fix_steps=[
                f"In Slack, run `/invite @your-bot` in {f'#{channel}' if channel else 'the channel'}",
                "Alternatively, narrow Vooda's channel filter so it skips channels the bot isn't on",
            ],
            doc_anchor="/docs?section=sources&provider=slack#membership",
            http_status=http_status,
            provider_code=err,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if err == "channel_not_found":
        return IntegrationError(
            code="slack.permission.not_in_channel",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Channel not visible to the bot",
            summary=(
                "Slack returned `channel_not_found`. Either the channel was deleted "
                "or the bot can't see it (private channels need explicit invite)."
            ),
            fix_steps=[
                "Confirm the channel still exists and isn't archived",
                "For private channels, invite the bot via `/invite @your-bot`",
            ],
            http_status=http_status,
            provider_code=err,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if err == "is_archived":
        return IntegrationError(
            code="slack.permission.is_archived",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.WARN,
            title="Channel is archived",
            summary="The channel is archived — Slack doesn't allow new reads against archived channels for bots.",
            fix_steps=[
                "Skip this channel in your scan filter, or",
                "Unarchive it in Slack if you need it scanned",
            ],
            http_status=http_status,
            provider_code=err,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if err == "user_not_found":
        return IntegrationError(
            code="slack.user_not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.WARN,
            title="User not found",
            summary="Slack couldn't resolve the user ID this call referenced.",
            fix_steps=["Verify the user is still in the workspace"],
            http_status=http_status,
            provider_code=err,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if err in ("invalid_arguments", "method_not_supported_for_channel_type"):
        return IntegrationError(
            code="slack.invalid_arguments",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Slack rejected the request shape",
            summary=f"Slack returned `{err}`. The request payload didn't match the API contract.",
            fix_steps=[
                "If you're scanning a DM channel, switch to a public channel — DMs need different scopes",
                "If this only happens on specific items, file a bug — Vooda may be malforming the request",
            ],
            http_status=http_status,
            provider_code=err,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if err in ("fatal_error", "internal_error"):
        return IntegrationError(
            code="slack.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Slack server error",
            summary=f"Slack returned `{err}`. This is on Slack's side.",
            fix_steps=[
                "Retry — most fatal_error responses are transient",
                "If persistent, check status.slack.com",
            ],
            http_status=http_status,
            provider_code=err,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── HTTP 5xx (rare) ────────────────────────────────────────────
    if 500 <= http_status < 600:
        return IntegrationError(
            code="slack.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Slack returned a 5xx",
            summary=f"Slack server returned HTTP {http_status}. This is on Slack's side.",
            fix_steps=["Retry", "If persistent, check status.slack.com"],
            http_status=http_status,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── Catch-all ──────────────────────────────────────────────────
    return IntegrationError(
        code="slack.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title="Slack rejected the request",
        summary=f"Slack returned `{err or 'unknown'}`.",
        fix_steps=[
            "Check the Slack API reference for this error string",
            "Retry once",
        ],
        http_status=http_status,
        provider_code=err,
        trace_id=trace,
        raw=_raw(response, body),
        context=ctx,
    )
