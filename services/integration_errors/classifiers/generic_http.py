# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Generic HTTP error classifier — for providers without distinctive
diagnostic envelopes (or where the marginal value of a per-provider
classifier doesn't justify the extra file).

Used by the long tail: asana, box, mattermost, postman, container
registry, Jenkins / CircleCI in cicd_logs, and any future small
providers we add.

The classifier interprets standard HTTP status codes (401, 403, 404,
413, 429, 5xx) into structured errors.  Adapters customise the
fix-step text per provider by passing ``fix_steps_*`` overrides —
defaults are usable but generic.

Code shape: ``{provider}.{category}`` — e.g. ``asana.auth.invalid_token``.
This keeps log filtering / dashboard slicing the same as the
dedicated classifiers.

Why a single function with provider parameterisation, instead of
N near-identical files: the actual diagnostic information for these
providers is just the status code + body message; the value-add is
the provider-specific fix-step language.  Parameterising fix steps
gives us that without N copies of the same dispatch tree.
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


def _parse(r: httpx.Response) -> tuple[str, Any]:
    """Best-effort message extraction for arbitrary providers.

    Tries common shapes in order: top-level ``message``,
    ``error.message``, ``errors[0].message``.  Falls back to text.
    """
    try:
        body = r.json()
    except ValueError:
        return r.text[:500], None
    if isinstance(body, dict):
        if isinstance(body.get("message"), str):
            return body["message"], body
        err = body.get("error")
        if isinstance(err, dict) and isinstance(err.get("message"), str):
            return err["message"], body
        if isinstance(err, str):
            return err, body
        errs = body.get("errors")
        if isinstance(errs, list) and errs:
            first = errs[0]
            if isinstance(first, dict) and isinstance(first.get("message"), str):
                return first["message"], body
    return "", body


def _retry_after(r: httpx.Response) -> int | None:
    ra = r.headers.get("Retry-After") or r.headers.get("retry-after")
    if not ra:
        return None
    try:
        return int(ra)
    except ValueError:
        return None


def classify_http_error(
    response: httpx.Response,
    *,
    provider: str,
    context: dict[str, Any] | None = None,
    auth_fix_steps: list[str] | None = None,
    permission_fix_steps: list[str] | None = None,
    not_found_fix_steps: list[str] | None = None,
    rate_limit_fix_steps: list[str] | None = None,
    doc_anchor: str | None = None,
) -> IntegrationError:
    """Classify a failure response from a HTTP provider.

    ``provider`` is used as the code prefix and in default text — pass
    the customer-recognisable name (e.g. ``"asana"``, ``"box"``).
    Optional ``*_fix_steps`` override the default 2-step fix lists for
    that error category; the defaults are always usable, just generic.
    """
    ctx = dict(context or {})
    message, body = _parse(response)
    http_status = response.status_code
    p = provider.lower()
    p_label = provider.capitalize()
    anchor = doc_anchor or f"/docs?section=sources&provider={p}"

    # ── Rate limit ─────────────────────────────────────────────────
    if http_status == 429:
        retry = _retry_after(response)
        return IntegrationError(
            code=f"{p}.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title=f"{p_label} rate-limited the request",
            summary=f"{p_label} threw 429. Vooda will back off and retry.",
            fix_steps=rate_limit_fix_steps or [
                f"Wait {retry}s and retry" if retry else "Wait at least 60s and retry",
                f"Lower scan concurrency on this {p_label} source",
            ],
            doc_anchor=anchor,
            http_status=http_status,
            provider_code="rate_limited",
            retry_after_s=retry,
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 401 ────────────────────────────────────────────────────────
    if http_status == 401:
        return IntegrationError(
            code=f"{p}.auth.invalid_credentials",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title=f"{p_label} rejected the credentials",
            summary=message or f"{p_label} returned 401. The credentials are wrong, expired, or revoked.",
            fix_steps=auth_fix_steps or [
                f"Open the {p_label} admin / developer console and verify the credential is still active",
                f"If it was rotated, regenerate and update the value in Vooda",
            ],
            doc_anchor=anchor,
            http_status=http_status,
            provider_code="invalid_credentials",
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 403 ────────────────────────────────────────────────────────
    if http_status == 403:
        return IntegrationError(
            code=f"{p}.permission.insufficient",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title=f"{p_label} denied the request",
            summary=message or f"{p_label} returned 403. The credentials authenticated but lack the required scope.",
            fix_steps=permission_fix_steps or [
                f"Confirm the credential has the scope this scan needs",
                f"If your {p_label} workspace enforces IP allow-lists, add the Vooda host's egress IP",
            ],
            doc_anchor=anchor,
            http_status=http_status,
            provider_code="forbidden",
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 404 ────────────────────────────────────────────────────────
    if http_status == 404:
        return IntegrationError(
            code=f"{p}.not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title=f"{p_label} returned 404",
            summary=message or f"The resource doesn't exist or isn't visible to this credential.",
            fix_steps=not_found_fix_steps or [
                f"Verify the URL / id matches what's in {p_label}",
                f"Confirm the credential's owner can see the resource",
            ],
            doc_anchor=anchor,
            http_status=http_status,
            provider_code="not_found",
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 400: bad request ───────────────────────────────────────────
    if http_status == 400:
        return IntegrationError(
            code=f"{p}.validation_error",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title=f"{p_label} rejected the request body",
            summary=message or f"{p_label} returned 400 — the request was malformed.",
            fix_steps=[
                f"Check the request shape against {p_label}'s API reference",
                "If this only happens for specific items, file a bug",
            ],
            doc_anchor=anchor,
            http_status=http_status,
            provider_code="bad_request",
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 413: payload too large ─────────────────────────────────────
    if http_status == 413:
        return IntegrationError(
            code=f"{p}.payload_too_large",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Request payload too large",
            summary=f"{p_label} rejected the request body for exceeding the size cap.",
            fix_steps=["Reduce per-page size in the scan settings"],
            doc_anchor=anchor,
            http_status=http_status,
            provider_code="payload_too_large",
            raw=_raw(response, body),
            context=ctx,
        )

    # ── 5xx ────────────────────────────────────────────────────────
    if 500 <= http_status < 600:
        return IntegrationError(
            code=f"{p}.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title=f"{p_label} server error",
            summary=f"{p_label} returned {http_status}. This is on {p_label}'s side.",
            fix_steps=[
                "Retry — most 5xx are transient",
                f"If persistent, check {p_label}'s status page",
            ],
            doc_anchor=anchor,
            http_status=http_status,
            provider_code="provider_fault",
            raw=_raw(response, body),
            context=ctx,
        )

    return IntegrationError(
        code=f"{p}.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title=f"{p_label} error",
        summary=message or f"{p_label} returned {http_status}.",
        fix_steps=["Retry once", f"Check {p_label}'s API reference for this status"],
        doc_anchor=anchor,
        http_status=http_status,
        raw=_raw(response, body),
        context=ctx,
    )


# ─────────────────────────────────────────────────────────────────
# SDK exception → IntegrationError translators
#
# For adapters that use vendor SDKs (boto3, docker CLI) rather than
# httpx, we can't classify at the response level.  These helpers
# translate SDK-style failures to the same shape so the rest of the
# pipeline stays uniform.
# ─────────────────────────────────────────────────────────────────


def classify_sdk_error(
    exc: Exception,
    *,
    provider: str,
    context: dict[str, Any] | None = None,
) -> IntegrationError:
    """Best-effort classification of an SDK exception.

    Recognises a few common patterns by string match on the message
    (e.g. ``InvalidAccessKeyId``, ``NoSuchBucket``, ``AccessDenied``).
    Falls back to a generic provider-fault label.
    """
    ctx = dict(context or {})
    msg = str(exc)
    msg_lower = msg.lower()
    p = provider.lower()
    p_label = provider.capitalize()

    if "invalidaccesskeyid" in msg_lower or "invalid access key" in msg_lower or "signaturedoesnotmatch" in msg_lower:
        return IntegrationError(
            code=f"{p}.auth.invalid_credentials",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title=f"{p_label} rejected the credentials",
            summary=f"{p_label} couldn't authenticate the SDK call. Access key wrong, secret rotated, or signature mismatch.",
            fix_steps=[
                "Re-issue the credential from the provider's console",
                "Update Vooda with the new value",
            ],
            doc_anchor=f"/docs?section=sources&provider={p}",
            raw=redact_secrets({"exception": msg[:500]}),
            context=ctx,
        )

    if "accessdenied" in msg_lower or "forbidden" in msg_lower:
        return IntegrationError(
            code=f"{p}.permission.insufficient",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title=f"{p_label} denied the request",
            summary=f"{p_label} authenticated the call but the IAM / RBAC policy doesn't permit the action.",
            fix_steps=[
                "Verify the credential has read access to the target resource",
                "Check IAM / policy rules in the provider's console",
            ],
            doc_anchor=f"/docs?section=sources&provider={p}",
            raw=redact_secrets({"exception": msg[:500]}),
            context=ctx,
        )

    if "nosuchbucket" in msg_lower or "404" in msg_lower or "not found" in msg_lower:
        return IntegrationError(
            code=f"{p}.not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title=f"{p_label} resource not found",
            summary=f"{p_label} can't find the resource — typo or wrong region/account.",
            fix_steps=[
                "Verify the resource name exactly",
                "Confirm region / account matches the credential",
            ],
            raw=redact_secrets({"exception": msg[:500]}),
            context=ctx,
        )

    return IntegrationError(
        code=f"{p}.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title=f"{p_label} SDK error",
        summary=msg[:200],
        fix_steps=[
            "Retry once",
            f"Check {p_label}'s status page",
        ],
        doc_anchor=f"/docs?section=sources&provider={p}",
        raw=redact_secrets({"exception": f"{type(exc).__name__}: {msg}"[:500]}),
        context=ctx,
    )
