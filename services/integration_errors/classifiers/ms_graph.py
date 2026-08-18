# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Microsoft Graph error classifier — covers MS Teams + OneDrive/SharePoint.

Two distinct API surfaces emit errors that we map here:

  1. The token endpoint at login.microsoftonline.com — returns
     ``error`` + ``error_description`` JSON for credential-level
     failures (AADSTS codes).  Handled by :func:`classify_graph_token_error`.

  2. The Graph API at graph.microsoft.com — returns an
     ``{error: {code, message, innerError: {request-id, date}}}``
     envelope, plus an ``x-failure-category`` header for some
     auth-layer rejections.  Handled by :func:`classify_graph_error`.

The split mirrors how the adapter actually fails — a token failure
shouldn't produce a "Graph permissions missing" message and a 403
on /teams shouldn't produce an "invalid client secret" message.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..model import ErrorCategory, ErrorSeverity, IntegrationError
from ..redact import redact_secrets


def _trace(r: httpx.Response) -> str | None:
    # Graph uses request-id; the token endpoint uses x-trace-id.
    return r.headers.get("request-id") or r.headers.get("x-trace-id")


def _raw(r: httpx.Response) -> dict[str, Any]:
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
        }
    )  # type: ignore[return-value]


# ─────────────────────────────────────────────────────────────────
# Token endpoint (login.microsoftonline.com)
# ─────────────────────────────────────────────────────────────────


def classify_graph_token_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    """Classify a failure from the OAuth token endpoint.

    The body shape is::

        {
            "error": "invalid_client" | "invalid_request" | "unauthorized_client",
            "error_description": "AADSTS<code>: <human-readable>...",
            ...
        }

    Each AADSTS code maps to a different cause; we recognise the most
    common ones and fall back to a generic "credentials wrong" message
    for the rest.
    """
    ctx = dict(context or {})
    trace = _trace(response)
    body: dict[str, Any] = {}
    try:
        body = response.json() if response.content else {}
    except ValueError:
        body = {}

    err = (body.get("error") or "").strip()
    desc = (body.get("error_description") or "").strip()
    aadsts = ""
    # AADSTS codes appear at the start of error_description: "AADSTS7000215: ..."
    if desc.startswith("AADSTS"):
        aadsts = desc.split(":", 1)[0]

    # ── AADSTS7000215 — invalid client secret ─────────────────────
    if aadsts == "AADSTS7000215" or err == "invalid_client":
        return IntegrationError(
            code="ms_graph.auth.invalid_client_secret",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Invalid client secret",
            summary=(
                "Microsoft Entra rejected the client secret. The most common cause is "
                "pasting the Secret ID instead of the Secret Value."
            ),
            fix_steps=[
                "Open Microsoft Entra → App registrations → Certificates & secrets",
                "Copy the Value column (not Secret ID); if it's hidden, generate a new client secret",
                "Paste the new value here",
            ],
            doc_anchor="/docs?section=sources#6.6.1",
            http_status=response.status_code,
            provider_code=aadsts or err,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── AADSTS900023 — bad tenant identifier ──────────────────────
    if aadsts == "AADSTS900023":
        return IntegrationError(
            code="ms_graph.auth.invalid_tenant",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Invalid tenant ID",
            summary="Microsoft Entra doesn't recognise this tenant ID.",
            fix_steps=[
                "Open Microsoft Entra → Overview and copy the Directory (tenant) ID",
                "Paste exactly — it should be a GUID (8-4-4-4-12 hex digits)",
            ],
            doc_anchor="/docs?section=sources#6.6.1",
            http_status=response.status_code,
            provider_code=aadsts,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── AADSTS700038 — bad client (application) ID ────────────────
    if aadsts == "AADSTS700038" or err == "unauthorized_client":
        return IntegrationError(
            code="ms_graph.auth.invalid_client_id",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Invalid application (client) ID",
            summary="Microsoft Entra doesn't recognise this Application (client) ID for the given tenant.",
            fix_steps=[
                "Open Microsoft Entra → App registrations → your app → Overview",
                "Copy the Application (client) ID — should be a GUID",
                "Confirm the app was registered in the same tenant whose ID you're using",
            ],
            doc_anchor="/docs?section=sources#6.6.1",
            http_status=response.status_code,
            provider_code=aadsts or err,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── AADSTS65001 — admin consent required ──────────────────────
    # Distinct from the post-token 403 case: here the token endpoint
    # itself rejects because the app's permissions exist but admin
    # consent was never granted (or was revoked).  Common landing
    # state right after an admin adds new scopes — the app has the
    # permission *configured* but not *consented*.
    if aadsts == "AADSTS65001":
        return IntegrationError(
            code="ms_graph.auth.consent_required",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Admin consent missing",
            summary=(
                "The application has the right permissions configured, but admin "
                "consent has not been granted (or was revoked). Microsoft Entra "
                "requires explicit consent before issuing tokens with these scopes."
            ),
            fix_steps=[
                "Open Microsoft Entra → App registrations → your app → API permissions",
                "Click 'Grant admin consent for <tenant>' at the top of the table",
                "This requires a Global Administrator account",
            ],
            doc_anchor="/docs?section=sources#6.6.1",
            http_status=response.status_code,
            provider_code=aadsts,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── AADSTS90002 — tenant exists in Entra but not for this app ─
    # Different from AADSTS900023 (which means the tenant ID is
    # *malformed*).  Here the GUID is well-formed but Entra has no
    # such tenant — usually a copy/paste from a different Vooda
    # deployment, or a tenant that was deleted.
    if aadsts == "AADSTS90002":
        return IntegrationError(
            code="ms_graph.auth.tenant_not_found",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Tenant not found",
            summary=(
                "Microsoft Entra knows what a tenant ID looks like, but doesn't have "
                "a record of this one. The GUID is well-formed but doesn't match any "
                "registered Entra tenant."
            ),
            fix_steps=[
                "Open Microsoft Entra → Overview and copy the Directory (tenant) ID exactly",
                "If you copy/pasted from another Vooda deployment, get the value from your own tenant",
            ],
            doc_anchor="/docs?section=sources#6.6.1",
            http_status=response.status_code,
            provider_code=aadsts,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── AADSTS50034 — user-account presented to Entra doesn't exist
    # In the application-permissions flow (which Vooda uses) this
    # surfaces when the app registration itself was deleted from
    # Azure AD between the time the user copied the IDs and now.
    if aadsts == "AADSTS50034":
        return IntegrationError(
            code="ms_graph.auth.user_not_found",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="App registration not found",
            summary=(
                "Microsoft Entra can't find the application or user account this "
                "client_id refers to. The app may have been deleted or moved tenants."
            ),
            fix_steps=[
                "Open Microsoft Entra → App registrations and confirm the app still exists",
                "If it's gone, register a new app and re-do the connection wizard",
            ],
            doc_anchor="/docs?section=sources#6.6.1",
            http_status=response.status_code,
            provider_code=aadsts,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── AADSTS50020 — guest user not part of this tenant ──────────
    # Multi-tenant edge case: the app is registered in tenant A but
    # the request is being made in the context of tenant B without
    # the cross-tenant federation set up.
    if aadsts == "AADSTS50020":
        return IntegrationError(
            code="ms_graph.auth.guest_not_in_tenant",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="App registered in a different tenant",
            summary=(
                "The application is registered in one tenant but you're trying to "
                "use it against a different tenant. Each Vooda source needs an app "
                "registered in the same tenant whose data it scans."
            ),
            fix_steps=[
                "Confirm the Tenant ID here matches the tenant where the app was registered",
                "If you genuinely need cross-tenant access, register a multi-tenant app and configure consent in each tenant",
            ],
            doc_anchor="/docs?section=sources#6.6.1",
            http_status=response.status_code,
            provider_code=aadsts,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── AADSTS70011 — invalid scope requested ────────────────────
    # The app asked for a scope it isn't allowed to ask for —
    # usually a typo in the manifest, or a scope that was removed
    # from the API permissions list after the app started using it.
    if aadsts == "AADSTS70011":
        return IntegrationError(
            code="ms_graph.auth.invalid_scope",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Invalid Graph scope",
            summary=(
                "Microsoft Entra rejected the requested scope. This is almost "
                "always an internal Vooda configuration issue rather than a "
                "customer one."
            ),
            fix_steps=[
                "Retry — if it persists, copy the trace ID and contact support",
            ],
            doc_anchor="/docs?section=sources#6.6.1",
            http_status=response.status_code,
            provider_code=aadsts,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── AADSTS700016 — app not found in directory (already deleted)
    # Closely related to AADSTS50034 but specifically when the app
    # was *removed* (not "moved") from the tenant.  Useful to
    # distinguish because the fix is "re-register," not "find."
    if aadsts == "AADSTS700016":
        return IntegrationError(
            code="ms_graph.auth.app_not_in_directory",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="App registration removed",
            summary=(
                "Microsoft Entra used to know this application but it has been "
                "removed from the tenant. You'll need to re-register it."
            ),
            fix_steps=[
                "Open Microsoft Entra → App registrations → New registration",
                "Re-create the app, grant the same scopes, then re-run the wizard with the new IDs",
            ],
            doc_anchor="/docs?section=sources#6.6.1",
            http_status=response.status_code,
            provider_code=aadsts,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── Generic OAuth failure ─────────────────────────────────────
    return IntegrationError(
        code="ms_graph.auth.token_request_failed",
        category=ErrorCategory.AUTHENTICATION,
        severity=ErrorSeverity.ERROR,
        title="Microsoft Entra rejected the credentials",
        summary=(
            "The OAuth token request failed."
            + (f" Provider says: {desc[:200]}" if desc else "")
        ),
        fix_steps=[
            "Verify Tenant ID, Application (Client) ID, and Client Secret are all from the same Entra app registration",
            "Generate a fresh client secret if the current one is older than its rotation period",
        ],
        doc_anchor="/docs?section=sources#6.6.1",
        http_status=response.status_code,
        provider_code=aadsts or err or None,
        trace_id=trace,
        raw=_raw(response),
        context=ctx,
    )


# ─────────────────────────────────────────────────────────────────
# Graph API (graph.microsoft.com)
# ─────────────────────────────────────────────────────────────────


def classify_graph_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    """Classify a failure from the Microsoft Graph data endpoints.

    The response includes an ``error`` envelope; we extract its ``code``
    field (e.g. ``"Authorization_RequestDenied"``) and route on that.
    """
    ctx = dict(context or {})
    code = response.status_code
    trace = _trace(response)

    # Pull the envelope's ``code`` and ``message``.
    body: dict[str, Any] = {}
    try:
        j = response.json()
        if isinstance(j, dict):
            body = j.get("error") or {}
    except ValueError:
        pass
    provider_code = (body.get("code") or "").strip()
    provider_msg = (body.get("message") or "").strip()

    # ── 403 — missing application permission / admin consent ──────
    if code == 403:
        return IntegrationError(
            code="ms_graph.permission.missing_application_role",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Missing Microsoft Graph permissions",
            summary=(
                "Authentication worked, but the access token has no Graph application "
                "roles for this endpoint. Either the scopes weren't added to the app "
                "registration, or admin consent wasn't granted."
                + (f" Provider says: {provider_msg[:200]}" if provider_msg else "")
            ),
            fix_steps=[
                "Open Microsoft Entra → App registrations → your app → API permissions",
                "Add the scopes the wizard listed (Channel.ReadBasic.All, ChannelMessage.Read.All for Teams; Sites.Read.All for OneDrive)",
                "Click 'Grant admin consent for <tenant>' — requires a Global Administrator",
            ],
            doc_anchor="/docs?section=sources#6.6.1",
            http_status=403,
            provider_code=provider_code or None,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 401 — token rejected (admin consent revoked mid-session) ─
    if code == 401:
        return IntegrationError(
            code="ms_graph.auth.token_rejected",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Microsoft Graph rejected the token",
            summary=(
                "The access token was issued but Graph rejected it. Admin consent may "
                "have been revoked, or the token expired between issue and use."
            ),
            fix_steps=[
                "Re-test the connection — Vooda will request a fresh token",
                "If it persists, confirm admin consent is still granted in Microsoft Entra",
            ],
            doc_anchor="/docs?section=sources#6.6.1",
            http_status=401,
            provider_code=provider_code or None,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 404 — wrong endpoint ─────────────────────────────────────
    if code == 404:
        return IntegrationError(
            code="ms_graph.not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Graph endpoint not found",
            summary="Microsoft Graph returned 404 for this request.",
            fix_steps=[
                "Confirm the tenant has the resources you're trying to scan (e.g. teams exist for the Teams source)",
            ],
            http_status=404,
            provider_code=provider_code or None,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 413 — payload too large (oversized OneDrive file) ─────────
    # Hits when scanning Microsoft 365 attachments / OneDrive items
    # whose size exceeds Graph's per-call cap.  Same shape as the
    # Atlassian counterpart — single item, rest of source unaffected.
    if code == 413:
        return IntegrationError(
            code="ms_graph.payload_too_large",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.WARN,
            title="Microsoft Graph response too large",
            summary=(
                "Graph rejected the request because the response would exceed their "
                "per-call size cap. Almost always an oversized OneDrive file or "
                "Teams attachment."
            ),
            fix_steps=[
                "Lower the per-attachment scan size cap, or",
                "Add a path-glob exclude for the file that triggered this",
                "Vooda continues scanning the rest of the source; this is only the one item",
            ],
            doc_anchor="/docs?section=sources#6.6",
            http_status=413,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── 429 — throttled ──────────────────────────────────────────
    if code == 429:
        retry = response.headers.get("retry-after")
        retry_s = int(retry) if retry and retry.isdigit() else None
        return IntegrationError(
            code="ms_graph.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="Microsoft Graph throttled",
            summary="Graph returned 429. Vooda will retry automatically.",
            fix_steps=["No action required — Vooda backs off and retries"],
            http_status=429,
            provider_code=provider_code or None,
            trace_id=trace,
            retry_after_s=retry_s,
            raw=_raw(response),
            context=ctx,
        )

    # ── 5xx — provider fault ─────────────────────────────────────
    if 500 <= code < 600:
        return IntegrationError(
            code="ms_graph.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.WARN,
            title="Microsoft Graph is having trouble",
            summary=f"Graph returned {code}. This is on Microsoft's side.",
            fix_steps=[
                "Check status.office.com",
                "Retry in a few minutes",
            ],
            http_status=code,
            trace_id=trace,
            raw=_raw(response),
            context=ctx,
        )

    # ── Catch-all ────────────────────────────────────────────────
    return IntegrationError(
        code="ms_graph.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title="Microsoft Graph error",
        summary=(
            f"Graph returned {code}."
            + (f" Provider says: {provider_msg[:200]}" if provider_msg else "")
        ),
        fix_steps=[
            "Retry — if it persists, copy the trace ID and contact support",
        ],
        http_status=code,
        provider_code=provider_code or None,
        trace_id=trace,
        raw=_raw(response),
        context=ctx,
    )
