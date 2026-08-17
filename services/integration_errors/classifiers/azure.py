# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Azure DevOps + Azure Storage error classifier.

Two distinct sub-surfaces, intentionally co-located because both
authenticate against Azure but with different envelopes:

  1. **Azure DevOps**: REST API at dev.azure.com, PAT-based Basic
     auth.  Error envelope::

         {
           "$id": "1", "innerException": null,
           "message": "TF400813: ...",
           "typeName": "...", "typeKey": "..."
         }

     The TF##### codes are stable.  TF400813 = "user not authorized",
     TF401019 = "git repo not found", etc.

  2. **Azure Storage** (Blob): REST API at *.blob.core.windows.net,
     SharedKey HMAC signed.  Error envelope is XML::

         <Error>
           <Code>AuthenticationFailed</Code>
           <Message>...</Message>
           <AuthenticationErrorDetail>...</AuthenticationErrorDetail>
         </Error>

     The ``Code`` element is the stable identifier.

Diagnostic header (both surfaces):

  - ``x-ms-request-id`` and ``x-ms-correlation-request-id`` carry
    Microsoft's per-request correlation IDs — copyable for support
    and visible in Azure Activity Log.

Error classes covered:

  Azure DevOps:
    azuredevops.auth.invalid_pat              401
    azuredevops.permission.insufficient       403
    azuredevops.not_found                     404
    azuredevops.payload_too_large             413
    azuredevops.rate_limited                  429
    azuredevops.provider_fault                5xx
    azuredevops.unknown                       catch-all

  Azure Storage:
    azureblob.auth.invalid_signature          AuthenticationFailed (signature mismatch)
    azureblob.auth.account_disabled           AccountIsDisabled / AccountAlreadyExists
    azureblob.permission.insufficient         AuthorizationPermissionMismatch
    azureblob.not_found                       ContainerNotFound / BlobNotFound / ResourceNotFound
    azureblob.rate_limited                    ServerBusy
    azureblob.provider_fault                  InternalError / 5xx
    azureblob.unknown                         catch-all
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from ..model import ErrorCategory, ErrorSeverity, IntegrationError
from ..redact import redact_secrets


_BLOB_CODE_RE = re.compile(r"<Code>([^<]+)</Code>", re.IGNORECASE)
_BLOB_MSG_RE = re.compile(r"<Message>([^<]+)</Message>", re.IGNORECASE)


def _trace(r: httpx.Response) -> str | None:
    return (
        r.headers.get("x-ms-correlation-request-id")
        or r.headers.get("x-ms-request-id")
        or r.headers.get("X-VSS-RequestId")
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


# ─────────────────────────────────────────────────────────────────
# Azure DevOps (PAT / Basic auth REST)
# ─────────────────────────────────────────────────────────────────


def _parse_devops(r: httpx.Response) -> tuple[str, str, dict[str, Any] | None]:
    """Return (typeKey, message, body)."""
    try:
        body = r.json()
    except ValueError:
        return "", r.text[:500], None
    if not isinstance(body, dict):
        return "", "", None
    return str(body.get("typeKey") or ""), str(body.get("message") or ""), body


def classify_azure_devops_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    ctx = dict(context or {})
    type_key, message, body = _parse_devops(response)
    http_status = response.status_code
    trace = _trace(response)

    if http_status == 429:
        ra = response.headers.get("Retry-After") or response.headers.get("retry-after")
        try:
            retry = int(ra) if ra else None
        except ValueError:
            retry = None
        return IntegrationError(
            code="azuredevops.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="Azure DevOps rate-limited the request",
            summary="Azure DevOps applies a Throughput Unit (TU) limit per organization.",
            fix_steps=[
                f"Wait {retry}s and retry" if retry else "Wait at least 60s and retry",
                "Lower scan concurrency",
                "Check org-level usage at dev.azure.com → Organization settings → Usage",
            ],
            doc_anchor="/docs?section=sources&provider=azuredevops#rate-limit",
            http_status=http_status,
            provider_code="rate_limited",
            retry_after_s=retry,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if http_status == 401:
        return IntegrationError(
            code="azuredevops.auth.invalid_pat",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Azure DevOps rejected the PAT",
            summary=(
                "Azure DevOps returned 401. The Personal Access Token is wrong, "
                "expired, or doesn't carry the required scopes."
            ),
            fix_steps=[
                "Open dev.azure.com → User settings → Personal access tokens",
                "Confirm the token is still listed and Active. If expired, regenerate it",
                "When regenerating, tick at least 'Work Items: Read' (and 'Code: Read' if scanning repos)",
            ],
            doc_anchor="/docs?section=sources&provider=azuredevops#pat",
            http_status=http_status,
            provider_code=type_key or "unauthenticated",
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if http_status == 403:
        return IntegrationError(
            code="azuredevops.permission.insufficient",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="PAT lacks permission for this project",
            summary=(
                "Azure DevOps authenticated the PAT but the user / scope doesn't "
                "permit access to this project. Common cause: the PAT was created "
                "with 'All accessible organizations' but the user isn't a member of "
                "this org's project."
            ),
            fix_steps=[
                "Confirm the PAT owner is a member of the project at dev.azure.com → Project settings → Permissions",
                "Recreate the PAT scoped to the right organization",
            ],
            doc_anchor="/docs?section=sources&provider=azuredevops#permissions",
            http_status=http_status,
            provider_code=type_key,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if http_status == 404:
        return IntegrationError(
            code="azuredevops.not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Azure DevOps returned 404",
            summary="The organization or project doesn't exist or isn't visible to this PAT.",
            fix_steps=[
                "Verify the organization slug — the URL is dev.azure.com/{organization}",
                "Verify the project name matches exactly",
                "If the project is restricted, ensure the PAT user is a member",
            ],
            http_status=http_status,
            provider_code=type_key,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if http_status == 413:
        return IntegrationError(
            code="azuredevops.payload_too_large",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Request payload too large",
            summary="Azure DevOps rejected the request body for exceeding the size cap.",
            fix_steps=["Reduce per-page result count", "Lower batch size in scan settings"],
            http_status=http_status,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if 500 <= http_status < 600:
        return IntegrationError(
            code="azuredevops.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Azure DevOps server error",
            summary=f"Azure DevOps returned {http_status}. This is on Microsoft's side.",
            fix_steps=["Retry", "If persistent, check status.dev.azure.com"],
            http_status=http_status,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    return IntegrationError(
        code="azuredevops.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title="Azure DevOps error",
        summary=message or f"Azure DevOps returned {http_status}.",
        fix_steps=["Retry once", "Check status.dev.azure.com"],
        http_status=http_status,
        provider_code=type_key,
        trace_id=trace,
        raw=_raw(response, body),
        context=ctx,
    )


# ─────────────────────────────────────────────────────────────────
# Azure Storage (SharedKey REST)
# ─────────────────────────────────────────────────────────────────


def _parse_blob(r: httpx.Response) -> tuple[str, str]:
    """Pull <Code>...</Code> + <Message>...</Message> from XML body."""
    code_m = _BLOB_CODE_RE.search(r.text or "")
    msg_m = _BLOB_MSG_RE.search(r.text or "")
    code = code_m.group(1) if code_m else ""
    msg = msg_m.group(1) if msg_m else ""
    # Some Azure responses surface the Code as a header.
    if not code:
        code = r.headers.get("x-ms-error-code") or ""
    return code, msg


def classify_azure_blob_error(
    response: httpx.Response, context: dict[str, Any] | None = None
) -> IntegrationError:
    ctx = dict(context or {})
    code, message = _parse_blob(response)
    http_status = response.status_code
    trace = _trace(response)
    body = response.text[:1000] if response.text else None

    if code == "AuthenticationFailed" or http_status == 403 and "Signature" in (message or ""):
        return IntegrationError(
            code="azureblob.auth.invalid_signature",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Azure Storage rejected the SharedKey signature",
            summary=(
                "The HMAC signature didn't match. This usually means the storage "
                "account key is wrong, has been rotated, or the account name typo'd."
            ),
            fix_steps=[
                "Open Azure Portal → Storage account → Access keys",
                "Copy 'key1' or 'key2' (paste exactly — both are valid)",
                "Verify the account name in Vooda matches the URL prefix (https://<name>.blob.core.windows.net)",
            ],
            doc_anchor="/docs?section=sources&provider=azureblob#auth",
            http_status=http_status,
            provider_code=code,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if code in ("AccountIsDisabled", "AccountAlreadyExists", "InsufficientAccountPermissions"):
        return IntegrationError(
            code="azureblob.auth.account_disabled",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.ERROR,
            title="Azure Storage account problem",
            summary=message or f"Azure returned `{code}` — the storage account is disabled or the key isn't permitted.",
            fix_steps=[
                "Confirm the storage account is active in the Azure Portal",
                "If you've migrated to Azure AD-only auth, generate a new account key first or migrate Vooda to AAD-based auth",
            ],
            http_status=http_status,
            provider_code=code,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if code == "AuthorizationPermissionMismatch":
        return IntegrationError(
            code="azureblob.permission.insufficient",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.ERROR,
            title="Storage key lacks permission",
            summary="The key is valid but doesn't grant access to this container/blob.",
            fix_steps=[
                "If using a SAS, regenerate it with Read + List permissions on the right container",
                "If using account key auth, verify the firewall settings allow the Vooda host",
            ],
            doc_anchor="/docs?section=sources&provider=azureblob#permissions",
            http_status=http_status,
            provider_code=code,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if code in ("ContainerNotFound", "BlobNotFound", "ResourceNotFound") or http_status == 404:
        return IntegrationError(
            code="azureblob.not_found",
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.ERROR,
            title="Azure Storage returned 404",
            summary="The container or blob doesn't exist (or isn't visible to this credential).",
            fix_steps=[
                "Verify the container name (case-sensitive)",
                "If you specified a prefix filter, double-check it matches actual blob names",
            ],
            http_status=http_status,
            provider_code=code,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if code == "ServerBusy" or http_status == 503:
        ra = response.headers.get("Retry-After") or response.headers.get("retry-after")
        try:
            retry = int(ra) if ra else None
        except ValueError:
            retry = None
        return IntegrationError(
            code="azureblob.rate_limited",
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.WARN,
            title="Azure Storage throttled the request",
            summary="Azure returned ServerBusy. The account is hitting its IOPS/bandwidth ceiling.",
            fix_steps=[
                f"Wait {retry}s and retry" if retry else "Wait at least 60s and retry",
                "Reduce concurrency for this scan source",
                "If persistent, ask the Azure admin to upgrade the storage account tier",
            ],
            doc_anchor="/docs?section=sources&provider=azureblob#throttling",
            http_status=http_status,
            provider_code=code or "ServerBusy",
            retry_after_s=retry,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    if 500 <= http_status < 600:
        return IntegrationError(
            code="azureblob.provider_fault",
            category=ErrorCategory.PROVIDER_FAULT,
            severity=ErrorSeverity.ERROR,
            title="Azure Storage server error",
            summary=f"Azure Storage returned {http_status} ({code or 'no code'}).",
            fix_steps=["Retry", "If persistent, check status.azure.com"],
            http_status=http_status,
            provider_code=code,
            trace_id=trace,
            raw=_raw(response, body),
            context=ctx,
        )

    return IntegrationError(
        code="azureblob.unknown",
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.ERROR,
        title="Azure Storage error",
        summary=message or f"Azure returned {http_status} ({code or 'no code'}).",
        fix_steps=["Check status.azure.com", "Retry once"],
        http_status=http_status,
        provider_code=code,
        trace_id=trace,
        raw=_raw(response, body),
        context=ctx,
    )
