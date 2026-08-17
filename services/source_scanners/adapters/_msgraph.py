# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Microsoft Graph auth + paging helpers, shared by Teams and OneDrive/SharePoint.

Auth model: Azure AD app registration with **client credentials**
(application permissions). The customer registers an app at
portal.azure.com → App registrations, grants the required application
scopes (admin consent), and provides Vooda with:

  - tenant_id     (their Azure AD tenant)
  - client_id     (the app's Application ID)
  - client_secret (or, in future, a certificate thumbprint)

Vooda then mints tokens via the v2.0 OAuth endpoint:
  POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
  scope=https://graph.microsoft.com/.default

The .default scope tells Azure AD "give me everything the app has been
pre-consented to" — which prevents per-call scope drift and matches
how Azure documents enterprise app integrations. Tokens are cached
for ~50 minutes (Microsoft issues 60-min tokens; we refresh with
10-minute headroom).

We deliberately keep this auth path SEPARATE from the existing
Atlassian OAuth (3LO) module because the two flows are very different
shapes — Microsoft Graph is two-legged service-to-service, Atlassian
is three-legged user-delegated.
"""
from __future__ import annotations

import asyncio
import time
from typing import AsyncIterator, Optional

import httpx
import structlog

from services.integration_errors.classifiers import (
    classify_graph_error,
    classify_graph_token_error,
    classify_network_error,
)
from packages.common.outbound_http import make_async_client

# Module logger — emits a structured ``scan_request_failed`` line when
# a mid-scan Graph call returns non-200, so a token expiring mid-scan
# or a per-team ACL failure surfaces as a grep-able event in the worker
# log stream rather than a silent items_scanned=0.  Mirrors the pattern
# applied to confluence.py / jira.py.
logger = structlog.get_logger(__name__)


GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
TOKEN_URL_FMT = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"


class MicrosoftGraphAuthError(RuntimeError):
    """Raised when the Graph token endpoint refuses the credentials.

    Carries the verbatim httpx response (when one exists) so callers
    can route it through ``classify_graph_token_error`` to produce the
    structured :class:`IntegrationError`.  When raised from a non-HTTP
    failure (e.g. unreachable host) ``response`` is ``None``.
    """

    def __init__(self, message: str, response: "httpx.Response | None" = None):
        super().__init__(message)
        self.response = response


class MicrosoftGraphClient:
    """Minimal async Graph client with token refresh + paging helpers.

    Designed for sharing across Teams + OneDrive/SharePoint adapters
    rather than duplicating auth code. Each adapter holds its own
    instance — Graph tokens are tenant-scoped so we don't need a
    process-wide singleton.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        timeout: int = 30,
        source_type: str = "ms_graph",
    ):
        if not (tenant_id and client_id and client_secret):
            raise ValueError("Microsoft Graph requires tenant_id, client_id, client_secret")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        # Caller-supplied logical source name ("ms_teams", "onedrive_sharepoint")
        # — used as the ``source_type`` field on emitted scan_request_failed
        # log lines so an operator can grep events per adapter without
        # parsing URLs.  Defaults to "ms_graph" for callers that don't care.
        self.source_type = source_type
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0

    async def _ensure_token(self, client: httpx.AsyncClient) -> str:
        # 60s skew so an in-flight call doesn't expire under us.
        if self._access_token and time.time() + 60 < self._token_expires_at:
            return self._access_token
        token_url = TOKEN_URL_FMT.format(tenant=self.tenant_id)
        r = await client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=self.timeout,
        )
        if r.status_code != 200:
            raise MicrosoftGraphAuthError(
                f"Graph token request failed: {r.status_code} {r.text[:200]}",
                response=r,
            )
        data = r.json()
        self._access_token = data["access_token"]
        self._token_expires_at = time.time() + int(data.get("expires_in", 3600))
        return self._access_token

    async def headers(self, client: httpx.AsyncClient) -> dict:
        tok = await self._ensure_token(client)
        return {"Authorization": f"Bearer {tok}", "Accept": "application/json"}

    async def test_connection(self, probe_path: str = "/teams?$top=1") -> dict:
        """Validate creds + the exact application permission Vooda needs.

        Probe shape rationale:
          - The token endpoint round-trip alone proves the (tenant, client,
            secret) tuple is valid; if it returns 200 we can decode roles
            from the token.
          - But "issued a token" doesn't imply "has permissions" — admin
            consent is a separate gate. So we follow up with a Graph call
            that requires an actual application role.
          - Default probe is ``GET /teams?$top=1`` which exercises
            ``Team.ReadBasic.All`` — exactly the scope the wizard's
            Step 2 tells the user to grant. So a 403 here is
            self-diagnostic: Graph's own error message names the
            missing role and the user knows what to add in Entra.
          - Adapters with different scope needs can override
            ``probe_path`` (e.g. OneDrive uses ``/sites?$top=1`` for
            ``Sites.Read.All``).

        Returns the legacy ``{status, message}`` dict for backward
        compatibility, plus the full structured ``IntegrationError``
        envelope under the same keys (title / summary / fix_steps /
        details).  Never raises.
        """
        ctx = {
            "adapter": "ms_graph",
            "tenant_id": self.tenant_id,
            "probe_path": probe_path,
        }
        try:
            async with make_async_client(timeout=self.timeout) as client:
                # Step 1: token issuance. AADSTS errors here are
                # credential-level (wrong secret / wrong tenant /
                # wrong client_id) — different cause space from a
                # post-token Graph rejection, so route them through
                # the *token* classifier.
                try:
                    h = await self.headers(client)
                except MicrosoftGraphAuthError as e:
                    if e.response is not None:
                        err = classify_graph_token_error(e.response, ctx)
                    else:
                        # No response captured (unusual — typically
                        # only on transport errors that AsyncClient
                        # would surface as httpx.* anyway).
                        err = classify_network_error(e, ctx)
                    return err.to_user_dict()

                # Step 2: scope probe. Token issued, so any failure
                # here is permission / 404 / rate-limit territory —
                # route through the *Graph* classifier which knows
                # how to read the Graph error envelope.
                r = await client.get(f"{GRAPH_ROOT}{probe_path}", headers=h)
                if r.status_code == 200:
                    return {"status": "success", "message": "Connected to Microsoft Graph"}
                err = classify_graph_error(r, {**ctx, "phase": "scope_probe"})
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def get_paged(
        self,
        client: httpx.AsyncClient,
        url: str,
        page_sleep_s: float = 0.25,
        max_pages: int = 200,
    ) -> AsyncIterator[dict]:
        """Yield items from a Graph collection across @odata.nextLink pages.

        - Refreshes auth headers between pages so a long-running scan
          can outlive a single 60-minute access token.
        - Sleeps a quarter-second between pages to stay friendly with
          Graph's per-app rate limits (15K req / 15 min default).
        - Hard-caps at 200 pages to defend against pathological loops.
        """
        page = 0
        next_url: Optional[str] = url
        while next_url and page < max_pages:
            h = await self.headers(client)
            r = await client.get(next_url, headers=h, timeout=self.timeout)
            if r.status_code == 429:
                # Microsoft tells you how long to back off; respect it.
                retry_after = int(r.headers.get("Retry-After", "5"))
                await asyncio.sleep(min(retry_after, 60))
                continue
            if r.status_code != 200:
                # Stop iterating, but classify + emit a structured log
                # line first so the silent-failure mode (items_scanned=0
                # with no diagnostic) becomes visible.  Mid-scan token
                # expiry, per-team ACL failures, and rate-limit fall-throughs
                # all land here — error_code distinguishes them.
                err = classify_graph_error(
                    r,
                    {
                        "adapter": self.source_type,
                        "tenant_id": self.tenant_id,
                        "phase": "get_paged",
                        "url": next_url,
                        "page": page,
                    },
                )
                logger.warning(
                    "scan_request_failed",
                    source_type=self.source_type,
                    error_code=err.code,
                    error_title=err.title,
                    trace_id=err.trace_id,
                    http_status=err.http_status,
                    phase="get_paged",
                    page=page,
                )
                return
            data = r.json()
            for item in data.get("value", []) or []:
                yield item
            next_url = data.get("@odata.nextLink")
            page += 1
            if next_url:
                await asyncio.sleep(page_sleep_s)
