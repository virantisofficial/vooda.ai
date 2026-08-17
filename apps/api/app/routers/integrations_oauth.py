# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""OAuth 2.0 (3LO) for upstream integrations.

Currently implemented: Atlassian (Jira / Confluence) — the procurement
gate for enterprise customers, since most security-conscious orgs
disallow long-lived static API tokens.

Flow:
  1. UI calls POST /oauth/atlassian/start with the IntegrationConfig
     id of a row that has `auth_type=oauth2`, `oauth_client_id`,
     `oauth_client_secret`, and the requested `oauth_scope`. We
     return the URL to redirect the user to.
  2. User authorizes at auth.atlassian.com → Atlassian redirects to
     `${OAUTH_REDIRECT_BASE}/atlassian/callback?code=...&state=...`.
  3. Callback exchanges the code for tokens at
     `https://auth.atlassian.com/oauth/token`, fetches the cloud_id
     via `/oauth/token/accessible-resources`, and persists everything
     back into the IntegrationConfig row's `config` JSONB.
  4. Adapters detect `auth_type=oauth2` and use the bearer token
     against `https://api.atlassian.com/ex/jira/{cloud_id}/...`,
     refreshing on 401 via the stored `refresh_token`.

Customer setup (one-time, manual — documented in
docs/oauth-atlassian.md):
  - Register an OAuth 2.0 (3LO) integration at
    developer.atlassian.com → Console → Apps → Create app.
  - Enable Jira / Confluence APIs as needed.
  - Add the redirect URI: `${OAUTH_REDIRECT_BASE}/atlassian/callback`.
  - Copy the client_id + client_secret into the Vooda Integration
    config (via the UI).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Optional
from urllib.parse import urlencode
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.config import settings
from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.integration import IntegrationConfig
from apps.api.app.models.user import User
from packages.common.encryption import encrypt_value, decrypt_value


router = APIRouter()


# ── Atlassian endpoints ────────────────────────────────────────────
# Single source of truth for the OAuth 2.0 (3LO) URLs. If Atlassian
# moves them (they did in 2023; doubt they will again soon), change
# here, not throughout the codebase.
AUTHZ_URL = "https://auth.atlassian.com/authorize"
TOKEN_URL = "https://auth.atlassian.com/oauth/token"
ACCESSIBLE_RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources"

# Default scopes for a Jira read-only secret-scanning use case.
# Customers can override per-integration via `oauth_scope`. We
# deliberately don't request write scopes for the scanning path —
# ticketing dispatch uses a separate IntegrationConfig.
DEFAULT_JIRA_SCOPES = "read:jira-work read:jira-user offline_access"
DEFAULT_CONFLUENCE_SCOPES = "read:confluence-content.all read:confluence-user offline_access"


# ── State-token signing ────────────────────────────────────────────
# We sign a compact JSON payload with HMAC-SHA256 keyed on the
# server's SECRET_KEY so a callback `state` can only have come from
# a /start we issued. Pinning the integration_id + tenant_id stops
# cross-tenant code-redemption attacks (the user authorized one
# tenant's app; the code is only valid for that tenant's row).

def _sign_state(payload: dict) -> str:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(settings.SECRET_KEY.encode(), body, hashlib.sha256).digest()
    # Base64-style encode without padding for URL safety.
    import base64
    return base64.urlsafe_b64encode(body).decode().rstrip("=") + "." + base64.urlsafe_b64encode(sig).decode().rstrip("=")


def _verify_state(state: str) -> Optional[dict]:
    import base64
    try:
        body_b64, sig_b64 = state.split(".", 1)
        # Re-pad before decoding.
        def _pad(s: str) -> bytes:
            return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        body = _pad(body_b64)
        sig = _pad(sig_b64)
        expected = hmac.new(settings.SECRET_KEY.encode(), body, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(body)
        if int(time.time()) - int(payload.get("ts", 0)) > settings.OAUTH_STATE_TTL_SECONDS:
            return None
        return payload
    except Exception:
        return None


# ── Token storage helpers ──────────────────────────────────────────
# Tokens live encrypted inside IntegrationConfig.config (JSONB).
# Same encryption helpers used everywhere else in the codebase
# (Fernet, `enc:` prefix). Three keys:
#   `oauth_access_token`   — Bearer for API calls.
#   `oauth_refresh_token`  — Long-lived, used to mint new access tokens.
#   `oauth_token_expires_at` — Unix epoch when access_token expires.
# We also persist `cloud_id` (selected Atlassian site) separately so
# adapters can build `https://api.atlassian.com/ex/jira/{cloud_id}/…`.

def _store_tokens(cfg: dict, token_response: dict, cloud_id: str, scope: str) -> dict:
    new_cfg = dict(cfg)
    new_cfg["oauth_access_token"] = encrypt_value(token_response["access_token"])
    if token_response.get("refresh_token"):
        new_cfg["oauth_refresh_token"] = encrypt_value(token_response["refresh_token"])
    expires_in = int(token_response.get("expires_in", 3600))
    new_cfg["oauth_token_expires_at"] = int(time.time()) + expires_in
    new_cfg["oauth_scope"] = scope
    new_cfg["cloud_id"] = cloud_id
    new_cfg["auth_type"] = "oauth2"
    return new_cfg


# ═══════════════════════════════════════════════════════════════════
#  Routes
# ═══════════════════════════════════════════════════════════════════

@router.post("/atlassian/start")
async def start_atlassian_oauth(
    integration_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Begin Atlassian OAuth 2.0 (3LO).

    The IntegrationConfig must already exist (provider=jira or
    confluence) with the customer's `oauth_client_id` /
    `oauth_client_secret` populated. We return the auth URL the UI
    should redirect the user to.
    """
    row = (await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == integration_id,
            IntegrationConfig.tenant_id == user.tenant_id,
        )
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Integration not found")
    cfg = row.config or {}
    client_id = cfg.get("oauth_client_id")
    if not client_id:
        raise HTTPException(400, "Integration is missing oauth_client_id — register an Atlassian OAuth app and save its client ID first")

    # Per-integration scope override; default depends on provider.
    if cfg.get("oauth_scope"):
        scope = cfg["oauth_scope"]
    elif row.provider == "confluence":
        scope = DEFAULT_CONFLUENCE_SCOPES
    else:
        scope = DEFAULT_JIRA_SCOPES

    # `state` pins the round-trip to this integration row + tenant +
    # a fresh nonce so a replayed `code` from a different tenant is
    # rejected at the callback. Short TTL via OAUTH_STATE_TTL_SECONDS.
    nonce = secrets.token_urlsafe(16)
    state = _sign_state({
        "integration_id": str(integration_id),
        "tenant_id": str(user.tenant_id),
        "nonce": nonce,
        "ts": int(time.time()),
    })

    redirect_uri = f"{settings.OAUTH_REDIRECT_BASE}/atlassian/callback"
    params = {
        "audience": "api.atlassian.com",
        "client_id": client_id,
        "scope": scope,
        "redirect_uri": redirect_uri,
        "state": state,
        "response_type": "code",
        "prompt": "consent",
    }
    return {
        "authorize_url": f"{AUTHZ_URL}?{urlencode(params)}",
        "redirect_uri": redirect_uri,
    }


@router.get("/atlassian/callback")
async def atlassian_oauth_callback(
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Atlassian redirects here after the user authorizes (or cancels).

    No `get_current_user` dependency: this is a redirect from
    auth.atlassian.com, not an authenticated FE request. Authorization
    is reconstructed from the signed `state` token, which pins the
    in-flight setup to a specific tenant + integration row.
    """
    fe_redirect = f"{settings.WEB_BASE_URL}/integrations?oauth=atlassian"

    if error:
        return RedirectResponse(
            url=f"{fe_redirect}&status=error&detail={error_description or error}",
            status_code=302,
        )
    if not code or not state:
        return RedirectResponse(url=f"{fe_redirect}&status=error&detail=missing+code+or+state", status_code=302)

    payload = _verify_state(state)
    if not payload:
        return RedirectResponse(url=f"{fe_redirect}&status=error&detail=invalid+state", status_code=302)

    integration_id = payload["integration_id"]
    tenant_id = payload["tenant_id"]

    row = (await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == UUID(integration_id),
            IntegrationConfig.tenant_id == UUID(tenant_id),
        )
    )).scalar_one_or_none()
    if not row:
        return RedirectResponse(url=f"{fe_redirect}&status=error&detail=integration+missing", status_code=302)

    cfg = row.config or {}
    client_id = cfg.get("oauth_client_id")
    client_secret = decrypt_value(cfg.get("oauth_client_secret", ""))
    if not client_id or not client_secret:
        return RedirectResponse(url=f"{fe_redirect}&status=error&detail=oauth+app+credentials+missing", status_code=302)

    redirect_uri = f"{settings.OAUTH_REDIRECT_BASE}/atlassian/callback"

    # Step 3a: Exchange the auth code for tokens.
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            token_resp = await client.post(TOKEN_URL, json={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            })
            if token_resp.status_code != 200:
                return RedirectResponse(
                    url=f"{fe_redirect}&status=error&detail=token+exchange+failed+{token_resp.status_code}",
                    status_code=302,
                )
            token_data = token_resp.json()

            # Step 3b: Discover the Atlassian site (cloud_id) the
            # user just authorized. A token is valid against many
            # sites the user has access to; we pick the FIRST Jira
            # site for default routing. Customer can override later
            # if they need to point at a non-default workspace.
            ar = await client.get(
                ACCESSIBLE_RESOURCES_URL,
                headers={"Authorization": f"Bearer {token_data['access_token']}"},
            )
            if ar.status_code != 200:
                return RedirectResponse(
                    url=f"{fe_redirect}&status=error&detail=accessible+resources+failed+{ar.status_code}",
                    status_code=302,
                )
            resources = ar.json() or []
            if not resources:
                return RedirectResponse(
                    url=f"{fe_redirect}&status=error&detail=no+accessible+atlassian+sites",
                    status_code=302,
                )
            site = resources[0]
            cloud_id = site.get("id", "")
    except Exception as e:
        return RedirectResponse(
            url=f"{fe_redirect}&status=error&detail=exchange+exception+{str(e)[:80]}",
            status_code=302,
        )

    # Step 3c: Persist encrypted tokens + cloud_id into the row.
    scope = cfg.get("oauth_scope") or (
        DEFAULT_CONFLUENCE_SCOPES if row.provider == "confluence" else DEFAULT_JIRA_SCOPES
    )
    row.config = _store_tokens(cfg, token_data, cloud_id, scope)
    # Also stash human-readable site URL so the UI can show "Connected
    # to acme.atlassian.net" without an extra round-trip.
    row.config["site_url"] = site.get("url", row.config.get("site_url", ""))
    row.config["site_name"] = site.get("name", "")
    await db.commit()

    return RedirectResponse(
        url=f"{fe_redirect}&status=success&integration_id={integration_id}",
        status_code=302,
    )


@router.post("/atlassian/disconnect")
async def disconnect_atlassian_oauth(
    integration_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Revoke the stored tokens + clear OAuth state.

    Doesn't touch the customer's `oauth_client_id` / `oauth_client_secret`
    so they can re-authorize without re-entering app credentials.
    """
    row = (await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == integration_id,
            IntegrationConfig.tenant_id == user.tenant_id,
        )
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Integration not found")
    cfg = dict(row.config or {})
    for k in ("oauth_access_token", "oauth_refresh_token", "oauth_token_expires_at", "cloud_id"):
        cfg.pop(k, None)
    cfg["auth_type"] = "basic"  # falls back to API token mode (if creds present)
    row.config = cfg
    await db.commit()
    return {"status": "disconnected"}


# ═══════════════════════════════════════════════════════════════════
#  Token refresh helper — used by adapters / scan workers
# ═══════════════════════════════════════════════════════════════════

async def refresh_atlassian_token_if_needed(
    db: AsyncSession,
    integration_id: UUID,
    skew_seconds: int = 60,
) -> str:
    """Return a non-expired Atlassian access token, refreshing if
    needed. Persists the new tokens back to IntegrationConfig.

    Adapters call this just before each scan; cheap when the token
    is fresh, single API roundtrip when expired.
    """
    row = (await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.id == integration_id)
    )).scalar_one_or_none()
    if not row:
        raise RuntimeError("Integration not found")
    cfg = row.config or {}
    if (cfg.get("auth_type") or "basic") != "oauth2":
        raise RuntimeError("Integration is not OAuth-mode")

    access = decrypt_value(cfg.get("oauth_access_token", ""))
    expires_at = int(cfg.get("oauth_token_expires_at", 0))
    # Refresh if we're past expiry or within `skew_seconds` of it
    # (avoid the race where the token expires between our check and
    # the upstream API call).
    if access and expires_at - skew_seconds > int(time.time()):
        return access

    refresh = decrypt_value(cfg.get("oauth_refresh_token", ""))
    if not refresh:
        raise RuntimeError("OAuth refresh token missing — user must reconnect")

    client_id = cfg.get("oauth_client_id")
    client_secret = decrypt_value(cfg.get("oauth_client_secret", ""))

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(TOKEN_URL, json={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh,
        })
        if r.status_code != 200:
            raise RuntimeError(f"Refresh failed: {r.status_code} {r.text[:200]}")
        token_data = r.json()

    cfg = dict(cfg)
    cfg["oauth_access_token"] = encrypt_value(token_data["access_token"])
    if token_data.get("refresh_token"):
        # Atlassian rotates refresh tokens occasionally — if a new
        # one is issued, store it; otherwise keep the existing one.
        cfg["oauth_refresh_token"] = encrypt_value(token_data["refresh_token"])
    cfg["oauth_token_expires_at"] = int(time.time()) + int(token_data.get("expires_in", 3600))
    row.config = cfg
    await db.commit()
    return token_data["access_token"]
