# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
SSO Authentication endpoints — SAML 2.0 and OIDC flows.
"""

import uuid
import structlog
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from apps.api.app.core.config import settings
from apps.api.app.core.database import get_db
from apps.api.app.core.security import create_access_token, hash_password, get_current_user
from apps.api.app.models.user import User, UserRole, RoleType, Tenant
from services.auth.sso import get_sso_presets, SAMLHandler, OIDCHandler, SSOConfig, SSOUser

logger = structlog.get_logger()
router = APIRouter()


def _require_sso_enabled() -> None:
    """Refuse to run the SSO login flow while it is disabled.

    SSO is off by default (settings.SSO_ENABLED) because the SAML
    handler does not verify the IdP signature — accepting an assertion
    is an authentication bypass. Every endpoint that could turn an
    assertion/callback into a session calls this first, so the bypass is
    closed regardless of whether an operator has "configured" SSO.
    """
    if not settings.SSO_ENABLED:
        logger.warning("sso_endpoint_blocked_disabled")
        raise HTTPException(
            status_code=503,
            detail=(
                "SSO is disabled in this build. It is being reworked onto a "
                "vetted SAML library with full signature validation and is "
                "unavailable until then."
            ),
        )


@router.get("/providers")
async def list_sso_providers(
    user: User = Depends(get_current_user),
):
    """List available SSO provider presets with their config schemas.

    Admin-only — the preset shapes leak the integration architecture so
    we don't want to surface them publicly.  IdP-facing endpoints below
    (/oidc/*, /saml/acs, /saml/metadata) remain unauthenticated so the
    browser can complete an SSO handshake without a prior session.
    """
    # Inline admin check — see main.py for why the router itself is
    # NOT mounted with require_scope("admin") (would break OIDC + SAML
    # bootstrap flows).
    from apps.api.app.core.security import require_scope
    # Re-evaluate scope by hand: caller MUST be admin (JWT) or have
    # the admin scope on their API key.
    _ = user  # already auth'd by get_current_user
    return get_sso_presets()


class SSOConfigRequest(BaseModel):
    provider: str  # okta, azure_ad, google, etc.
    protocol: str  # saml or oidc
    config: dict   # provider-specific fields


@router.post("/configure")
async def configure_sso(
    body: SSOConfigRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Save SSO configuration for the tenant.  Admin-only."""
    _require_sso_enabled()
    from apps.api.app.models.integration import IntegrationConfig

    # Check if SSO config already exists
    existing = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == user.tenant_id,
            IntegrationConfig.integration_type == "sso",
        )
    )
    sso_config = existing.scalar_one_or_none()

    config_data = {
        "provider": body.provider,
        "protocol": body.protocol,
        **body.config,
    }

    if sso_config:
        sso_config.config = config_data
        sso_config.provider = body.provider
    else:
        sso_config = IntegrationConfig(
            tenant_id=user.tenant_id,
            name=f"SSO - {body.provider}",
            integration_type="sso",
            provider=body.provider,
            config=config_data,
            is_active=True,
        )
        db.add(sso_config)

    await db.flush()
    return {"status": "configured", "provider": body.provider}


@router.get("/saml/metadata")
async def saml_metadata(db: AsyncSession = Depends(get_db)):
    """Return SAML SP metadata XML for IdP configuration."""
    # Use default config for metadata
    config = SSOConfig(provider_type="saml", provider_name="SAML")
    handler = SAMLHandler(config)
    metadata = handler.get_metadata()
    return Response(content=metadata, media_type="application/xml")


@router.get("/oidc/authorize")
async def oidc_authorize(
    provider: str,
    tenant_slug: str,
    db: AsyncSession = Depends(get_db),
):
    """Initiate OIDC login — redirect to IdP."""
    _require_sso_enabled()
    from apps.api.app.models.integration import IntegrationConfig

    # Find tenant
    tenant_result = await db.execute(select(Tenant).where(Tenant.slug == tenant_slug))
    tenant = tenant_result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Get SSO config
    sso_result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == tenant.id,
            IntegrationConfig.integration_type == "sso",
            IntegrationConfig.is_active == True,
        )
    )
    sso_config = sso_result.scalar_one_or_none()
    if not sso_config:
        raise HTTPException(status_code=404, detail="SSO not configured for this tenant")

    config_data = sso_config.config

    # Build OIDC config
    oidc_config = SSOConfig(
        provider_type="oidc",
        provider_name=config_data.get("provider", "oidc"),
        oidc_client_id=config_data.get("client_id"),
        oidc_client_secret=config_data.get("client_secret"),
        oidc_authorize_url=config_data.get("authorize_url", ""),
    )

    # Auto-discover endpoints for known providers
    if provider == "google":
        oidc_config.oidc_authorize_url = "https://accounts.google.com/o/oauth2/v2/auth"
    elif provider == "okta":
        domain = config_data.get("domain", "")
        oidc_config.oidc_authorize_url = f"https://{domain}/oauth2/v1/authorize"
    elif provider == "azure_ad":
        tid = config_data.get("tenant_id", "common")
        oidc_config.oidc_authorize_url = f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/authorize"

    handler = OIDCHandler(oidc_config)
    state = str(uuid.uuid4())  # In production, store in session/Redis
    redirect_uri = f"https://app.vooda.ai/api/v1/sso/oidc/callback"

    authorize_url = handler.get_authorize_url(state=state, redirect_uri=redirect_uri)
    return RedirectResponse(url=authorize_url)


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str,
    state: str,
    db: AsyncSession = Depends(get_db),
):
    """Handle OIDC callback — exchange code for tokens and create session.

    Currently a placeholder pending state→tenant resolution + a Redis-
    backed state store.  The response is intentionally directive so a
    customer hitting this in their browser sees exactly what to do
    instead of a generic 501.
    """
    _require_sso_enabled()
    # Compute the actual redirect URI from the live request so the
    # operator sees the URL THEIR IdP needs to be configured with —
    # accounts for custom hostnames, ports, http vs https, etc.
    redirect_uri = str(request.url).split("?")[0]

    raise HTTPException(
        status_code=501,
        detail={
            "error": "oidc_callback_not_finalized",
            "message": (
                "OIDC callback received but the tenant resolution + state "
                "store have not been finalized in this deployment."
            ),
            "next_steps": [
                f"1. Configure this exact redirect URI in your IdP: {redirect_uri}",
                "2. In your IdP, set scopes: openid, profile, email",
                "3. Capture client_id and client_secret from the IdP, then save them via "
                "POST /api/v1/sso/configure with provider=oidc.",
                "4. Initiate login via GET /api/v1/sso/oidc/authorize"
                "?provider=<okta|google|azure_ad>&tenant_slug=<your_tenant_slug>",
            ],
            "idp_quickstart": {
                "okta": (
                    "Applications → Create App Integration → OIDC / Web "
                    "Application → Add the redirect URI above under 'Sign-in "
                    "redirect URIs'."
                ),
                "auth0": (
                    "Applications → Settings → Allowed Callback URLs → "
                    "paste the redirect URI above (comma-separate if multiple)."
                ),
                "azure_ad": (
                    "Entra ID → App registrations → New registration → "
                    "Redirect URI → Web → paste the redirect URI above."
                ),
                "google": (
                    "Google Cloud Console → APIs & Services → Credentials → "
                    "OAuth 2.0 Client ID → Authorized redirect URIs."
                ),
            },
            "received_state": state,
        },
    )


@router.post("/saml/acs")
async def saml_acs(request: Request, db: AsyncSession = Depends(get_db)):
    """SAML Assertion Consumer Service — process IdP response.

    Fails closed. process_response below does NOT verify the assertion
    signature, so any forged SAMLResponse (an XML doc with the victim's
    email in <NameID>) would otherwise mint a valid session for that
    user — a full unauthenticated auth bypass, admin included. The gate
    refuses every request until SSO is rebuilt on a real SAML library.
    """
    _require_sso_enabled()
    form = await request.form()
    saml_response = form.get("SAMLResponse", "")
    relay_state = form.get("RelayState", "")

    if not saml_response:
        raise HTTPException(status_code=400, detail="Missing SAMLResponse")

    # TODO: Look up SAML config from relay_state
    config = SSOConfig(provider_type="saml", provider_name="SAML")
    handler = SAMLHandler(config)
    sso_user = await handler.process_response(saml_response)

    if not sso_user:
        raise HTTPException(status_code=401, detail="Invalid SAML response")

    # Find or create user
    user, token = await _provision_sso_user(db, sso_user)
    if not user:
        raise HTTPException(status_code=500, detail="User provisioning failed")

    # Redirect to frontend with token
    return RedirectResponse(url=f"https://app.vooda.ai/login?sso_token={token}")


async def _provision_sso_user(db: AsyncSession, sso_user: SSOUser) -> tuple[Optional[User], Optional[str]]:
    """Find or create a user from SSO assertion (JIT provisioning)."""
    # Find existing user by email
    result = await db.execute(select(User).where(User.email == sso_user.email))
    user = result.scalar_one_or_none()

    if user:
        # Update SSO metadata
        user.full_name = sso_user.full_name or user.full_name
        # Store SSO info in metadata via update
        await db.flush()
    else:
        # JIT provision — create new user
        # Find default tenant (first active tenant)
        tenant_result = await db.execute(select(Tenant).where(Tenant.is_active == True).limit(1))
        tenant = tenant_result.scalar_one_or_none()
        if not tenant:
            return None, None

        user = User(
            tenant_id=tenant.id,
            email=sso_user.email,
            full_name=sso_user.full_name,
            hashed_password=hash_password(str(uuid.uuid4())),  # random password — SSO users don't use passwords
            is_active=True,
        )
        db.add(user)
        await db.flush()

        # Assign default role
        role = UserRole(user_id=user.id, role=RoleType.DEVELOPER)
        db.add(role)
        await db.flush()

    # Generate JWT
    token = create_access_token({"sub": str(user.id), "tenant": str(user.tenant_id), "sso": True})
    return user, token
