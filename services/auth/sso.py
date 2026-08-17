# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
SSO Authentication Service — SAML 2.0 and OIDC handler.

Supports enterprise identity providers:
- SAML 2.0: Okta, Azure AD, OneLogin, PingIdentity, any SAML IdP
- OIDC: Google Workspace, Azure AD, Okta, Auth0, Keycloak, any OIDC provider
- LDAP/AD: via LDAP bind (future)

Flow:
1. User clicks "Sign in with SSO" on login page
2. Backend redirects to IdP (SAML AuthnRequest or OIDC authorize URL)
3. IdP authenticates user and redirects back with assertion/token
4. Backend validates assertion, creates/updates user, issues JWT
"""

import uuid
import structlog
from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = structlog.get_logger()


@dataclass
class SSOConfig:
    """Configuration for an SSO provider."""
    provider_type: str  # "saml" or "oidc"
    provider_name: str  # display name: "Okta", "Azure AD", etc.

    # SAML-specific
    saml_entity_id: Optional[str] = None
    saml_sso_url: Optional[str] = None
    saml_certificate: Optional[str] = None  # X.509 cert for signature verification
    saml_acs_url: Optional[str] = None  # Assertion Consumer Service URL

    # OIDC-specific
    oidc_issuer: Optional[str] = None
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None
    oidc_authorize_url: Optional[str] = None
    oidc_token_url: Optional[str] = None
    oidc_userinfo_url: Optional[str] = None
    oidc_scopes: list[str] = field(default_factory=lambda: ["openid", "email", "profile"])

    # Common
    attribute_mapping: dict = field(default_factory=lambda: {
        "email": "email",
        "full_name": "name",
        "given_name": "given_name",
        "family_name": "family_name",
    })
    default_role: str = "developer"
    auto_create_users: bool = True
    jit_provisioning: bool = True  # Just-In-Time user provisioning


@dataclass
class SSOUser:
    """User info extracted from SSO assertion."""
    email: str
    full_name: str
    sso_provider: str
    sso_subject_id: str
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    groups: list[str] = field(default_factory=list)
    raw_attributes: dict = field(default_factory=dict)


# ═══ SAML Handler ════════════════════════════════════════

class SAMLHandler:
    """SAML 2.0 authentication handler."""

    def __init__(self, config: SSOConfig):
        self.config = config

    def get_login_url(self, relay_state: str = "") -> str:
        """
        Generate SAML AuthnRequest URL.
        In production, use python3-saml library for proper request signing.
        """
        import urllib.parse

        # Simplified — production should use python3-saml
        params = {
            "SAMLRequest": "",  # Base64-encoded AuthnRequest XML
            "RelayState": relay_state,
        }
        return f"{self.config.saml_sso_url}?{urllib.parse.urlencode(params)}"

    def get_metadata(self) -> str:
        """Generate SP metadata XML for the IdP to consume."""
        acs_url = self.config.saml_acs_url or "https://app.vooda.ai/api/v1/sso/saml/acs"
        entity_id = self.config.saml_entity_id or "https://app.vooda.ai"

        return f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{entity_id}">
    <md:SPSSODescriptor
        AuthnRequestsSigned="true"
        WantAssertionsSigned="true"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="{acs_url}"
            index="0" />
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    </md:SPSSODescriptor>
</md:EntityDescriptor>"""

    async def process_response(self, saml_response: str) -> Optional[SSOUser]:
        """
        Process SAML Response from IdP.
        In production, validate signature with python3-saml.
        """
        try:
            import base64
            from defusedxml import ElementTree as ET

            # Decode response
            xml_data = base64.b64decode(saml_response)
            root = ET.fromstring(xml_data)

            # Extract namespace
            ns = {
                "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
                "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            }

            # Extract NameID (email)
            name_id = root.find(".//saml:NameID", ns)
            email = name_id.text if name_id is not None else None

            if not email:
                logger.error("saml_no_email_in_response")
                return None

            # Extract attributes
            attrs = {}
            for attr in root.findall(".//saml:Attribute", ns):
                name = attr.get("Name", "")
                values = [v.text for v in attr.findall("saml:AttributeValue", ns) if v.text]
                if values:
                    attrs[name] = values[0] if len(values) == 1 else values

            # Map attributes
            mapping = self.config.attribute_mapping
            full_name = attrs.get(mapping.get("full_name", "name"), "")
            if not full_name:
                given = attrs.get(mapping.get("given_name", "given_name"), "")
                family = attrs.get(mapping.get("family_name", "family_name"), "")
                full_name = f"{given} {family}".strip() or email.split("@")[0]

            return SSOUser(
                email=email,
                full_name=full_name,
                sso_provider="saml",
                sso_subject_id=email,
                groups=attrs.get("groups", attrs.get("memberOf", [])),
                raw_attributes=attrs,
            )

        except Exception as e:
            logger.error("saml_response_processing_failed", error=str(e)[:200])
            return None


# ═══ OIDC Handler ════════════════════════════════════════

class OIDCHandler:
    """OpenID Connect authentication handler."""

    def __init__(self, config: SSOConfig):
        self.config = config

    def get_authorize_url(self, state: str, redirect_uri: str) -> str:
        """Generate OIDC authorization URL."""
        import urllib.parse

        params = {
            "client_id": self.config.oidc_client_id,
            "response_type": "code",
            "scope": " ".join(self.config.oidc_scopes),
            "redirect_uri": redirect_uri,
            "state": state,
        }
        base = self.config.oidc_authorize_url
        return f"{base}?{urllib.parse.urlencode(params)}"

    async def exchange_code(self, code: str, redirect_uri: str) -> Optional[SSOUser]:
        """Exchange authorization code for tokens and user info."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                # Exchange code for tokens
                token_resp = await client.post(
                    self.config.oidc_token_url,
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": redirect_uri,
                        "client_id": self.config.oidc_client_id,
                        "client_secret": self.config.oidc_client_secret,
                    },
                )

                if token_resp.status_code != 200:
                    logger.error("oidc_token_exchange_failed", status=token_resp.status_code)
                    return None

                tokens = token_resp.json()
                access_token = tokens.get("access_token")

                if not access_token:
                    logger.error("oidc_no_access_token")
                    return None

                # Get user info
                userinfo_url = self.config.oidc_userinfo_url
                if not userinfo_url:
                    # Try to derive from issuer
                    userinfo_url = f"{self.config.oidc_issuer}/userinfo"

                user_resp = await client.get(
                    userinfo_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )

                if user_resp.status_code != 200:
                    logger.error("oidc_userinfo_failed", status=user_resp.status_code)
                    return None

                userinfo = user_resp.json()

                email = userinfo.get("email")
                if not email:
                    logger.error("oidc_no_email")
                    return None

                full_name = userinfo.get("name", "")
                if not full_name:
                    given = userinfo.get("given_name", "")
                    family = userinfo.get("family_name", "")
                    full_name = f"{given} {family}".strip() or email.split("@")[0]

                return SSOUser(
                    email=email,
                    full_name=full_name,
                    sso_provider="oidc",
                    sso_subject_id=userinfo.get("sub", email),
                    given_name=userinfo.get("given_name"),
                    family_name=userinfo.get("family_name"),
                    groups=userinfo.get("groups", []),
                    raw_attributes=userinfo,
                )

        except Exception as e:
            logger.error("oidc_exchange_failed", error=str(e)[:200])
            return None


# ═══ Provider Presets ════════════════════════════════════

PROVIDER_PRESETS = {
    "okta": {
        "name": "Okta",
        "supports": ["saml", "oidc"],
        "oidc_discovery": "https://{domain}/.well-known/openid-configuration",
        "config_fields": [
            {"key": "domain", "label": "Okta Domain", "placeholder": "yourcompany.okta.com", "required": True},
            {"key": "client_id", "label": "Client ID", "required": True},
            {"key": "client_secret", "label": "Client Secret", "type": "password", "required": True},
        ],
    },
    "azure_ad": {
        "name": "Azure AD (Entra ID)",
        "supports": ["saml", "oidc"],
        "oidc_discovery": "https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration",
        "config_fields": [
            {"key": "tenant_id", "label": "Tenant ID", "required": True},
            {"key": "client_id", "label": "Application (Client) ID", "required": True},
            {"key": "client_secret", "label": "Client Secret", "type": "password", "required": True},
        ],
    },
    "google": {
        "name": "Google Workspace",
        "supports": ["oidc"],
        "oidc_discovery": "https://accounts.google.com/.well-known/openid-configuration",
        "config_fields": [
            {"key": "client_id", "label": "Client ID", "required": True},
            {"key": "client_secret", "label": "Client Secret", "type": "password", "required": True},
            {"key": "hosted_domain", "label": "Hosted Domain (optional)", "placeholder": "yourcompany.com"},
        ],
    },
    "onelogin": {
        "name": "OneLogin",
        "supports": ["saml", "oidc"],
        "config_fields": [
            {"key": "subdomain", "label": "OneLogin Subdomain", "required": True},
            {"key": "client_id", "label": "Client ID", "required": True},
            {"key": "client_secret", "label": "Client Secret", "type": "password", "required": True},
        ],
    },
    "ping_identity": {
        "name": "PingIdentity",
        "supports": ["saml", "oidc"],
        "config_fields": [
            {"key": "environment_id", "label": "Environment ID", "required": True},
            {"key": "client_id", "label": "Client ID", "required": True},
            {"key": "client_secret", "label": "Client Secret", "type": "password", "required": True},
        ],
    },
    "keycloak": {
        "name": "Keycloak",
        "supports": ["saml", "oidc"],
        "config_fields": [
            {"key": "server_url", "label": "Keycloak Server URL", "required": True},
            {"key": "realm", "label": "Realm", "required": True},
            {"key": "client_id", "label": "Client ID", "required": True},
            {"key": "client_secret", "label": "Client Secret", "type": "password", "required": True},
        ],
    },
    "saml_generic": {
        "name": "SAML 2.0 (Generic)",
        "supports": ["saml"],
        "config_fields": [
            {"key": "entity_id", "label": "IdP Entity ID", "required": True},
            {"key": "sso_url", "label": "SSO URL", "required": True},
            {"key": "certificate", "label": "X.509 Certificate", "type": "textarea", "required": True},
        ],
    },
    "oidc_generic": {
        "name": "OIDC (Generic)",
        "supports": ["oidc"],
        "config_fields": [
            {"key": "issuer", "label": "Issuer URL", "required": True},
            {"key": "client_id", "label": "Client ID", "required": True},
            {"key": "client_secret", "label": "Client Secret", "type": "password", "required": True},
            {"key": "authorize_url", "label": "Authorization Endpoint", "required": True},
            {"key": "token_url", "label": "Token Endpoint", "required": True},
        ],
    },
    "ldap": {
        "name": "LDAP / Active Directory",
        "supports": ["ldap"],
        "config_fields": [
            {"key": "server_url", "label": "LDAP Server URL", "placeholder": "ldaps://ldap.example.com:636", "required": True},
            {"key": "bind_dn", "label": "Bind DN", "required": True},
            {"key": "bind_password", "label": "Bind Password", "type": "password", "required": True},
            {"key": "base_dn", "label": "Base DN", "placeholder": "dc=example,dc=com", "required": True},
            {"key": "user_filter", "label": "User Search Filter", "placeholder": "(sAMAccountName={username})", "required": True},
        ],
    },
}


def get_sso_presets() -> dict:
    """Return all SSO provider presets for the settings UI."""
    return PROVIDER_PRESETS
