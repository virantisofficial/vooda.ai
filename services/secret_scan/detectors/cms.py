# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""CMS and content platform detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-CONTENTFUL-001", title="Contentful Delivery API Token", secret_type="contentful_token", severity="medium",
        pattern=r'(?:contentful[_-]?(?:delivery[_-]?)?(?:api[_-]?)?token|CONTENTFUL_ACCESS_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{43,})["\']?',
        keywords=["contentful", "CONTENTFUL"], confidence=0.75, description="Contentful CMS delivery API token.", fix_hint="Regenerate at Contentful → Settings → API Keys."),
    SecretRule(rule_id="VOODA-SEC-SANITY-001", title="Sanity API Token", secret_type="sanity_token", severity="medium",
        pattern=r'(?:sanity[_-]?(?:api[_-]?)?token|SANITY_API_TOKEN|SANITY_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9]{80,})["\']?',
        keywords=["sanity_token", "SANITY_TOKEN", "SANITY_API"], confidence=0.75, description="Sanity CMS API token.", fix_hint="Regenerate at Sanity → Manage → API → Tokens."),
    SecretRule(rule_id="VOODA-SEC-STRAPI-002", title="Strapi Admin JWT Secret", secret_type="strapi_jwt_secret", severity="high",
        pattern=r'(?:ADMIN_JWT_SECRET|APP_KEYS|API_TOKEN_SALT)\s*[=:]\s*["\']?([A-Za-z0-9+/=]{20,})["\']?',
        keywords=["ADMIN_JWT_SECRET", "API_TOKEN_SALT"], confidence=0.70, description="Strapi CMS admin JWT secret or API token salt.", fix_hint="Regenerate secrets in Strapi .env configuration."),
    SecretRule(rule_id="VOODA-SEC-PRISMIC-002", title="Prismic Access Token", secret_type="prismic_token", severity="medium",
        pattern=r'(?:prismic[_-]?(?:access[_-]?)?token|PRISMIC_ACCESS_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{40,})["\']?',
        keywords=["prismic", "PRISMIC"], confidence=0.75, description="Prismic headless CMS access token.", fix_hint="Regenerate at Prismic → Settings → API & Security."),
    SecretRule(rule_id="VOODA-SEC-CLERK-001", title="Clerk Secret Key", secret_type="clerk_secret_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(sk_live_[A-Za-z0-9]{27,})(?:[^A-Za-z0-9]|$)',
        keywords=["sk_live_"], confidence=0.70, description="Clerk authentication secret key.", fix_hint="Rotate at Clerk Dashboard → API Keys."),
    SecretRule(rule_id="VOODA-SEC-WORKOS-002", title="WorkOS API Key", secret_type="workos_api_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(sk_[a-z]+_[A-Za-z0-9]{20,})(?:[^A-Za-z0-9]|$)',
        keywords=["workos", "WORKOS"], confidence=0.60, description="WorkOS API key.", fix_hint="Rotate at WorkOS Dashboard → API Keys."),
]
