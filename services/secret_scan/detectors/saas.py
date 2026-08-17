# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""SaaS platform detectors (Shopify, HubSpot, Datadog, New Relic, etc.)."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-SHOPIFY-001", title="Shopify Access Token", secret_type="shopify_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(shpat_[a-fA-F0-9]{32})(?:[^A-Za-z0-9]|$)', keywords=["shpat_"], confidence=0.98,
        description="Shopify Admin API access token.", fix_hint="Revoke at Shopify Admin → Apps → Develop apps."),
    SecretRule(rule_id="VOODA-SEC-SHOPIFY-002", title="Shopify Shared Secret", secret_type="shopify_shared_secret", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(shpss_[a-fA-F0-9]{32})(?:[^A-Za-z0-9]|$)', keywords=["shpss_"], confidence=0.98,
        description="Shopify shared secret.", fix_hint="Regenerate in Shopify app settings."),
    SecretRule(rule_id="VOODA-SEC-DATADOG-001", title="Datadog API Key", secret_type="datadog_api_key", severity="high",
        pattern=r'(?:datadog[_-]?api[_-]?key|DD_API_KEY|DATADOG_API_KEY)\s*[=:]\s*["\']?([a-f0-9]{32})["\']?',
        keywords=["datadog", "DD_API_KEY", "DATADOG_API_KEY"], confidence=0.80, description="Datadog API key.", fix_hint="Revoke at Datadog → Organization Settings → API Keys."),
    SecretRule(rule_id="VOODA-SEC-DATADOG-002", title="Datadog Application Key", secret_type="datadog_app_key", severity="high",
        pattern=r'(?:datadog[_-]?app[_-]?key|DD_APP_KEY|DATADOG_APP_KEY)\s*[=:]\s*["\']?([a-f0-9]{40})["\']?',
        keywords=["DD_APP_KEY", "DATADOG_APP_KEY", "datadog_app"], confidence=0.80, description="Datadog application key.", fix_hint="Revoke at Datadog → Organization Settings → Application Keys."),
    SecretRule(rule_id="VOODA-SEC-NEWRELIC-001", title="New Relic API Key", secret_type="newrelic_api_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(NRAK-[A-Z0-9]{27})(?:[^A-Za-z0-9]|$)', keywords=["NRAK-"], confidence=0.98,
        description="New Relic API key.", fix_hint="Regenerate at New Relic → API Keys."),
    SecretRule(rule_id="VOODA-SEC-NEWRELIC-002", title="New Relic License Key", secret_type="newrelic_license_key", severity="high",
        pattern=r'(?:new_relic_license_key|NEW_RELIC_LICENSE_KEY|newrelic_key)\s*[=:]\s*["\']?([a-f0-9]{40})["\']?',
        keywords=["new_relic_license", "NEW_RELIC_LICENSE", "newrelic_key"], confidence=0.80, description="New Relic ingest license key.", fix_hint="Rotate at New Relic → API Keys."),
    SecretRule(rule_id="VOODA-SEC-HUBSPOT-001", title="HubSpot API Key", secret_type="hubspot_api_key", severity="high",
        pattern=r'(?:hubspot[_-]?api[_-]?key|HUBSPOT_API_KEY)\s*[=:]\s*["\']?([a-f0-9\-]{36})["\']?',
        keywords=["hubspot", "HUBSPOT"], confidence=0.75, description="HubSpot API key.", fix_hint="Regenerate at HubSpot → Settings → Integrations → API Key."),
    SecretRule(rule_id="VOODA-SEC-INTERCOM-002", title="Intercom Access Token", secret_type="intercom_token", severity="high",
        pattern=r'(?:intercom[_-]?(?:access[_-]?)?token|INTERCOM_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9=_\-]{20,})["\']?',
        keywords=["intercom", "INTERCOM"], confidence=0.70, description="Intercom access token.", fix_hint="Regenerate at Intercom → Settings → Developers → Access Token."),
    SecretRule(rule_id="VOODA-SEC-LINEAR-001", title="Linear API Key", secret_type="linear_api_key", severity="medium",
        pattern=r'(?:^|[^A-Za-z0-9])(lin_api_[A-Za-z0-9]{40,})(?:[^A-Za-z0-9]|$)', keywords=["lin_api_"], confidence=0.98,
        description="Linear project management API key.", fix_hint="Revoke at Linear → Settings → API."),
    SecretRule(rule_id="VOODA-SEC-SENTRY-001", title="Sentry Auth Token", secret_type="sentry_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(sntrys_[A-Za-z0-9]{50,})(?:[^A-Za-z0-9]|$)', keywords=["sntrys_"], confidence=0.98,
        description="Sentry authentication token.", fix_hint="Revoke at Sentry → Settings → Auth Tokens."),
    SecretRule(rule_id="VOODA-SEC-SENTRY-002", title="Sentry DSN", secret_type="sentry_dsn", severity="medium",
        pattern=r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+',
        keywords=["ingest.sentry.io"], confidence=0.90, description="Sentry DSN with embedded key.", fix_hint="Rotate DSN at Sentry → Project Settings → Client Keys."),
    SecretRule(rule_id="VOODA-SEC-ALGOLIA-001", title="Algolia Admin API Key", secret_type="algolia_admin_key", severity="high",
        pattern=r'(?:algolia[_-]?admin[_-]?key|ALGOLIA_ADMIN_KEY)\s*[=:]\s*["\']?([a-f0-9]{32})["\']?',
        keywords=["algolia", "ALGOLIA"], confidence=0.75, description="Algolia admin API key.", fix_hint="Rotate at Algolia → Settings → API Keys."),
]
