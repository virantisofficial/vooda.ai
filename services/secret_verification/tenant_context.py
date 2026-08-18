# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""
Tenant Context Extraction — finds tenant identifiers in the file
surrounding a finding so tenant-scoped verifiers can actually verify
instead of returning "unsupported".

Many providers (Okta, Auth0, Zendesk, Shopify, Supabase, Jira, etc.) are
multi-tenant — their verification endpoint includes the customer's
subdomain/project URL/app ID. Without that context, the verifier can
only return "unsupported".

In practice, the tenant identifier is almost always visible in the same
file as the API key — developers write URLs like
`https://company.zendesk.com/api/...` or env vars like
`AUTH0_DOMAIN=company.us.auth0.com` right next to the key.

This module parses the file and populates source_metadata with the
extracted tenant values. The worker's verification step injects it
into the verifier dispatcher call.
"""

import re
from typing import Optional


# ── Per-provider extraction patterns ─────────────────────────
#
# Each provider maps to (field_name_expected_by_verifier, [regex_patterns]).
# The FIRST capture group in each pattern is the tenant value.
# Patterns are tried in order; first match wins.

_TENANT_PATTERNS: dict[str, tuple[str, list[str]]] = {
    # Okta — subdomain or full .okta.com host
    "okta": ("tenant_domain", [
        r'https?://([a-z0-9-]+\.okta\.com)',
        r'https?://([a-z0-9-]+\.oktapreview\.com)',
        r'(?i)OKTA_?DOMAIN\s*[=:]\s*[\'"]?([a-z0-9.-]+\.okta(?:preview)?\.com)',
        r'(?i)OKTA_?ORG(?:_URL)?\s*[=:]\s*[\'"]?(?:https?://)?([a-z0-9-]+\.okta\.com)',
    ]),

    # Auth0 — tenant domain
    "auth0": ("tenant_domain", [
        r'https?://([a-z0-9-]+\.(?:us|eu|au|jp)\.auth0\.com)',
        r'https?://([a-z0-9-]+\.auth0\.com)',
        r'(?i)AUTH0_?DOMAIN\s*[=:]\s*[\'"]?([a-z0-9.-]+\.auth0\.com)',
        r'(?i)AUTH0_?ISSUER\s*[=:]\s*[\'"]?(?:https?://)?([a-z0-9.-]+\.auth0\.com)',
    ]),

    # Zendesk — subdomain only (verifier appends .zendesk.com)
    "zendesk": ("tenant_domain", [
        r'https?://([a-z0-9-]+)\.zendesk\.com',
        r'(?i)ZENDESK_?SUBDOMAIN\s*[=:]\s*[\'"]?([a-z0-9-]+)',
        r'(?i)ZENDESK_?URL\s*[=:]\s*[\'"]?(?:https?://)?([a-z0-9-]+)\.zendesk\.com',
    ]),

    # Shopify — full myshopify.com domain
    "shopify": ("tenant_domain", [
        r'https?://([a-z0-9-]+\.myshopify\.com)',
        r'(?i)SHOPIFY_?SHOP\s*[=:]\s*[\'"]?([a-z0-9.-]+\.myshopify\.com)',
        r'(?i)SHOPIFY_?DOMAIN\s*[=:]\s*[\'"]?([a-z0-9.-]+\.myshopify\.com)',
    ]),

    # Algolia — 10-char uppercase application ID
    "algolia": ("app_id", [
        r'https?://([A-Z0-9]{10})-dsn\.algolia(?:net)?\.net',
        r'https?://([A-Z0-9]{10})\.algolia(?:net)?\.net',
        r'(?i)ALGOLIA_?(?:APP(?:LICATION)?)?_?ID\s*[=:]\s*[\'"]?([A-Z0-9]{10})',
        r'(?i)NEXT_PUBLIC_ALGOLIA_APP_ID\s*[=:]\s*[\'"]?([A-Z0-9]{10})',
        # Client-side SDK constructor: algoliasearch("APPID", "searchKey")
        r'algoliasearch\s*\(\s*[\'"]([A-Z0-9]{10})[\'"]',
    ]),

    # Supabase — project ref or full URL
    "supabase": ("project_url", [
        r'https?://([a-z0-9]+\.supabase\.(?:co|io))',
        r'(?i)SUPABASE_URL\s*[=:]\s*[\'"]?(?:https?://)?([a-z0-9.-]+\.supabase\.(?:co|io))',
        r'(?i)NEXT_PUBLIC_SUPABASE_URL\s*[=:]\s*[\'"]?(?:https?://)?([a-z0-9.-]+\.supabase\.(?:co|io))',
    ]),

    # Jira — atlassian.net domain
    "jira": ("tenant_domain", [
        r'https?://([a-z0-9-]+\.atlassian\.net)',
        r'(?i)JIRA_?URL\s*[=:]\s*[\'"]?(?:https?://)?([a-z0-9.-]+\.atlassian\.net)',
        r'(?i)JIRA_?DOMAIN\s*[=:]\s*[\'"]?([a-z0-9.-]+\.atlassian\.net)',
    ]),

    # Chronosphere — {company}.chronosphere.io
    "chronosphere": ("tenant_domain", [
        r'https?://([a-z0-9-]+\.chronosphere\.io)',
        r'(?i)CHRONOSPHERE_?URL\s*[=:]\s*[\'"]?(?:https?://)?([a-z0-9.-]+\.chronosphere\.io)',
    ]),

    # Deputy — subdomain
    "deputy": ("tenant_domain", [
        r'https?://([a-z0-9-]+)\.(?:[a-z]{2}\.)?deputy\.com',
        r'(?i)DEPUTY_?URL\s*[=:]\s*[\'"]?(?:https?://)?([a-z0-9-]+)\.(?:[a-z]{2}\.)?deputy\.com',
    ]),

    # BambooHR — subdomain
    "bamboohr": ("tenant_domain", [
        r'(?i)BAMBOO_?(?:HR_?)?SUBDOMAIN\s*[=:]\s*[\'"]?([a-z0-9-]+)',
        r'/api/gateway\.php/([a-z0-9-]+)/v1/',
        r'https?://api\.bamboohr\.com/api/gateway\.php/([a-z0-9-]+)',
    ]),

    # Octopus Deploy — full server URL
    "octopus": ("tenant_domain", [
        r'(https?://[a-z0-9-]+\.octopus\.app)',
        r'(?i)OCTOPUS_?URL\s*[=:]\s*[\'"]?(https?://[a-z0-9.-]+)',
    ]),

    # Jira — also need the email paired with the API token
    "jira_email": ("email", [
        r'(?i)JIRA_?(?:USER|EMAIL)\s*[=:]\s*[\'"]?([A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        r'(?i)ATLASSIAN_?EMAIL\s*[=:]\s*[\'"]?([A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})',
    ]),

    # Copper CRM — needs user email for X-PW-UserEmail header
    "copper": ("email", [
        r'(?i)COPPER_?(?:USER_?)?EMAIL\s*[=:]\s*[\'"]?([A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        r'(?i)X-PW-UserEmail[\'"]?\s*[:,]\s*[\'"]?([A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})',
    ]),

    # Trello — key AND user token (key is primary, token is secondary)
    "trello": ("user_token", [
        r'(?i)TRELLO_?TOKEN\s*[=:]\s*[\'"]?([A-Fa-f0-9]{64,})',
        r'(?i)trello.*[?&]token=([A-Fa-f0-9]{64,})',
    ]),

    # Gong — access key secret (paired with access key)
    "gong": ("gong_secret", [
        r'(?i)GONG_?(?:ACCESS_?)?(?:KEY_?)?SECRET\s*[=:]\s*[\'"]?([A-Za-z0-9+/=]{40,100})',
    ]),

    # BrowserStack — access key (paired with username)
    "browserstack": ("access_key", [
        r'(?i)BROWSERSTACK_?ACCESS_?KEY\s*[=:]\s*[\'"]?([A-Za-z0-9]{20,40})',
        r'(?i)BS_?ACCESS_?KEY\s*[=:]\s*[\'"]?([A-Za-z0-9]{20,40})',
    ]),

    # PayPal — client secret (paired with client id)
    "paypal": ("paypal_client_secret", [
        r'(?i)PAYPAL_?(?:CLIENT_?)?SECRET\s*[=:]\s*[\'"]?([A-Z0-9_-]{60,90})',
    ]),

    # Amadeus — paired client credentials
    "amadeus": ("amadeus_client_secret", [
        r'(?i)AMADEUS_?(?:CLIENT_?)?SECRET\s*[=:]\s*[\'"]?([A-Za-z0-9]{16})',
    ]),

    # Zoho — regional suffix (com / eu / in / au)
    "zoho": ("region", [
        r'accounts\.zoho\.(com|eu|in|au|com\.cn|com\.au)',
        r'(?i)ZOHO_?REGION\s*[=:]\s*[\'"]?(com|eu|in|au|com\.cn|com\.au)',
    ]),
}


def extract_tenant_context(
    provider: str,
    file_content: str,
    primary_line: int = 0,
    window_lines: int = 60,
) -> dict:
    """Extract tenant identifier(s) from surrounding file content.

    Args:
        provider: normalized provider name (e.g. "okta", "supabase")
        file_content: full content of the file containing the finding
        primary_line: 1-based line number of the primary finding; search
                      window centers here
        window_lines: number of lines around primary_line to search

    Returns:
        dict of source_metadata field → extracted value. Empty dict if
        no patterns match.
    """
    if not file_content or not provider:
        return {}

    out: dict[str, str] = {}

    # Build the search window. When primary_line is supplied we restrict
    # to ±window_lines to avoid cross-contamination from unrelated tenants
    # in large files. Without line context we search the entire file.
    if primary_line > 0:
        lines = file_content.splitlines()
        lo = max(0, primary_line - window_lines - 1)
        hi = min(len(lines), primary_line + window_lines)
        window = "\n".join(lines[lo:hi])
    else:
        window = file_content

    # Try direct pattern match for the provider
    for key, (field, patterns) in _TENANT_PATTERNS.items():
        # Match provider directly OR the "provider_role" composite keys
        # (e.g. "jira_email" → trigger when provider == "jira")
        if key == provider or key.startswith(provider + "_"):
            for pat in patterns:
                m = re.search(pat, window)
                if m:
                    out[field] = m.group(1)
                    break

    return out


def enrich_source_metadata_with_tenant(
    source_metadata: dict,
    provider: str,
    file_content: str,
    primary_line: int = 0,
) -> dict:
    """Return a copy of source_metadata with extracted tenant fields merged in.

    Existing fields in source_metadata take precedence — never override
    user-supplied values with extracted ones.
    """
    extracted = extract_tenant_context(provider, file_content, primary_line)
    if not extracted:
        return source_metadata
    enriched = dict(source_metadata or {})
    for field, value in extracted.items():
        if field not in enriched or not enriched[field]:
            enriched[field] = value
    return enriched
