# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Miscellaneous cloud provider detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-DO-001",
        title="DigitalOcean Personal Access Token",
        secret_type="digitalocean_token",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(dop_v1_[a-f0-9]{64})(?:[^A-Za-z0-9]|$)',
        keywords=["dop_v1_"],
        confidence=0.98,
        description="DigitalOcean personal access token.",
        fix_hint="Revoke at DigitalOcean → API → Tokens. Generate a new scoped token.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-DO-002",
        title="DigitalOcean OAuth Token",
        secret_type="digitalocean_oauth",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(doo_v1_[a-f0-9]{64})(?:[^A-Za-z0-9]|$)',
        keywords=["doo_v1_"],
        confidence=0.98,
        description="DigitalOcean OAuth application token.",
        fix_hint="Revoke the OAuth application authorization.",
    ),
    # VOODA-SEC-ALI-001 removed 2026-05-22 (Track-A Phase 5, Option A).
    # Exact-pattern duplicate consolidated into VOODA-SEC-ALIBABA-AKID-001.
    # The canonical was escalated high → critical to preserve the
    # severity classification ALI-001 carried.
    # See services/secret_scan/detectors/registry.py:RULE_ID_ALIASES.
    SecretRule(
        rule_id="VOODA-SEC-HEROKU-001",
        title="Heroku API Key",
        secret_type="heroku_api_key",
        severity="high",
        pattern=r'(?:heroku_api_key|HEROKU_API_KEY|heroku_auth_token)\s*[=:]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']?',
        keywords=["heroku_api_key", "HEROKU_API_KEY", "heroku_auth_token"],
        confidence=0.90,
        description="Heroku API key or auth token.",
        fix_hint="Regenerate at Heroku Dashboard → Account Settings → API Key.",
    ),
]
