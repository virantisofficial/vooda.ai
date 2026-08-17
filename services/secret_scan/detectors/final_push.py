# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Final 10 rules to cross 400+ threshold.
High-confidence prefix-based patterns for modern platforms."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-VERCEL-003", title="Vercel OIDC Token", secret_type="vercel_oidc_token", severity="high",
        pattern=r'(vc_prod_[a-zA-Z0-9]{24,})', keywords=["vc_prod_"], confidence=0.95,
        description="Vercel production OIDC token.", fix_hint="Regenerate at Vercel → Settings → Tokens."),
    SecretRule(rule_id="VOODA-SEC-PLANETSCALE-004", title="PlanetScale Service Token", secret_type="planetscale_service_token", severity="high",
        pattern=r'(pscale_tkn_[a-zA-Z0-9\-_]{32,})', keywords=["pscale_tkn_"], confidence=0.98,
        description="PlanetScale database service token.", fix_hint="Revoke at PlanetScale → Organization → Service Tokens."),
    SecretRule(rule_id="VOODA-SEC-TURSO-002", title="Turso Database URL", secret_type="turso_db_url", severity="high",
        pattern=r'(libsql://[a-zA-Z0-9\-]+\.turso\.io)', keywords=["turso.io", "libsql://"], confidence=0.90,
        description="Turso database connection URL.", fix_hint="Check if auth token is also exposed. Rotate at Turso Dashboard."),
    SecretRule(rule_id="VOODA-SEC-NHOST-001", title="Nhost Admin Secret", secret_type="nhost_admin_secret", severity="critical",
        pattern=r'(?:NHOST_ADMIN_SECRET|nhost_admin_secret)\s*[=:]\s*["\']?([a-f0-9]{32,})["\']?', keywords=["NHOST_ADMIN_SECRET", "nhost_admin"], confidence=0.85,
        description="Nhost backend-as-a-service admin secret.", fix_hint="Regenerate at Nhost → Settings → Hasura."),
    SecretRule(rule_id="VOODA-SEC-TRIGGER-001", title="Trigger.dev API Key", secret_type="triggerdev_key", severity="high",
        pattern=r'(tr_(?:dev|prod)_[a-zA-Z0-9]{24,})', keywords=["tr_dev_", "tr_prod_"], confidence=0.95,
        description="Trigger.dev background jobs API key.", fix_hint="Regenerate at Trigger.dev → Project → API Keys."),
    SecretRule(rule_id="VOODA-SEC-INNGEST-001", title="Inngest Signing Key", secret_type="inngest_key", severity="high",
        pattern=r'(signkey-(?:prod|test)-[a-f0-9]{32,})', keywords=["signkey-"], confidence=0.95,
        description="Inngest event-driven function signing key.", fix_hint="Regenerate at Inngest → Settings → Signing Key."),
    SecretRule(rule_id="VOODA-SEC-UPSTASH-002", title="Upstash QStash Token", secret_type="upstash_qstash", severity="high",
        pattern=r'(?:QSTASH_TOKEN|qstash_token)\s*[=:]\s*["\']?(eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)["\']?', keywords=["QSTASH_TOKEN", "qstash_token"], confidence=0.85,
        description="Upstash QStash message queue token.", fix_hint="Regenerate at Upstash Console → QStash → Settings."),
    SecretRule(rule_id="VOODA-SEC-AXIOM-001", title="Axiom API Token", secret_type="axiom_token", severity="high",
        pattern=r'(xaat-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', keywords=["xaat-"], confidence=0.98,
        description="Axiom observability API token.", fix_hint="Regenerate at Axiom → Settings → API Tokens."),
    SecretRule(rule_id="VOODA-SEC-TINYBIRD-001", title="Tinybird Admin Token", secret_type="tinybird_token", severity="high",
        pattern=r'(p\.eyJ[a-zA-Z0-9\-_]{80,})', keywords=["p.eyJ"], confidence=0.85,
        description="Tinybird real-time data platform admin token.", fix_hint="Regenerate at Tinybird → Tokens."),
    SecretRule(rule_id="VOODA-SEC-BASELIME-001", title="Baselime API Key", secret_type="baselime_key", severity="medium",
        pattern=r'(?:baselime|BASELIME)[\w\s=:"\'-]*([a-f0-9]{40,})', keywords=["baselime", "BASELIME"], confidence=0.75,
        description="Baselime serverless observability API key.", fix_hint="Regenerate at Baselime → Settings → API Keys."),
]
