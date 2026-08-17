# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Cloud infrastructure detectors (Vercel, Netlify, Supabase, Cloudflare, Fly.io, Render, etc.)."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-VERCEL-001", title="Vercel Token", secret_type="vercel_token", severity="high",
        pattern=r'(?:vercel[_-]?token|VERCEL_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9]{24,})["\']?',
        keywords=["vercel_token", "VERCEL_TOKEN"], confidence=0.75, description="Vercel deployment token.", fix_hint="Regenerate at Vercel → Settings → Tokens."),
    SecretRule(rule_id="VOODA-SEC-NETLIFY-001", title="Netlify Personal Access Token", secret_type="netlify_token", severity="high",
        pattern=r'(?:netlify[_-]?(?:auth[_-]?)?token|NETLIFY_AUTH_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{40,})["\']?',
        keywords=["netlify", "NETLIFY"], confidence=0.75, description="Netlify personal access token.", fix_hint="Regenerate at Netlify → User Settings → Applications → Personal access tokens."),
    SecretRule(rule_id="VOODA-SEC-SUPABASE-001", title="Supabase Service Role Key", secret_type="supabase_service_key", severity="critical",
        pattern=r'(?:supabase[_-]?service[_-]?(?:role[_-]?)?key|SUPABASE_SERVICE_ROLE_KEY)\s*[=:]\s*["\']?(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)["\']?',
        keywords=["supabase_service", "SUPABASE_SERVICE"], confidence=0.90, description="Supabase service role key with full database access.", fix_hint="Rotate at Supabase → Project Settings → API."),
    SecretRule(rule_id="VOODA-SEC-CF-001", title="Cloudflare API Token", secret_type="cloudflare_api_token", severity="high",
        pattern=r'(?:cloudflare[_-]?api[_-]?token|CF_API_TOKEN|CLOUDFLARE_API_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{40,})["\']?',
        keywords=["cloudflare", "CF_API_TOKEN", "CLOUDFLARE_API"], confidence=0.75, description="Cloudflare API token.", fix_hint="Revoke at Cloudflare → My Profile → API Tokens."),
    SecretRule(rule_id="VOODA-SEC-CF-002", title="Cloudflare Global API Key", secret_type="cloudflare_global_key", severity="critical",
        pattern=r'(?:cloudflare[_-]?api[_-]?key|CF_API_KEY|CLOUDFLARE_API_KEY)\s*[=:]\s*["\']?([a-f0-9]{37})["\']?',
        keywords=["CF_API_KEY", "CLOUDFLARE_API_KEY", "cloudflare_api_key"], confidence=0.80, description="Cloudflare Global API Key. Full account access.", fix_hint="Use scoped API tokens instead. View at Cloudflare → My Profile → API Tokens."),
    SecretRule(rule_id="VOODA-SEC-FLY-001", title="Fly.io Access Token", secret_type="flyio_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(fo1_[A-Za-z0-9_\-]{40,})(?:[^A-Za-z0-9]|$)', keywords=["fo1_"], confidence=0.95,
        description="Fly.io personal access token.", fix_hint="Revoke at Fly.io → Account → Access Tokens."),
    SecretRule(rule_id="VOODA-SEC-RENDER-001", title="Render API Key", secret_type="render_api_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(rnd_[A-Za-z0-9]{32,})(?:[^A-Za-z0-9]|$)', keywords=["rnd_"], confidence=0.95,
        description="Render cloud platform API key.", fix_hint="Regenerate at Render → Account Settings → API Keys."),
    SecretRule(rule_id="VOODA-SEC-CONFLUENT-001", title="Confluent Cloud API Key", secret_type="confluent_api_key", severity="high",
        pattern=r'(?:confluent[_-]?(?:cloud[_-]?)?api[_-]?key|CONFLUENT_API_KEY)\s*[=:]\s*["\']?([A-Z0-9]{16})["\']?',
        keywords=["confluent", "CONFLUENT"], confidence=0.70, description="Confluent Cloud (Kafka) API key.", fix_hint="Rotate at Confluent Cloud → Administration → API Keys."),
        # VOODA-SEC-DATABRICKS-001 removed 2026-05-22 (Track-A Phase 1, collision audit) —
    # shadow of live rule in partner_patterns.py; shadow lacks length upper bound (live has 32-40).
    # Removal restored 1 dead-code rule to the registry's correct
    # state (was silently shadowed by last-wins dedup).
    # Renamed from -002 → -003 during P3 (2026-05-22): -002 was already
    # taken by trufflehog_final.py (Snowflake JWT Key Pair detector).
    # -001 is the partner_patterns Snowflake PAT detector.  Three distinct
    # Snowflake threats; each gets its own id so all three fire.
    SecretRule(rule_id="VOODA-SEC-SNOWFLAKE-003", title="Snowflake Credentials (assignment context)", secret_type="snowflake_credentials", severity="critical",
        pattern=r'(?:snowflake[_-]?(?:password|account|token)|SNOWFLAKE_(?:PASSWORD|ACCOUNT|TOKEN))\s*[=:]\s*["\']?([^\s"\']{8,})["\']?',
        keywords=["snowflake", "SNOWFLAKE"], confidence=0.70, description="Snowflake database credentials in config-key assignment.", fix_hint="Rotate credentials in Snowflake admin. Use key-pair authentication."),
    SecretRule(rule_id="VOODA-SEC-AIVEN-002", title="Aiven Token", secret_type="aiven_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(aivenv1-[A-Za-z0-9]{56,})(?:[^A-Za-z0-9]|$)', keywords=["aivenv1-"], confidence=0.95,
        description="Aiven cloud database platform token.", fix_hint="Revoke at Aiven Console → User Profile → Authentication."),
]
