# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""
Partner Pattern Detectors — strict-format tokens with cryptographically
unique prefixes.

These rules match credentials whose format is unambiguously issued by a
specific provider. Because the prefix + charset + length combination is
effectively unforgeable, any match is guaranteed to be a real credential
of that type (verified or not). Confidence is ≥0.95 by construction.

This file is the P0 / partner-pattern hot-list: patterns that give
100% precision without needing live API verification. Populated from
the TruffleHog detector list (github.com/trufflesecurity/trufflehog)
and provider-published format specs.

Do NOT add regex-without-unique-prefix patterns here — those belong in
generic.py or saas.py where lower confidence is appropriate.
"""

from services.secret_scan.detectors.base import SecretRule


RULES: list[SecretRule] = [
    # ── SaaS — Project / Issue Tracking ──────────────────────────────
    # VOODA-SEC-CLICKUP-001 removed 2026-05-22 (Track-A Phase 5, Option A).
    # Exact-pattern duplicate consolidated into VOODA-SEC-CLICKUP-V2-001.
    # See services/secret_scan/detectors/registry.py:RULE_ID_ALIASES.

    # ── Auth / Identity ──────────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-CLERK-LIVE-001",
        title="Clerk Secret Key (Live)",
        secret_type="clerk_secret_key",
        severity="critical",
        pattern=r'\b(sk_live_[A-Za-z0-9]{40,64})\b',
        keywords=["sk_live_"],
        confidence=0.96,
        description="Clerk production secret key. Full user-management access.",
        fix_hint="Rotate at Clerk Dashboard → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-CLERK-TEST-001",
        title="Clerk Secret Key (Test)",
        secret_type="clerk_secret_key_test",
        severity="medium",
        pattern=r'\b(sk_test_[A-Za-z0-9]{40,64})\b',
        keywords=["sk_test_"],
        confidence=0.95,
        description="Clerk test secret key. Non-production but leaked keys indicate poor hygiene.",
        fix_hint="Rotate at Clerk Dashboard → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-OKTA-API-002",
        title="Okta API Token",
        secret_type="okta_api_token_v2",
        severity="critical",
        # 2-pass: re2-compatible base pattern + Python keyword-proximity
        # check via post_filter_* (was `(?=.*okta|.*SSWS)` lookahead).
        # Track-A Option B-1 (2026-05-24).
        pattern=r'\b(00[A-Za-z0-9_-]{40})\b',
        keywords=["okta", "SSWS"],
        post_filter_keywords=["okta", "SSWS"],
        post_filter_window=500,
        confidence=0.95,
        description="Okta API token. Grants administrative access to Okta org.",
        fix_hint="Revoke at Okta Admin → Security → API → Tokens.",
    ),

    # ── Databases / DaaS ─────────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-SUPABASE-SERVICE-001",
        title="Supabase Service Role Key",
        secret_type="supabase_service_key",
        severity="critical",
        pattern=r'\b(sbp_[A-Za-z0-9]{40})\b',
        keywords=["sbp_"],
        confidence=0.98,
        description="Supabase service role key. Bypasses Row Level Security — full DB access.",
        fix_hint="Revoke at Supabase → Project Settings → API → reset service_role key.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-SUPABASE-ACCESS-001",
        title="Supabase Management Access Token",
        secret_type="supabase_access_token",
        severity="critical",
        pattern=r'\b(sbs_[a-f0-9]{40})\b',
        keywords=["sbs_"],
        confidence=0.98,
        description="Supabase management API token. Controls all projects in an organization.",
        fix_hint="Revoke at Supabase → Account → Access Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-NEON-001",
        title="Neon API Key",
        secret_type="neon_api_key",
        severity="high",
        pattern=r'\b(neon_[a-zA-Z0-9_]{40,})\b',
        keywords=["neon_"],
        confidence=0.95,
        description="Neon Postgres API key. Grants access to databases and branches.",
        fix_hint="Revoke at Neon → Account Settings → API Keys.",
    ),
    # VOODA-SEC-DATABRICKS-001 removed 2026-05-22 (Track-A Phase 5, Option A).
    # Exact-pattern duplicate consolidated into VOODA-SEC-DATABRICKS-PAT-001.
    # See services/secret_scan/detectors/registry.py:RULE_ID_ALIASES.
    SecretRule(
        rule_id="VOODA-SEC-MONGODB-ATLAS-001",
        title="MongoDB Atlas Public/Private Key Pair (Private Key)",
        secret_type="mongodb_atlas_private_key",
        severity="critical",
        # 2-pass — was `(?=.*(mongodb|atlas))` lookahead.
        pattern=r'\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b',
        post_filter_keywords=["mongodb", "atlas"],
        post_filter_window=500,
        keywords=["mongodb", "atlas", "MCLI_PRIVATE_API_KEY"],
        confidence=0.90,
        description="MongoDB Atlas private API key (UUID format, paired with public key).",
        fix_hint="Rotate at Atlas → Organization → Access Manager → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-SNOWFLAKE-001",
        title="Snowflake Programmatic Access Token",
        secret_type="snowflake_pat",
        severity="critical",
        pattern=r'\b(ETMsDgAAA[A-Za-z0-9_-]{80,})\b',
        keywords=["snowflake", "ETMsDg"],
        confidence=0.97,
        description="Snowflake programmatic access token (legacy or PAT). Warehouse and data access.",
        fix_hint="Revoke in Snowflake → User Preferences → Security → Revoke token.",
    ),

    # ── AI / LLM Providers ───────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-DEEPSEEK-001",
        title="DeepSeek API Key",
        secret_type="deepseek_api_key",
        severity="high",
        # Requires nearby 'deepseek' context somewhere on the same line
        pattern=r'(?i)deepseek[^\n]{0,100}(sk-[a-f0-9]{32})|(sk-[a-f0-9]{32})[^\n]{0,100}deepseek',
        keywords=["deepseek", "DEEPSEEK", "DeepSeek"],
        confidence=0.92,
        description="DeepSeek API key for model inference. Usage charges on account.",
        fix_hint="Rotate at platform.deepseek.com → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-OPENROUTER-001",
        title="OpenRouter API Key",
        secret_type="openrouter_api_key",
        severity="high",
        pattern=r'\b(sk-or-v1-[a-f0-9]{64})\b',
        keywords=["sk-or-v1-", "openrouter"],
        confidence=0.98,
        description="OpenRouter unified LLM API key. Charges against billing account.",
        fix_hint="Revoke at openrouter.ai → Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-ANYSCALE-001",
        title="Anyscale API Key",
        secret_type="anyscale_api_key",
        severity="high",
        pattern=r'\b(esecret_[A-Za-z0-9]{40,})\b',
        keywords=["esecret_", "anyscale"],
        confidence=0.96,
        description="Anyscale endpoints / compute platform API key.",
        fix_hint="Revoke at anyscale.com → Account → API Keys.",
    ),

    # ── Package Registries ───────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-NPM-TOKEN-001",
        title="npm Access Token (v2)",
        secret_type="npm_access_token_v2",
        severity="critical",
        pattern=r'\b(npm_[A-Za-z0-9]{36})\b',
        keywords=["npm_"],
        confidence=0.98,
        description="npm publish/readonly access token. Can publish malicious packages.",
        fix_hint="Revoke at npmjs.com → Access Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-PYPI-001",
        title="PyPI API Token",
        secret_type="pypi_api_token",
        severity="critical",
        pattern=r'\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{70,})\b',
        keywords=["pypi-AgEI"],
        confidence=0.99,
        description="PyPI publish API token (Macaroon). Can publish malicious packages.",
        fix_hint="Revoke at pypi.org → Account Settings → API tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-CRATES-IO-001",
        title="Crates.io API Token",
        secret_type="crates_io_token",
        severity="critical",
        pattern=r'\b(cio[A-Za-z0-9]{32})\b',
        keywords=["cio", "cargo", "crates"],
        confidence=0.93,
        description="Crates.io Rust package registry token. Can publish malicious crates.",
        fix_hint="Revoke at crates.io → Account → API Tokens.",
    ),

    # ── Email / Notifications ────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-BREVO-SMTP-001",
        title="Brevo (Sendinblue) SMTP Key",
        secret_type="brevo_smtp_key",
        severity="high",
        pattern=r'\b(xsmtpsib-[a-f0-9]{64}-[A-Za-z0-9]{16})\b',
        keywords=["xsmtpsib-", "brevo", "sendinblue"],
        confidence=0.98,
        description="Brevo/Sendinblue SMTP API key. Can send emails from your domain.",
        fix_hint="Revoke at brevo.com → SMTP & API → API Keys.",
    ),
    # VOODA-SEC-BREVO-API-001 removed 2026-05-22 (Track-A Phase 5, Option A).
    # Triplet member consolidated into VOODA-SEC-SENDINBLUE-V3-001 (the
    # critical-severity canonical).  See registry.py:RULE_ID_ALIASES.
    SecretRule(
        rule_id="VOODA-SEC-MAILERLITE-001",
        title="MailerLite API Token",
        secret_type="mailerlite_api_token",
        severity="high",
        # 2-pass — was `(?=.*mailerlite)` lookahead.
        pattern=r'\b(eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\.[A-Za-z0-9_-]{200,500}\.[A-Za-z0-9_-]{40,200})\b',
        post_filter_keywords=["mailerlite"],
        post_filter_window=500,
        keywords=["mailerlite"],
        confidence=0.90,
        description="MailerLite API JWT. Contact and campaign management access.",
        fix_hint="Revoke at MailerLite → Integrations → API.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-LOOPS-001",
        title="Loops.so API Key",
        secret_type="loops_api_key",
        severity="medium",
        pattern=r'\b([a-f0-9]{32})\b',
        # 2-pass: lookahead → post_filter_* (Option B-1 codemod, 2026-05-24).
        post_filter_keywords=['loops.so', 'loops_api_key'],
        post_filter_window=500,
        keywords=["loops.so", "LOOPS_API"],
        confidence=0.85,
        description="Loops.so transactional email API key.",
        fix_hint="Revoke at loops.so → Settings → API.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-CONVERTKIT-001",
        title="ConvertKit/Kit API Secret",
        secret_type="convertkit_api_secret",
        severity="high",
        # 2-pass proximity gate. The capture is a generic 22-char token, so the
        # keyword gate is what makes this a *ConvertKit* finding rather than "any
        # 22-char string". Two FP-driven corrections (2026-06-14, opus×vooda
        # benchmark — `secrets-patterns-db/db/rules-stable.yml:6175` matched the
        # pattern *name* `trex_okta_client_token` (22 chars), validated by a
        # `twilio_api_secret` 8 lines below):
        #   1. Dropped `api_secret` from the keyword set — it is an extremely
        #      common field name and let any 22-char token near *any* provider's
        #      `*_api_secret` pass as ConvertKit. Require real ConvertKit context
        #      (`convertkit`/`kit.com`), matching the canonical secrets-patterns-db
        #      rule `(?:convertkit).{0,40}\b([a-z0-9A-Z_]{22})\b`.
        #   2. direction after→both + window 500→64: the canonical shape is
        #      keyword-BEFORE the value (`CONVERTKIT_API_SECRET=<token>`), which an
        #      after-only window missed; `both`+64 catches before AND after in a
        #      tight window. Proven recall-safe (ck_dir proof, 2026-06-14): the FP
        #      dies, every real ConvertKit shape still fires, and the keyword-before
        #      shape the old rule missed is now caught. A real `…=<value>` is
        #      additionally caught by GEN-001 regardless.
        pattern=r'\b([A-Za-z0-9_-]{22})\b',
        post_filter_keywords=["convertkit", "kit.com"],
        post_filter_window=64,
        post_filter_direction="both",
        keywords=["convertkit", "kit.com", "CONVERTKIT"],
        confidence=0.80,
        description="ConvertKit (Kit) API secret. Subscriber list + automation access.",
        fix_hint="Revoke at app.kit.com → Account → Account Info.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-MAILCHIMP-001",
        title="Mailchimp API Key",
        secret_type="mailchimp_api_key",
        severity="high",
        # Mailchimp keys are strictly lowercase hex; IGNORECASE would risk
        # matching uppercase hex that happens to end -us10
        pattern=r'\b([a-f0-9]{32}-us\d{1,2})\b',
        keywords=["mailchimp", "MAILCHIMP", "MC_API_KEY"],
        confidence=0.97,
        description="Mailchimp API key (hex-dc format). Full list and campaign access.",
        fix_hint="Revoke at mailchimp.com → Account → Extras → API keys.",
        case_sensitive=True,
    ),

    # ── Payments ────────────────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-CHARGEBEE-LIVE-001",
        title="Chargebee Live API Key",
        secret_type="chargebee_live_key",
        severity="critical",
        # Context anywhere on the same line (before or after the value)
        pattern=r'(?i)chargebee[^\n]{0,100}(live_[A-Za-z0-9]{24,})|(live_[A-Za-z0-9]{24,})[^\n]{0,100}chargebee',
        keywords=["chargebee", "CHARGEBEE"],
        confidence=0.92,
        description="Chargebee production API key. Full billing and subscription access.",
        fix_hint="Revoke at Chargebee → Settings → API Keys.",
    ),

    # ── Dev / Analytics ──────────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-CLOUDINARY-001",
        title="Cloudinary URL",
        secret_type="cloudinary_url",
        severity="high",
        pattern=r'cloudinary://\d{12,18}:[A-Za-z0-9_-]{20,30}@[a-z0-9_-]{3,40}',
        keywords=["cloudinary://"],
        confidence=0.98,
        description="Cloudinary URL containing API key + secret + cloud name. Media upload/delete access.",
        fix_hint="Rotate secret at Cloudinary → Dashboard → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-ABLY-001",
        title="Ably API Key",
        secret_type="ably_api_key",
        severity="high",
        # 2-pass — was `(?=.*ably|.*ABLY)` lookahead.
        pattern=r'\b([A-Za-z0-9_-]{11,18}\.[A-Za-z0-9_-]{6,12}:[A-Za-z0-9_/+=-]{30,50})\b',
        post_filter_keywords=["ably"],
        post_filter_window=500,
        keywords=["ably", "ABLY"],
        confidence=0.93,
        description="Ably realtime messaging API key (keyname:keysecret format).",
        fix_hint="Revoke at ably.com → Apps → API Keys.",
    ),

    # ── CI / Build / Deploy ──────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-CLOUDFLARE-R2-001",
        title="Cloudflare R2 Access Key Pair (Access Key ID)",
        secret_type="cloudflare_r2_access_key",
        severity="critical",
        pattern=r'\b([a-f0-9]{32})\b',
        # 2-pass: lookahead → post_filter_* (Option B-1 codemod, 2026-05-24).
        # WS6 2026-06-05: the pattern is MD5-shaped (any 32-hex) and the old
        # ``r2`` post-filter keyword is a 2-char substring that matches
        # ``error2`` / ``for2`` / random ids, so it gated almost nothing. Require
        # a SPECIFIC Cloudflare-R2 marker, both directions. Recall-safe — real R2
        # usage references cloudflare / the r2.cloudflarestorage endpoint / an
        # R2_ACCESS var; a bare MD5 digest does not.
        post_filter_keywords=['cloudflare', 'r2.cloudflarestorage', 'cloudflare_r2', 'r2_access', 'r2_secret'],
        post_filter_window=400, post_filter_direction="both",
        keywords=["r2", "R2", "CLOUDFLARE_R2"],
        confidence=0.85,
        description="Cloudflare R2 S3-compatible access key. Object storage read/write.",
        fix_hint="Rotate at Cloudflare Dashboard → R2 → Manage R2 API Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-AKAMAI-001",
        title="Akamai API Client Token",
        secret_type="akamai_client_token",
        severity="critical",
        # Case-sensitive "akab-" prefix is always lowercase in Akamai tokens
        pattern=r'\b(akab-[A-Za-z0-9]{16}-[A-Za-z0-9]{16})\b',
        keywords=["akab-"],
        confidence=0.98,
        description="Akamai EdgeGrid API client token. CDN configuration access.",
        fix_hint="Revoke at control.akamai.com → Identity → API Users.",
        case_sensitive=True,
    ),

    # ── Observability / Monitoring ───────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-ROLLBAR-SERVER-001",
        title="Rollbar Server Access Token",
        secret_type="rollbar_server_token",
        severity="medium",
        pattern=r'\b([a-f0-9]{32})\b',
        # 2-pass: lookahead → post_filter_* (Option B-1 codemod, 2026-05-24).
        post_filter_groups=[['rollbar', 'ROLLBAR_'], ['server', 'post_server_item']],
        post_filter_window=500,
        keywords=["rollbar", "ROLLBAR", "post_server_item"],
        confidence=0.85,
        description="Rollbar server-side access token. Error reporting write access.",
        fix_hint="Rotate at rollbar.com → Project → Access Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-ROLLBAR-READ-001",
        title="Rollbar Read/Admin Token",
        secret_type="rollbar_admin_token",
        severity="high",
        pattern=r'\b([a-f0-9]{32})\b',
        # 2-pass: lookahead → post_filter_* (Option B-1 codemod, 2026-05-24).
        post_filter_groups=[['rollbar', 'ROLLBAR_'], ['admin', 'read', 'write']],
        post_filter_window=500,
        keywords=["rollbar_read", "rollbar_admin", "rollbar_write"],
        confidence=0.85,
        description="Rollbar project-level read/write/admin token.",
        fix_hint="Rotate at rollbar.com → Project → Access Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-CODACY-001",
        title="Codacy API Token",
        secret_type="codacy_api_token",
        severity="high",
        pattern=r'(?i)codacy[^\n]{0,100}([a-f0-9]{40})|([a-f0-9]{40})[^\n]{0,100}codacy',
        keywords=["codacy", "CODACY"],
        confidence=0.85,
        description="Codacy API token. Project management and results access.",
        fix_hint="Revoke at codacy.com → Account → API Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-ADAFRUIT-IO-001",
        title="Adafruit IO Key",
        secret_type="adafruit_io_key",
        severity="medium",
        pattern=r'\b(aio_[A-Za-z0-9]{28})\b',
        keywords=["aio_", "adafruit"],
        confidence=0.96,
        description="Adafruit IO key. IoT feed publish/subscribe access.",
        fix_hint="Rotate at io.adafruit.com → My Key.",
    ),

    # ── Finance / APIs ───────────────────────────────────────────────
        # VOODA-SEC-POSTGRES-URL-001 removed 2026-05-22 (Track-A Phase 1, collision audit) —
    # shadow of live rule in trufflehog_port_v4.py; shadow has same pattern with looser bounds.
    # Removal restored 1 dead-code rule to the registry's correct
    # state (was silently shadowed by last-wins dedup).
        # VOODA-SEC-MYSQL-URL-001 removed 2026-05-22 (Track-A Phase 1, collision audit) —
    # shadow of live rule in trufflehog_port_v4.py; shadow has same pattern with looser bounds.
    # Removal restored 1 dead-code rule to the registry's correct
    # state (was silently shadowed by last-wins dedup).
    SecretRule(
        rule_id="VOODA-SEC-REDIS-URL-AUTH-001",
        title="Redis Connection URL with Password",
        secret_type="redis_connection_url_auth",
        severity="high",
        pattern=r'redis(?:s)?://(?:[A-Za-z0-9_-]+)?:[A-Za-z0-9_!@#$%^&*-]{8,64}@[A-Za-z0-9.-]+(?::\d+)?',
        keywords=["redis://", "rediss://"],
        confidence=0.93,
        description="Redis connection URL with embedded password.",
        fix_hint="Move credentials to secret manager; use AUTH command.",
    ),

    # ── Productivity / CRM ──────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-CAL-COM-001",
        title="Cal.com API Key",
        secret_type="cal_com_api_key",
        severity="high",
        pattern=r'\b(cal_live_[a-f0-9]{32})\b',
        keywords=["cal_live_"],
        confidence=0.98,
        description="Cal.com production API key. Scheduling and event access.",
        fix_hint="Revoke at cal.com → Settings → Developer → API Keys.",
    ),

    # ── Auth / OAuth ─────────────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-AUTH0-JWT-001",
        title="Auth0 Management API Token (JWT)",
        secret_type="auth0_management_jwt",
        severity="critical",
        pattern=r'\b(eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\.[A-Za-z0-9_-]{200,600}\.[A-Za-z0-9_-]{60,300})\b',
        # 2-pass: lookahead → post_filter_* (Option B-1 codemod, 2026-05-24).
        post_filter_keywords=['auth0', 'AUTH0_MGMT'],
        post_filter_window=500,
        keywords=["auth0", "AUTH0_MGMT"],
        confidence=0.90,
        description="Auth0 Management API token. Full tenant configuration and user data access.",
        fix_hint="Rotate the Auth0 Management client secret at manage.auth0.com.",
    ),

    # ── Monitoring / Observability ───────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-SEGMENT-WRITE-001",
        title="Segment Write Key",
        secret_type="segment_write_key",
        severity="medium",
        pattern=r'\b([A-Za-z0-9]{32})\b',
        # Tier A 2026-06-07: the bare word "segment" within 500 chars matched any
        # 32-char hash/ID sitting near "segment tree" / "network segment" / "user
        # segment" → 211 FP / 0 TP on the 100-repo benchmark. Require the
        # CANONICAL write-key assignment anchor in a tight both-direction window
        # instead — a real Segment write key is always assigned to
        # writeKey / SEGMENT_WRITE_KEY / analytics.load(...). Recall held by the
        # writeKey TP fixture in test_tier_a_rule_tightening.py.
        post_filter_keywords=['write_key', 'writekey', 'segment_write_key', 'analytics.load(', 'analytics.write_key'],
        post_filter_window=60,
        post_filter_direction="both",
        keywords=["segment", "SEGMENT_WRITE_KEY", "writeKey", "write_key"],
        confidence=0.85,
        description="Segment analytics write key. Event pipeline access (source-level).",
        fix_hint="Rotate at app.segment.com → Sources → Settings → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-PLAUSIBLE-001",
        title="Plausible Analytics API Key",
        secret_type="plausible_api_key",
        severity="low",
        pattern=r'\b([A-Za-z0-9_-]{43})\b',
        # 2-pass: lookahead → post_filter_* (Option B-1 codemod, 2026-05-24).
        post_filter_keywords=['plausible', 'PLAUSIBLE_API_KEY'],
        post_filter_window=500,
        keywords=["plausible", "PLAUSIBLE_API_KEY"],
        confidence=0.85,
        description="Plausible Analytics API key. Read-only site stats access.",
        fix_hint="Revoke at plausible.io → Account Settings → API Keys.",
    ),

    # ── Webhook URLs with embedded tokens ────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-DISCORD-WEBHOOK-002",
        title="Discord Webhook URL",
        secret_type="discord_webhook_url",
        severity="high",
        pattern=r'https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,80}',
        keywords=["discord.com/api/webhooks", "discordapp.com/api/webhooks"],
        confidence=0.99,
        description="Discord webhook URL. Anyone with URL can post messages to the channel.",
        fix_hint="Delete at Server Settings → Integrations → Webhooks.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-SLACK-WEBHOOK-001",
        title="Slack Incoming Webhook URL",
        secret_type="slack_webhook_url",
        severity="high",
        pattern=r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,28}',
        keywords=["hooks.slack.com"],
        confidence=0.99,
        description="Slack incoming webhook URL. Can post messages to configured channel.",
        fix_hint="Revoke at api.slack.com → Your Apps → Incoming Webhooks.",
        case_sensitive=True,
    ),
    SecretRule(
        rule_id="VOODA-SEC-TEAMS-WEBHOOK-001",
        title="Microsoft Teams Webhook URL",
        secret_type="teams_webhook_url",
        severity="high",
        pattern=r'https://[a-zA-Z0-9.-]+\.webhook\.office\.com/webhookb2/[a-f0-9-]{36}@[a-f0-9-]{36}/IncomingWebhook/[a-f0-9]{32}/[a-f0-9-]{36}',
        keywords=["webhook.office.com"],
        confidence=0.99,
        description="Microsoft Teams incoming webhook URL.",
        fix_hint="Revoke at Teams → Channel → Connectors → Configure.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-TELEGRAM-BOT-001",
        title="Telegram Bot Token",
        secret_type="telegram_bot_token",
        severity="high",
        pattern=r'\b(\d{8,10}:[A-Za-z0-9_-]{35})\b',
        keywords=["bot", "api.telegram.org", "TELEGRAM"],
        confidence=0.96,
        description="Telegram bot API token. Can send messages from the bot.",
        fix_hint="Revoke via @BotFather → /revoke.",
    ),

    # ── CI / Containers ──────────────────────────────────────────────
    # VOODA-SEC-CI-GITLAB-DEPLOY-001 removed 2026-05-22 (Track-A Phase 5, Option A).
    # Exact-pattern duplicate consolidated into VOODA-SEC-GITLAB-DEPLOY-TOKEN-001.
    # See services/secret_scan/detectors/registry.py:RULE_ID_ALIASES.
    # VOODA-SEC-GITHUB-ACTIONS-TOKEN-001 removed 2026-05-22 (Track-A
    # Recommendation #1).  Exact-pattern duplicate of the
    # CRITICAL-severity GITHUB-APP-INSTALLATION-001 detector (both
    # match ghs_… tokens).  Severity-conflict resolved in favour of
    # the worst-case classification; verifier disambiguates type at
    # runtime.  See services/secret_scan/detectors/registry.py:RULE_ID_ALIASES
    # for the alias mapping.
]
