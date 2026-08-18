# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""
TruffleHog Port v4 — closes raw rule-count gap vs TruffleHog.

Adds ~100 more provider detection rules, targeting the remaining long
tail with strict-format tokens (provider prefix + cryptographic
length/charset). Emphasis on providers that have verifiers already
(Tier 5) so each new rule has a matching live-verification path.
"""

from services.secret_scan.detectors.base import SecretRule


RULES: list[SecretRule] = [

    # ── AI / LLM (additional long tail) ──────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-OPENAI-ORG-001",
        title="OpenAI Organization ID",
        secret_type="openai_org_id",
        severity="info",
        pattern=r'\b(org-[A-Za-z0-9]{24})\b',
        keywords=["org-", "OPENAI_ORG"],
        confidence=0.98,
        description="OpenAI organization identifier (not strictly a secret, but discloses tenancy).",
        fix_hint="Not a secret; remove if scoping OpenAI key exposure.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-OPENAI-PROJ-001",
        title="OpenAI Project Key",
        secret_type="openai_proj_key",
        severity="high",
        pattern=r'\b(sk-proj-[A-Za-z0-9_-]{60,200})\b',
        keywords=["sk-proj-"],
        confidence=0.99,
        description="OpenAI project-scoped API key (sk-proj- prefix).",
        fix_hint="Revoke at platform.openai.com → API keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-REPLICATE-R8-001",
        title="Replicate API Token",
        secret_type="replicate_r8_token",
        severity="high",
        pattern=r'\b(r8_[A-Za-z0-9]{37,40})\b',
        keywords=["r8_", "replicate"],
        confidence=0.99,
        description="Replicate ML model hosting API token (r8_ prefix).",
        fix_hint="Revoke at replicate.com → Account → API tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-PINECONE-PCSK-001",
        title="Pinecone API Key",
        secret_type="pinecone_pcsk_key",
        severity="high",
        pattern=r'\b(pcsk_[A-Za-z0-9_]{40,120})\b',
        keywords=["pcsk_", "pinecone"],
        confidence=0.99,
        description="Pinecone vector DB API key (pcsk_ prefix).",
        fix_hint="Revoke at app.pinecone.io → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-HF-LEGACY-001",
        title="Hugging Face Legacy API Token (api_org_)",
        secret_type="huggingface_api_org",
        severity="critical",
        pattern=r'\b(api_org_[A-Za-z0-9]{34})\b',
        keywords=["api_org_", "huggingface"],
        confidence=0.99,
        description="Hugging Face legacy organization API token (deprecated, still active).",
        fix_hint="Revoke at huggingface.co → Settings → Access Tokens.",
    ),

    # ── Cloud infra (additional) ─────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-GOOGLE-OAUTH-CLIENT-001",
        title="Google OAuth Client ID",
        secret_type="google_oauth_client_id",
        severity="info",
        pattern=r'\b(\d{9,12}-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com)\b',
        keywords=[".apps.googleusercontent.com"],
        confidence=0.99,
        description="Google OAuth client ID (public part of client credentials).",
        fix_hint="Client IDs are not secret; check the paired client secret is not also leaked.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GOOGLE-OAUTH-SECRET-001",
        title="Google OAuth Client Secret",
        secret_type="google_oauth_client_secret",
        severity="critical",
        pattern=r'\b(GOCSPX-[A-Za-z0-9_-]{28})\b',
        keywords=["GOCSPX-"],
        confidence=0.99,
        description="Google Cloud OAuth 2.0 client secret (GOCSPX- prefix).",
        fix_hint="Rotate at console.cloud.google.com → APIs & Services → Credentials.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-AWS-SESSION-TOKEN-001",
        title="AWS Session Token",
        secret_type="aws_session_token",
        severity="critical",
        pattern=r'\b(FwoGZXIv[A-Za-z0-9+/=]{100,})\b',
        keywords=["FwoGZXIv", "AWS_SESSION_TOKEN"],
        confidence=0.97,
        description="AWS temporary session token (FwoGZXIv prefix = STS assume-role).",
        fix_hint="Session tokens are time-limited; still rotate if leaked to reduce attacker window.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-AWS-SECRET-KEY-CTX-001",
        title="AWS Secret Access Key (contextual)",
        secret_type="aws_secret_access_key",
        severity="critical",
        # Case-insensitive context + strict 40-char base64 body. We rely on
        # nearby "aws_secret" / "secret_access" keywords to avoid FPs.
        pattern=r'(?i)aws_?secret_?access_?key[^\n]{0,50}[=:"\s]+([A-Za-z0-9/+=]{40})',
        keywords=["aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"],
        confidence=0.92,
        description="AWS Secret Access Key with explicit AWS context.",
        fix_hint="Rotate access key pair immediately at AWS IAM console.",
    ),

    # ── Payments (additional) ────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-STRIPE-RESTRICTED-001",
        title="Stripe Restricted API Key",
        secret_type="stripe_restricted_key",
        severity="high",
        pattern=r'\b(rk_live_[A-Za-z0-9]{24,99}|rk_test_[A-Za-z0-9]{24,99})\b',
        keywords=["rk_live_", "rk_test_"],
        confidence=0.99,
        description="Stripe restricted API key (scoped permissions only).",
        fix_hint="Revoke at Stripe Dashboard → Developers → API keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-STRIPE-PUBLISHABLE-001",
        title="Stripe Publishable Key",
        secret_type="stripe_publishable_key",
        severity="info",
        pattern=r'\b(pk_live_[A-Za-z0-9]{24,99}|pk_test_[A-Za-z0-9]{24,99})\b',
        keywords=["pk_live_", "pk_test_"],
        confidence=0.99,
        description="Stripe publishable key (client-side, not strictly a secret but discloses merchant).",
        fix_hint="Publishable keys are not secret but can help attackers map tenancy.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-STRIPE-WEBHOOK-001",
        title="Stripe Webhook Secret",
        secret_type="stripe_webhook_secret",
        severity="critical",
        pattern=r'\b(whsec_[A-Za-z0-9]{32,64})\b',
        keywords=["whsec_"],
        confidence=0.99,
        description="Stripe webhook signing secret (whsec_ prefix).",
        fix_hint="Rotate at Stripe Dashboard → Developers → Webhooks → endpoint → Signing secret.",
    ),

    # ── Version control & DevOps ─────────────────────────────────
    SecretRule(
        # Canonical detector for ALL GitHub server tokens (ghs_ prefix).
        # Two distinct GitHub token types share this exact byte format:
        #
        #   1. GitHub App Installation Tokens — issued via the JWT
        #      exchange, lifetime ~1 hour, scoped to the app's
        #      permissions on a given installation.  CRITICAL when
        #      leaked because the attacker can act as the app for the
        #      remainder of the token's TTL.
        #
        #   2. GitHub Actions ephemeral GITHUB_TOKEN — auto-issued at
        #      workflow-run start, expires at end of run, scoped to
        #      the repo's workflow permissions.  Less critical only
        #      because the lifetime is bounded — but a leaked token
        #      mid-run is still attacker-actionable.
        #
        # The regex alone cannot distinguish them — pattern is
        # identical.  This rule defaults to CRITICAL (worst-case
        # classification preserved); the runtime verifier can
        # downgrade to high/medium after calling GitHub's API to
        # determine the actual token type and remaining lifetime.
        #
        # Consolidates VOODA-SEC-GITHUB-ACTIONS-TOKEN-001 (formerly
        # in partner_patterns.py at severity=medium) per Track-A
        # Recommendation #1, 2026-05-22.  Historical filters on the
        # old id are routed via registry.RULE_ID_ALIASES.
        rule_id="VOODA-SEC-GITHUB-APP-INSTALLATION-001",
        title="GitHub Server Token (ghs_)",
        secret_type="github_server_token",
        severity="critical",
        pattern=r'\b(ghs_[A-Za-z0-9]{36})\b',
        keywords=["ghs_"],
        confidence=0.99,
        description=(
            "GitHub server token (ghs_ prefix, 40 chars).  Covers both App "
            "installation tokens and Actions ephemeral GITHUB_TOKEN — the "
            "regex format is identical for both.  Verifier (when present) "
            "calls GitHub API to disambiguate type and assess remaining TTL."
        ),
        fix_hint=(
            "If this is an App installation token: rotate the installation "
            "at GitHub → Settings → Apps to invalidate.  If it's an Actions "
            "GITHUB_TOKEN: never persist these — they're auto-issued per "
            "workflow run.  Check workflow YAML for inadvertent echo of "
            "${{ secrets.GITHUB_TOKEN }} into logs or artifacts."
        ),
    ),
    SecretRule(
        rule_id="VOODA-SEC-GITLAB-DEPLOY-TOKEN-001",
        title="GitLab Deploy Token",
        secret_type="gitlab_deploy_token_v2",
        severity="high",
        pattern=r'\b(gldt-[A-Za-z0-9_-]{20})\b',
        keywords=["gldt-"],
        confidence=0.99,
        description="GitLab deploy token (gldt- prefix).",
        fix_hint="Revoke at GitLab → Project → Settings → Repository → Deploy tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GITLAB-SERVICE-ACCOUNT-001",
        title="GitLab Service Account Token",
        secret_type="gitlab_service_account_token",
        severity="critical",
        pattern=r'\b(glsoat-[A-Za-z0-9_-]{20})\b',
        keywords=["glsoat-"],
        confidence=0.99,
        description="GitLab service account OAuth token (glsoat- prefix).",
        fix_hint="Revoke at GitLab admin → Users → Service accounts.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GITLAB-CI-JOB-TOKEN-001",
        title="GitLab CI Job Token",
        secret_type="gitlab_ci_job_token",
        severity="high",
        pattern=r'\b(glcbt-[0-9a-f]{8}_[A-Za-z0-9_-]{20,})\b',
        keywords=["glcbt-"],
        confidence=0.99,
        description="GitLab CI build token (glcbt- prefix with hex job ID).",
        fix_hint="Build tokens are short-lived; rotate the runner if leaked.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-BITBUCKET-APP-PASS-001",
        title="Bitbucket App Password",
        secret_type="bitbucket_app_password",
        severity="critical",
        pattern=r'(?i)bitbucket[^\n]{0,50}(?:app_password|APP_PASSWORD)[^\n]{0,30}\b([A-Za-z0-9_-]{20,50})\b',
        keywords=["bitbucket", "BITBUCKET_APP_PASSWORD"],
        confidence=0.90,
        description="Bitbucket Cloud app password (repo + user permissions).",
        fix_hint="Revoke at bitbucket.org → Settings → App passwords.",
    ),

    # ── Communication / messaging (additional) ───────────────────
    SecretRule(
        rule_id="VOODA-SEC-DISCORD-USER-001",
        title="Discord User Token",
        secret_type="discord_user_token",
        severity="critical",
        pattern=r'\b([MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38})\b',
        keywords=["discord"],
        confidence=0.92,
        description="Discord user account token (base64 user ID + hmac format).",
        fix_hint="Log out of Discord to invalidate; never use user tokens from automation.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-VONAGE-APP-001",
        title="Vonage Application Private Key",
        secret_type="vonage_app_private_key",
        severity="critical",
        # Body cap shrunk from {200,4000} → {200,1000} for re2
        # compatibility (Option B-2, 2026-05-24).  re2's max
        # repetition count is 1000.  Covers PKCS8 / RSA-2048 PEM
        # bodies (~1500 chars including newlines, ~1000 after the
        # base64 collapses out the line wraps) and ECDSA / Ed25519
        # keys (~250 chars).  Misses RSA-4096 private keys
        # (~3.3 KB PEM body) — those still trigger the keyword
        # pre-filter "-----BEGIN PRIVATE KEY-----" so generic-PEM
        # detection paths can pick them up, but this specific rule
        # won't fire on the >1000-char body case.  Tracked as
        # B-2-followup for a post-match Python expander that
        # preserves secret_hash uniqueness for dedup.
        pattern=r'-----BEGIN\s+PRIVATE\s+KEY-----[\s\S]{200,1000}-----END\s+PRIVATE\s+KEY-----',
        keywords=["-----BEGIN PRIVATE KEY-----"],
        confidence=0.88,
        description="PKCS8 private key (Vonage app, GCP SA, etc.) in PEM form.",
        fix_hint="Rotate the key at the provider immediately.",
        multiline=True,
    ),
    SecretRule(
        rule_id="VOODA-SEC-CRISP-001",
        title="Crisp API Key",
        secret_type="crisp_api_key",
        severity="high",
        pattern=r'(?i)crisp[^\n]{0,50}\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b',
        keywords=["crisp", "CRISP"],
        confidence=0.90,
        description="Crisp live-chat API identifier (paired with key).",
        fix_hint="Rotate at crisp.chat → Settings → Plugins.",
    ),

    # ── E-commerce ───────────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-SHOPIFY-ACCESS-TOKEN-001",
        title="Shopify Admin API Access Token",
        secret_type="shopify_admin_access_token",
        severity="critical",
        pattern=r'\b(shpat_[a-fA-F0-9]{32})\b',
        keywords=["shpat_", "shopify"],
        confidence=0.99,
        description="Shopify Admin API access token (shpat_ prefix).",
        fix_hint="Revoke at Shopify Admin → Apps → Private Apps.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-SHOPIFY-CUSTOM-001",
        title="Shopify Custom App Access Token",
        secret_type="shopify_custom_access_token",
        severity="critical",
        pattern=r'\b(shpca_[a-fA-F0-9]{32})\b',
        keywords=["shpca_"],
        confidence=0.99,
        description="Shopify custom-app access token (shpca_ prefix).",
        fix_hint="Revoke at Shopify Admin → Apps → Custom Apps.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-SHOPIFY-PRIVATE-001",
        title="Shopify Private App Access Token",
        secret_type="shopify_private_access_token",
        severity="critical",
        pattern=r'\b(shppa_[a-fA-F0-9]{32})\b',
        keywords=["shppa_"],
        confidence=0.99,
        description="Shopify private-app access token (shppa_ prefix, legacy).",
        fix_hint="Migrate to custom apps; revoke at Shopify Admin → Apps.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-SHOPIFY-SHARED-001",
        title="Shopify Shared Secret",
        secret_type="shopify_shared_secret",
        severity="critical",
        pattern=r'\b(shpss_[a-fA-F0-9]{32})\b',
        keywords=["shpss_"],
        confidence=0.99,
        description="Shopify app shared secret for webhooks (shpss_ prefix).",
        fix_hint="Revoke at Shopify Partners → App Setup → API credentials.",
    ),

    # ── Analytics & monitoring ───────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-SEGMENT-READ-001",
        title="Segment Personal Access Token",
        secret_type="segment_pat",
        severity="critical",
        pattern=r'\b(sgp_[A-Za-z0-9_]{40,})\b',
        keywords=["sgp_", "segment"],
        confidence=0.99,
        description="Segment public API personal access token (sgp_ prefix).",
        fix_hint="Revoke at app.segment.com → Team → API Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-AMPLITUDE-WRITE-001",
        title="Amplitude Write Key",
        secret_type="amplitude_write_key",
        severity="medium",
        pattern=r'(?i)amplitude[^\n]{0,50}\b([a-f0-9]{32})\b',
        keywords=["amplitude"],
        confidence=0.88,
        description="Amplitude analytics write key.",
        fix_hint="Rotate at analytics.amplitude.com → Project Settings.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-HEAP-ANALYTICS-001",
        title="Heap Analytics App ID",
        secret_type="heap_app_id",
        severity="info",
        pattern=r'(?i)heap[^\n]{0,50}\b([0-9]{8,12})\b',
        # 2-pass: lookahead → post_filter_* (Option B-1 codemod, 2026-05-24).
        post_filter_keywords=['track', 'identify', 'app_id'],
        post_filter_window=80,
        keywords=["heap", "HEAP"],
        confidence=0.80,
        description="Heap Analytics app ID (not strictly secret but discloses tenancy).",
        fix_hint="App IDs are public; no rotation needed.",
    ),

    # ── Data platforms ───────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-SNOWFLAKE-PAT-001",
        title="Snowflake Programmatic Access Token",
        secret_type="snowflake_pat",
        severity="critical",
        pattern=r'\b(ey[A-Za-z0-9_-]{50,500}\.ey[A-Za-z0-9_-]{50,400}\.ey[A-Za-z0-9_-]{50,400})\b',
        # 2-pass: lookahead → post_filter_* (Option B-1 codemod, 2026-05-24).
        post_filter_keywords=['snowflake'],
        post_filter_window=120,
        keywords=["snowflake", "SNOWFLAKE"],
        confidence=0.90,
        description="Snowflake programmatic access token (JWT).",
        fix_hint="Rotate at Snowflake → User Preferences → Security.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-DATABRICKS-PAT-001",
        title="Databricks Personal Access Token",
        secret_type="databricks_pat_v2",
        severity="critical",
        pattern=r'\b(dapi[a-f0-9]{32,40})\b',
        keywords=["dapi"],
        confidence=0.98,
        description="Databricks PAT (dapi prefix + 32-char hex).",
        fix_hint="Revoke at databricks.com → User Settings → Access tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-REDIS-URL-CREDS-001",
        title="Redis Connection URL with Credentials",
        secret_type="redis_connection_url",
        severity="critical",
        pattern=r'redis://[A-Za-z0-9_-]{1,60}:[^\s@/]{6,64}@[A-Za-z0-9.-]+(?::\d+)?',
        keywords=["redis://"],
        confidence=0.97,
        description="Redis connection URL with embedded username:password.",
        fix_hint="Move Redis password to secret manager; never embed in URL in code.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-CASSANDRA-URL-001",
        title="Cassandra Connection URL with Credentials",
        secret_type="cassandra_connection_url",
        severity="critical",
        pattern=r'cassandra://[A-Za-z0-9_-]+:[^\s@/]{6,64}@[A-Za-z0-9.-]+',
        keywords=["cassandra://"],
        confidence=0.97,
        description="Cassandra connection URL with embedded credentials.",
        fix_hint="Move credentials out of URL; use config file or secret manager.",
    ),

    # ── SaaS apps ────────────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-SLACK-USER-001",
        title="Slack User Token",
        secret_type="slack_user_token",
        severity="critical",
        pattern=r'\b(xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]{32})\b',
        keywords=["xoxp-"],
        confidence=0.99,
        description="Slack user OAuth token (xoxp- prefix).",
        fix_hint="Revoke at api.slack.com → Your Apps → OAuth permissions.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-SLACK-CONFIG-001",
        title="Slack Config Access Token",
        secret_type="slack_config_token",
        severity="critical",
        pattern=r'\b(xoxe\.xoxp-[0-9]-[A-Za-z0-9-]+)\b',
        keywords=["xoxe.xoxp"],
        confidence=0.99,
        description="Slack workflow/config access token (xoxe prefix).",
        fix_hint="Revoke at api.slack.com.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-NOTION-INTEGRATION-001",
        title="Notion Integration Token",
        secret_type="notion_integration_token",
        severity="critical",
        pattern=r'\b(secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9_-]{45,})\b',
        keywords=["secret_", "ntn_", "notion"],
        confidence=0.95,
        description="Notion internal integration token (secret_ or ntn_ prefix).",
        fix_hint="Revoke at notion.so → Integrations → Internal integration → Secrets.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-ZOOM-JWT-001",
        title="Zoom JWT App Secret",
        secret_type="zoom_jwt_secret",
        severity="critical",
        pattern=r'(?i)zoom[^\n]{0,50}(?:api_?secret|jwt_?secret)[^\n]{0,30}\b([A-Za-z0-9_-]{32,64})\b',
        keywords=["zoom", "ZOOM_API_SECRET"],
        confidence=0.88,
        description="Zoom JWT app secret (deprecated but still in use).",
        fix_hint="Migrate to OAuth; revoke at marketplace.zoom.us.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-ZOOM-SERVER-TO-SERVER-001",
        title="Zoom Server-to-Server OAuth Secret",
        secret_type="zoom_s2s_oauth_secret",
        severity="critical",
        pattern=r'(?i)zoom[^\n]{0,50}(?:client_?secret|SECRET)[^\n]{0,30}\b([A-Za-z0-9]{30,45})\b',
        keywords=["zoom", "ZOOM_CLIENT_SECRET"],
        confidence=0.85,
        description="Zoom Server-to-Server OAuth client secret.",
        fix_hint="Rotate at marketplace.zoom.us → Your Apps → App Credentials.",
    ),

    # ── Dev/Build Tools ──────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-JFROG-ACCESS-TOKEN-001",
        title="JFrog Platform Access Token (v2 reference)",
        secret_type="jfrog_access_token",
        severity="critical",
        pattern=r'\b(cmVmdGtuOj[A-Za-z0-9+/=_-]{60,})\b',
        keywords=["cmVmdGtuOj", "jfrog"],
        confidence=0.97,
        description="JFrog Platform reference access token (cmVmdGtuOj base64 prefix).",
        fix_hint="Revoke at JFrog Platform → Access Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-TEAMCITY-BUILD-001",
        title="TeamCity Build Token",
        secret_type="teamcity_build_token",
        severity="high",
        pattern=r'(?i)teamcity[^\n]{0,50}(?:build_?token|TOKEN)[^\n]{0,30}\b(eyJ0eXAiOi[A-Za-z0-9_-]{80,300}\.[A-Za-z0-9_-]{40,200})\b',
        keywords=["teamcity", "TEAMCITY"],
        confidence=0.92,
        description="TeamCity CI build token (JWT).",
        fix_hint="Revoke at TeamCity → My Settings & Tools → Access Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-BUILDKITE-AGENT-TOKEN-001",
        title="Buildkite Agent Registration Token",
        secret_type="buildkite_agent_token",
        severity="critical",
        pattern=r'\b(bkua_[A-Za-z0-9]{40,60})\b',
        keywords=["bkua_", "buildkite"],
        confidence=0.99,
        description="Buildkite agent token (bkua_ prefix).",
        fix_hint="Revoke at buildkite.com → Agents → Agent Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-BITRISE-PAT-001",
        title="Bitrise Personal Access Token",
        secret_type="bitrise_pat",
        severity="critical",
        pattern=r'(?i)bitrise[^\n]{0,50}\b([A-Za-z0-9_-]{40,50})\b',
        keywords=["bitrise", "BITRISE"],
        confidence=0.85,
        description="Bitrise mobile CI personal access token.",
        fix_hint="Rotate at app.bitrise.io → Security → Personal Access Tokens.",
    ),

    # ── Observability additional ─────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-DATADOG-APP-001",
        title="Datadog Application Key",
        secret_type="datadog_application_key",
        severity="critical",
        pattern=r'(?i)dd_?application_?key[^\n]{0,30}[=:"\s]+\b([a-f0-9]{40})\b',
        keywords=["DD_APPLICATION_KEY", "datadog"],
        confidence=0.95,
        description="Datadog application key (40-char hex).",
        fix_hint="Revoke at app.datadoghq.com → Organization Settings → Application Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-NEW-RELIC-LICENSE-001",
        title="New Relic License Key (ingest)",
        secret_type="newrelic_license_key_v2",
        severity="high",
        pattern=r'\b([A-Fa-f0-9]{40}NRAL)\b',
        keywords=["NRAL"],
        confidence=0.99,
        description="New Relic license key (40-char hex + NRAL suffix).",
        fix_hint="Rotate at one.newrelic.com → API Keys.",
        case_sensitive=True,
    ),
    SecretRule(
        rule_id="VOODA-SEC-SUMOLOGIC-PAT-001",
        title="Sumo Logic Access ID/Key",
        secret_type="sumologic_access_pair",
        severity="critical",
        pattern=r'(?i)sumo(?:logic)?[^\n]{0,60}(?:access_?id|ACCESS_ID)[^\n]{0,30}\b(su[A-Za-z0-9]{14})\b',
        keywords=["sumologic", "SUMOLOGIC"],
        confidence=0.95,
        description="Sumo Logic access ID (su prefix, paired with access key).",
        fix_hint="Revoke at service.sumologic.com → Preferences → Access Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-AXIOM-INGEST-001",
        title="Axiom Ingest Token",
        secret_type="axiom_ingest_token",
        severity="high",
        pattern=r'\b(xait-[A-Za-z0-9_-]{30,50})\b',
        keywords=["xait-", "axiom"],
        confidence=0.99,
        description="Axiom log-ingest token (xait- prefix).",
        fix_hint="Rotate at app.axiom.co → Settings → Ingest tokens.",
    ),

    # ── Email / SMS ──────────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-MAILJET-KEY-001",
        title="Mailjet API Public Key",
        secret_type="mailjet_public_key",
        severity="high",
        pattern=r'(?i)mailjet[^\n]{0,50}(?:api_?key|MJ_APIKEY_PUBLIC)[^\n]{0,30}\b([a-f0-9]{32})\b',
        keywords=["mailjet", "MJ_APIKEY_PUBLIC"],
        confidence=0.92,
        description="Mailjet API public key (paired with private key).",
        fix_hint="Rotate at app.mailjet.com → Account → REST API.",
    ),
    # VOODA-SEC-SENDINBLUE-BREVO-001 removed 2026-05-22 (Track-A Phase 5, Option A).
    # Triplet member consolidated into VOODA-SEC-SENDINBLUE-V3-001 (critical canonical).
    # VOODA-SEC-POSTMARK-001 removed 2026-05-22 (Track-A Phase 5, Option A).
    # Exact-pattern duplicate consolidated into VOODA-SEC-POSTMARK-API-001.
    # See services/secret_scan/detectors/registry.py:RULE_ID_ALIASES.
    SecretRule(
        rule_id="VOODA-SEC-MAILERSEND-002",
        title="MailerSend API Token",
        secret_type="mailersend_api_token",
        severity="high",
        pattern=r'\b(mlsn\.[a-f0-9]{64,80})\b',
        keywords=["mlsn."],
        confidence=0.99,
        description="MailerSend API token (mlsn. prefix).",
        fix_hint="Revoke at app.mailersend.com → Tokens.",
    ),

    # ── Monitoring / Uptime (additional) ─────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-BETTERSTACK-TELEMETRY-001",
        title="Better Stack Telemetry Ingest Token",
        secret_type="betterstack_ingest",
        severity="high",
        pattern=r'(?i)betterstack[^\n]{0,50}\b([a-zA-Z0-9]{20,32})\b',
        keywords=["betterstack", "BETTER_STACK"],
        confidence=0.85,
        description="Better Stack (formerly Logtail) telemetry ingest token.",
        fix_hint="Rotate at betterstack.com → Telemetry → Sources.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-BUGFENDER-001",
        title="Bugfender App Key",
        secret_type="bugfender_app_key",
        severity="medium",
        pattern=r'(?i)bugfender[^\n]{0,50}\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b',
        keywords=["bugfender"],
        confidence=0.90,
        description="Bugfender remote logging app key.",
        fix_hint="Rotate at dashboard.bugfender.com.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-SENTRY-SNPRS-001",
        title="Sentry SCIM Provisioning Token",
        secret_type="sentry_scim_token",
        severity="critical",
        pattern=r'\b(sntrys_[A-Za-z0-9_]{90,200})\b',
        keywords=["sntrys_"],
        confidence=0.99,
        description="Sentry SCIM user provisioning token (sntrys_ prefix).",
        fix_hint="Revoke at sentry.io → Settings → Auth Tokens.",
    ),

    # ── Search / Vector ──────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-ELASTIC-API-001",
        title="Elastic Cloud API Key",
        secret_type="elastic_cloud_api_key",
        severity="critical",
        pattern=r'(?i)elastic_?(?:cloud|search)[^\n]{0,50}(?:api_?key|API_KEY)[^\n]{0,30}\b([A-Za-z0-9+/_=]{60,})\b',
        keywords=["elastic", "ES_API_KEY", "ELASTIC"],
        confidence=0.85,
        description="Elasticsearch/Elastic Cloud API key (base64 encoded).",
        fix_hint="Revoke at cloud.elastic.co → Account → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-TYPESENSE-API-001",
        title="Typesense API Key",
        secret_type="typesense_api_key",
        severity="critical",
        pattern=r'(?i)typesense[^\n]{0,50}(?:api_?key|X-TYPESENSE-API-KEY)[^\n]{0,30}\b([A-Za-z0-9]{32,64})\b',
        keywords=["typesense", "TYPESENSE"],
        confidence=0.90,
        description="Typesense search admin API key.",
        fix_hint="Rotate at cloud.typesense.org → Cluster → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-MEILISEARCH-MASTER-001",
        title="Meilisearch Master Key",
        secret_type="meilisearch_master_key",
        severity="critical",
        pattern=r'(?i)meilisearch[^\n]{0,50}(?:master_?key|MEILI_MASTER_KEY)[^\n]{0,30}\b([A-Za-z0-9]{20,64})\b',
        keywords=["meilisearch", "MEILI_MASTER_KEY"],
        confidence=0.90,
        description="Meilisearch master/admin key.",
        fix_hint="Rotate at Meilisearch Cloud or local config.",
    ),

    # ── Content / CMS ────────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-WORDPRESS-APP-PASS-001",
        title="WordPress Application Password",
        secret_type="wordpress_app_password",
        severity="critical",
        pattern=r'\b([A-Za-z0-9]{4}\s[A-Za-z0-9]{4}\s[A-Za-z0-9]{4}\s[A-Za-z0-9]{4}\s[A-Za-z0-9]{4}\s[A-Za-z0-9]{4})\b',
        # 2-pass: lookahead → post_filter_* (Option B-1 codemod, 2026-05-24).
        post_filter_keywords=['wp-json', 'wordpress', 'WP_APP'],
        post_filter_window=120,
        keywords=["wordpress", "wp-json", "WP_APP"],
        confidence=0.92,
        description="WordPress application password (6 x 4-char groups).",
        fix_hint="Revoke at WP-Admin → Users → Application Passwords.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-STRAPI-JWT-001",
        title="Strapi JWT Secret",
        secret_type="strapi_jwt_secret",
        severity="critical",
        pattern=r'(?i)strapi[^\n]{0,50}(?:jwt_?secret|JWT_SECRET)[^\n]{0,30}\b([A-Za-z0-9+/=_-]{20,100})\b',
        keywords=["strapi", "STRAPI_JWT"],
        confidence=0.88,
        description="Strapi CMS JWT signing secret.",
        fix_hint="Rotate the JWT_SECRET env var and invalidate all sessions.",
    ),

    # ── Identity / SSO (additional) ──────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-AUTH0-MGMT-TOKEN-001",
        title="Auth0 Management API Token",
        secret_type="auth0_mgmt_token",
        severity="critical",
        # JWT body cap shrunk from {400,2000} → {400,1000} for re2
        # compatibility (Option B-2, 2026-05-24).  Auth0 management
        # tokens >1000 chars are rare; the prefix anchor
        # `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCI` (35 chars) is
        # highly specific, so the false-negative cost of the
        # tightened upper bound is minimal in practice.
        pattern=r'\b(eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCI[A-Za-z0-9_.=-]{400,1000})\b',
        # 2-pass: lookahead → post_filter_* (Option B-1 codemod, 2026-05-24).
        post_filter_keywords=['auth0'],
        post_filter_window=120,
        keywords=["auth0", "AUTH0"],
        confidence=0.88,
        description="Auth0 management API JWT token.",
        fix_hint="Rotate at manage.auth0.com → API Explorer or OAuth client.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-OKTA-API-001",
        title="Okta SSWS API Token",
        secret_type="okta_api_token",
        severity="critical",
        pattern=r'(?i)(?:ssws|okta)[^\n]{0,50}\b(00[A-Za-z0-9_-]{40})\b',
        keywords=["SSWS", "okta", "OKTA"],
        confidence=0.95,
        description="Okta admin API token (00 prefix + 40 chars).",
        fix_hint="Revoke at admin.okta.com → Security → API → Tokens.",
    ),

    # ── Miscellaneous ────────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-GRAFANA-SA-001",
        title="Grafana Service Account Token",
        secret_type="grafana_sa_token",
        severity="critical",
        pattern=r'\b(glsa_[A-Za-z0-9_]{40,60}_[a-f0-9]{8})\b',
        keywords=["glsa_"],
        confidence=0.99,
        description="Grafana service account token (glsa_ prefix).",
        fix_hint="Revoke at Grafana → Administration → Service Accounts.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-DOPPLER-TOKEN-001",
        title="Doppler Service Token",
        secret_type="doppler_service_token",
        severity="critical",
        pattern=r'\b(dp\.(?:st|pt|sa|ct)\.[a-zA-Z0-9._-]{36,60})\b',
        keywords=["dp.st.", "dp.pt.", "dp.sa.", "dp.ct.", "doppler"],
        confidence=0.99,
        description="Doppler secret manager token (dp.XX. prefix).",
        fix_hint="Revoke at dashboard.doppler.com → Access → Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-DIGITALOCEAN-V2-001",
        title="DigitalOcean Personal Access Token",
        secret_type="digitalocean_pat",
        severity="critical",
        pattern=r'\b(dop_v1_[a-f0-9]{64})\b',
        keywords=["dop_v1_"],
        confidence=0.99,
        description="DigitalOcean v2 personal access token (dop_v1_ prefix).",
        fix_hint="Revoke at cloud.digitalocean.com → API → Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-LINEAR-API-001",
        title="Linear API Key",
        secret_type="linear_api_key",
        severity="critical",
        pattern=r'\b(lin_api_[A-Za-z0-9]{40,45})\b',
        keywords=["lin_api_"],
        confidence=0.99,
        description="Linear personal API key (lin_api_ prefix).",
        fix_hint="Revoke at linear.app → Settings → API → Personal API keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-LINEAR-OAUTH-001",
        title="Linear OAuth Access Token",
        secret_type="linear_oauth_token",
        severity="critical",
        pattern=r'\b(lin_oauth_[A-Za-z0-9]{40,})\b',
        keywords=["lin_oauth_"],
        confidence=0.99,
        description="Linear OAuth access token.",
        fix_hint="Revoke at linear.app → Settings → API → OAuth applications.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-CLICKUP-V2-001",
        title="ClickUp Personal API Token",
        secret_type="clickup_pat",
        severity="high",
        pattern=r'\b(pk_\d{8}_[A-Z0-9]{32})\b',
        keywords=["pk_"],
        confidence=0.99,
        description="ClickUp personal API token (pk_<user_id>_<random>).",
        fix_hint="Revoke at app.clickup.com → Settings → Apps → API Token.",
        case_sensitive=True,
    ),
    SecretRule(
        rule_id="VOODA-SEC-ASANA-PAT-001",
        title="Asana Personal Access Token",
        secret_type="asana_pat",
        severity="critical",
        pattern=r'\b(1/\d{14,20}:[a-f0-9]{32})\b',
        keywords=["asana", "ASANA"],
        confidence=0.95,
        description="Asana personal access token (1/id:hash format).",
        fix_hint="Revoke at asana.com → My Profile Settings → Apps.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-INTERCOM-001",
        title="Intercom Access Token",
        secret_type="intercom_access_token",
        severity="critical",
        pattern=r'\b(dG9r[A-Za-z0-9_=]{100,})\b',
        # 2-pass: lookahead → post_filter_* (Option B-1 codemod, 2026-05-24).
        post_filter_keywords=['intercom'],
        post_filter_window=120,
        keywords=["intercom", "INTERCOM"],
        confidence=0.92,
        description="Intercom access token (dG9r base64 prefix).",
        fix_hint="Revoke at app.intercom.com → Settings → Apps & integrations.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-MIXPANEL-PROJECT-001",
        title="Mixpanel Service Account Secret",
        secret_type="mixpanel_service_account",
        severity="critical",
        pattern=r'(?i)mixpanel[^\n]{0,50}(?:secret|service_account)[^\n]{0,30}\b([a-f0-9]{32,})\b',
        keywords=["mixpanel"],
        confidence=0.88,
        description="Mixpanel service account secret for API access.",
        fix_hint="Rotate at mixpanel.com → Project Settings → Service Accounts.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-PAGERDUTY-INTEG-001",
        title="PagerDuty Integration Key",
        secret_type="pagerduty_integration_key",
        severity="high",
        pattern=r'(?i)pagerduty[^\n]{0,50}(?:integration_?key|ROUTING_KEY)[^\n]{0,30}\b([a-f0-9]{32})\b',
        keywords=["pagerduty", "PAGERDUTY"],
        confidence=0.92,
        description="PagerDuty Events API integration/routing key.",
        fix_hint="Rotate at PagerDuty → Service → Integrations.",
    ),

    # ── Observability additional 2 ───────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-SYSDIG-001",
        title="Sysdig API Token",
        secret_type="sysdig_api_token",
        severity="high",
        pattern=r'(?i)sysdig[^\n]{0,50}\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b',
        keywords=["sysdig", "SYSDIG"],
        confidence=0.90,
        description="Sysdig Secure/Monitor API token (UUID).",
        fix_hint="Rotate at app.sysdigcloud.com → Settings → User Profile → API.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-PROMETHEUS-REMOTE-WRITE-001",
        title="Prometheus Remote Write URL with Basic Auth",
        secret_type="prometheus_remote_write",
        severity="high",
        pattern=r'(https?://[A-Za-z0-9._-]+:[^@\s]+@[A-Za-z0-9.-]+/api/v1/write)',
        keywords=["/api/v1/write", "prometheus"],
        confidence=0.97,
        description="Prometheus remote-write URL with embedded basic-auth credentials.",
        fix_hint="Move credentials to separate config; use bearer auth or TLS client certs.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-LOGDNA-INGEST-001",
        title="LogDNA (Mezmo) Ingestion Key",
        secret_type="logdna_ingestion_key",
        severity="high",
        pattern=r'(?i)(?:logdna|mezmo)[^\n]{0,50}\b([a-f0-9]{32})\b',
        keywords=["logdna", "mezmo", "LOGDNA_KEY"],
        confidence=0.93,
        description="LogDNA / Mezmo log ingestion key.",
        fix_hint="Revoke at app.mezmo.com → Organization → API Keys.",
    ),

    # ── Blockchain & Web3 additional ─────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-ALCHEMY-API-001",
        title="Alchemy API Key (in URL)",
        secret_type="alchemy_api_key_url",
        severity="critical",
        pattern=r'https://[a-z0-9-]+\.(?:alchemy|g\.alchemy)\.com/v2/([A-Za-z0-9_-]{32,40})',
        keywords=["alchemy.com", "g.alchemy.com"],
        confidence=0.99,
        description="Alchemy Web3 RPC URL with embedded API key.",
        fix_hint="Rotate at dashboard.alchemy.com → Apps → API key.",
    ),
    # VOODA-SEC-INFURA-PROJECT-001 removed 2026-05-22 (Track-A Phase 5, Option A).
    # Exact-pattern duplicate consolidated into VOODA-SEC-INFURA-URL-001.
    # See services/secret_scan/detectors/registry.py:RULE_ID_ALIASES.
    SecretRule(
        rule_id="VOODA-SEC-WALLETCONNECT-001",
        title="WalletConnect Project ID",
        secret_type="walletconnect_project_id",
        severity="medium",
        pattern=r'(?i)walletconnect[^\n]{0,50}\b([a-f0-9]{32})\b',
        keywords=["walletconnect", "WALLETCONNECT"],
        confidence=0.88,
        description="WalletConnect project ID (semi-public but scope-specific).",
        fix_hint="Rotate at cloud.walletconnect.com → Project.",
    ),

    # ── Additional AI / ML providers ─────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-COHERE-API-001",
        title="Cohere API Key",
        secret_type="cohere_api_key",
        severity="high",
        pattern=r'(?i)cohere[^\n]{0,50}\b([A-Za-z0-9]{40})\b',
        keywords=["cohere", "COHERE"],
        confidence=0.90,
        description="Cohere large-language-model API key.",
        fix_hint="Revoke at dashboard.cohere.com → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-VOYAGE-API-001",
        title="Voyage AI API Key",
        secret_type="voyage_ai_key",
        severity="high",
        pattern=r'\b(pa-[A-Za-z0-9_-]{40,60})\b',
        keywords=["pa-", "voyage"],
        confidence=0.95,
        description="Voyage AI embeddings API key (pa- prefix).",
        fix_hint="Revoke at dash.voyageai.com → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-COHERE-TRIAL-001",
        title="Cohere Trial API Key",
        secret_type="cohere_trial_key",
        severity="medium",
        pattern=r'\btrial-[A-Za-z0-9]{40}\b',
        keywords=["trial-"],
        confidence=0.98,
        description="Cohere trial/free-tier API key.",
        fix_hint="Rotate at dashboard.cohere.com → API Keys.",
    ),

    # ── CDN / Edge ───────────────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-CLOUDFLARE-API-TOKEN-001",
        title="Cloudflare API Token",
        secret_type="cloudflare_api_token",
        severity="critical",
        pattern=r'(?i)cloudflare[^\n]{0,50}(?:api_?token|CF_API_TOKEN)[^\n]{0,30}\b([A-Za-z0-9_-]{40})\b',
        keywords=["cloudflare", "CF_API_TOKEN"],
        confidence=0.90,
        description="Cloudflare scoped API token.",
        fix_hint="Revoke at dash.cloudflare.com → My Profile → API Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-CLOUDFLARE-ORIGIN-CA-001",
        title="Cloudflare Origin CA Key",
        secret_type="cloudflare_origin_ca_key",
        severity="critical",
        pattern=r'\b(v1\.0-[0-9a-fA-F]{40}(?:-[0-9a-fA-F]{80,200}))\b',
        keywords=["v1.0-", "cloudflare"],
        confidence=0.99,
        description="Cloudflare Origin CA certificate signing key (v1.0- prefix).",
        fix_hint="Rotate at dash.cloudflare.com → SSL/TLS → Origin Server.",
    ),

    # ── Secret scanners (meta, detect our own) ───────────────────
    SecretRule(
        rule_id="VOODA-SEC-GITGUARDIAN-001",
        title="GitGuardian API Key",
        secret_type="gitguardian_api_key",
        severity="high",
        pattern=r'(?i)gitguardian[^\n]{0,50}\b([A-Za-z0-9]{40})\b',
        keywords=["gitguardian", "GITGUARDIAN"],
        confidence=0.90,
        description="GitGuardian secret scanner API key.",
        fix_hint="Rotate at dashboard.gitguardian.com → API.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-SEMGREP-APP-001",
        title="Semgrep App Token",
        secret_type="semgrep_app_token",
        severity="high",
        pattern=r'(?i)semgrep[^\n]{0,50}\b([a-f0-9]{40,64})\b',
        keywords=["semgrep", "SEMGREP"],
        confidence=0.90,
        description="Semgrep AppSec app token.",
        fix_hint="Rotate at semgrep.dev → Settings → Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-SNYK-API-001",
        title="Snyk API Token",
        secret_type="snyk_api_token",
        severity="high",
        pattern=r'(?i)snyk[^\n]{0,50}(?:token|API_TOKEN)[^\n]{0,30}\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b',
        keywords=["snyk", "SNYK"],
        confidence=0.93,
        description="Snyk API token (UUID format).",
        fix_hint="Revoke at app.snyk.io → Account Settings → API Token.",
    ),

    # ── Connection strings ───────────────────────────────────────
    SecretRule(
        rule_id="VOODA-SEC-POSTGRES-URL-001",
        title="Postgres Connection URL with Credentials",
        secret_type="postgres_connection_url",
        severity="critical",
        pattern=r'postgres(?:ql)?://[A-Za-z0-9_-]+:[^@\s/]{3,64}@[A-Za-z0-9.-]+(?::\d+)?/[A-Za-z0-9_-]+',
        keywords=["postgres://", "postgresql://"],
        confidence=0.97,
        description="Postgres connection URL with embedded username:password.",
        fix_hint="Move DB credentials to secret manager; use env vars.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-MYSQL-URL-001",
        title="MySQL Connection URL with Credentials",
        secret_type="mysql_connection_url",
        severity="critical",
        pattern=r'mysql://[A-Za-z0-9_-]+:[^@\s/]{3,64}@[A-Za-z0-9.-]+(?::\d+)?/[A-Za-z0-9_-]+',
        keywords=["mysql://"],
        confidence=0.97,
        description="MySQL connection URL with embedded credentials.",
        fix_hint="Move DB credentials to secret manager; use env vars.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-MONGODB-URL-001",
        title="MongoDB Connection URL with Credentials",
        secret_type="mongodb_connection_url",
        severity="critical",
        pattern=r'mongodb(?:\+srv)?://[A-Za-z0-9_-]+:[^@\s/]{3,64}@[A-Za-z0-9.-]+',
        keywords=["mongodb://", "mongodb+srv://"],
        confidence=0.97,
        description="MongoDB connection URL with embedded credentials.",
        fix_hint="Move DB credentials to secret manager.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-MSSQL-URL-001",
        title="MSSQL Connection String with Password",
        secret_type="mssql_connection_string",
        severity="critical",
        pattern=r'(?i)(?:server|data source)\s*=\s*[^;]+;[^;]*(?:user|uid)\s*=\s*[^;]+;[^;]*(?:password|pwd)\s*=\s*[^;\s]{4,}',
        keywords=["user id=", "uid=", "pwd=", "password="],
        confidence=0.92,
        description="MSSQL/ODBC connection string with embedded password.",
        fix_hint="Move credentials to secret manager; use Windows auth where possible.",
    ),
]
