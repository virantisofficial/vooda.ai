# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Gitleaks-sourced detectors batch 4: Additional GitLab, Slack, remaining services.
Plus TruffleHog-inspired additional patterns."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    # ── GitLab Extended ──
    SecretRule(rule_id="VOODA-SEC-GL-004", title="GitLab CI/CD Job Token", secret_type="gitlab_cicd_token", severity="high",
        pattern=r'(glcbt-[a-zA-Z0-9]{20}[a-zA-Z0-9\-_=]{0,20})', keywords=["glcbt-"], confidence=0.95,
        description="GitLab CI/CD job token.", fix_hint="CI/CD tokens are short-lived. Check pipeline for leaked credentials."),
    SecretRule(rule_id="VOODA-SEC-GL-005", title="GitLab Feed Token", secret_type="gitlab_feed_token", severity="medium",
        pattern=r'(glft-[a-zA-Z0-9\-_]{20,})', keywords=["glft-"], confidence=0.95,
        description="GitLab RSS feed token.", fix_hint="Reset at GitLab → User Settings → Feed Token."),
    SecretRule(rule_id="VOODA-SEC-GL-006", title="GitLab OAuth App Secret", secret_type="gitlab_oauth_secret", severity="high",
        pattern=r'(gloas-[a-f0-9]{64})', keywords=["gloas-"], confidence=0.98,
        description="GitLab OAuth application secret.", fix_hint="Regenerate at GitLab → Applications → Edit."),
    SecretRule(rule_id="VOODA-SEC-GL-007", title="GitLab Kubernetes Agent Token", secret_type="gitlab_k8s_agent_token", severity="high",
        pattern=r'(glagent-[a-zA-Z0-9\-_]{50,})', keywords=["glagent-"], confidence=0.98,
        description="GitLab Kubernetes agent token.", fix_hint="Revoke at GitLab → Infrastructure → Kubernetes Clusters."),
    SecretRule(rule_id="VOODA-SEC-GL-008", title="GitLab SCIM Token", secret_type="gitlab_scim_token", severity="high",
        pattern=r'(glsoat-[a-zA-Z0-9\-_]{20,})', keywords=["glsoat-"], confidence=0.95,
        description="GitLab SCIM provisioning token.", fix_hint="Reset at GitLab → Group → Settings → SAML SSO → SCIM Configuration."),
    SecretRule(rule_id="VOODA-SEC-GL-009", title="GitLab Runner Registration Token (routable)", secret_type="gitlab_runner_routable", severity="high",
        pattern=r'(GR1348941[a-zA-Z0-9\-_]{20,})', keywords=["GR1348941"], confidence=0.98,
        description="GitLab runner registration token.", fix_hint="Reset at GitLab → Admin → CI/CD → Runners."),
    # ── Slack Extended ──
    SecretRule(rule_id="VOODA-SEC-SLACK-006", title="Slack Config Access Token", secret_type="slack_config_access_token", severity="high",
        pattern=r'(xoxe\.xox[bp]-\d-[a-zA-Z0-9]{163,166})', keywords=["xoxe.xox"], confidence=0.98,
        description="Slack configuration access token.", fix_hint="Revoke at Slack → Your Apps → OAuth & Permissions."),
    SecretRule(rule_id="VOODA-SEC-SLACK-007", title="Slack Config Refresh Token", secret_type="slack_config_refresh_token", severity="high",
        pattern=r'(xoxe-\d-[a-zA-Z0-9]{146})', keywords=["xoxe-"], confidence=0.98,
        description="Slack configuration refresh token.", fix_hint="Revoke at Slack → Your Apps → OAuth & Permissions."),
    # ── Sentry Extended ──
    SecretRule(rule_id="VOODA-SEC-SENTRY-003", title="Sentry Organization Auth Token", secret_type="sentry_org_token", severity="high",
        pattern=r'(sntryo_[A-Za-z0-9]{50,})', keywords=["sntryo_"], confidence=0.98,
        description="Sentry organization-scoped auth token.", fix_hint="Revoke at Sentry → Settings → Auth Tokens."),
    SecretRule(rule_id="VOODA-SEC-SENTRY-004", title="Sentry User Auth Token", secret_type="sentry_user_token", severity="high",
        pattern=r'(sntryu_[A-Za-z0-9]{50,})', keywords=["sntryu_"], confidence=0.98,
        description="Sentry user-scoped auth token.", fix_hint="Revoke at Sentry → Settings → Auth Tokens."),
    # ── Heroku v2 ──
    SecretRule(rule_id="VOODA-SEC-HEROKU-002", title="Heroku API Key v2", secret_type="heroku_api_key_v2", severity="high",
        pattern=r'(?:heroku)[\w\s=:"\'-]*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', keywords=["heroku"], confidence=0.80,
        description="Heroku API key (UUID format).", fix_hint="Regenerate at Heroku Dashboard → Account Settings."),
    # ── Facebook ──
    SecretRule(rule_id="VOODA-SEC-FB-003", title="Facebook Page Access Token", secret_type="facebook_page_token", severity="high",
        pattern=r'(EAA[MC][a-zA-Z0-9]{100,})', keywords=["EAAM", "EAAC"], confidence=0.90,
        description="Facebook/Meta Page access token.", fix_hint="Token will expire. Revoke at Facebook Business Settings."),
    # ── Sidekiq ──
    SecretRule(rule_id="VOODA-SEC-SIDEKIQ-001", title="Sidekiq Sensitive URL", secret_type="sidekiq_url", severity="high",
        pattern=r'https?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems\.contribsys\.com|enterprise\.contribsys\.com)', keywords=["contribsys.com"], confidence=0.95,
        description="Sidekiq Pro/Enterprise license URL with embedded credentials.", fix_hint="Regenerate license key at contribsys.com."),
    # ── Yandex Extended ──
    SecretRule(rule_id="VOODA-SEC-YANDEX-002", title="Yandex AWS Access Token", secret_type="yandex_aws_token", severity="high",
        pattern=r'(YC[a-zA-Z0-9_\-]{38})', keywords=["YC"], confidence=0.70,
        # WS6 2026-06-05: the bare ``YC`` prefix matches any 40-char base64 blob
        # (audit: 2094 findings / 8 TP). ``keywords=["YC"]`` is a no-op because
        # the token itself contains "YC". Require a real Yandex marker nearby so
        # random YC-blobs stop matching; ``yc_token``/``yc-token`` keep the bare
        # env-var case (``YC_TOKEN=YC...``) detected so recall on real tokens holds.
        post_filter_keywords=["yandex", "ydb", "yc_token", "yc-token", "cloud.yandex"],
        post_filter_window=300, post_filter_direction="both",  # marker is usually BEFORE the token
        description="Yandex Cloud AWS-compatible access token.", fix_hint="Revoke at Yandex Cloud Console → Service Accounts."),
    # ── TruffleHog-inspired patterns ──
    SecretRule(rule_id="VOODA-SEC-AZURE-004", title="Azure DevOps Personal Access Token", secret_type="azure_devops_pat_v2", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])([a-z0-9]{52})(?:[^A-Za-z0-9]|$)', keywords=["azure_devops", "ado_pat", "AZURE_DEVOPS_PAT"], confidence=0.50,
        provider_override="azure_devops",
        description="Azure DevOps personal access token (52-char).", fix_hint="Revoke at Azure DevOps → User Settings → PATs."),
    SecretRule(rule_id="VOODA-SEC-OPENAI-004", title="OpenAI API Key (new format)", secret_type="openai_api_key_v2", severity="high",
        pattern=r'(sk-[a-zA-Z0-9]{48,})', keywords=["sk-"], confidence=0.70,
        description="OpenAI API key (new format, longer than classic).", fix_hint="Revoke at platform.openai.com → API keys."),
    SecretRule(rule_id="VOODA-SEC-MISTRAL-002", title="Mistral AI API Key", secret_type="mistral_api_key", severity="high",
        pattern=r'(?:mistral)[\w\s=:"\'-]*([a-zA-Z0-9]{32})', keywords=["mistral", "MISTRAL"], confidence=0.75,
        description="Mistral AI API key.", fix_hint="Regenerate at console.mistral.ai → API Keys."),
    SecretRule(rule_id="VOODA-SEC-GROQ-002", title="Groq API Key", secret_type="groq_api_key", severity="high",
        pattern=r'(gsk_[a-zA-Z0-9]{52})', keywords=["gsk_"], confidence=0.95,
        description="Groq AI inference API key.", fix_hint="Regenerate at console.groq.com → API Keys."),
    SecretRule(rule_id="VOODA-SEC-DEEPSEEK-002", title="DeepSeek API Key", secret_type="deepseek_api_key", severity="high",
        pattern=r'(sk-[a-f0-9]{48})', keywords=["deepseek", "DEEPSEEK"], confidence=0.60,
        description="DeepSeek AI API key.", fix_hint="Regenerate at platform.deepseek.com → API Keys."),
    SecretRule(rule_id="VOODA-SEC-TOGETHER-001", title="Together AI API Key", secret_type="together_api_key", severity="high",
        pattern=r'(?:together)[\w\s=:"\'-]*([a-f0-9]{64})', keywords=["together", "TOGETHER_API"], confidence=0.75,
        description="Together AI inference API key.", fix_hint="Regenerate at api.together.xyz → Settings → API Keys."),
    SecretRule(rule_id="VOODA-SEC-FIREWORKS-001", title="Fireworks AI API Key", secret_type="fireworks_api_key", severity="high",
        pattern=r'(fw_[a-zA-Z0-9]{40,})', keywords=["fw_"], confidence=0.85,
        description="Fireworks AI API key.", fix_hint="Regenerate at fireworks.ai → Account → API Keys."),
    SecretRule(rule_id="VOODA-SEC-CEREBRAS-001", title="Cerebras API Key", secret_type="cerebras_api_key", severity="high",
        pattern=r'(csk-[a-zA-Z0-9]{40,})', keywords=["csk-"], confidence=0.90,
        description="Cerebras AI inference API key.", fix_hint="Regenerate at cloud.cerebras.ai → API Keys."),
    SecretRule(rule_id="VOODA-SEC-SAMBANOVA-001", title="SambaNova API Key", secret_type="sambanova_api_key", severity="high",
        pattern=r'(?:sambanova|SAMBANOVA)[\w\s=:"\'-]*([a-f0-9]{64})', keywords=["sambanova", "SAMBANOVA"], confidence=0.75,
        description="SambaNova AI API key.", fix_hint="Regenerate at SambaNova Cloud."),
    # ── Additional Infrastructure ──
    SecretRule(rule_id="VOODA-SEC-RAILWAY-002", title="Railway API Token", secret_type="railway_token", severity="high",
        pattern=r'(?:railway)[\w\s=:"\'-]*([a-f0-9\-]{36})', keywords=["railway", "RAILWAY_TOKEN"], confidence=0.75,
        description="Railway PaaS API token.", fix_hint="Regenerate at Railway → Account → API Tokens."),
    SecretRule(rule_id="VOODA-SEC-COOLIFY-001", title="Coolify API Token", secret_type="coolify_token", severity="high",
        pattern=r'(?:coolify)[\w\s=:"\'-]*([a-zA-Z0-9|]{50,})', keywords=["coolify", "COOLIFY"], confidence=0.70,
        description="Coolify self-hosted PaaS API token.", fix_hint="Regenerate at Coolify → Settings → API."),
    SecretRule(rule_id="VOODA-SEC-TAILSCALE-001", title="Tailscale API Key", secret_type="tailscale_key", severity="high",
        pattern=r'(tskey-api-[a-zA-Z0-9\-]{20,})', keywords=["tskey-api-"], confidence=0.98,
        description="Tailscale API key.", fix_hint="Revoke at Tailscale Admin → Settings → Keys."),
    SecretRule(rule_id="VOODA-SEC-TAILSCALE-002", title="Tailscale Auth Key", secret_type="tailscale_authkey", severity="high",
        pattern=r'(tskey-auth-[a-zA-Z0-9\-]{20,})', keywords=["tskey-auth-"], confidence=0.98,
        description="Tailscale auth key for device enrollment.", fix_hint="Revoke at Tailscale Admin → Settings → Keys."),
    SecretRule(rule_id="VOODA-SEC-ZEROTIER-001", title="ZeroTier API Token", secret_type="zerotier_token", severity="high",
        pattern=r'(?:zerotier)[\w\s=:"\'-]*([a-zA-Z0-9]{32})', keywords=["zerotier", "ZEROTIER"], confidence=0.75,
        description="ZeroTier network API token.", fix_hint="Regenerate at ZeroTier Central → Account."),
    # ── Additional SaaS ──
    SecretRule(rule_id="VOODA-SEC-OPENSHIFT-001", title="OpenShift User Token", secret_type="openshift_token", severity="high",
        pattern=r'(sha256~[a-zA-Z0-9_\-]{43})', keywords=["sha256~"], confidence=0.95,
        description="OpenShift user authentication token.", fix_hint="Delete via `oc logout` and regenerate."),
    SecretRule(rule_id="VOODA-SEC-EXPO-001", title="Expo Access Token", secret_type="expo_token", severity="medium",
        pattern=r'(?:expo)[\w\s=:"\'-]*([a-zA-Z0-9\-_]{40,})', keywords=["expo_token", "EXPO_TOKEN"], confidence=0.70,
        description="Expo (React Native) access token.", fix_hint="Regenerate at expo.dev → Account → Access Tokens."),
    SecretRule(rule_id="VOODA-SEC-SUPABASE-002", title="Supabase Anon Key", secret_type="supabase_anon_key", severity="medium",
        pattern=r'(?:supabase_anon|SUPABASE_ANON|NEXT_PUBLIC_SUPABASE_ANON_KEY)[\w\s=:"\'-]*(eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)', keywords=["supabase_anon", "SUPABASE_ANON", "NEXT_PUBLIC_SUPABASE"], confidence=0.85,
        description="Supabase anonymous/public key (JWT).", fix_hint="Anon keys are public by design but should be in env vars. Rotate at Supabase → Project Settings → API."),
    SecretRule(rule_id="VOODA-SEC-CONVEX-001", title="Convex Deploy Key", secret_type="convex_deploy_key", severity="high",
        pattern=r'(?:convex)[\w\s=:"\'-]*(prod:[a-zA-Z0-9\-_]{40,}|dev:[a-zA-Z0-9\-_]{40,})', keywords=["convex", "CONVEX_DEPLOY_KEY"], confidence=0.80,
        description="Convex backend deployment key.", fix_hint="Regenerate at Convex Dashboard → Settings."),
    SecretRule(rule_id="VOODA-SEC-NEON-002", title="Neon API Key", secret_type="neon_api_key", severity="high",
        pattern=r'(?:neon)[\w\s=:"\'-]*([a-zA-Z0-9]{60,})', keywords=["neon_api", "NEON_API_KEY"], confidence=0.70,
        description="Neon serverless Postgres API key.", fix_hint="Regenerate at Neon Console → Account Settings → API Keys."),
    # ── PKI / Certificates ──
    SecretRule(rule_id="VOODA-SEC-PKCS12-001", title="PKCS12 File", secret_type="pkcs12_file", severity="high",
        pattern=r'(?:\.p12|\.pfx)', keywords=[".p12", ".pfx"], confidence=0.50,
        description="PKCS#12 certificate file (may contain private key).", fix_hint="Remove from source code. Store certificates in a vault or certificate manager."),
    SecretRule(rule_id="VOODA-SEC-DSAPRIVKEY-001", title="DSA Private Key", secret_type="dsa_private_key", severity="critical",
        pattern=r'-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----', keywords=["BEGIN DSA PRIVATE KEY"], confidence=0.95,
        description="DSA private key in PEM format.", fix_hint="Remove from repository. DSA is deprecated — migrate to ECDSA or Ed25519.",
        multiline=True),
    SecretRule(rule_id="VOODA-SEC-ENCPRIVKEY-001", title="Encrypted Private Key", secret_type="encrypted_private_key", severity="high",
        pattern=r'-----BEGIN ENCRYPTED PRIVATE KEY-----[\s\S]*?-----END ENCRYPTED PRIVATE KEY-----', keywords=["BEGIN ENCRYPTED PRIVATE KEY"], confidence=0.80,
        description="Encrypted private key (password-protected). Still should not be in source code.", fix_hint="Remove from repository. Use a key management service.",
        multiline=True),
    # ── Hashicorp Extended ──
    SecretRule(rule_id="VOODA-SEC-TF-002", title="Terraform Cloud Password", secret_type="terraform_password", severity="high",
        pattern=r'(?:terraform|TF_)[\w\s=:"\'-]*(?:password|token)[\w\s=:"\'-]*([a-zA-Z0-9\-_.]{30,})', keywords=["TF_TOKEN", "terraform_token", "TF_API_TOKEN"], confidence=0.65,
        description="Terraform Cloud API token or password.", fix_hint="Regenerate at Terraform Cloud → User Settings → Tokens."),
]
