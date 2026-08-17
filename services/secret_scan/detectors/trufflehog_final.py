# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Final batch: TruffleHog-sourced high-confidence detectors.
Focus on distinctive prefix patterns and AI/ML platforms.
Each rule has been verified against official provider documentation."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    # ══════════════════════════════════════════
    # AI/ML PLATFORMS (fastest-growing leak category)
    # ══════════════════════════════════════════
    SecretRule(rule_id="VOODA-SEC-ELEVENLABS-002", title="ElevenLabs API Key", secret_type="elevenlabs_key", severity="high",
        pattern=r'(?:elevenlabs|ELEVEN_LABS|xi-api-key)[\w\s=:"\'-]*([a-f0-9]{32})', keywords=["elevenlabs", "ELEVEN_LABS", "xi-api-key", "xi_api_key"], confidence=0.80,
        description="ElevenLabs voice AI API key.", fix_hint="Regenerate at elevenlabs.io → Profile → API Keys."),
    SecretRule(rule_id="VOODA-SEC-DEEPGRAM-002", title="Deepgram API Key", secret_type="deepgram_key", severity="high",
        pattern=r'(?:deepgram|DEEPGRAM)[\w\s=:"\'-]*([a-f0-9]{40})', keywords=["deepgram", "DEEPGRAM_API_KEY"], confidence=0.80,
        description="Deepgram speech-to-text API key.", fix_hint="Regenerate at Deepgram → Settings → API Keys."),
    SecretRule(rule_id="VOODA-SEC-ASSEMBLYAI-002", title="AssemblyAI API Key", secret_type="assemblyai_key", severity="high",
        pattern=r'(?:assemblyai|ASSEMBLYAI|assembly_ai)[\w\s=:"\'-]*([a-f0-9]{32})', keywords=["assemblyai", "ASSEMBLYAI", "assembly_ai"], confidence=0.80,
        description="AssemblyAI transcription API key.", fix_hint="Regenerate at assemblyai.com → Account → API Keys."),
    SecretRule(rule_id="VOODA-SEC-LANGFUSE-001", title="Langfuse Secret Key", secret_type="langfuse_key", severity="high",
        pattern=r'(sk-lf-[a-zA-Z0-9\-]{32,})', keywords=["sk-lf-"], confidence=0.95,
        description="Langfuse LLM observability secret key.", fix_hint="Regenerate at Langfuse → Settings → API Keys."),
    SecretRule(rule_id="VOODA-SEC-LANGSMITH-002", title="LangSmith API Key", secret_type="langsmith_key", severity="high",
        pattern=r'(lsv2_pt_[a-f0-9]{32,})', keywords=["lsv2_pt_"], confidence=0.98,
        description="LangSmith (LangChain) API key.", fix_hint="Regenerate at smith.langchain.com → Settings → API Keys."),
    SecretRule(rule_id="VOODA-SEC-WANDB-001", title="Weights & Biases API Key", secret_type="wandb_key", severity="high",
        pattern=r'(?:wandb|WANDB)[\w\s=:"\'-]*([a-f0-9]{40})', keywords=["wandb", "WANDB_API_KEY"], confidence=0.80,
        description="Weights & Biases ML experiment tracking API key.", fix_hint="Regenerate at wandb.ai → Settings → API Keys."),
    SecretRule(rule_id="VOODA-SEC-NGC-001", title="NVIDIA NGC API Key", secret_type="nvidia_ngc_key", severity="high",
        pattern=r'(nvapi-[a-zA-Z0-9\-_]{50,})', keywords=["nvapi-"], confidence=0.95,
        description="NVIDIA NGC (GPU Cloud) API key.", fix_hint="Regenerate at ngc.nvidia.com → Setup → API Key."),
    SecretRule(rule_id="VOODA-SEC-XAI-001", title="xAI (Grok) API Key", secret_type="xai_key", severity="high",
        pattern=r'(xai-[a-zA-Z0-9]{40,})', keywords=["xai-"], confidence=0.90,
        description="xAI Grok API key.", fix_hint="Regenerate at x.ai → API Keys."),
    SecretRule(rule_id="VOODA-SEC-GOOGLEAI-001", title="Google Gemini API Key", secret_type="google_gemini_key", severity="high",
        pattern=r'(?:GOOGLE_API_KEY|GEMINI_API_KEY|google_gemini)[\w\s=:"\'-]*(AIza[0-9A-Za-z\-_]{35})', keywords=["GOOGLE_API_KEY", "GEMINI_API_KEY", "google_gemini"], confidence=0.90,
        description="Google Gemini/AI Studio API key.", fix_hint="Regenerate at aistudio.google.com → Get API Key."),

    # ══════════════════════════════════════════
    # DISTINCTIVE PREFIX PATTERNS (highest confidence)
    # ══════════════════════════════════════════
    SecretRule(rule_id="VOODA-SEC-POSTHOG-001", title="PostHog API Key", secret_type="posthog_key", severity="medium",
        pattern=r'(phx_[a-zA-Z0-9]{40,}|phc_[a-zA-Z0-9]{40,})', keywords=["phx_", "phc_"], confidence=0.95,
        description="PostHog analytics API key.", fix_hint="Regenerate at PostHog → Project Settings → API Key."),
    SecretRule(rule_id="VOODA-SEC-PINATA-001", title="Pinata API Key", secret_type="pinata_key", severity="medium",
        pattern=r'(?:pinata|PINATA)[\w\s=:"\'-]*([a-f0-9]{64})', keywords=["pinata", "PINATA_API_KEY"], confidence=0.75,
        description="Pinata IPFS pinning service API key.", fix_hint="Regenerate at pinata.cloud → API Keys."),
    SecretRule(rule_id="VOODA-SEC-NIGHTFALL-001", title="Nightfall AI API Key", secret_type="nightfall_key", severity="high",
        pattern=r'(NF-[a-zA-Z0-9]{32,})', keywords=["NF-"], confidence=0.90,
        description="Nightfall DLP API key.", fix_hint="Regenerate at Nightfall → Settings → API Keys."),
    SecretRule(rule_id="VOODA-SEC-PORTAINER-001", title="Portainer API Token", secret_type="portainer_token", severity="high",
        pattern=r'(ptr_[a-zA-Z0-9]{30,})', keywords=["ptr_"], confidence=0.90,
        description="Portainer container management API token.", fix_hint="Revoke at Portainer → User Settings → Access Tokens."),
    SecretRule(rule_id="VOODA-SEC-PERCY-001", title="Percy Token", secret_type="percy_token", severity="medium",
        pattern=r'(?:percy|PERCY)[\w\s=:"\'-]*([a-f0-9]{64})', keywords=["percy", "PERCY_TOKEN"], confidence=0.80,
        description="Percy visual testing token.", fix_hint="Regenerate at Percy → Project Settings → Token."),
    SecretRule(rule_id="VOODA-SEC-PREFECT-002", title="Prefect Cloud API Key (pnu_)", secret_type="prefect_key_v2", severity="high",
        pattern=r'(pnu_[a-zA-Z0-9]{36,})', keywords=["pnu_"], confidence=0.98,
        description="Prefect Cloud API key.", fix_hint="Revoke at Prefect Cloud → API Keys."),
    SecretRule(rule_id="VOODA-SEC-PIPEDREAM-001", title="Pipedream API Key", secret_type="pipedream_key", severity="medium",
        pattern=r'(pd_[a-zA-Z0-9]{30,})', keywords=["pd_"], confidence=0.85,
        description="Pipedream workflow API key.", fix_hint="Regenerate at Pipedream → Account → API Keys."),

    # ══════════════════════════════════════════
    # PAYMENT & FINTECH (high business impact)
    # ══════════════════════════════════════════
    SecretRule(rule_id="VOODA-SEC-PAYSTACK-001", title="Paystack Secret Key", secret_type="paystack_secret", severity="critical",
        pattern=r'(sk_(?:live|test)_[a-f0-9]{40})', keywords=["sk_live_", "sk_test_", "paystack"], confidence=0.85,
        description="Paystack payment gateway secret key.", fix_hint="Regenerate at Paystack → Settings → API Keys."),
    SecretRule(rule_id="VOODA-SEC-LEMONSQUEEZY-001", title="Lemon Squeezy API Key", secret_type="lemonsqueezy_key", severity="high",
        pattern=r'(?:lemonsqueezy|LEMON_SQUEEZY)[\w\s=:"\'-]*(eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)', keywords=["lemonsqueezy", "LEMON_SQUEEZY"], confidence=0.80,
        description="Lemon Squeezy payment platform API key.", fix_hint="Regenerate at app.lemonsqueezy.com → Settings → API."),
    SecretRule(rule_id="VOODA-SEC-PADDLE-001", title="Paddle API Key", secret_type="paddle_key", severity="high",
        pattern=r'(?:paddle|PADDLE)[\w\s=:"\'-]*([a-f0-9]{64})', keywords=["paddle", "PADDLE_API_KEY"], confidence=0.75,
        description="Paddle payment/subscription API key.", fix_hint="Regenerate at Paddle → Developer Tools → API Keys."),

    # ══════════════════════════════════════════
    # SECURITY & IDENTITY (critical impact)
    # ══════════════════════════════════════════
    SecretRule(rule_id="VOODA-SEC-SNYK-002", title="Snyk Auth Token (context)", secret_type="snyk_token_ctx", severity="high",
        pattern=r'(?:snyk|SNYK)[\w\s=:"\'-]*([a-f0-9\-]{36})', keywords=["snyk", "SNYK_TOKEN"], confidence=0.80,
        description="Snyk security scanner auth token.", fix_hint="Revoke at Snyk → Account Settings → Auth Token."),
    SecretRule(rule_id="VOODA-SEC-WIZ-001", title="Wiz API Client Secret", secret_type="wiz_secret", severity="critical",
        pattern=r'(?:wiz|WIZ)[\w\s=:"\'-]*client_secret[\w\s=:"\'-]*([a-zA-Z0-9\-_.]{30,})', keywords=["wiz", "WIZ_CLIENT_SECRET"], confidence=0.75,
        description="Wiz cloud security platform client secret.", fix_hint="Regenerate at Wiz → Settings → Service Accounts."),
    SecretRule(rule_id="VOODA-SEC-CROWDSTRIKE-002", title="CrowdStrike API Secret", secret_type="crowdstrike_secret", severity="critical",
        pattern=r'(?:crowdstrike|CROWDSTRIKE|falcon)[\w\s=:"\'-]*client_secret[\w\s=:"\'-]*([a-zA-Z0-9]{40})', keywords=["crowdstrike", "CROWDSTRIKE", "falcon_client_secret"], confidence=0.75,
        description="CrowdStrike Falcon API client secret.", fix_hint="Regenerate at CrowdStrike → Support → API Clients."),
    SecretRule(rule_id="VOODA-SEC-ONELOGIN-001", title="OneLogin Client Secret", secret_type="onelogin_secret", severity="high",
        pattern=r'(?:onelogin|ONELOGIN)[\w\s=:"\'-]*client_secret[\w\s=:"\'-]*([a-f0-9]{64})', keywords=["onelogin", "ONELOGIN"], confidence=0.75,
        description="OneLogin identity provider client secret.", fix_hint="Regenerate at OneLogin → Developers → API Credentials."),

    # ══════════════════════════════════════════
    # DATA & ANALYTICS
    # ══════════════════════════════════════════
    SecretRule(rule_id="VOODA-SEC-SNOWFLAKE-002", title="Snowflake JWT Key Pair", secret_type="snowflake_jwt", severity="critical",
        pattern=r'(?:snowflake|SNOWFLAKE)[\w\s=:"\'-]*private_key[\w\s=:"\'-]*-----BEGIN', keywords=["snowflake", "SNOWFLAKE", "private_key"], confidence=0.85,
        description="Snowflake JWT authentication private key.", fix_hint="Generate new key pair via Snowflake and update config.",
        multiline=True),
    SecretRule(rule_id="VOODA-SEC-DBT-002", title="dbt Cloud Service Token", secret_type="dbt_service_token", severity="high",
        pattern=r'(dbtc_[a-zA-Z0-9]{40,})', keywords=["dbtc_"], confidence=0.95,
        description="dbt Cloud service account token.", fix_hint="Regenerate at dbt Cloud → Account Settings → Service Tokens."),
    SecretRule(rule_id="VOODA-SEC-LOOKER-002", title="Looker Client ID", secret_type="looker_client_id", severity="medium",
        pattern=r'(?:looker)[\w\s=:"\'-]*client_id[\w\s=:"\'-]*([a-zA-Z0-9]{20})', keywords=["looker_client_id", "LOOKER_CLIENT_ID"], confidence=0.75,
        description="Looker BI client ID.", fix_hint="Regenerate at Looker → Admin → API → Edit Credentials."),
    SecretRule(rule_id="VOODA-SEC-METABASE-001", title="Metabase Session Token", secret_type="metabase_token", severity="high",
        pattern=r'(?:metabase|METABASE)[\w\s=:"\'-]*([a-f0-9\-]{36})', keywords=["metabase", "METABASE_SESSION"], confidence=0.70,
        description="Metabase analytics session or API token.", fix_hint="Session tokens expire. For API keys, regenerate at Metabase → Admin → API Keys."),

    # ══════════════════════════════════════════
    # COMMUNICATION & COLLABORATION
    # ══════════════════════════════════════════
    SecretRule(rule_id="VOODA-SEC-WEBEX-002", title="Cisco Webex Access Token", secret_type="webex_token_v2", severity="high",
        pattern=r'(OTk[a-zA-Z0-9\-_]{80,})', keywords=["OTk"], confidence=0.70,
        # WS6 2026-06-05: same anti-pattern as YANDEX-002 — the ``OTk`` prefix
        # matches any 83-char base64 blob and ``keywords=["OTk"]`` is a no-op
        # (the token contains "OTk"). Require a Webex/Cisco marker nearby.
        post_filter_keywords=["webex", "ciscospark", "cisco_spark", "webex_token", "spark.io"],
        post_filter_window=300, post_filter_direction="both",
        description="Cisco Webex access token (base64-encoded).", fix_hint="Regenerate at developer.webex.com."),
    SecretRule(rule_id="VOODA-SEC-ZULIP-001", title="Zulip Chat API Key", secret_type="zulip_key", severity="medium",
        pattern=r'(?:zulip|ZULIP)[\w\s=:"\'-]*([a-zA-Z0-9]{32})', keywords=["zulip", "ZULIP"], confidence=0.75,
        description="Zulip open-source chat API key.", fix_hint="Regenerate at Zulip → Settings → API Key."),
    SecretRule(rule_id="VOODA-SEC-ROCKET-001", title="Rocket.Chat Token", secret_type="rocketchat_token", severity="medium",
        pattern=r'(?:rocketchat|ROCKET_CHAT)[\w\s=:"\'-]*([a-zA-Z0-9\-_]{40,})', keywords=["rocketchat", "ROCKET_CHAT"], confidence=0.65,
        description="Rocket.Chat authentication token.", fix_hint="Regenerate at Rocket.Chat → Admin → Integrations."),

    # ══════════════════════════════════════════
    # INFRASTRUCTURE & DEVOPS
    # ══════════════════════════════════════════
    SecretRule(rule_id="VOODA-SEC-RABBITMQ-001", title="RabbitMQ Credentials", secret_type="rabbitmq_creds", severity="critical",
        pattern=r'amqps?://[^:\s]+:[^@\s]+@[^\s/]+', keywords=["amqp://", "amqps://"], confidence=0.90,
        description="RabbitMQ connection URL with embedded credentials.", fix_hint="Use environment variables for AMQP credentials."),
    SecretRule(rule_id="VOODA-SEC-KAFKA-001", title="Kafka SASL Credentials", secret_type="kafka_sasl_creds", severity="critical",
        pattern=r'(?:sasl\.password|KAFKA_SASL_PASSWORD|sasl_plain_password)\s*[=:]\s*["\']?([^\s"\']{12,})["\']?', keywords=["sasl.password", "KAFKA_SASL_PASSWORD", "sasl_plain_password"], confidence=0.80,
        description="Apache Kafka SASL authentication password.", fix_hint="Rotate credentials in your Kafka cluster config. Use SCRAM or mTLS instead of PLAIN."),
    SecretRule(rule_id="VOODA-SEC-OPENSEARCH-001", title="OpenSearch Credentials", secret_type="opensearch_creds", severity="critical",
        pattern=r'https?://[^:\s]+:[^@\s]+@[^\s]*(?:opensearch|es|elasticsearch)[^\s]*', keywords=["opensearch", "elasticsearch"], confidence=0.85,
        description="OpenSearch/Elasticsearch URL with embedded credentials.", fix_hint="Use API keys or certificates instead of basic auth in URLs."),
    SecretRule(rule_id="VOODA-SEC-GRAFANACLOUD-001", title="Grafana Cloud Stack Token", secret_type="grafana_cloud_stack", severity="high",
        pattern=r'(glc_[a-zA-Z0-9+/=]{32,})', keywords=["glc_"], confidence=0.95,
        description="Grafana Cloud Stack API key.", fix_hint="Rotate at Grafana Cloud → Stacks → API Keys."),
    SecretRule(rule_id="VOODA-SEC-HONEYCOMB-002", title="Honeycomb API Key", secret_type="honeycomb_key", severity="high",
        pattern=r'(?:honeycomb|HONEYCOMB)[\w\s=:"\'-]*([a-zA-Z0-9]{22})', keywords=["honeycomb", "HONEYCOMB_API_KEY"], confidence=0.80,
        description="Honeycomb observability API key.", fix_hint="Rotate at Honeycomb → Team Settings → API Keys."),

    # ══════════════════════════════════════════
    # HEADLESS CMS & E-COMMERCE
    # ══════════════════════════════════════════
    SecretRule(rule_id="VOODA-SEC-STORYBLOK-002", title="Storyblok Access Token", secret_type="storyblok_token", severity="medium",
        pattern=r'(?:storyblok|STORYBLOK)[\w\s=:"\'-]*([a-zA-Z0-9]{22,})', keywords=["storyblok", "STORYBLOK"], confidence=0.70,
        description="Storyblok headless CMS access token.", fix_hint="Regenerate at Storyblok → Settings → Access Tokens."),
    SecretRule(rule_id="VOODA-SEC-COMMERCEJS-001", title="Commerce.js API Key", secret_type="commercejs_key", severity="medium",
        pattern=r'(pk_(?:live|test)_[a-f0-9]{48})', keywords=["pk_live_", "pk_test_", "commercejs", "chec"], confidence=0.80,
        description="Commerce.js e-commerce API key.", fix_hint="Regenerate at Commerce.js → Developer → API Keys."),
    SecretRule(rule_id="VOODA-SEC-SNIPCART-001", title="Snipcart API Key", secret_type="snipcart_key", severity="high",
        pattern=r'(?:snipcart|SNIPCART)[\w\s=:"\'-]*([a-zA-Z0-9\-]{36})', keywords=["snipcart", "SNIPCART"], confidence=0.75,
        description="Snipcart e-commerce API key.", fix_hint="Regenerate at Snipcart → Account → API Keys."),
]
