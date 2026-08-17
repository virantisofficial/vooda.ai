# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Gitleaks-sourced detectors batch 3: Communication, Shipping, E-commerce, Misc.
Patterns from https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml"""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    # ── SendBird ──
    SecretRule(rule_id="VOODA-SEC-SENDBIRD-001", title="SendBird Access Token", secret_type="sendbird_token", severity="high",
        pattern=r'(?:sendbird)[\w\s=:"\'-]*([a-f0-9]{40})', keywords=["sendbird"], confidence=0.80,
        description="SendBird chat API access token.", fix_hint="Regenerate at SendBird Dashboard → Settings."),
    # ── Brevo (Sendinblue) ──
    SecretRule(rule_id="VOODA-SEC-BREVO-001", title="Brevo (Sendinblue) API Token", secret_type="brevo_token", severity="high",
        pattern=r'(xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16})', keywords=["xkeysib-"], confidence=0.98,
        description="Brevo (formerly Sendinblue) email API token.", fix_hint="Regenerate at Brevo → SMTP & API → API Keys."),
    # ── Shippo ──
    SecretRule(rule_id="VOODA-SEC-SHIPPO-001", title="Shippo API Token", secret_type="shippo_token", severity="high",
        pattern=r'(shippo_(?:live|test)_[a-fA-F0-9]{40})', keywords=["shippo_"], confidence=0.98,
        description="Shippo shipping API token.", fix_hint="Regenerate at Shippo → Settings → API."),
    # ── Shopify Custom Access ──
    SecretRule(rule_id="VOODA-SEC-SHOPIFY-003", title="Shopify Custom App Access Token", secret_type="shopify_custom_token", severity="high",
        pattern=r'(shpca_[a-fA-F0-9]{32})', keywords=["shpca_"], confidence=0.98,
        description="Shopify custom app access token.", fix_hint="Regenerate at Shopify Admin → Apps → Develop Apps."),
    # ── Shopify Private App ──
    SecretRule(rule_id="VOODA-SEC-SHOPIFY-004", title="Shopify Private App Token", secret_type="shopify_private_token", severity="high",
        pattern=r'(shppa_[a-fA-F0-9]{32})', keywords=["shppa_"], confidence=0.98,
        description="Shopify private app access token.", fix_hint="Regenerate at Shopify Admin → Apps → Manage Private Apps."),
    # ── Slack App Token ──
    SecretRule(rule_id="VOODA-SEC-SLACK-004", title="Slack App-Level Token", secret_type="slack_app_token", severity="high",
        pattern=r'(xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)', keywords=["xapp-"], confidence=0.98,
        description="Slack app-level token for Socket Mode and Events API.", fix_hint="Regenerate at Slack API → Your Apps → Basic Information."),
    # ── Slack Legacy ──
    SecretRule(rule_id="VOODA-SEC-SLACK-005", title="Slack Legacy Token", secret_type="slack_legacy_token", severity="critical",
        pattern=r'(xox[os]-\d+-\d+-\d+-[a-fA-F0-9]+)', keywords=["xoxo-", "xoxs-"], confidence=0.98,
        description="Slack legacy token (deprecated but still functional).", fix_hint="These tokens should be migrated to OAuth 2.0. Revoke immediately."),
    # ── Sourcegraph ──
    SecretRule(rule_id="VOODA-SEC-SOURCEGRAPH-001", title="Sourcegraph Access Token", secret_type="sourcegraph_token", severity="high",
        pattern=r'(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})', keywords=["sgp_"], confidence=0.95,
        description="Sourcegraph code search access token.", fix_hint="Revoke at Sourcegraph → User Settings → Access Tokens."),
    # ── Squarespace ──
    SecretRule(rule_id="VOODA-SEC-SQUARESPACE-002", title="Squarespace Access Token", secret_type="squarespace_token", severity="medium",
        pattern=r'(?:squarespace)[\w\s=:"\'-]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', keywords=["squarespace"], confidence=0.80,
        description="Squarespace API access token.", fix_hint="Regenerate at Squarespace → Settings → Advanced → Developer API."),
    # ── Sumo Logic ──
    SecretRule(rule_id="VOODA-SEC-SUMOLOGIC-002", title="Sumo Logic Access Token", secret_type="sumologic_token", severity="high",
        pattern=r'(?:sumo)[\w\s=:"\'-]*([a-z0-9]{64})', keywords=["sumo"], confidence=0.80,
        description="Sumo Logic log analytics access token.", fix_hint="Revoke at Sumo Logic → Administration → Security → Access Keys."),
    # ── Typeform ──
    SecretRule(rule_id="VOODA-SEC-TYPEFORM-002", title="Typeform API Token", secret_type="typeform_token", severity="medium",
        pattern=r'(tfp_[a-z0-9\-_.=]{59})', keywords=["tfp_"], confidence=0.98,
        description="Typeform survey API token.", fix_hint="Regenerate at Typeform → Settings → Personal Tokens."),
    # ── Vault Batch Token ──
    SecretRule(rule_id="VOODA-SEC-VAULT-002", title="HashiCorp Vault Batch Token", secret_type="vault_batch_token", severity="critical",
        pattern=r'(hvb\.[\w\-]{138,300})', keywords=["hvb."], confidence=0.98,
        description="HashiCorp Vault batch token.", fix_hint="Revoke via `vault token revoke`. Batch tokens cannot be renewed."),
    # ── Yandex ──
    SecretRule(rule_id="VOODA-SEC-YANDEX-001", title="Yandex API Key", secret_type="yandex_api_key", severity="high",
        pattern=r'(AQVN[A-Za-z0-9_\-]{35,38})', keywords=["AQVN"], confidence=0.95,
        description="Yandex Cloud API key.", fix_hint="Revoke at Yandex Cloud Console → Service Accounts."),
    # ── Zendesk ──
    SecretRule(rule_id="VOODA-SEC-ZENDESK-002", title="Zendesk Secret Key (context)", secret_type="zendesk_secret_ctx", severity="high",
        pattern=r'(?:zendesk)[\w\s=:"\'-]*([a-z0-9]{40})', keywords=["zendesk"], confidence=0.80,
        description="Zendesk API secret key.", fix_hint="Regenerate at Zendesk → Admin → APIs."),
    # ── Atlassian ──
    # Matches the documented Atlassian classic API token format:
    #   ATATT3xFf<32+ chars of [A-Za-z0-9_=\-]>=<8 hex chars>
    # (Example: ATATT3xFfGF0DCe0PA_AO5y5...Coygz8vw6wo1SzeMTWqY9xbis=B58DE9CF)
    # Same shape used by the redaction layer (packages/common/logging_config.py)
    # and the atlassian classifier docstring.  Previous regex
    # `(?:atlassian|jira|confluence|bitbucket)[\w\s=:"\'-]*([A-Za-z0-9]{24})`
    # falsely matched any 24 alphanumeric characters near an Atlassian
    # keyword — captured arbitrary substrings (not the real token), gave
    # the wrong line_start (regex started at the keyword, not at the
    # token), and produced a misleading secret_hash that didn't represent
    # the credential.  Fixed 2026-05-09.
    #
    # Atlassian token detector confidence is 0.85 — actually-matching the
    # documented prefix is high signal, comparable to AWS / GitHub / Stripe
    # provider rules.
    SecretRule(rule_id="VOODA-SEC-ATLASSIAN-001", title="Atlassian API Token", secret_type="atlassian_token", severity="high",
        pattern=r'(ATATT3xFf[A-Za-z0-9_=\-]{32,}=[A-F0-9]{8})', keywords=["ATATT3xFf", "atlassian"], confidence=0.85,
        description="Atlassian (Jira/Confluence/Bitbucket) classic API token. Format: ATATT3xFf<base64-ish>=<8 hex>.",
        fix_hint="Revoke at id.atlassian.com → Security → API Tokens, then rotate."),
    # ── Cisco Meraki ──
    SecretRule(rule_id="VOODA-SEC-MERAKI-001", title="Cisco Meraki API Key", secret_type="meraki_api_key", severity="high",
        pattern=r'(?:meraki)[\w\s=:"\'-]*([a-f0-9]{40})', keywords=["meraki"], confidence=0.80,
        description="Cisco Meraki dashboard API key.", fix_hint="Regenerate at Meraki Dashboard → Organization → API Keys."),
    # ── ClickHouse ──
    SecretRule(rule_id="VOODA-SEC-CLICKHOUSE-002", title="ClickHouse Cloud API Secret", secret_type="clickhouse_secret", severity="high",
        pattern=r'(?:clickhouse)[\w\s=:"\'-]*([a-zA-Z0-9]{40})', keywords=["clickhouse"], confidence=0.75,
        description="ClickHouse Cloud API secret key.", fix_hint="Regenerate at ClickHouse Cloud → API Keys."),
    # ── Etsy ──
    # Tier A 2026-06-07: 90 FP / 0 TP. Two root causes, both fixed here:
    #  (1) the bridge was UNBOUNDED (`[...]*`), so "etsy" spanned a whole codegen
    #      JSON to any 24-char token; and
    #  (2) the bare `(?:etsy)` matched case-insensitively, so the 4 letters
    #      "ETSY" buried inside a base64 diagram blob (…eheSETSYg6jbu…) anchored
    #      a match against the following mixed-case run.
    # Now require: a WORD BOUNDARY before etsy (\b — never true inside a
    # contiguous base64 blob, where etsy is surrounded by word chars), an
    # optional credential identifier tail ([\w]{0,16} → _keystring/_api_key/
    # _access_token), and a MANDATORY separator ([\s:="'-]{1,6} → kills contiguous
    # base64). Real `etsy_keystring = "<24>"` still matches; recall held by the
    # TP fixture in test_tier_a_rule_tightening.py.
    SecretRule(rule_id="VOODA-SEC-ETSY-002", title="Etsy Access Token", secret_type="etsy_token", severity="medium",
        pattern=r'\betsy[\w]{0,16}[\s:="\'-]{1,6}([a-z0-9]{24})', keywords=["etsy", "ETSY"], confidence=0.80,
        description="Etsy Open API access token.", fix_hint="Regenerate at etsy.com/developers/your-apps."),
    # ── Microsoft Teams Webhook ──
    SecretRule(rule_id="VOODA-SEC-TEAMS-001", title="Microsoft Teams Webhook URL", secret_type="teams_webhook", severity="medium",
        pattern=r'(https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9\-]+/IncomingWebhook/[a-f0-9]+/[a-f0-9\-]+)', keywords=["webhook.office.com", "IncomingWebhook"], confidence=0.95,
        description="Microsoft Teams incoming webhook URL.", fix_hint="Delete the connector and create a new one in Teams → Channel → Connectors."),
    # ── Kubernetes Secret ──
    SecretRule(rule_id="VOODA-SEC-K8S-001", title="Kubernetes Secret YAML", secret_type="kubernetes_secret", severity="critical",
        pattern=r'apiVersion:\s*v1\s+kind:\s*Secret', keywords=["kind: Secret", "apiVersion"], confidence=0.85,
        description="Kubernetes Secret manifest with potentially embedded credentials.", fix_hint="Use sealed-secrets, external-secrets, or vault-injector instead of plaintext K8s secrets.",
        multiline=True),
    # ── Adafruit ──
    SecretRule(rule_id="VOODA-SEC-ADAFRUIT-001", title="Adafruit IO API Key", secret_type="adafruit_key", severity="medium",
        pattern=r'(?:adafruit|aio)[\w\s=:"\'-]*([a-z0-9]{32})', keywords=["adafruit", "aio_key", "AIO_KEY"], confidence=0.75,
        description="Adafruit IO API key.", fix_hint="Regenerate at io.adafruit.com → Settings → API Key."),
    # ── Travis CI ──
    SecretRule(rule_id="VOODA-SEC-TRAVIS-002", title="Travis CI Access Token (context)", secret_type="travis_token_ctx", severity="high",
        pattern=r'(?:travis)[\w\s=:"\'-]*([a-zA-Z0-9\-]{22,})', keywords=["travis"], confidence=0.70,
        description="Travis CI API token.", fix_hint="Regenerate at Travis CI → Settings → API Token."),
    # ── Twitch ──
    SecretRule(rule_id="VOODA-SEC-TWITCH-002", title="Twitch API Token (context)", secret_type="twitch_token_ctx", severity="medium",
        pattern=r'(?:twitch)[\w\s=:"\'-]*([a-z0-9]{30})', keywords=["twitch"], confidence=0.75,
        description="Twitch API token.", fix_hint="Regenerate at dev.twitch.tv → Console → Applications."),
    # ── PrivateAI ──
    SecretRule(rule_id="VOODA-SEC-PRIVATEAI-001", title="Private AI API Token", secret_type="privateai_token", severity="high",
        pattern=r'(?:private.?ai)[\w\s=:"\'-]*([a-zA-Z0-9]{30,})', keywords=["privateai", "private_ai", "PRIVATE_AI"], confidence=0.70,
        description="Private AI data privacy API token.", fix_hint="Regenerate at Private AI Dashboard."),
    # ── NYTimes ──
    SecretRule(rule_id="VOODA-SEC-NYTIMES-001", title="New York Times API Token", secret_type="nytimes_token", severity="low",
        pattern=r'(?:nytimes|nyt)[\w\s=:"\'-]*([a-zA-Z0-9]{32})', keywords=["nytimes", "nyt_api", "NYT_API"], confidence=0.70,
        description="New York Times API key.", fix_hint="Regenerate at developer.nytimes.com → Apps."),
    # ── NuGet ──
    SecretRule(rule_id="VOODA-SEC-NUGET-001", title="NuGet API Key", secret_type="nuget_api_key", severity="high",
        pattern=r'(?:nuget)[\w\s=:"\'-]*([a-z0-9]{46})', keywords=["nuget"], confidence=0.75,
        description="NuGet package registry API key.", fix_hint="Regenerate at nuget.org → API Keys."),
    # ── Confluent Secret Key ──
    SecretRule(rule_id="VOODA-SEC-CONFLUENT-002", title="Confluent Secret Key", secret_type="confluent_secret_key", severity="high",
        pattern=r'(?:confluent)[\w\s=:"\'-]*([a-zA-Z0-9+/]{60,}={0,2})', keywords=["confluent"], confidence=0.75,
        description="Confluent Cloud (Kafka) API secret key.", fix_hint="Rotate at Confluent Cloud → Administration → API Keys."),
    # ── Curl Auth Header ──
    SecretRule(rule_id="VOODA-SEC-CURL-001", title="Curl Auth Header", secret_type="curl_auth_header", severity="high",
        pattern=r'''curl\s.*-H\s+['"]*Authorization:\s*(?:Bearer|Basic|Token)\s+([A-Za-z0-9\-_.~+/=]{20,})''', keywords=["curl", "Authorization"], confidence=0.75,
        description="Curl command with embedded authorization header.", fix_hint="Never hardcode auth tokens in scripts. Use credential helpers or environment variables."),
]
