# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Gitleaks-sourced detectors batch 2: SaaS, Messaging, Collaboration.
Patterns from https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml"""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    # ── FreshBooks ──
    SecretRule(rule_id="VOODA-SEC-FRESHBOOKS-001", title="FreshBooks Access Token", secret_type="freshbooks_token", severity="medium",
        pattern=r'(?:freshbooks)[\w\s=:"\'-]*([a-z0-9]{64})', keywords=["freshbooks"], confidence=0.80,
        description="FreshBooks accounting API token.", fix_hint="Regenerate at FreshBooks → Settings → Developer Portal."),
    # ── Gitter ──
    SecretRule(rule_id="VOODA-SEC-GITTER-001", title="Gitter Access Token", secret_type="gitter_token", severity="medium",
        pattern=r'(?:gitter)[\w\s=:"\'-]*([a-z0-9_\-]{40})', keywords=["gitter"], confidence=0.80,
        description="Gitter chat API access token.", fix_hint="Regenerate at Gitter → Your Apps."),
    # ── GoCardless ──
    SecretRule(rule_id="VOODA-SEC-GOCARDLESS-001", title="GoCardless API Token", secret_type="gocardless_token", severity="high",
        pattern=r'(live_[a-zA-Z0-9_\-=]{40})', keywords=["live_", "gocardless"], confidence=0.75,
        description="GoCardless payment API live token.", fix_hint="Revoke at GoCardless → Developers → API Keys."),
    # ── Grafana Service Account ──
    SecretRule(rule_id="VOODA-SEC-GRAFANA-003", title="Grafana Service Account Token", secret_type="grafana_sa_token", severity="high",
        pattern=r'(glsa_[a-zA-Z0-9]{32}_[a-fA-F0-9]{8})', keywords=["glsa_"], confidence=0.98,
        description="Grafana service account token.", fix_hint="Revoke at Grafana → Administration → Service Accounts."),
    # ── Infracost ──
    SecretRule(rule_id="VOODA-SEC-INFRACOST-001", title="Infracost API Token", secret_type="infracost_token", severity="medium",
        pattern=r'(ico-[a-zA-Z0-9]{32})', keywords=["ico-"], confidence=0.95,
        description="Infracost cloud cost estimation API token.", fix_hint="Regenerate at Infracost → Settings → API Key."),
    # ── JFrog Identity ──
    SecretRule(rule_id="VOODA-SEC-JFROG-003", title="JFrog Identity Token", secret_type="jfrog_identity_token", severity="high",
        pattern=r'(?:jfrog|artifactory|bintray|xray)[\w\s=:"\'-]*([a-z0-9]{64})', keywords=["jfrog", "artifactory", "bintray", "xray"], confidence=0.80,
        description="JFrog platform identity token.", fix_hint="Revoke at JFrog → Identity and Access → Access Tokens."),
    # ── Kraken ──
    SecretRule(rule_id="VOODA-SEC-KRAKEN-001", title="Kraken Access Token", secret_type="kraken_token", severity="high",
        pattern=r'(?:kraken)[\w\s=:"\'-]*([a-z0-9]{30})', keywords=["kraken"], confidence=0.80,
        description="Kraken cryptocurrency exchange API key.", fix_hint="Revoke at Kraken → Security → API."),
    # ── KuCoin ──
    SecretRule(rule_id="VOODA-SEC-KUCOIN-001", title="KuCoin Access Token", secret_type="kucoin_token", severity="high",
        pattern=r'(?:kucoin)[\w\s=:"\'-]*([a-f0-9]{24})', keywords=["kucoin"], confidence=0.80,
        description="KuCoin exchange API access token.", fix_hint="Revoke at KuCoin → API Management."),
    # ── Linear Client Secret ──
    SecretRule(rule_id="VOODA-SEC-LINEAR-002", title="Linear Client Secret", secret_type="linear_client_secret", severity="high",
        pattern=r'(?:linear)[\w\s=:"\'-]*([a-f0-9]{32})', keywords=["linear"], confidence=0.75,
        description="Linear project management OAuth client secret.", fix_hint="Regenerate at Linear → Settings → API."),
    # ── Lob ──
    SecretRule(rule_id="VOODA-SEC-LOB-001", title="Lob API Key", secret_type="lob_api_key", severity="high",
        pattern=r'((?:live|test)_[a-f0-9]{35})', keywords=["live_", "test_", "lob"], confidence=0.75,
        description="Lob print/mail API key.", fix_hint="Regenerate at Lob → Settings → API Keys."),
    # ── Looker ──
    SecretRule(rule_id="VOODA-SEC-LOOKER-001", title="Looker Client Secret", secret_type="looker_secret", severity="high",
        pattern=r'(?:looker)[\w\s=:"\'-]*([a-z0-9]{24})', keywords=["looker"], confidence=0.80,
        description="Looker BI client secret.", fix_hint="Regenerate at Looker → Admin → API → Edit Credentials."),
    # ── MaxMind ──
    SecretRule(rule_id="VOODA-SEC-MAXMIND-002", title="MaxMind License Key", secret_type="maxmind_license_key", severity="medium",
        pattern=r'([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)', keywords=["_mmk"], confidence=0.98,
        description="MaxMind GeoIP license key.", fix_hint="Regenerate at MaxMind → Account → License Keys."),
    # ── Netlify ──
    SecretRule(rule_id="VOODA-SEC-NETLIFY-002", title="Netlify Access Token (context)", secret_type="netlify_token_ctx", severity="high",
        pattern=r'(?:netlify)[\w\s=:"\'-]*([a-z0-9=_\-]{40,46})', keywords=["netlify"], confidence=0.80,
        description="Netlify personal access token.", fix_hint="Regenerate at Netlify → User Settings → Applications."),
    # ── New Relic Browser ──
    SecretRule(rule_id="VOODA-SEC-NEWRELIC-003", title="New Relic Browser API Token", secret_type="newrelic_browser_token", severity="medium",
        pattern=r'(NRJS-[a-f0-9]{19})', keywords=["NRJS-"], confidence=0.98,
        description="New Relic browser monitoring API token.", fix_hint="Regenerate at New Relic → API Keys."),
    # ── New Relic Insert Key ──
    SecretRule(rule_id="VOODA-SEC-NEWRELIC-004", title="New Relic Insert Key", secret_type="newrelic_insert_key", severity="high",
        pattern=r'(NRII-[a-z0-9\-]{32})', keywords=["NRII-"], confidence=0.98,
        description="New Relic data ingest insert key.", fix_hint="Regenerate at New Relic → API Keys."),
    # ── Notion ──
    SecretRule(rule_id="VOODA-SEC-NOTION-002", title="Notion Integration Token (ntn_ prefix)", secret_type="notion_token_v2", severity="medium",
        pattern=r'(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})', keywords=["ntn_"], confidence=0.98,
        description="Notion internal integration token.", fix_hint="Regenerate at Notion → Settings → Connections."),
    # ── Octopus Deploy ──
    SecretRule(rule_id="VOODA-SEC-OCTOPUS-001", title="Octopus Deploy API Key", secret_type="octopus_deploy_key", severity="high",
        pattern=r'(API-[A-Z0-9]{26})', keywords=["API-"], confidence=0.80,
        description="Octopus Deploy API key.", fix_hint="Revoke at Octopus → Profile → API Keys."),
    # ── Perplexity ──
    SecretRule(rule_id="VOODA-SEC-PERPLEXITY-002", title="Perplexity API Key", secret_type="perplexity_key", severity="high",
        pattern=r'(pplx-[a-zA-Z0-9]{48})', keywords=["pplx-"], confidence=0.98,
        description="Perplexity AI API key.", fix_hint="Regenerate at Perplexity → Settings → API."),
    # ── Plaid ──
    SecretRule(rule_id="VOODA-SEC-PLAID-002", title="Plaid Secret Key (context)", secret_type="plaid_secret_ctx", severity="critical",
        pattern=r'(?:plaid)[\w\s=:"\'-]*([a-z0-9]{30})', keywords=["plaid"], confidence=0.80,
        description="Plaid banking API secret key.", fix_hint="Rotate at Plaid Dashboard → Team Settings → Keys."),
    # ── PlanetScale Password ──
    SecretRule(rule_id="VOODA-SEC-PLANETSCALE-003", title="PlanetScale Database Password", secret_type="planetscale_password", severity="critical",
        pattern=r'(pscale_pw_[a-zA-Z0-9=_.\-]{32,64})', keywords=["pscale_pw_"], confidence=0.98,
        description="PlanetScale database password.", fix_hint="Reset at PlanetScale → Database → Settings → Passwords."),
    # ── Postman ──
    SecretRule(rule_id="VOODA-SEC-POSTMAN-001", title="Postman API Token", secret_type="postman_token", severity="medium",
        pattern=r'(PMAK-[a-f0-9]{24}-[a-f0-9]{34})', keywords=["PMAK-"], confidence=0.98,
        description="Postman API key.", fix_hint="Regenerate at Postman → Settings → API Keys."),
    # ── RapidAPI ──
    SecretRule(rule_id="VOODA-SEC-RAPID-002", title="RapidAPI Access Token (context)", secret_type="rapidapi_token_ctx", severity="medium",
        pattern=r'(?:rapidapi)[\w\s=:"\'-]*([a-z0-9_\-]{50})', keywords=["rapidapi"], confidence=0.80,
        description="RapidAPI marketplace access token.", fix_hint="Rotate at RapidAPI Dashboard → Security."),
    # ── ReadMe ──
    SecretRule(rule_id="VOODA-SEC-README-001", title="ReadMe API Token", secret_type="readme_token", severity="medium",
        pattern=r'(rdme_[a-z0-9]{70})', keywords=["rdme_"], confidence=0.98,
        description="ReadMe documentation API token.", fix_hint="Regenerate at ReadMe → Settings → API Keys."),
    # ── RubyGems ──
    SecretRule(rule_id="VOODA-SEC-RUBYGEMS-001", title="RubyGems API Token", secret_type="rubygems_token", severity="high",
        pattern=r'(rubygems_[a-f0-9]{48})', keywords=["rubygems_"], confidence=0.98,
        description="RubyGems package registry API token.", fix_hint="Revoke at rubygems.org → Settings → API Keys."),
    # ── Scalingo ──
    SecretRule(rule_id="VOODA-SEC-SCALINGO-001", title="Scalingo API Token", secret_type="scalingo_token", severity="high",
        pattern=r'(tk-us-[\w\-]{48})', keywords=["tk-us-"], confidence=0.98,
        description="Scalingo PaaS API token.", fix_hint="Regenerate at Scalingo → Account → API Tokens."),
]
