# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Gitleaks-sourced detectors batch 1: Cloud, DevOps, Crypto platforms.
Patterns sourced from https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
Adapted from Go regex to Python regex."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    # ── 1Password ──
    SecretRule(rule_id="VOODA-SEC-1PASS-002", title="1Password Service Account Token", secret_type="onepassword_service_token", severity="critical",
        pattern=r'(ops_eyJ[a-zA-Z0-9+/]{250,}={0,3})', keywords=["ops_eyJ"], confidence=0.98,
        description="1Password service account token.", fix_hint="Revoke at 1Password → Integrations → Service Accounts."),
    # ── Adobe ──
    SecretRule(rule_id="VOODA-SEC-ADOBE-001", title="Adobe Client Secret", secret_type="adobe_client_secret", severity="high",
        pattern=r'(p8e-[a-zA-Z0-9]{32})', keywords=["p8e-"], confidence=0.95,
        description="Adobe OAuth client secret.", fix_hint="Regenerate at Adobe Developer Console → Credentials."),
    # ── Age Encryption ──
    SecretRule(rule_id="VOODA-SEC-AGE-001", title="Age Secret Key", secret_type="age_secret_key", severity="critical",
        pattern=r'(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})', keywords=["AGE-SECRET-KEY-1"], confidence=0.99,
        description="Age encryption secret key.", fix_hint="Generate a new age key pair. Never commit private keys."),
    # ── Airtable ──
    SecretRule(rule_id="VOODA-SEC-AIRTABLE-002", title="Airtable API Key", secret_type="airtable_api_key", severity="medium",
        pattern=r'(?:airtable)[\w\s=:"\'-]*([a-z0-9]{17})', keywords=["airtable"], confidence=0.75,
        description="Airtable API key.", fix_hint="Regenerate at airtable.com → Account → API."),
    # ── Authress ──
    SecretRule(rule_id="VOODA-SEC-AUTHRESS-001", title="Authress Service Client Access Key", secret_type="authress_access_key", severity="high",
        pattern=r'((?:sc|ext|scauth|authress)_[a-zA-Z0-9]{5,30}\.[a-zA-Z0-9]{4,6}\.acc[_-][a-zA-Z0-9\-]{10,32}\.[a-zA-Z0-9+/_=\-]{30,120})', keywords=["sc_", "ext_", "scauth_", "authress_"], confidence=0.95,
        description="Authress service client access key.", fix_hint="Revoke at Authress Management Portal."),
    # ── Beamer ──
    SecretRule(rule_id="VOODA-SEC-BEAMER-001", title="Beamer API Token", secret_type="beamer_token", severity="medium",
        pattern=r'(?:beamer)[\w\s=:"\'-]*(b_[a-z0-9=_\-]{44})', keywords=["beamer", "b_"], confidence=0.85,
        description="Beamer product changelog API token.", fix_hint="Regenerate at Beamer → Settings → API."),
    # ── Bittrex ──
    SecretRule(rule_id="VOODA-SEC-BITTREX-001", title="Bittrex Access Key", secret_type="bittrex_key", severity="high",
        pattern=r'(?:bittrex)[\w\s=:"\'-]*([a-z0-9]{32})', keywords=["bittrex"], confidence=0.80,
        description="Bittrex cryptocurrency exchange API key.", fix_hint="Revoke at Bittrex → Account → API Keys."),
    # ── Clojars ──
    SecretRule(rule_id="VOODA-SEC-CLOJARS-001", title="Clojars API Token", secret_type="clojars_token", severity="high",
        pattern=r'(CLOJARS_[a-z0-9]{60})', keywords=["CLOJARS_"], confidence=0.98,
        description="Clojars package registry deploy token.", fix_hint="Revoke at Clojars → Tokens."),
    # ── Cloudflare Origin CA ──
    SecretRule(rule_id="VOODA-SEC-CF-003", title="Cloudflare Origin CA Key", secret_type="cloudflare_origin_ca", severity="critical",
        pattern=r'(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})', keywords=["v1.0-"], confidence=0.98,
        description="Cloudflare Origin CA key for SSL/TLS.", fix_hint="Revoke at Cloudflare → SSL/TLS → Origin Server."),
    # ── Codecov ──
    SecretRule(rule_id="VOODA-SEC-CODECOV-002", title="Codecov Access Token", secret_type="codecov_token_ctx", severity="medium",
        pattern=r'(?:codecov)[\w\s=:"\'-]*([a-z0-9]{32})', keywords=["codecov"], confidence=0.80,
        description="Codecov upload token.", fix_hint="Regenerate at Codecov → Settings → General."),
    # ── Coinbase ──
    SecretRule(rule_id="VOODA-SEC-COINBASE-001", title="Coinbase Access Token", secret_type="coinbase_token", severity="high",
        pattern=r'(?:coinbase)[\w\s=:"\'-]*([a-z0-9_\-]{64})', keywords=["coinbase"], confidence=0.80,
        description="Coinbase API access token.", fix_hint="Revoke at Coinbase → Settings → API."),
    # ── Databricks ──
    SecretRule(rule_id="VOODA-SEC-DATABRICKS-002", title="Databricks API Token (dapi prefix)", secret_type="databricks_token_v2", severity="critical",
        pattern=r'(dapi[a-f0-9]{32}(?:-\d)?)', keywords=["dapi"], confidence=0.95,
        description="Databricks personal access token.", fix_hint="Revoke at Databricks → User Settings → Access Tokens."),
    # ── Defined Networking ──
    SecretRule(rule_id="VOODA-SEC-DNKEY-001", title="Defined Networking API Token", secret_type="defined_networking_token", severity="high",
        pattern=r'(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})', keywords=["dnkey-"], confidence=0.98,
        description="Defined Networking (Nebula) API token.", fix_hint="Revoke at Defined Networking Dashboard."),
    # ── Discord ──
    SecretRule(rule_id="VOODA-SEC-DISCORD-002", title="Discord API Token (context)", secret_type="discord_api_token", severity="high",
        pattern=r'(?:discord)[\w\s=:"\'-]*([a-f0-9]{64})', keywords=["discord"], confidence=0.80,
        description="Discord bot or API token.", fix_hint="Regenerate at Discord Developer Portal → Bot → Reset Token."),
    # ── Doppler ──
    SecretRule(rule_id="VOODA-SEC-DOPPLER-003", title="Doppler Personal Token", secret_type="doppler_personal_token", severity="high",
        pattern=r'(dp\.pt\.[a-zA-Z0-9]{43})', keywords=["dp.pt."], confidence=0.98,
        description="Doppler personal access token.", fix_hint="Revoke at Doppler Dashboard → Access."),
    # ── Dropbox ──
    SecretRule(rule_id="VOODA-SEC-DROPBOX-001", title="Dropbox Long-Lived API Token", secret_type="dropbox_long_token", severity="high",
        pattern=r'(?:dropbox)[\w\s=:"\'-]*([a-z0-9]{11}AAAAAAAAAA[a-z0-9\-_=]{43})', keywords=["dropbox", "AAAAAAAAAA"], confidence=0.90,
        description="Dropbox long-lived API access token.", fix_hint="Revoke at Dropbox → App Console → Settings."),
    # ── Duffel ──
    SecretRule(rule_id="VOODA-SEC-DUFFEL-001", title="Duffel API Token", secret_type="duffel_token", severity="high",
        pattern=r'(duffel_(?:test|live)_[a-zA-Z0-9_\-=]{43})', keywords=["duffel_"], confidence=0.98,
        description="Duffel travel API token.", fix_hint="Regenerate at Duffel Dashboard → API Tokens."),
    # ── Dynatrace ──
    SecretRule(rule_id="VOODA-SEC-DYNATRACE-002", title="Dynatrace API Token", secret_type="dynatrace_token", severity="high",
        pattern=r'(dt0c01\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{64})', keywords=["dt0c01."], confidence=0.98,
        description="Dynatrace API token.", fix_hint="Revoke at Dynatrace → Access Tokens."),
    # ── EasyPost ──
    SecretRule(rule_id="VOODA-SEC-EASYPOST-001", title="EasyPost API Token", secret_type="easypost_token", severity="high",
        pattern=r'(EZAK[a-zA-Z0-9]{54})', keywords=["EZAK"], confidence=0.98,
        description="EasyPost shipping API token.", fix_hint="Regenerate at EasyPost → Account Settings → API Keys."),
    # ── Fastly ──
    SecretRule(rule_id="VOODA-SEC-FASTLY-001", title="Fastly API Token", secret_type="fastly_token", severity="high",
        pattern=r'(?:fastly)[\w\s=:"\'-]*([a-z0-9=_\-]{32})', keywords=["fastly"], confidence=0.80,
        description="Fastly CDN API token.", fix_hint="Revoke at Fastly → Account → API Tokens."),
    # ── Finicity ──
    SecretRule(rule_id="VOODA-SEC-FINICITY-001", title="Finicity API Token", secret_type="finicity_token", severity="high",
        pattern=r'(?:finicity)[\w\s=:"\'-]*([a-f0-9]{32})', keywords=["finicity"], confidence=0.80,
        description="Finicity open banking API token.", fix_hint="Regenerate at Finicity Developer Portal."),
    # ── Finnhub ──
    SecretRule(rule_id="VOODA-SEC-FINNHUB-002", title="Finnhub Access Token", secret_type="finnhub_token", severity="medium",
        pattern=r'(?:finnhub)[\w\s=:"\'-]*([a-z0-9]{20})', keywords=["finnhub"], confidence=0.80,
        description="Finnhub stock API access token.", fix_hint="Regenerate at Finnhub → Dashboard → API Key."),
    # ── Flickr ──
    SecretRule(rule_id="VOODA-SEC-FLICKR-002", title="Flickr Access Token", secret_type="flickr_token", severity="medium",
        pattern=r'(?:flickr)[\w\s=:"\'-]*([a-z0-9]{32})', keywords=["flickr"], confidence=0.75,
        description="Flickr API access token.", fix_hint="Regenerate at Flickr → App Garden."),
    # ── Flutterwave ──
    SecretRule(rule_id="VOODA-SEC-FLUTTER-001", title="Flutterwave Secret Key", secret_type="flutterwave_secret", severity="critical",
        pattern=r'(FLWSECK_TEST-[a-h0-9]{32}-X)', keywords=["FLWSECK_TEST"], confidence=0.98,
        description="Flutterwave payment secret key.", fix_hint="Regenerate at Flutterwave Dashboard → Settings → API."),
    # ── Frame.io ──
    SecretRule(rule_id="VOODA-SEC-FRAMEIO-001", title="Frame.io API Token", secret_type="frameio_token", severity="high",
        pattern=r'(fio-u-[a-zA-Z0-9\-_=]{64})', keywords=["fio-u-"], confidence=0.98,
        description="Frame.io video collaboration API token.", fix_hint="Regenerate at Frame.io → Developer → Tokens."),
]
