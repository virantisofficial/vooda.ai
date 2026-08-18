# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""
Provider-to-default-risk map.

Only 30 of the 246 verifiers emit a structured ``permissions_detail``
with an explicit ``risk_level`` (B1 waves 1-3). The other 216 return
the legacy plain-string shape. Without this fallback, those 216
wouldn't light up the risk pill in the Blast Radius UI panel — the
customer would see different-shaped rendering depending on which
provider happened to leak.

This module closes that gap with a lightweight per-provider default.
The worker consults :func:`inferred_risk` when the verifier didn't set
``risk_level`` explicitly. The inferred value rides through
``source_metadata["verification_risk_level"]`` the same way B1-native
data does, so the UI renders it identically.

Calibration
-----------
Risk levels follow the same rubric as the B1 structured verifiers:

* **critical** — payments, infra provisioning, production deploy
  control, code-signing, supply-chain writes
* **high**     — billing-linked inference, customer data, email/SMS
  send, broad SaaS admin, repo access
* **medium**   — user-scoped SaaS, read-heavy observability, project
  management
* **low**      — geocoding, FX rates, web-scraping utilities, DNS/
  cert history; anything where a leak costs money but no data

When a provider isn't in the map we default to ``None`` (UI falls
back to rule severity or no pill). Adding a new provider here is a
1-line change — the map is not authoritative, just a sensible default.
"""

from typing import Optional


PROVIDER_DEFAULT_RISK: dict[str, str] = {
    # ── CRITICAL ─────────────────────────────────────────────
    # Cloud / infra control — provisioning, deploys, IaC state
    "aws_paired": "critical",
    "azure_ad_paired": "critical",
    "gcp": "critical",
    "digitalocean": "critical",
    "linode": "critical",
    "hetzner": "critical",
    "vultr": "critical",
    "scaleway": "critical",
    "flyio": "critical",
    "render": "critical",
    "railway": "critical",
    "vercel": "critical",
    "netlify": "critical",
    "heroku": "critical",
    "cockroachdb": "critical",
    "neon": "critical",
    "planetscale": "critical",
    "terraform": "critical",
    "pulumi": "critical",
    "harness": "critical",
    "buildkite": "critical",
    "circleci": "critical",
    "bitrise": "critical",
    # Payments
    "stripe": "critical",
    "stripe_connect_paired": "critical",
    "paypal_paired": "critical",
    "adyen": "critical",
    "wise": "critical",
    "gocardless": "critical",
    "paystack": "critical",
    "coinbase": "critical",
    # Shopify = commerce data + payments
    "shopify": "critical",
    # Supply-chain writes
    "dockerhub": "critical",
    "npm": "critical",
    "rubygems": "critical",
    "cratesio": "critical",
    "github": "critical",        # tokens with 'repo' scope; conservative default
    # Snowflake = data warehouse
    "snowflake_paired": "critical",

    # ── HIGH ─────────────────────────────────────────────────
    # Source-control / version-control (non-GitHub)
    "gitlab": "high",
    "bitbucket": "high",
    # Error / observability with write + trace access
    "datadog": "high",
    "sentry": "high",
    "rollbar": "high",
    "pagerduty": "high",
    "opsgenie": "high",
    "grafana": "high",
    "airbrake": "high",
    "honeybadger": "high",
    # Email / SMS / push — fraud + spam vectors
    "sendgrid": "high",
    "mailgun": "high",
    "mailchimp": "high",
    "mailersend": "high",
    "mailjet_paired": "high",
    "postmark": "high",
    "resend": "high",
    "loops": "high",
    "elasticemail": "high",
    "twilio_paired": "high",
    "messagebird": "high",
    "infobip": "high",
    "onesignal": "high",
    "courier": "high",
    # AI / LLM — billing-linked inference
    "openai": "high",
    "anthropic": "high",
    "cohere": "high",
    "mistral": "high",
    "groq": "high",
    "together": "high",
    "deepinfra": "high",
    "perplexity": "high",
    "anyscale": "high",
    "huggingface": "high",
    "replicate": "high",
    "fireworks": "high",
    "ai21": "high",
    "nvidia": "high",
    "xai": "high",
    "deepseek": "high",
    "openrouter": "high",
    "stability": "high",
    "elevenlabs": "high",
    "gemini": "high",
    "runway": "high",
    # Auth / identity — subject to scope; default high
    "okta": "high",
    "auth0": "high",
    "clerk": "high",
    "supabase": "high",
    "firebase": "high",
    # CRM / customer data
    "hubspot": "high",
    "intercom": "high",
    "helpscout": "high",
    "klaviyo": "high",
    "customerio": "high",
    "zendesk": "high",
    "salesloft": "high",
    "outreach": "high",
    "apollo": "high",
    "drift": "high",
    "pipedrive": "high",
    "close": "high",
    "copper": "high",
    "front": "high",
    "freshdesk": "high",
    # Communication / collab
    "slack": "high",
    "discord": "high",
    "telegram": "high",
    "zoom": "high",
    "chatwork": "high",
    # Search / data / CMS
    "algolia": "high",
    "contentful": "high",
    "storyblok": "high",
    "datocms": "high",
    "sanity": "high",
    "gitbook": "high",
    "webflow": "high",
    "prismic": "high",
    "phrase": "high",
    "crowdin": "high",
    # Analytics / feature flags
    "mixpanel": "high",
    "amplitude": "high",
    "posthog": "high",
    "segment": "high",
    "launchdarkly": "high",
    "flagsmith": "high",
    "split": "high",
    # Misc SaaS with customer-data-like access
    "airtable": "high",
    # "xata" and "fauna" entries removed 2026-05-20 — both providers
    # sunset their hosted DB products and the matching verifiers
    # (verify_xata_key, verify_fauna_key) were removed in commit
    # 1847afe (Track-A audit cleanup).  Keeping the risk-map entries
    # would lie to the codebase: a provider with no verifier can't
    # have a meaningful risk-weighting because no finding will ever
    # carry that provider tag.  Detection rules are intentionally
    # kept so legacy tokens in code are still flagged, but they
    # surface with provider="unknown" and pick up the default risk.
    "dbt": "high",
    "statuspage": "high",
    "papertrail": "high",
    "betterstack": "high",
    "gong": "high",
    "persona": "high",
    "onfido": "high",
    "pandadoc": "high",
    "dropbox_sign": "high",
    "dropbox": "high",
    "deputy": "high",
    "workable": "high",
    "greenhouse": "high",
    "ashby": "high",
    "rippling": "high",
    "deel": "high",
    "bamboohr": "high",
    "gitguardian": "high",
    "snyk": "high",
    "sonarcloud": "high",
    "virustotal": "high",
    "shodan": "high",
    "securitytrails": "high",
    "greynoise": "high",
    "abuseipdb": "high",
    "urlscan": "high",
    "gitbook": "high",
    "jira": "high",
    "basecamp": "high",
    "wrike": "high",
    "smartsheet": "high",
    "clickup": "high",
    "trello": "high",
    "monday": "high",
    "notion": "high",
    "linear": "high",
    # Stateful infrastructure
    "doppler": "high",
    "fastly": "high",
    "bunny": "high",
    "cloudflare": "high",
    "chronosphere": "high",
    # Connection strings
    "postman": "high",
    "cockroach": "high",

    # ── MEDIUM ───────────────────────────────────────────────
    # Project management, time tracking, low-impact SaaS
    "asana": "medium",
    "figma": "medium",
    "airtable": "medium",   # Note: overrides higher above — whichever is declared later wins
    "calendly": "medium",
    "checkly": "medium",
    "pingdom": "medium",
    "uptimerobot": "medium",
    "surveymonkey": "medium",
    "typeform": "medium",
    "wakatime": "medium",
    "buffer": "medium",
    "convertkit": "medium",
    "pushbullet": "medium",
    "giphy": "medium",
    "tenor": "medium",
    "unsplash": "medium",
    "pexels": "medium",
    "webhook": "medium",    # outbound webhook URLs
    "codecov": "medium",
    "apify": "medium",
    "bitrise": "medium",
    "cronitor": "medium",
    "healthchecks": "medium",
    "pushover": "medium",
    "twitch": "medium",
    "steam": "medium",
    "riot": "medium",
    "wistia": "medium",
    "persona": "medium",

    # ── LOW ──────────────────────────────────────────────────
    # Lookups / utilities where a leak costs money but no data
    "openweather": "low",
    "weatherapi": "low",
    "tomorrow_io": "low",
    "tomtom": "low",
    "opencage": "low",
    "heremaps": "low",
    "positionstack": "low",
    "ipinfo": "low",
    "ipstack": "low",
    "ipgeolocation": "low",
    "fixer": "low",
    "openexchangerates": "low",
    "currencylayer": "low",
    "exchangerate": "low",
    "alphavantage": "low",
    "finnhub": "low",
    "polygon": "low",
    "tiingo": "low",
    "coinmarketcap": "low",
    "etherscan": "low",
    "thirdweb": "low",
    "scrapingbee": "low",
    "scraperapi": "low",
    "zenrows": "low",
    "proxycurl": "low",
    "emailable": "low",
    "zerobounce": "low",
    "hunter": "low",
    "deepl": "low",
    "assemblyai": "low",
    "amadeus": "low",
    "shodan": "low",  # OSINT lookups — note: overrides earlier high; deliberate for read-only key

    # ── Remaining providers (mapped 2026-04-19 for 100% coverage) ──
    "airbyte": "high",               # data pipeline config + connection strings
    "axiom": "high",                 # log query, write
    "browserstack": "medium",        # CI test automation credential
    "gumroad": "high",               # commerce
    "here": "low",                   # maps / geocoding
    "hibp": "low",                   # HaveIBeenPwned breach query
    "hightouch": "high",             # data activation — customer PII
    "iterable": "high",              # email/SMS/push messaging
    "jotform": "high",               # form builder — often holds customer data
    "jumpcloud": "critical",         # directory-as-a-service, IAM
    "kickbox": "low",                # email verification lookup
    "koyeb": "critical",             # serverless deploy
    "lemonsqueezy": "high",          # digital-goods commerce
    "lever": "high",                 # ATS — candidate PII
    "locationiq": "low",             # geocoding
    "lokalise": "medium",            # translation platform
    "magic": "high",                 # passwordless auth
    "mapbox": "low",                 # maps
    "mongodb_atlas_paired": "critical",  # DB admin
    "moralis": "medium",             # Web3 node access
    "neverbounce": "low",            # email verification
    "newrelic": "high",              # observability
    "ngrok": "high",                 # tunneling — traffic interception
    "novita": "high",                # inference API
    "octopus": "critical",           # deployment automation
    "pinecone": "high",              # vector DB, customer data
    "square": "critical",            # payments
    "yelp": "low",                   # business lookup
    "zoho": "high",                  # CRM / mail
}


def inferred_risk(provider: str) -> Optional[str]:
    """Return the default risk level for a provider, or None.

    The worker calls this when the verifier returned
    ``status="active"`` but didn't populate
    ``VerificationResult.risk_level`` itself. Case-insensitive on the
    ``provider`` argument.
    """
    if not provider:
        return None
    return PROVIDER_DEFAULT_RISK.get(provider.strip().lower())


__all__ = ["inferred_risk", "PROVIDER_DEFAULT_RISK"]
