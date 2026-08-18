# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Scanner branding layer — maps internal detection engine names to customer-facing names.

Architecture:
- Internal layer: preserves actual engine name (vooda_engine) for debugging and audit
- UI layer: shows branded "Vooda AI Engine" name to customers
- Export layer: includes full tool chain metadata (SARIF compliance)

Usage:
    from packages.common.scanner_branding import brand_scanner_name, brand_rule_id

    ui_name = brand_scanner_name("vooda_engine")               # "Vooda AI Engine"
    ui_rule = brand_rule_id("VOODA-SEC-AWS-001")               # "AWS-001"
"""

from typing import Optional


# ── Scanner name mapping ──────────────────────────────────

_SCANNER_DISPLAY_NAMES = {
    "vooda_standalone": "Vooda AI Engine",
    "vooda_regex": "Vooda AI Engine",
    "vooda_engine": "Vooda AI Engine",
}

_EXTERNAL_SCANNERS = {
    "checkmarx", "fortify", "veracode", "sonarqube", "codeql",
    "snyk", "bandit", "brakeman", "gosec",
    "eslint-security", "spotbugs", "findsecbugs",
}

VOODA_ENGINE_INTERNAL = "vooda_engine"


def brand_scanner_name(internal_name: str) -> str:
    lower = internal_name.lower().strip()
    if lower in _SCANNER_DISPLAY_NAMES:
        return _SCANNER_DISPLAY_NAMES[lower]
    return internal_name.replace("_", " ").title()


def is_vooda_engine(scanner_name: str) -> bool:
    return scanner_name.lower().strip() in _SCANNER_DISPLAY_NAMES


def get_internal_scanner_name() -> str:
    return VOODA_ENGINE_INTERNAL


# ── Rule ID mapping ───────────────────────────────────────

_RULE_PREFIX_STRIP = [
    "VOODA-SEC-",
]

_RULE_CATEGORY_MAP = {
    "aws": "AWS Credential",
    "gcp": "GCP Credential",
    "azure": "Azure Credential",
    "github": "GitHub Token",
    "gitlab": "GitLab Token",
    "bitbucket": "Bitbucket Credential",
    "stripe": "Payment Key",
    "slack": "Slack Token",
    "twilio": "Communication Credential",
    "sendgrid": "Email API Key",
    "mailgun": "Email API Key",
    "mailchimp": "Email API Key",
    "discord": "Discord Webhook",
    "database": "Database Credential",
    "postgresql": "Database Credential",
    "mysql": "Database Credential",
    "mongodb": "Database Credential",
    "redis": "Database Credential",
    "firebase": "Database Credential",
    "private-key": "Private Key",
    "rsa": "Private Key",
    "ssh": "Private Key",
    "pgp": "Private Key",
    "pkcs": "Private Key",
    "certificate": "Certificate",
    "docker": "Container Registry Token",
    "npm": "Package Registry Token",
    "pypi": "Package Registry Token",
    "terraform": "Infrastructure Token",
    "vault": "Infrastructure Token",
    "jenkins": "CI/CD Token",
    "heroku": "Cloud Platform Token",
    "digitalocean": "Cloud Platform Token",
    "alibaba": "Cloud Platform Token",
    "oauth": "OAuth Credential",
    "jwt": "Authentication Token",
    "auth0": "Identity Provider Token",
    "okta": "Identity Provider Token",
    "api-key": "API Key",
    "api_key": "API Key",
    "password": "Hardcoded Password",
    "bearer": "Authentication Token",
    "basic-auth": "HTTP Credential",
    "connection-string": "Connection String",
    "webhook": "Webhook URL",
    "entropy": "High-Entropy Secret",
    "hardcoded-secret": "Hardcoded Secret",
    "hardcoded-credential": "Hardcoded Credential",
    "secret": "Hardcoded Secret",
    "token": "Authentication Token",
    "credential": "Hardcoded Credential",
}


def brand_rule_id(rule_id: str) -> str:
    """
    Clean up a rule ID for customer-facing display.

    Examples:
        'VOODA-SEC-AWS-001' → 'AWS-001'
        'VOODA-SEC-ENTROPY-BASE64' → 'ENTROPY-BASE64'
    """
    if not rule_id:
        return rule_id

    cleaned = rule_id
    for prefix in _RULE_PREFIX_STRIP:
        if cleaned.upper().startswith(prefix):
            cleaned = cleaned[len(prefix):]

    return cleaned


def get_rule_category(rule_id: str) -> Optional[str]:
    """Try to extract a human-readable category from a rule ID."""
    lower = rule_id.lower()
    for pattern, category in _RULE_CATEGORY_MAP.items():
        if pattern in lower:
            return category
    return None


# ── Export metadata ───────────────────────────────────────

def get_sarif_tool_info() -> dict:
    return {
        "driver": {
            "name": "Vooda AI Security Engine",
            "organization": "Vooda AI",
            "version": "0.1.0",
            "informationUri": "https://vooda.ai",
            "properties": {
                "detection_engines": [
                    {
                        "name": "Vooda AI Secret Scanner",
                        "version": "0.1.0",
                    },
                ],
                "ai_engines": [
                    "Vooda AI Triage Engine",
                    "Vooda AI Remediation Engine",
                ],
            },
        },
    }


# ── Legal / Attribution ───────────────────────────────────

OPEN_SOURCE_ATTRIBUTION = """
Vooda AI Security Engine
==========================

Detection Components:
- Vooda AI Secret Scanner — proprietary secret detection engine with 80+ provider-specific
  detectors, Shannon entropy analysis, and context-aware false positive filtering.

AI Analysis:
- AI triage and remediation engines are proprietary to Vooda AI.
- AI models are provided by Anthropic (Claude), OpenAI, or customer-configured providers.

All open-source component licenses are respected and attributed per their terms.
"""


def get_attribution_text() -> str:
    return OPEN_SOURCE_ATTRIBUTION.strip()
