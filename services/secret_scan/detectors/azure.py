# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Azure secret detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-AZ-001",
        title="Azure Storage Account Key",
        secret_type="azure_storage_key",
        severity="critical",
        pattern=r'(?:AccountKey|azure_storage_key|AZURE_STORAGE_KEY)\s*[=:]\s*["\']?([A-Za-z0-9+/]{86}==)["\']?',
        keywords=["AccountKey", "azure_storage", "AZURE_STORAGE"],
        confidence=0.90,
        description="Azure Storage account access key detected.",
        fix_hint="Rotate key in Azure Portal → Storage Account → Access keys. Use Managed Identity instead.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-AZ-002",
        title="Azure AD Client Secret",
        secret_type="azure_ad_secret",
        severity="critical",
        # Azure-named variables only. A bare `client_secret` is the
        # OAuth2 field name every provider uses, so claiming it branded
        # other vendors' secrets as Azure AD — a MuleSoft secret was
        # reported as Azure at critical/0.75, which sends the responder
        # to the wrong portal. VOODA-SEC-OAUTH-001 is the correctly
        # generic rule for an unattributed client_secret.
        pattern=r'(?:AZURE_CLIENT_SECRET|azure_ad_secret|azure[_-]?client[_-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9~._\-]{34,})["\']?',
        keywords=["AZURE_CLIENT_SECRET", "azure_ad_secret"],
        confidence=0.75,
        description="Azure Active Directory client secret detected.",
        fix_hint="Rotate in Azure Portal → App Registrations → Certificates & secrets. Use Managed Identity.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-AZ-003",
        title="Azure Connection String",
        secret_type="azure_connection_string",
        severity="high",
        pattern=r'(?:DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,})',
        keywords=["DefaultEndpointsProtocol", "AccountKey"],
        confidence=0.95,
        description="Azure Storage connection string with embedded access key.",
        fix_hint="Use Azure Key Vault to store connection strings. Reference via environment variable.",
    ),
]
