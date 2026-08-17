# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Enterprise SaaS and B2B platform detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-ZOOM-001", title="Zoom JWT API Secret", secret_type="zoom_secret", severity="high",
        pattern=r'(?:zoom[_-]?(?:api[_-]?)?secret|ZOOM_(?:API_)?SECRET)\s*[=:]\s*["\']?([A-Za-z0-9]{20,})["\']?',
        keywords=["zoom", "ZOOM"], confidence=0.75, description="Zoom API secret key.", fix_hint="Regenerate at marketplace.zoom.us → App credentials."),
    SecretRule(rule_id="VOODA-SEC-DOCUSIGN-001", title="DocuSign Integration Key", secret_type="docusign_key", severity="high",
        pattern=r'(?:docusign[_-]?(?:integration[_-]?)?key|DOCUSIGN_(?:INTEGRATION_)?KEY)\s*[=:]\s*["\']?([a-f0-9\-]{36})["\']?',
        keywords=["docusign", "DOCUSIGN"], confidence=0.75, description="DocuSign API integration key.", fix_hint="Regenerate at DocuSign Admin → API and Keys."),
    SecretRule(rule_id="VOODA-SEC-ZENDESK-001", title="Zendesk API Token", secret_type="zendesk_token", severity="high",
        pattern=r'(?:zendesk[_-]?(?:api[_-]?)?token|ZENDESK_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9]{40})["\']?',
        keywords=["zendesk", "ZENDESK"], confidence=0.75, description="Zendesk API token.", fix_hint="Regenerate at Zendesk Admin → Apps and integrations → APIs."),
    SecretRule(rule_id="VOODA-SEC-FRESHDESK-001", title="Freshdesk API Key", secret_type="freshdesk_key", severity="medium",
        pattern=r'(?:freshdesk[_-]?(?:api[_-]?)?key|FRESHDESK_API_KEY)\s*[=:]\s*["\']?([A-Za-z0-9]{20,})["\']?',
        keywords=["freshdesk", "FRESHDESK"], confidence=0.75, description="Freshdesk API key.", fix_hint="Find at Freshdesk → Profile Settings → API Key."),
    SecretRule(rule_id="VOODA-SEC-SALESFORCE-001", title="Salesforce OAuth Secret", secret_type="salesforce_secret", severity="critical",
        pattern=r'(?:salesforce[_-]?(?:client[_-]?)?secret|SF_(?:CLIENT_)?SECRET|SFDC_SECRET)\s*[=:]\s*["\']?([A-F0-9]{64})["\']?',
        keywords=["salesforce", "SALESFORCE", "SF_SECRET", "SFDC"], confidence=0.80, description="Salesforce Connected App OAuth client secret.", fix_hint="Rotate at Salesforce Setup → App Manager → Connected Apps."),
    SecretRule(rule_id="VOODA-SEC-SALESFORCE-002", title="Salesforce Security Token", secret_type="salesforce_token", severity="high",
        pattern=r'(?:salesforce[_-]?(?:security[_-]?)?token|SF_(?:SECURITY_)?TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9]{24,})["\']?',
        keywords=["salesforce_token", "SF_TOKEN", "SF_SECURITY_TOKEN"], confidence=0.70, description="Salesforce user security token.", fix_hint="Reset at Salesforce → Settings → My Personal Information → Reset Security Token."),
    SecretRule(rule_id="VOODA-SEC-SAP-001", title="SAP API Key", secret_type="sap_api_key", severity="high",
        pattern=r'(?:sap[_-]?(?:api[_-]?)?key|SAP_API_KEY)\s*[=:]\s*["\']?([A-Za-z0-9]{32,})["\']?',
        keywords=["sap_api", "SAP_API"], confidence=0.70, description="SAP Business Technology Platform API key.", fix_hint="Regenerate at SAP BTP Cockpit → Security → API Credentials."),
]
