# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Payment platform detectors (Square, PayPal, Plaid, Braintree)."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-SQUARE-001", title="Square Access Token", secret_type="square_access_token", severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(sq0atp-[A-Za-z0-9\-_]{22,})(?:[^A-Za-z0-9]|$)', keywords=["sq0atp-"], confidence=0.95,
        description="Square payment platform access token.", fix_hint="Regenerate at Square Dashboard → Credentials."),
    SecretRule(rule_id="VOODA-SEC-SQUARE-002", title="Square OAuth Secret", secret_type="square_oauth_secret", severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(sq0csp-[A-Za-z0-9\-_]{43,})(?:[^A-Za-z0-9]|$)', keywords=["sq0csp-"], confidence=0.95,
        description="Square OAuth application secret.", fix_hint="Rotate in Square Developer Dashboard."),
    SecretRule(rule_id="VOODA-SEC-PAYPAL-001", title="PayPal Client Secret", secret_type="paypal_client_secret", severity="critical",
        pattern=r'(?:paypal[_-]?(?:client[_-]?)?secret|PAYPAL[_-]?(?:CLIENT[_-]?)?SECRET)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{20,})["\']?',
        keywords=["paypal", "PAYPAL"], confidence=0.75, description="PayPal OAuth client secret.", fix_hint="Rotate at PayPal Developer Dashboard → My Apps."),
    SecretRule(rule_id="VOODA-SEC-PLAID-001", title="Plaid Client Secret", secret_type="plaid_client_secret", severity="critical",
        pattern=r'(?:plaid[_-]?(?:client[_-]?)?secret|PLAID[_-]?(?:CLIENT[_-]?)?SECRET)\s*[=:]\s*["\']?([a-f0-9]{30,})["\']?',
        keywords=["plaid", "PLAID"], confidence=0.80, description="Plaid banking API client secret.", fix_hint="Rotate at Plaid Dashboard → Team Settings → Keys."),
    SecretRule(rule_id="VOODA-SEC-BRAINTREE-002", title="Braintree Access Token", secret_type="braintree_token", severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32})(?:[^A-Za-z0-9]|$)',
        keywords=["access_token$"], confidence=0.95, description="Braintree payment gateway access token.", fix_hint="Regenerate in Braintree Control Panel."),
]
