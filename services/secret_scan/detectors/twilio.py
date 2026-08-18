# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Twilio secret detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-TWILIO-001",
        title="Twilio Account SID",
        secret_type="twilio_account_sid",
        severity="medium",
        pattern=r'(?:^|[^A-Za-z0-9])(AC[a-f0-9]{32})(?:[^A-Za-z0-9]|$)',
        keywords=["AC"],
        confidence=0.85,
        description="Twilio account SID. Not a secret alone but enables API access when paired with auth token.",
        fix_hint="If paired with an auth token, rotate the auth token in Twilio Console.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-TWILIO-002",
        title="Twilio Auth Token",
        secret_type="twilio_auth_token",
        severity="critical",
        pattern=r'(?:twilio_auth_token|TWILIO_AUTH_TOKEN|twilio_token)\s*[=:]\s*["\']?([a-f0-9]{32})["\']?',
        keywords=["twilio_auth_token", "TWILIO_AUTH_TOKEN", "twilio_token"],
        confidence=0.90,
        description="Twilio auth token. Grants full API access to send SMS, make calls.",
        fix_hint="Rotate in Twilio Console → Account → API keys and tokens.",
    ),
]
