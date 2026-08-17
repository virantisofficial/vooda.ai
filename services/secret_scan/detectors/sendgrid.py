# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""SendGrid secret detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-SG-001",
        title="SendGrid API Key",
        secret_type="sendgrid_api_key",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})(?:[^A-Za-z0-9]|$)',
        keywords=["SG."],
        confidence=0.98,
        description="SendGrid API key. Can send emails on behalf of the account.",
        fix_hint="Delete and recreate at SendGrid → Settings → API Keys.",
    ),
]
