# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Bitbucket secret detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-BB-001",
        title="Bitbucket App Password",
        secret_type="bitbucket_app_password",
        severity="high",
        pattern=r'(?:bitbucket|BITBUCKET)[\w_]*(?:password|PASSWORD|token|TOKEN|secret|SECRET)\s*[=:]\s*["\']?([A-Za-z0-9]{16,})["\']?',
        keywords=["bitbucket", "BITBUCKET"],
        confidence=0.70,
        description="Bitbucket app password or API token.",
        fix_hint="Revoke at Bitbucket → Personal settings → App passwords.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-BB-002",
        title="Bitbucket HTTP Credentials",
        secret_type="bitbucket_http_auth",
        severity="high",
        pattern=r'https?://[^:]+:[^@]+@bitbucket\.org',
        keywords=["bitbucket.org"],
        confidence=0.90,
        description="Bitbucket repository URL with embedded credentials.",
        fix_hint="Use SSH keys or app passwords via credential helper instead of URL-embedded credentials.",
    ),
]
