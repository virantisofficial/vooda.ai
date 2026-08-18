# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""GitHub token detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-GH-001",
        title="GitHub Personal Access Token (Classic)",
        secret_type="github_pat",
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(ghp_[A-Za-z0-9_]{36,})(?:[^A-Za-z0-9]|$)',
        keywords=["ghp_"],
        confidence=0.98,
        description="GitHub classic personal access token. Grants repo, user, and org access.",
        fix_hint="Revoke at GitHub → Settings → Developer settings → Personal access tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GH-002",
        title="GitHub Fine-Grained PAT",
        secret_type="github_pat_fine_grained",
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(github_pat_[A-Za-z0-9_]{22,})(?:[^A-Za-z0-9]|$)',
        keywords=["github_pat_"],
        confidence=0.98,
        description="GitHub fine-grained personal access token with scoped permissions.",
        fix_hint="Revoke at GitHub → Settings → Developer settings → Fine-grained tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GH-003",
        title="GitHub OAuth Access Token",
        secret_type="github_oauth",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(gho_[A-Za-z0-9_]{36,})(?:[^A-Za-z0-9]|$)',
        keywords=["gho_"],
        confidence=0.98,
        description="GitHub OAuth access token.",
        fix_hint="Revoke the OAuth app authorization in GitHub → Settings → Applications.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GH-004",
        title="GitHub App Token",
        secret_type="github_app_token",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(ghu_[A-Za-z0-9_]{36,}|ghs_[A-Za-z0-9_]{36,}|ghr_[A-Za-z0-9_]{36,})(?:[^A-Za-z0-9]|$)',
        keywords=["ghu_", "ghs_", "ghr_"],
        confidence=0.98,
        description="GitHub App user, server, or refresh token.",
        fix_hint="These tokens are short-lived. Ensure the GitHub App installation is authorized.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GH-005",
        title="GitHub App Private Key",
        secret_type="github_app_private_key",
        severity="critical",
        pattern=r'-----BEGIN RSA PRIVATE KEY-----[\s\S]{100,}-----END RSA PRIVATE KEY-----',
        keywords=["BEGIN RSA PRIVATE KEY"],
        confidence=0.85,
        description="RSA private key, potentially for GitHub App authentication.",
        fix_hint="Regenerate the private key in GitHub App settings. Never commit private keys.",
        multiline=True,
    ),
]
