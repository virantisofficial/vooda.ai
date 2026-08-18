# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""GitLab token detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-GL-001",
        title="GitLab Personal Access Token",
        secret_type="gitlab_pat",
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(glpat-[A-Za-z0-9\-_]{20,})(?:[^A-Za-z0-9]|$)',
        keywords=["glpat-"],
        confidence=0.98,
        description="GitLab personal access token with API/repository access.",
        fix_hint="Revoke at GitLab → User Settings → Access Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GL-002",
        title="GitLab Pipeline Trigger Token",
        secret_type="gitlab_pipeline_token",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(glptt-[a-f0-9]{40,})(?:[^A-Za-z0-9]|$)',
        keywords=["glptt-"],
        confidence=0.98,
        description="GitLab pipeline trigger token for CI/CD.",
        fix_hint="Revoke at GitLab → Project → Settings → CI/CD → Pipeline triggers.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GL-003",
        title="GitLab Runner Registration Token",
        secret_type="gitlab_runner_token",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(glrt-[A-Za-z0-9\-_]{20,})(?:[^A-Za-z0-9]|$)',
        keywords=["glrt-"],
        confidence=0.98,
        description="GitLab runner registration token.",
        fix_hint="Reset at GitLab → Admin → CI/CD → Runners.",
    ),
]
