# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""CI/CD and infrastructure token detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-DOCKER-001",
        title="Docker Hub Personal Access Token",
        secret_type="dockerhub_token",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(dckr_pat_[A-Za-z0-9\-_]{27,})(?:[^A-Za-z0-9]|$)',
        keywords=["dckr_pat_"],
        confidence=0.98,
        description="Docker Hub personal access token for registry authentication.",
        fix_hint="Delete at Docker Hub → Account Settings → Security → Access Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-NPM-001",
        title="npm Access Token",
        secret_type="npm_token",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(npm_[A-Za-z0-9]{36,})(?:[^A-Za-z0-9]|$)',
        keywords=["npm_"],
        confidence=0.98,
        description="npm registry access token. Can publish packages.",
        fix_hint="Revoke at npmjs.com → Access Tokens. Create a new scoped token.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-PYPI-002",
        title="PyPI API Token",
        secret_type="pypi_token",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(pypi-AgEIcH[A-Za-z0-9\-_]{50,})(?:[^A-Za-z0-9]|$)',
        keywords=["pypi-AgEIcH"],
        confidence=0.98,
        description="PyPI API token for Python package publishing.",
        fix_hint="Delete at pypi.org → Account Settings → API tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-TF-001",
        title="Terraform Cloud API Token",
        secret_type="terraform_cloud_token",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])([a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_]{60,})(?:[^A-Za-z0-9]|$)',
        keywords=["atlasv1"],
        confidence=0.95,
        description="Terraform Cloud / Enterprise API token.",
        fix_hint="Regenerate at Terraform Cloud → User Settings → Tokens.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-VAULT-001",
        title="HashiCorp Vault Token",
        secret_type="vault_token",
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(hvs\.[A-Za-z0-9\-_]{24,})(?:[^A-Za-z0-9]|$)',
        keywords=["hvs."],
        confidence=0.95,
        description="HashiCorp Vault service token. Grants access to secrets stored in Vault.",
        fix_hint="Revoke token via `vault token revoke`. Use short-lived tokens with AppRole auth.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-VAULT-005",
        title="HashiCorp Vault Legacy Token",
        secret_type="vault_token",
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(s\.[A-Za-z0-9]{24,})(?:[^A-Za-z0-9]|$)',
        keywords=["s.", "vault", "VAULT"],
        # WS6 2026-06-05: the legacy ``s.`` prefix collides with Go/JS method
        # calls on a variable named `s` (``s.verifyNotificationDisplayed`` etc.),
        # which is the entire 64+25-finding FP population in the audited repos.
        # Require a Vault marker in the proximity window. Recall guard: the one
        # live TP corpus-wide sits in Vault usage context; ``post_filter_direction
        # ="both"`` so a ``VAULT_TOKEN = s.…`` marker BEFORE the token is seen.
        post_filter_keywords=["vault"],
        post_filter_window=300, post_filter_direction="both",
        confidence=0.80,
        description="HashiCorp Vault legacy service token (s. prefix format).",
        fix_hint="Revoke via `vault token revoke`. Migrate to newer hvs. token format.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-VAULT-003",
        title="HashiCorp Vault Batch Token",
        secret_type="vault_batch_token",
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(hvb\.[A-Za-z0-9\-_]{24,})(?:[^A-Za-z0-9]|$)',
        keywords=["hvb."],
        confidence=0.95,
        description="HashiCorp Vault batch token. Short-lived but grants Vault access.",
        fix_hint="Batch tokens cannot be revoked individually. Revoke the parent token.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-VAULT-004",
        title="HashiCorp Vault Recovery Token",
        secret_type="vault_recovery_token",
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(hvr\.[A-Za-z0-9\-_]{24,})(?:[^A-Za-z0-9]|$)',
        keywords=["hvr."],
        confidence=0.95,
        description="HashiCorp Vault recovery token. Used for disaster recovery operations.",
        fix_hint="Revoke via `vault operator generate-root -cancel`. Recovery tokens grant root-level access.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-JENKINS-001",
        title="Jenkins API Token",
        secret_type="jenkins_token",
        severity="high",
        pattern=r'(?:jenkins_(?:api_)?token|JENKINS_(?:API_)?TOKEN)\s*[=:]\s*["\']?([a-f0-9]{34})["\']?',
        keywords=["jenkins_token", "JENKINS_TOKEN", "jenkins_api_token", "JENKINS_API_TOKEN"],
        confidence=0.85,
        description="Jenkins API token for CI/CD automation.",
        fix_hint="Regenerate at Jenkins → User → Configure → API Token.",
    ),
]
