# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Developer tools and platform detectors (Azure DevOps, CircleCI, Travis, etc.)."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-ADO-001", title="Azure DevOps PAT", secret_type="azure_devops_pat", severity="high",
        pattern=r'(?:azure[_-]?devops[_-]?pat|ADO_PAT|AZURE_DEVOPS_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9]{52,})["\']?',
        keywords=["azure_devops", "ADO_PAT", "AZURE_DEVOPS_TOKEN"], confidence=0.75,
        # Force the verifier to dispatch to `azure_devops` (not the
        # `azure` IAM verifier) — `secret_type.split("_")[0]` would
        # otherwise route to the wrong provider key.
        provider_override="azure_devops",
        description="Azure DevOps personal access token.", fix_hint="Revoke at Azure DevOps → User Settings → Personal Access Tokens."),
    SecretRule(rule_id="VOODA-SEC-CIRCLE-001", title="CircleCI Token", secret_type="circleci_token", severity="high",
        pattern=r'(?:circleci[_-]?token|CIRCLECI_TOKEN|CIRCLE_TOKEN)\s*[=:]\s*["\']?([a-f0-9]{40})["\']?',
        keywords=["circleci", "CIRCLECI", "CIRCLE_TOKEN"], confidence=0.80, description="CircleCI API token.", fix_hint="Revoke at CircleCI → User Settings → Personal API Tokens."),
    SecretRule(rule_id="VOODA-SEC-TRAVIS-001", title="Travis CI Token", secret_type="travis_token", severity="high",
        pattern=r'(?:travis[_-]?(?:api[_-]?)?token|TRAVIS_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9\-]{20,})["\']?',
        keywords=["travis_token", "TRAVIS_TOKEN", "travis_api"], confidence=0.75, description="Travis CI API token.", fix_hint="Regenerate at Travis CI → Settings → API Token."),
    SecretRule(rule_id="VOODA-SEC-CODECOV-001", title="Codecov Token", secret_type="codecov_token", severity="medium",
        pattern=r'(?:codecov[_-]?token|CODECOV_TOKEN)\s*[=:]\s*["\']?([a-f0-9\-]{36})["\']?',
        keywords=["codecov", "CODECOV_TOKEN"], confidence=0.80, description="Codecov upload token.", fix_hint="Regenerate at Codecov → Settings → General."),
    SecretRule(rule_id="VOODA-SEC-SONAR-001", title="SonarQube/SonarCloud Token", secret_type="sonar_token", severity="high",
        pattern=r'(?:sonar[_-]?(?:cloud[_-]?)?token|SONAR_TOKEN|sonar\.login)\s*[=:]\s*["\']?([a-f0-9]{40})["\']?',
        keywords=["sonar_token", "SONAR_TOKEN", "sonar.login"], confidence=0.80, description="SonarQube or SonarCloud analysis token.", fix_hint="Revoke at SonarCloud → My Account → Security."),
    SecretRule(rule_id="VOODA-SEC-GRAFANA-001", title="Grafana API Key", secret_type="grafana_api_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[^A-Za-z0-9]|$)',
        keywords=["glsa_"], confidence=0.95, description="Grafana Cloud service account token.", fix_hint="Revoke at Grafana → Administration → Service Accounts."),
    SecretRule(rule_id="VOODA-SEC-GRAFANA-002", title="Grafana Cloud API Key", secret_type="grafana_cloud_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(glc_[A-Za-z0-9\+/=]{32,})(?:[^A-Za-z0-9]|$)',
        keywords=["glc_"], confidence=0.90, description="Grafana Cloud API key.", fix_hint="Rotate at Grafana Cloud → API Keys."),
    SecretRule(rule_id="VOODA-SEC-PULUMI-001", title="Pulumi Access Token", secret_type="pulumi_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(pul-[a-f0-9]{40})(?:[^A-Za-z0-9]|$)', keywords=["pul-"], confidence=0.95,
        description="Pulumi access token for infrastructure-as-code.", fix_hint="Revoke at Pulumi → Settings → Access Tokens."),
]
