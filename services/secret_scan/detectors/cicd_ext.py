# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Extended CI/CD and DevOps platform detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
        # VOODA-SEC-BUILDKITE-001 removed 2026-05-22 (Track-A Phase 1, collision audit) —
    # shadow of live rule in trufflehog_port.py; shadow is permissive variant of live's strict regex.
    # Removal restored 1 dead-code rule to the registry's correct
    # state (was silently shadowed by last-wins dedup).
    SecretRule(rule_id="VOODA-SEC-BUILDKITE-002", title="Buildkite API Token", secret_type="buildkite_api_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(bkp_[A-Za-z0-9]{40,})(?:[^A-Za-z0-9]|$)',
        keywords=["bkp_"], confidence=0.95, description="Buildkite API access token.", fix_hint="Revoke at Buildkite → Personal Settings → API Access Tokens."),
    SecretRule(rule_id="VOODA-SEC-DRONE-001", title="Drone CI Token", secret_type="drone_token", severity="high",
        pattern=r'(?:drone[_-]?token|DRONE_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9]{32,})["\']?',
        keywords=["drone_token", "DRONE_TOKEN"], confidence=0.75, description="Drone CI personal token.", fix_hint="Regenerate at Drone CI → User Settings."),
    SecretRule(rule_id="VOODA-SEC-TEAMCITY-002", title="TeamCity API Token", secret_type="teamcity_token", severity="high",
        pattern=r'(?:teamcity[_-]?(?:api[_-]?)?token|TEAMCITY_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9]{20,})["\']?',
        keywords=["teamcity", "TEAMCITY"], confidence=0.75, description="JetBrains TeamCity API token.", fix_hint="Revoke at TeamCity → My Settings & Tools → Access Tokens."),
    SecretRule(rule_id="VOODA-SEC-BAMBOO-001", title="Bamboo API Token", secret_type="bamboo_token", severity="high",
        pattern=r'(?:bamboo[_-]?(?:api[_-]?)?token|BAMBOO_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9]{20,})["\']?',
        keywords=["bamboo", "BAMBOO"], confidence=0.70, description="Atlassian Bamboo API token.", fix_hint="Regenerate at Bamboo → Profile → Personal access tokens."),
    SecretRule(rule_id="VOODA-SEC-ARGOCD-002", title="ArgoCD Auth Token", secret_type="argocd_token", severity="high",
        pattern=r'(?:argocd[_-]?(?:auth[_-]?)?token|ARGOCD_TOKEN|ARGOCD_AUTH_TOKEN)\s*[=:]\s*["\']?(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)["\']?',
        keywords=["argocd", "ARGOCD"], confidence=0.80, description="ArgoCD authentication token (JWT).", fix_hint="Regenerate via ArgoCD CLI or API."),
    SecretRule(rule_id="VOODA-SEC-HARBOR-001", title="Harbor Registry Credentials", secret_type="harbor_credentials", severity="high",
        pattern=r'(?:harbor[_-]?(?:password|secret|token)|HARBOR_(?:PASSWORD|SECRET|TOKEN))\s*[=:]\s*["\']?([^\s"\']{12,})["\']?',
        keywords=["harbor", "HARBOR"], confidence=0.70, description="Harbor container registry credentials.", fix_hint="Rotate at Harbor → User Profile → CLI Secret."),
    SecretRule(rule_id="VOODA-SEC-JFROG-001", title="JFrog Artifactory API Key", secret_type="jfrog_api_key", severity="high",
        pattern=r'(?:jfrog[_-]?(?:api[_-]?)?key|ARTIFACTORY_(?:API_)?KEY|JFROG_API_KEY)\s*[=:]\s*["\']?([A-Za-z0-9]{73})["\']?',
        keywords=["jfrog", "JFROG", "ARTIFACTORY", "artifactory"], confidence=0.80, description="JFrog Artifactory API key.", fix_hint="Regenerate at JFrog → User Profile → API Key."),
    SecretRule(rule_id="VOODA-SEC-JFROG-002", title="JFrog Access Token", secret_type="jfrog_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(cmVmdGtuOi[A-Za-z0-9\-_+/=]{50,})(?:[^A-Za-z0-9]|$)',
        keywords=["cmVmdGtuOi"], confidence=0.90, description="JFrog platform access token (base64-encoded).", fix_hint="Revoke at JFrog → Identity and Access → Access Tokens."),
    SecretRule(rule_id="VOODA-SEC-HARNESS-002", title="Harness API Key", secret_type="harness_key", severity="high",
        pattern=r'(?:harness[_-]?(?:api[_-]?)?key|HARNESS_API_KEY)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{30,})["\']?',
        keywords=["harness", "HARNESS"], confidence=0.70, description="Harness CI/CD API key.", fix_hint="Regenerate at Harness → Account Settings → API Keys."),
    SecretRule(rule_id="VOODA-SEC-CONSUL-001", title="HashiCorp Consul Token", secret_type="consul_token", severity="high",
        pattern=r'(?:consul[_-]?(?:http[_-]?)?token|CONSUL_HTTP_TOKEN)\s*[=:]\s*["\']?([a-f0-9\-]{36})["\']?',
        keywords=["consul", "CONSUL"], confidence=0.80, description="HashiCorp Consul ACL token.", fix_hint="Revoke via `consul acl token delete`."),
    SecretRule(rule_id="VOODA-SEC-NOMAD-001", title="HashiCorp Nomad Token", secret_type="nomad_token", severity="high",
        pattern=r'(?:nomad[_-]?token|NOMAD_TOKEN)\s*[=:]\s*["\']?([a-f0-9\-]{36})["\']?',
        keywords=["nomad_token", "NOMAD_TOKEN"], confidence=0.80, description="HashiCorp Nomad ACL token.", fix_hint="Revoke via `nomad acl token delete`."),
]
