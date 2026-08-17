# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Kubernetes secret and config detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-K8S-002",
        title="Kubernetes Secret with stringData",
        secret_type="kubernetes_secret_stringdata",
        severity="critical",
        pattern=r'kind:\s*Secret[\s\S]{0,500}stringData:\s*\n(?:\s+[\w][\w.-]*:\s*.+\n?)+',
        keywords=["kind: Secret", "stringData"],
        confidence=0.90,
        multiline=True,
        description="Kubernetes Secret manifest with plaintext values in stringData block. These values are stored unencrypted in etcd by default.",
        fix_hint="Use sealed-secrets, external-secrets-operator, or a Vault CSI driver instead of plaintext stringData.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-K8S-003",
        title="Kubernetes Secret Data Value",
        secret_type="kubernetes_secret_data",
        severity="high",
        pattern=r'(?:kind:\s*Secret[\s\S]{0,500}data:\s*\n\s+[\w][\w.-]*:\s*)([A-Za-z0-9+/=]{20,})',
        keywords=["kind: Secret", "data:"],
        confidence=0.80,
        multiline=True,
        description="Base64-encoded value in a Kubernetes Secret data block. The value may contain credentials, TLS keys, or tokens.",
        fix_hint="Avoid committing K8s Secrets to version control. Use sealed-secrets or external-secrets-operator.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-K8S-004",
        title="Kubernetes ConfigMap with Sensitive Key",
        secret_type="kubernetes_configmap_secret",
        severity="high",
        pattern=r'kind:\s*ConfigMap[\s\S]{0,500}data:\s*\n\s+(?:[\w.-]*(?:password|token|secret|key|credential|api.key)[\w.-]*):\s*(.+)',
        keywords=["kind: ConfigMap"],
        confidence=0.70,
        multiline=True,
        description="Kubernetes ConfigMap containing a key with sensitive naming (password, token, secret). ConfigMaps are not encrypted.",
        fix_hint="Move sensitive values from ConfigMap to Secret resources, and use encryption at rest.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-HELM-001",
        title="Helm Values with Hardcoded Secret",
        secret_type="helm_secret_value",
        severity="high",
        pattern=r'(?:password|token|secret|apiKey|secretKey|accessKey)\s*:\s*["\']?([A-Za-z0-9\-_+/=.]{8,})["\']?\s*(?:#|$)',
        keywords=["password:", "token:", "secret:", "apiKey:", "secretKey:", "accessKey:"],
        # Calibrated 2026-04-25: 7/69 TP (10%) on gold-validated data
        # AFTER the api/docs/*.yaml exclusion was added. Even with the
        # path skip in place, the regex still matches enough YAML
        # structure scaffolding (kustomize patches, K8s manifest
        # placeholders, etc.) that the AI/human review gate is the
        # right default rather than auto-confidence. Original: 0.60.
        confidence=0.30,
        description="Hardcoded secret value in Helm values file or Kubernetes YAML configuration.",
        fix_hint="Use Helm secrets plugin, Vault agent injector, or external-secrets-operator.",
        # OpenAPI / Swagger specifications embed literal example values for
        # every documented field (JoinToken, IdentityToken, ...) and the
        # `description:` schema lines use words like "Secret token" to
        # describe semantic meaning — neither is a real credential.
        # Measured 2026-04-24: moby's `api/docs/v*.yaml` produced 105 of
        # 112 HELM-001 findings as Sonnet-labeled false positives. Same
        # structural pattern applies to `openapi.yaml` / `swagger.yaml`
        # specs at any depth. Scanner-level path exclusion avoids the
        # AI cycle entirely and can't be undone by a prompt edit.
        exclude_path_patterns=[
            "api/docs/*.yaml", "api/docs/*.yml",
            "**/api/docs/*.yaml", "**/api/docs/*.yml",
            "openapi.yaml", "openapi.yml", "**/openapi.yaml", "**/openapi.yml",
            "swagger.yaml", "swagger.yml", "**/swagger.yaml", "**/swagger.yml",
        ],
    ),
]
