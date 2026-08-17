# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Extended cloud provider detectors (Linode, Vultr, Hetzner, OVH, Scaleway, Backblaze, etc.)."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-LINODE-001", title="Linode Personal Access Token", secret_type="linode_token", severity="high",
        pattern=r'(?:linode[_-]?(?:api[_-]?)?token|LINODE_TOKEN)\s*[=:]\s*["\']?([a-f0-9]{64})["\']?',
        keywords=["linode", "LINODE"], confidence=0.80, description="Linode/Akamai cloud API token.", fix_hint="Revoke at Linode Cloud Manager → API Tokens."),
    SecretRule(rule_id="VOODA-SEC-VULTR-001", title="Vultr API Key", secret_type="vultr_api_key", severity="high",
        pattern=r'(?:vultr[_-]?(?:api[_-]?)?key|VULTR_API_KEY)\s*[=:]\s*["\']?([A-Z0-9]{36})["\']?',
        keywords=["vultr", "VULTR"], confidence=0.80, description="Vultr cloud API key.", fix_hint="Regenerate at Vultr → Account → API."),
    SecretRule(rule_id="VOODA-SEC-HETZNER-001", title="Hetzner API Token", secret_type="hetzner_token", severity="high",
        pattern=r'(?:hetzner[_-]?(?:api[_-]?)?token|HETZNER_TOKEN|HCLOUD_TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9]{64})["\']?',
        keywords=["hetzner", "HETZNER", "HCLOUD"], confidence=0.80, description="Hetzner Cloud API token.", fix_hint="Revoke at Hetzner Cloud Console → Security → API Tokens."),
    SecretRule(rule_id="VOODA-SEC-OVH-002", title="OVH API Credentials", secret_type="ovh_credentials", severity="high",
        pattern=r'(?:ovh[_-]?(?:application[_-]?)?(?:key|secret)|OVH_(?:APP_)?(?:KEY|SECRET))\s*[=:]\s*["\']?([A-Za-z0-9]{16,})["\']?',
        keywords=["ovh", "OVH"], confidence=0.70, description="OVH cloud API application key or secret.", fix_hint="Regenerate at OVH API Console."),
    SecretRule(rule_id="VOODA-SEC-SCALEWAY-002", title="Scaleway API Key", secret_type="scaleway_key", severity="high",
        pattern=r'(?:scaleway[_-]?(?:api[_-]?)?(?:key|token)|SCW_(?:SECRET_)?KEY)\s*[=:]\s*["\']?([a-f0-9\-]{36})["\']?',
        keywords=["scaleway", "SCALEWAY", "SCW_"], confidence=0.75, description="Scaleway cloud API key.", fix_hint="Revoke at Scaleway Console → Credentials."),
    SecretRule(rule_id="VOODA-SEC-B2-001", title="Backblaze B2 Application Key", secret_type="backblaze_key", severity="high",
        pattern=r'(?:b2[_-]?(?:application[_-]?)?key|B2_APP(?:LICATION)?_KEY|BACKBLAZE_KEY)\s*[=:]\s*["\']?([A-Za-z0-9]{31})["\']?',
        keywords=["b2_app", "B2_APP", "BACKBLAZE", "backblaze"], confidence=0.80, description="Backblaze B2 application key.", fix_hint="Regenerate at Backblaze → App Keys."),
        # VOODA-SEC-WASABI-001 removed 2026-05-22 (Track-A Phase 1, collision audit) —
    # shadow of live rule in trufflehog_port_v2.py; shadow uses keyword-context; live targets actual key shape (strict subset).
    # Removal restored 1 dead-code rule to the registry's correct
    # state (was silently shadowed by last-wins dedup).
    SecretRule(rule_id="VOODA-SEC-MINIO-001", title="MinIO Credentials", secret_type="minio_credentials", severity="high",
        pattern=r'(?:minio[_-]?(?:secret[_-]?)?key|MINIO_SECRET_KEY|MINIO_ROOT_PASSWORD)\s*[=:]\s*["\']?([A-Za-z0-9+/]{20,})["\']?',
        keywords=["minio", "MINIO"], confidence=0.75, description="MinIO object storage secret key.", fix_hint="Rotate via MinIO admin or environment variables."),
]
