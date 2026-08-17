# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Productivity and project management detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-ASANA-001", title="Asana Access Token", secret_type="asana_token", severity="medium",
        pattern=r'(?:asana[_-]?(?:access[_-]?)?token|ASANA_TOKEN)\s*[=:]\s*["\']?([0-9]/[0-9]{16}/[A-Za-z0-9]{32})["\']?',
        keywords=["asana", "ASANA"], confidence=0.85, description="Asana personal access token.", fix_hint="Revoke at Asana → My Profile Settings → Apps → Manage Developer Apps."),
    SecretRule(rule_id="VOODA-SEC-NOTION-001", title="Notion Integration Token", secret_type="notion_token", severity="medium",
        pattern=r'(?:^|[^A-Za-z0-9])(ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{43})(?:[^A-Za-z0-9]|$)',
        keywords=["ntn_", "notion"], confidence=0.85, description="Notion integration or internal token.", fix_hint="Regenerate at notion.so → Settings → Connections."),
        # VOODA-SEC-AIRTABLE-001 removed 2026-05-22 (Track-A Phase 1, collision audit) —
    # shadow of live rule in trufflehog_port.py; shadow is equivalent regex with looser anchors.
    # Removal restored 1 dead-code rule to the registry's correct
    # state (was silently shadowed by last-wins dedup).
    SecretRule(rule_id="VOODA-SEC-FIGMA-001", title="Figma Personal Access Token", secret_type="figma_token", severity="medium",
        pattern=r'(?:^|[^A-Za-z0-9])(figd_[A-Za-z0-9\-_]{40,})(?:[^A-Za-z0-9]|$)',
        keywords=["figd_"], confidence=0.95, description="Figma personal access token.", fix_hint="Regenerate at figma.com → Settings → Personal access tokens."),
    SecretRule(rule_id="VOODA-SEC-MONDAY-001", title="Monday.com API Token", secret_type="monday_token", severity="medium",
        pattern=r'(?:monday[_-]?(?:api[_-]?)?token|MONDAY_TOKEN)\s*[=:]\s*["\']?(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)["\']?',
        keywords=["monday", "MONDAY"], confidence=0.80, description="Monday.com API token (JWT format).", fix_hint="Regenerate at monday.com → Admin → API."),
]
