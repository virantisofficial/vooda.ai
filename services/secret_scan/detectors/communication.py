# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Communication platform detectors (Mailgun, Mailchimp, Discord)."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-MAILGUN-001",
        title="Mailgun API Key",
        secret_type="mailgun_api_key",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(key-[a-f0-9]{32})(?:[^A-Za-z0-9]|$)',
        keywords=["key-"],
        confidence=0.85,
        description="Mailgun API key. Can send emails from your domain.",
        fix_hint="Regenerate at Mailgun → Settings → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-MAILCHIMP-002",
        title="Mailchimp API Key",
        secret_type="mailchimp_api_key",
        severity="medium",
        pattern=r'(?:^|[^A-Za-z0-9])([a-f0-9]{32}-us[0-9]{1,2})(?:[^A-Za-z0-9]|$)',
        keywords=["-us"],
        confidence=0.85,
        description="Mailchimp API key with data center suffix.",
        fix_hint="Regenerate at Mailchimp → Account → Extras → API Keys.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-DISCORD-001",
        title="Discord Webhook URL",
        secret_type="discord_webhook",
        severity="medium",
        pattern=r'(https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+)',
        keywords=["discord.com/api/webhooks", "discordapp.com/api/webhooks"],
        confidence=0.95,
        description="Discord webhook URL. Allows posting messages to a channel.",
        fix_hint="Delete the webhook in Discord → Server Settings → Integrations → Webhooks.",
    ),
]
