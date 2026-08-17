# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Slack secret detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-SLACK-001",
        title="Slack Bot Token",
        secret_type="slack_bot_token",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,})(?:[^A-Za-z0-9]|$)',
        keywords=["xoxb-"],
        confidence=0.98,
        description="Slack bot token. Can read/send messages, access channels and user info.",
        fix_hint="Regenerate at Slack API → Your Apps → OAuth & Permissions.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-SLACK-002",
        title="Slack User Token",
        secret_type="slack_user_token",
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32})(?:[^A-Za-z0-9]|$)',
        keywords=["xoxp-"],
        confidence=0.98,
        description="Slack user token. Acts on behalf of a user with their full permissions.",
        fix_hint="Revoke at Slack → Your Apps → OAuth & Permissions. Rotate immediately.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-SLACK-003",
        title="Slack Webhook URL",
        secret_type="slack_webhook",
        severity="medium",
        pattern=r'(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,})',
        keywords=["hooks.slack.com/services"],
        confidence=0.98,
        description="Slack incoming webhook URL. Allows posting messages to a channel.",
        fix_hint="Regenerate webhook in Slack → Your Apps → Incoming Webhooks.",
    ),
]
