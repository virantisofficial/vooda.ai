# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Messaging and real-time communication detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-PUSHER-001", title="Pusher App Secret", secret_type="pusher_secret", severity="high",
        pattern=r'(?:pusher[_-]?(?:app[_-]?)?secret|PUSHER_SECRET|PUSHER_APP_SECRET)\s*[=:]\s*["\']?([a-f0-9]{20})["\']?',
        keywords=["pusher_secret", "PUSHER_SECRET", "PUSHER_APP_SECRET"], confidence=0.80, description="Pusher channels app secret.", fix_hint="Regenerate at Pusher Dashboard → App Keys."),
    SecretRule(rule_id="VOODA-SEC-ABLY-002", title="Ably API Key", secret_type="ably_api_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])([A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{16}:[A-Za-z0-9\-_]{16,})(?:[^A-Za-z0-9]|$)',
        keywords=["ably", "ABLY"], confidence=0.70, description="Ably realtime API key.", fix_hint="Revoke at Ably Dashboard → App → API Keys."),
    SecretRule(rule_id="VOODA-SEC-VONAGE-001", title="Vonage API Secret", secret_type="vonage_secret", severity="high",
        pattern=r'(?:vonage[_-]?(?:api[_-]?)?secret|VONAGE_API_SECRET|NEXMO_API_SECRET)\s*[=:]\s*["\']?([A-Za-z0-9]{16})["\']?',
        keywords=["vonage", "VONAGE", "nexmo", "NEXMO"], confidence=0.80, description="Vonage (Nexmo) API secret.", fix_hint="Regenerate at Vonage Dashboard → Settings."),
    SecretRule(rule_id="VOODA-SEC-BANDWIDTH-001", title="Bandwidth API Credentials", secret_type="bandwidth_credentials", severity="high",
        pattern=r'(?:bandwidth[_-]?(?:api[_-]?)?(?:token|secret)|BANDWIDTH_API_(?:TOKEN|SECRET))\s*[=:]\s*["\']?([A-Za-z0-9\-_]{20,})["\']?',
        keywords=["bandwidth", "BANDWIDTH"], confidence=0.75, description="Bandwidth communications API credentials.", fix_hint="Regenerate at Bandwidth Dashboard → Account."),
    SecretRule(rule_id="VOODA-SEC-MESSAGEBIRD-002", title="MessageBird API Key", secret_type="messagebird_key", severity="high",
        pattern=r'(?:messagebird[_-]?(?:api[_-]?)?key|MESSAGEBIRD_API_KEY)\s*[=:]\s*["\']?([A-Za-z0-9]{25})["\']?',
        keywords=["messagebird", "MESSAGEBIRD"], confidence=0.80, description="MessageBird API key.", fix_hint="Regenerate at MessageBird Dashboard → Developers → API access."),
    SecretRule(rule_id="VOODA-SEC-RESEND-001", title="Resend API Key", secret_type="resend_api_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(re_[A-Za-z0-9]{30,})(?:[^A-Za-z0-9]|$)',
        keywords=["re_"], confidence=0.85, description="Resend email API key.", fix_hint="Regenerate at Resend → API Keys."),
    SecretRule(rule_id="VOODA-SEC-POSTMARK-002", title="Postmark Server Token", secret_type="postmark_token", severity="high",
        pattern=r'(?:postmark[_-]?(?:server[_-]?)?token|POSTMARK_SERVER_TOKEN)\s*[=:]\s*["\']?([a-f0-9\-]{36})["\']?',
        keywords=["postmark", "POSTMARK"], confidence=0.80, description="Postmark transactional email server token.", fix_hint="Regenerate at Postmark → Server → API Tokens."),
]
