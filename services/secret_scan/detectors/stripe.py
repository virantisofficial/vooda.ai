# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Stripe secret detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-STRIPE-001",
        title="Stripe Secret Key (Live)",
        secret_type="stripe_secret_key",
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(sk_live_[A-Za-z0-9]{24,})(?:[^A-Za-z0-9]|$)',
        keywords=["sk_live_"],
        confidence=0.98,
        description="Stripe live secret key. Grants full access to payment operations.",
        fix_hint="Roll key at Stripe Dashboard → Developers → API keys. Use restricted keys with limited permissions.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-STRIPE-002",
        title="Stripe Publishable Key (Live)",
        secret_type="stripe_publishable_key",
        severity="medium",
        pattern=r'(?:^|[^A-Za-z0-9])(pk_live_[A-Za-z0-9]{24,})(?:[^A-Za-z0-9]|$)',
        keywords=["pk_live_"],
        confidence=0.95,
        description="Stripe live publishable key. Lower risk but should not be in server-side code.",
        fix_hint="Use environment variables. Publishable keys are meant for client-side only.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-STRIPE-003",
        title="Stripe Webhook Signing Secret",
        secret_type="stripe_webhook_secret",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(whsec_[A-Za-z0-9]{24,})(?:[^A-Za-z0-9]|$)',
        keywords=["whsec_"],
        confidence=0.98,
        description="Stripe webhook signing secret used to verify webhook payloads.",
        fix_hint="Regenerate in Stripe Dashboard → Developers → Webhooks. Store as environment variable.",
    ),
]
