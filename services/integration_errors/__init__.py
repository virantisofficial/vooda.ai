# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Centralized integration-error model and classifier registry.

Why this package exists
-----------------------
Before 2026-05-09, every integration adapter (Slack, Confluence, Microsoft
Graph, S3, GitHub, …) handled connection errors in its own way.  Some
returned a verbatim provider string (`"missing_scope"`), others wrapped
an HTTP code (`"Confluence returned 401"`), and one (Microsoft Teams,
after today's fix) returned a multi-paragraph guidance block.  Three
consequences:

  - Inconsistent UX — the wizard couldn't tell auth failures apart from
    permission failures because both arrived as anonymous strings.
  - Inconsistent observability — SIEM rules and Prometheus counters
    couldn't aggregate by error class because the strings differed by
    provider.
  - Inconsistent engineering — every new adapter reinvented error
    handling from scratch.

This package fixes that by giving every adapter ONE error model
(:class:`IntegrationError`) and ONE classifier per provider that maps a
raw upstream response into that model.

Two-layer presentation, modeled after Azure Portal / Google Cloud
Console / Stripe Dashboard:

  Layer 1 (always shown to user):
    title        — ≤8 words, plain English
    summary      — ≤2 sentences, plain English
    fix_steps    — ≤3 imperative steps
    doc_anchor   — link to the exact docs section

  Layer 2 (shown on user demand — "Show details"):
    code         — stable, machine-readable (e.g. atlassian.auth.token_revoked)
    trace_id     — verbatim provider correlation ID, copyable for support
    occurred_at  — ISO timestamp

  Layer 3 (logs only, NEVER rendered in UI):
    http_status, provider_code, raw, context
    — full forensic detail; routed to worker logs and SIEM

Public exports kept minimal — most callers only need IntegrationError
and the per-provider ``classify_*`` helpers.
"""

from .model import (
    IntegrationError,
    IntegrationFailure,
    ErrorCategory,
    ErrorSeverity,
)
from .redact import redact_secrets

__all__ = [
    "IntegrationError",
    "IntegrationFailure",
    "ErrorCategory",
    "ErrorSeverity",
    "redact_secrets",
]
