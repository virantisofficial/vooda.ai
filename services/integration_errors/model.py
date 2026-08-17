# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Domain model for centralized integration-error handling.

The single :class:`IntegrationError` shape replaces every ad-hoc
``{status: error, message: <free-form string>}`` returned by adapters.
It carries:

  - User-facing presentation (title/summary/fix_steps/doc_anchor)
  - On-demand reference (code/trace_id/occurred_at)
  - Forensic detail (http_status/provider_code/raw/context)

The split is deliberate: the wizard renders only the first two tiers;
the third stays in worker logs and the audit table.  See package
docstring for the design rationale.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ErrorCategory(str, Enum):
    """High-level bucket for dashboards and SIEM aggregation.

    Kept intentionally short — these become Prometheus label values.
    Adding a new category means updating dashboards, so resist the urge.
    """

    AUTHENTICATION = "authentication"   # creds wrong / revoked / expired
    AUTHORIZATION = "authorization"      # creds ok, perms missing
    NETWORK = "network"                  # timeout, dns, tls handshake
    RATE_LIMIT = "rate_limit"            # 429 / quota exhausted
    PROVIDER_FAULT = "provider_fault"    # 5xx on the upstream
    CONFIGURATION = "configuration"      # malformed URL/body, wrong type
    UNKNOWN = "unknown"                  # last-resort bucket


class ErrorSeverity(str, Enum):
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    CRITICAL = "critical"


class IntegrationError(BaseModel):
    """Standardized error shape used by every adapter and surfaced to UI.

    Field order follows the three-tier user model — Layer 1 fields up
    top so a quick read of the class explains what the user sees.
    """

    # ── Layer 1 — always shown to user ─────────────────────────────
    title: str = Field(
        ...,
        max_length=80,
        description="Short headline, ≤ 8 words, plain English. No provider jargon.",
    )
    summary: str = Field(
        ...,
        max_length=400,
        description="≤ 2 sentences, plain English. What happened, in user terms.",
    )
    fix_steps: list[str] = Field(
        default_factory=list,
        description="Up to 3 imperative steps. Each ≤ 120 chars.",
    )
    doc_anchor: Optional[str] = Field(
        default=None,
        description="Path + anchor that lands on the exact docs section, e.g. /docs?section=sources#6.4.5",
    )

    # ── Layer 2 — shown when user clicks "Show details" ────────────
    code: str = Field(
        ...,
        description="Stable machine-readable code, e.g. atlassian.auth.token_revoked",
    )
    trace_id: Optional[str] = Field(
        default=None,
        description="Verbatim provider correlation ID. Copyable for support tickets.",
    )
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # ── Layer 3 — log-only, never rendered to the user ─────────────
    category: ErrorCategory = ErrorCategory.UNKNOWN
    severity: ErrorSeverity = ErrorSeverity.ERROR
    http_status: Optional[int] = None
    provider_code: Optional[str] = None
    retry_after_s: Optional[int] = Field(
        default=None,
        description="Only set on rate-limit errors — seconds the caller should back off.",
    )
    raw: Optional[dict[str, Any]] = Field(
        default=None,
        description=(
            "Verbatim provider response (headers + redacted body). NEVER rendered in "
            "the UI — surfaced to logs / SIEM only via to_log_dict()."
        ),
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Caller-supplied: scan_source_id, user_id, tenant_id, etc.",
    )

    # ── Serializers ────────────────────────────────────────────────

    def to_user_dict(self) -> dict[str, Any]:
        """Return the JSON shape the API exposes to clients.

        Layer 1 fields are top-level (the wizard renders them by default).
        Layer 2 fields land under ``details`` (the wizard reveals them
        when the user clicks "Show details").  Layer 3 fields are
        omitted — they never travel over the API.

        Backward compatibility note: also emits the legacy
        ``{status, message}`` keys so any pre-existing client code
        that reads ``response.message`` keeps working.  New clients
        should switch to the structured shape.
        """
        return {
            # Legacy shape — keep populated until every client migrates
            "status": "error",
            "message": self.summary,

            # Layer 1
            "title": self.title,
            "summary": self.summary,
            "fix_steps": list(self.fix_steps),
            "doc_anchor": self.doc_anchor,

            # Layer 2
            "details": {
                "code": self.code,
                "trace_id": self.trace_id,
                "occurred_at": self.occurred_at.isoformat(),
            },
        }

    def to_log_dict(self) -> dict[str, Any]:
        """Full forensic shape for worker logs / audit log / SIEM.

        Includes Layer 3 (raw provider response, http_status, context).
        Caller is responsible for not piping this into a user-facing
        surface.
        """
        return {
            "code": self.code,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "summary": self.summary,
            "fix_steps": list(self.fix_steps),
            "http_status": self.http_status,
            "provider_code": self.provider_code,
            "trace_id": self.trace_id,
            "retry_after_s": self.retry_after_s,
            "doc_anchor": self.doc_anchor,
            "raw": self.raw,
            "context": dict(self.context),
            "occurred_at": self.occurred_at.isoformat(),
        }

    def to_short_log_string(self) -> str:
        """One-line representation suitable for ``last_scan_error`` storage.

        Format: ``<code>: <summary>`` — keeps the code grep-able while
        still being readable.  Truncated to 200 chars to fit the
        existing JSONB column constraint without further work.
        """
        s = f"{self.code}: {self.summary}"
        return s[:200]


class IntegrationFailure(Exception):
    """Raised by adapter helpers to propagate a classified error.

    Carries an :class:`IntegrationError` so the caller doesn't have to
    repeat the classification.  Adapters write::

        raise IntegrationFailure(classify_atlassian(response, ctx))

    and the worker / API layer catches the exception and converts to
    the appropriate response (UI dict, log dict, etc.) at the boundary.
    """

    def __init__(self, error: IntegrationError):
        super().__init__(error.summary)
        self.error = error
