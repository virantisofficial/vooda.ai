# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Pydantic schemas for the Rule Overrides API.

Kept in a separate module from suppressions because — despite both
surfaces dealing with "this rule shouldn't produce noise" — they have
distinct shapes:

  - Suppressions match on scanner_rule_id + pattern_hash + file globs
    and apply AFTER a finding has been persisted.
  - Rule overrides match on scanner_rule_id + repository scope only
    and apply BEFORE a finding is persisted.

Mixing the schemas would push every API client into a defensive
union type.  Cleaner to keep them apart.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


# ── Read ─────────────────────────────────────────────────────────────

class RuleOverrideResponse(BaseModel):
    """Wire shape for a single rule override row.

    Scope rules (mirror the model + migration y2z3a4b5c6d7):
      - both repository_id and scan_source_id NULL → org-wide
      - repository_id non-NULL                     → repo-scoped
      - scan_source_id non-NULL                    → source-scoped
      - never both non-NULL (DB CHECK constraint)
    """

    id: UUID
    scanner_rule_id: str
    repository_id: Optional[UUID] = None
    scan_source_id: Optional[UUID] = None
    # Convenience fields populated by the router so the UI doesn't have
    # to do a second lookup to render the row.  At most one of
    # repository_name / source_name is set (mirrors the XOR scope).
    repository_name: Optional[str] = None
    source_name: Optional[str] = None
    # Set when scan_source_id is non-NULL.  Drives an inline pill on the
    # row so admins can tell at a glance whether the override targets a
    # Slack workspace vs Jira project vs Confluence space.
    source_type: Optional[str] = None
    mode: str
    reason: Optional[str] = None
    created_by: Optional[UUID] = None
    # Same convenience pattern — the email / display name of the
    # creating user.  None if the user has since been deleted (FK is
    # ON DELETE SET NULL).
    created_by_email: Optional[str] = None
    is_active: bool
    times_blocked: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Create ───────────────────────────────────────────────────────────

class RuleOverrideCreate(BaseModel):
    """POST body for creating a new rule override.

    Scope is determined by which (if any) target id is set:
      - both NULL                 → org-wide
      - repository_id set         → repo-scoped
      - scan_source_id set        → source-scoped
      - both set                  → 422 (the model_validator below rejects)

    reason is required to keep the audit trail useful; the API also
    rejects whitespace-only strings via the validator."""

    # Field name is ``scanner_rule_id`` (NOT ``rule_id``) — this matches
    # the column on the scanner rule pack and surfaces in the audit
    # log identically to how the scanner reports a rule hit.
    scanner_rule_id: str = Field(
        ..., min_length=1, max_length=255,
        examples=["aws-access-key-id", "stripe-secret-key", "acme-internal-token-v1"],
        description="Built-in or custom rule id. GET /rule-overrides/available-rules for the catalog.",
    )
    repository_id: Optional[UUID] = Field(
        None, examples=["3fa85f64-5717-4562-b3fc-2c963f66afa6"],
        description="Set for repo-scoped override; leave NULL for org-wide.",
    )
    scan_source_id: Optional[UUID] = Field(
        None, description="Set for source-scoped override. Mutually exclusive with repository_id.",
    )
    mode: str = Field(
        default="disabled", max_length=20,
        examples=["disabled", "monitor_only"],
    )
    reason: str = Field(
        ..., min_length=1, max_length=2000,
        examples=["AWS demo credentials in /examples — internal docs only."],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "scanner_rule_id": "aws-access-key-id",
                "mode": "disabled",
                "reason": "AWS demo credentials in /examples; not real keys.",
            }],
        },
    }

    @field_validator("scanner_rule_id")
    @classmethod
    def _strip_rule_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("scanner_rule_id cannot be empty")
        return v

    @field_validator("reason")
    @classmethod
    def _strip_reason(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("reason cannot be empty — explain why the rule is muted")
        return v

    @field_validator("mode")
    @classmethod
    def _validate_mode(cls, v: str) -> str:
        # Today only "disabled" is supported.  Validate here rather than
        # at the DB layer so a future "warn_only" can be added without
        # an outage window.
        allowed = {"disabled"}
        if v not in allowed:
            raise ValueError(f"mode must be one of {sorted(allowed)}; got {v!r}")
        return v

    @model_validator(mode="after")
    def _validate_scope_xor(self) -> "RuleOverrideCreate":
        # Mirrors the DB CHECK constraint ck_rule_overrides_scope_xor.
        # Rejected with a 422 + actionable message rather than letting
        # asyncpg surface the raw integrity error to the client.
        if self.repository_id is not None and self.scan_source_id is not None:
            raise ValueError(
                "Pick a scope: an override can target a repository OR a scan "
                "source, not both.  Leave both unset for an org-wide override."
            )
        return self


# ── Update ───────────────────────────────────────────────────────────

class RuleOverrideUpdate(BaseModel):
    """PATCH body — every field optional so callers can toggle is_active
    without re-sending mode / reason."""

    mode: Optional[str] = Field(default=None, max_length=20)
    reason: Optional[str] = Field(default=None, max_length=2000)
    is_active: Optional[bool] = None

    @field_validator("reason")
    @classmethod
    def _strip_reason(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError("reason cannot be empty")
        return v

    @field_validator("mode")
    @classmethod
    def _validate_mode(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        allowed = {"disabled"}
        if v not in allowed:
            raise ValueError(f"mode must be one of {sorted(allowed)}; got {v!r}")
        return v


# ── Available rules (catalogue) ──────────────────────────────────────

class AvailableRule(BaseModel):
    """One entry in the catalogue of rules that CAN be overridden.

    Returned by GET /rule-overrides/available-rules so the "Add override"
    modal can offer a typeahead picker instead of asking the admin to
    remember the rule id verbatim.

    Sourced from services/secret_scan/detectors/* at API import time —
    see routers/rule_overrides.py:_build_rule_catalogue.
    """

    rule_id: str
    name: str
    category: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None


# ── Stats ────────────────────────────────────────────────────────────

class RuleOverrideStats(BaseModel):
    """GET /rule-overrides/stats — surfaced in the admin tab header."""

    total_active: int
    total_inactive: int
    org_wide_active: int
    repo_scoped_active: int
    # Added with the source-scope expansion (migration y2z3a4b5c6d7).
    # Counts the rows where scan_source_id IS NOT NULL — separate from
    # repo_scoped_active so the admin tab can show three columns at a
    # glance.
    source_scoped_active: int = 0
    total_findings_blocked: int  # SUM(times_blocked) across active rows
