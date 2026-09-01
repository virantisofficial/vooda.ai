# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Rule Override model — proactive muting of a specific scanner rule for a
single repository or org-wide.

This is the *proactive* counterpart to SuppressionRule (which is reactive
post-finding triage).  See the migration x1y2z3a4b5c6_add_rule_overrides
docstring for the audit / lifecycle reasoning behind keeping the two
surfaces separate.

The worker consults rule_overrides BEFORE persisting a NormalizedFinding
(apps/worker/tasks.py): if an active override matches the tenant + the
scanner_rule_id + (repository_id == repo.id OR repository_id IS NULL),
the finding is skipped and times_blocked is incremented.

scanner_rule_id is intentionally a free-form string — Vooda's secret-scan
engine emits values like ``VOODA-SEC-AWS-001``, ``VOODA-SEC-CONFIG-ASSIGN``,
``VOODA-SEC-ENTROPY-{charset}``.  We don't want to hard-code an enum here
because future detector packs will introduce new prefixes.
"""

from sqlalchemy import Column, String, Integer, Boolean, Text, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class RuleOverride(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "rule_overrides"

    # Which detector rule this override applies to.  Format is whatever
    # the secret-scan engine emits — typically VOODA-SEC-XXX-NNN today.
    scanner_rule_id = Column(String(255), nullable=False, index=True)

    # Scope columns — at most ONE may be non-NULL on a given row
    # (enforced by ck_rule_overrides_scope_xor in migration y2z3a4b5c6d7):
    #   - both NULL                        → org-wide   (every scan target)
    #   - repository_id  non-NULL          → repo-scoped
    #   - scan_source_id non-NULL          → source-scoped (Slack workspace,
    #                                        Jira project, Confluence space, …)
    # The XOR shape is deliberate.  A rule muted on a Slack workspace has
    # different audit semantics than a rule muted on a git repo — the
    # admin should pick one explicitly rather than mute "everywhere that
    # happens to be both," which would silently broaden scope.
    repository_id = Column(
        UUID(as_uuid=True),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    scan_source_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scan_sources.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Today only "disabled" is supported (the rule never fires for the
    # scope).  Stored as a string instead of an enum so future modes
    # like "downgrade_severity" or "warn_only" don't need a migration.
    mode = Column(String(20), nullable=False, default="disabled")

    # Free-text justification.  Required by the UI but nullable here so
    # API clients aren't forced to fabricate strings.
    reason = Column(Text, nullable=True)

    # Who created the override.  SET NULL on user delete so the override
    # itself survives audit purges.
    created_by = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Soft-disable instead of hard-delete so re-enabling a rule keeps
    # the audit history visible.
    is_active = Column(Boolean, default=True, nullable=False)

    # Optional snooze-until. NULL = mute until someone turns it off.
    # Enforcement is purely read-side: the worker's loader skips rows
    # whose expiry has passed, so findings resurface at the next scan
    # with no cron and no state flip. The row survives its own expiry
    # for the audit trail, and re-dating it re-arms the mute.
    expires_at = Column(DateTime(timezone=True), nullable=True)

    # Incremented by the worker every time this override short-circuits
    # a would-be finding.  Drives the "doing-work" stat in the admin UI
    # so security engineers can spot rules that ARE silently muted
    # everywhere (i.e. probably worth turning off entirely) and rules
    # that should probably be off but aren't (zero hits over months).
    times_blocked = Column(Integer, default=0, nullable=False)
