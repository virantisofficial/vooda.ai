# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add rule_overrides table for per-repo / org-wide scanner rule muting

Revision ID: x1y2z3a4b5c6
Revises: w0x1y2z3a4b5
Create Date: 2026-05-16 14:00:00.000000

Why
---
A proactive Rule Overrides surface — separate from the existing,
reactive Suppressions surface.  This mirrors how the mature competitors
draw the line:

  - Snyk Code      : "Security Policies" (proactive)  +  "Ignores"   (reactive)
  - GitHub GHAS    : "Custom Patterns"   (proactive)  +  "Alert dismissals"
                                                          (reactive)
  - GitGuardian    : "Exclusion Rules"   (proactive)  +  incident triage
  - Aikido         : "Custom SAST Rules" + .aikido    +  "Muted findings"

The two surfaces stay distinct for three reasons that survived a
careful review pass with the user:

  1. Audit semantics differ.  Suppressions document a decision about a
     finding that already exists ("we looked, it's FP").  Rule overrides
     document an admin's choice to stop a detector from firing in a
     given scope.  Compliance reviewers — and incident-response retros —
     read them differently.

  2. Lifecycle differs.  Suppressions accumulate as findings are triaged
     and live next to the finding.  Rule overrides are admin-managed,
     small in number, and live next to scanner configuration.

  3. Failure mode if conflated.  Mixing them invites a class of bug
     where an admin "suppression" intended as "this rule never fires
     for repo X" silently fails to short-circuit the worker, because
     the worker currently consults SuppressionRule AFTER the finding is
     persisted.  Rule overrides are explicitly a *pre-persist* gate.

Schema
------
  rule_overrides
    id                UUID         PK
    tenant_id         UUID         NOT NULL, indexed
    scanner_rule_id   VARCHAR(255) NOT NULL, indexed
                                   The VOODA-SEC-XXX-NNN identifier emitted
                                   by the secret-scan engine (see
                                   services/secret_scan/engine.py and the
                                   detectors/ package).  Stored as a string
                                   so future detector packs can introduce
                                   new prefixes without a migration.
    repository_id     UUID         NULL, FK -> repositories.id  ON DELETE CASCADE
                                   NULL means org-wide (all repos in the
                                   tenant).  Non-NULL scopes the override
                                   to one repo.
    mode              VARCHAR(20)  NOT NULL, default "disabled"
                                   Today the only supported mode is
                                   "disabled" (the rule never fires).
                                   Reserved for future modes like
                                   "downgrade_severity" or "warn_only" so
                                   we don't paint ourselves into a corner.
    reason            TEXT         NULL
                                   Why the override exists.  Required by
                                   policy but enforced at the UI layer so
                                   API clients aren't forced to fabricate
                                   strings.
    created_by        UUID         NULL, FK -> users.id           ON DELETE SET NULL
                                   The admin who created the override.
                                   SET NULL on user delete so we don't
                                   lose the override itself.
    is_active         BOOLEAN      NOT NULL, default TRUE
                                   Soft-disable instead of hard-delete so
                                   we keep the audit trail when a security
                                   engineer wants to re-enable a rule.
    times_blocked     INTEGER      NOT NULL, default 0
                                   Incremented by the worker every time
                                   the override short-circuits a finding.
                                   Drives the "this override is doing
                                   work" stat in the admin UI.
    created_at        TIMESTAMPTZ  NOT NULL
    updated_at        TIMESTAMPTZ  NOT NULL

Indexes
-------
  - ix_rule_overrides_tenant_id           (TenantMixin convention)
  - ix_rule_overrides_scanner_rule_id     (hot path: worker lookup per finding)
  - ix_rule_overrides_repository_id       (used by per-repo summary card)
  - ux_rule_overrides_tenant_rule_scope   UNIQUE on
        (tenant_id, scanner_rule_id, repository_id, is_active)
    so a tenant can't have two ACTIVE overrides for the same rule + scope.
    Soft-deleted (is_active=FALSE) duplicates are fine and intentional —
    that's how the audit trail survives re-enabling.

The unique constraint includes is_active because two soft-deleted rows
for the same scope are legitimate history, not a constraint violation.

Downgrade drops the whole table.  Safe to run because no other table
holds an FK to rule_overrides.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "x1y2z3a4b5c6"
down_revision = "w0x1y2z3a4b5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rule_overrides",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "tenant_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "scanner_rule_id",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "repository_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("repositories.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "mode",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'disabled'"),
        ),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column(
            "created_by",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "times_blocked",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_rule_overrides_tenant_id",
        "rule_overrides",
        ["tenant_id"],
    )
    op.create_index(
        "ix_rule_overrides_scanner_rule_id",
        "rule_overrides",
        ["scanner_rule_id"],
    )
    op.create_index(
        "ix_rule_overrides_repository_id",
        "rule_overrides",
        ["repository_id"],
    )
    # See module docstring for why is_active participates in the unique key.
    op.create_index(
        "ux_rule_overrides_tenant_rule_scope",
        "rule_overrides",
        ["tenant_id", "scanner_rule_id", "repository_id", "is_active"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ux_rule_overrides_tenant_rule_scope", table_name="rule_overrides")
    op.drop_index("ix_rule_overrides_repository_id", table_name="rule_overrides")
    op.drop_index("ix_rule_overrides_scanner_rule_id", table_name="rule_overrides")
    op.drop_index("ix_rule_overrides_tenant_id", table_name="rule_overrides")
    op.drop_table("rule_overrides")
