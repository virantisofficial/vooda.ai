# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""extend rule_overrides to source-scope (org / repo / source)

Revision ID: y2z3a4b5c6d7
Revises: x1y2z3a4b5c6
Create Date: 2026-05-17 02:00:00.000000

Why
---
The Rule Overrides surface shipped in x1y2z3a4b5c6 supported two
scopes: org-wide (repository_id NULL) and per-repository.  We now
need a third scope: per-scan-source, so admins can mute a noisy
rule on a specific Slack workspace / Jira project / Confluence
space without touching repo behaviour.

Schema change
-------------
1. New nullable FK column:
       scan_source_id  UUID  NULL  REFERENCES scan_sources(id) ON DELETE CASCADE

2. CHECK constraint: a row may scope to a repo OR a source, never
   both at once.  Both NULL = org-wide is still valid.
        CHECK (NOT (repository_id IS NOT NULL AND scan_source_id IS NOT NULL))

3. The old unique index (tenant_id, scanner_rule_id, repository_id,
   is_active) is replaced by THREE PARTIAL unique indexes — one per
   scope — for two reasons:

     a. Postgres treats NULL as distinct in unique indexes, so the
        old shape never actually enforced uniqueness for org-wide
        rows (the application's create endpoint did the dedup check
        in Python).  Tests caught this only because the dedup logic
        in the router worked.  Move enforcement to the DB.

     b. The three scopes have different identity columns:
          - org-wide:    (tenant_id, scanner_rule_id)
          - repo-scoped: (tenant_id, scanner_rule_id, repository_id)
          - src-scoped:  (tenant_id, scanner_rule_id, scan_source_id)
        A single index can't express all three.

   All three partial indexes are scoped to is_active = true so
   soft-disabled history rows can coexist (same pattern as before).

4. New plain index on scan_source_id, mirroring repository_id, to
   make the worker's "fetch all active overrides for this source"
   query cheap.

Downgrade reverses everything: drop the new indexes, drop the
CHECK, drop the column, restore the original 4-column unique index.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "y2z3a4b5c6d7"
down_revision = "x1y2z3a4b5c6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Column
    op.add_column(
        "rule_overrides",
        sa.Column(
            "scan_source_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_sources.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )

    # 2. Mutual-exclusion CHECK
    op.create_check_constraint(
        "ck_rule_overrides_scope_xor",
        "rule_overrides",
        "NOT (repository_id IS NOT NULL AND scan_source_id IS NOT NULL)",
    )

    # 3a. Drop the old unique index (was repo-scoped only effectively).
    op.drop_index("ux_rule_overrides_tenant_rule_scope", table_name="rule_overrides")

    # 3b. Three partial unique indexes — one per scope, scoped to active rows.
    op.create_index(
        "ux_rule_overrides_org_active",
        "rule_overrides",
        ["tenant_id", "scanner_rule_id"],
        unique=True,
        postgresql_where=sa.text(
            "is_active = true AND repository_id IS NULL AND scan_source_id IS NULL"
        ),
    )
    op.create_index(
        "ux_rule_overrides_repo_active",
        "rule_overrides",
        ["tenant_id", "scanner_rule_id", "repository_id"],
        unique=True,
        postgresql_where=sa.text(
            "is_active = true AND repository_id IS NOT NULL"
        ),
    )
    op.create_index(
        "ux_rule_overrides_source_active",
        "rule_overrides",
        ["tenant_id", "scanner_rule_id", "scan_source_id"],
        unique=True,
        postgresql_where=sa.text(
            "is_active = true AND scan_source_id IS NOT NULL"
        ),
    )

    # 4. Plain index for the worker's hot-path lookup.
    op.create_index(
        "ix_rule_overrides_scan_source_id",
        "rule_overrides",
        ["scan_source_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_rule_overrides_scan_source_id", table_name="rule_overrides")
    op.drop_index("ux_rule_overrides_source_active", table_name="rule_overrides")
    op.drop_index("ux_rule_overrides_repo_active", table_name="rule_overrides")
    op.drop_index("ux_rule_overrides_org_active", table_name="rule_overrides")
    # Restore the original (effectively repo-only) unique index.
    op.create_index(
        "ux_rule_overrides_tenant_rule_scope",
        "rule_overrides",
        ["tenant_id", "scanner_rule_id", "repository_id", "is_active"],
        unique=True,
    )
    op.drop_constraint("ck_rule_overrides_scope_xor", "rule_overrides", type_="check")
    op.drop_column("rule_overrides", "scan_source_id")
