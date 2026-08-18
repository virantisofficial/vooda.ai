# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add_correlation_and_suppression

Revision ID: bc0423892c95
Revises: a0b1c2d3e4f5
Create Date: 2026-03-28 11:14:02.789900

Idempotency note (2026-05-03):
The initial-schema migration `a0b1c2d3e4f5` now creates every table
defined in the SQLAlchemy models — including `suppression_rules`
and the `normalized_findings` columns this migration originally
added. To avoid double-creation errors when running the chain
forwards on a fresh database, every CREATE/ADD here is now wrapped
in `IF NOT EXISTS` (or a `has_table` / `has_column` check via
op.execute). DROP INDEX statements use `IF EXISTS` to gracefully
skip cleanup of legacy indexes that the initial migration never
created. All down_revision links are preserved so existing
upgrade-history rows in alembic_version still resolve.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'bc0423892c95'
down_revision: Union[str, None] = 'a0b1c2d3e4f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── suppression_rules ──
    # The initial-schema migration already creates this table from
    # the SQLAlchemy model. Use a conditional wrapper so re-running
    # this migration on a partially-migrated database is a no-op
    # rather than an error.
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if 'suppression_rules' not in inspector.get_table_names():
        op.create_table('suppression_rules',
            sa.Column('name', sa.String(length=255), nullable=False),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('suppression_type', sa.String(length=50), nullable=False),
            sa.Column('scanner_rule_id', sa.String(length=255), nullable=True),
            sa.Column('pattern_hash', sa.String(length=64), nullable=True),
            sa.Column('vulnerability_category', sa.String(length=255), nullable=True),
            sa.Column('cwe', sa.String(length=20), nullable=True),
            sa.Column('file_path_pattern', sa.String(length=1024), nullable=True),
            sa.Column('evidence_count', sa.Integer(), nullable=True),
            sa.Column('evidence_repo_count', sa.Integer(), nullable=True),
            sa.Column('evidence_finding_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.Column('confidence', sa.Float(), nullable=True),
            sa.Column('sample_code', sa.Text(), nullable=True),
            sa.Column('is_active', sa.Boolean(), nullable=False),
            sa.Column('created_by', sa.String(length=100), nullable=True),
            sa.Column('times_applied', sa.Integer(), nullable=True),
            sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
            sa.Column('tenant_id', sa.UUID(), nullable=False),
            sa.PrimaryKeyConstraint('id')
        )

    # ── Indexes on suppression_rules ──
    # Plain `op.create_index` raises if the index already exists.
    # Switching to raw SQL with `CREATE INDEX IF NOT EXISTS` keeps
    # the migration idempotent.
    op.execute("CREATE INDEX IF NOT EXISTS ix_suppression_rules_is_active ON suppression_rules (is_active)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_suppression_rules_pattern_hash ON suppression_rules (pattern_hash)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_suppression_rules_scanner_rule_id ON suppression_rules (scanner_rule_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_suppression_rules_tenant_id ON suppression_rules (tenant_id)")

    # ── ai_model_configs index rename ──
    # Original migration assumed `idx_ai_models_tenant` existed (it
    # was created by the manual init-db.sql before Alembic). On a
    # fresh DB that legacy index never existed, so the bare DROP
    # would fail. `IF EXISTS` makes the cleanup a no-op when
    # appropriate.
    op.execute("DROP INDEX IF EXISTS idx_ai_models_tenant")
    op.execute("CREATE INDEX IF NOT EXISTS ix_ai_model_configs_tenant_id ON ai_model_configs (tenant_id)")

    # ── normalized_findings columns ──
    # The initial-schema migration adds these from the model.
    # `ADD COLUMN IF NOT EXISTS` is Postgres-native and idempotent.
    op.execute("ALTER TABLE normalized_findings ADD COLUMN IF NOT EXISTS suppression_reason VARCHAR(255)")
    op.execute("ALTER TABLE normalized_findings ADD COLUMN IF NOT EXISTS correlation_group_id UUID")
    op.execute("ALTER TABLE normalized_findings ADD COLUMN IF NOT EXISTS correlated_finding_ids JSONB")
    op.execute("ALTER TABLE normalized_findings ADD COLUMN IF NOT EXISTS aggregate_confidence DOUBLE PRECISION")
    op.execute("ALTER TABLE normalized_findings ADD COLUMN IF NOT EXISTS is_correlation_primary BOOLEAN")
    op.execute("CREATE INDEX IF NOT EXISTS ix_normalized_findings_correlation_group_id ON normalized_findings (correlation_group_id)")

    # ── role_definitions index rename ──
    # Same pattern as ai_model_configs above — legacy name might
    # not exist on a fresh DB.
    op.execute("DROP INDEX IF EXISTS idx_role_defs_tenant")
    op.execute("CREATE INDEX IF NOT EXISTS ix_role_definitions_tenant_id ON role_definitions (tenant_id)")


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_role_definitions_tenant_id'), table_name='role_definitions')
    op.create_index('idx_role_defs_tenant', 'role_definitions', ['tenant_id'], unique=False)
    op.drop_index(op.f('ix_normalized_findings_correlation_group_id'), table_name='normalized_findings')
    op.drop_column('normalized_findings', 'is_correlation_primary')
    op.drop_column('normalized_findings', 'aggregate_confidence')
    op.drop_column('normalized_findings', 'correlated_finding_ids')
    op.drop_column('normalized_findings', 'correlation_group_id')
    op.drop_column('normalized_findings', 'suppression_reason')
    op.drop_index(op.f('ix_ai_model_configs_tenant_id'), table_name='ai_model_configs')
    op.create_index('idx_ai_models_tenant', 'ai_model_configs', ['tenant_id'], unique=False)
    op.drop_index(op.f('ix_suppression_rules_tenant_id'), table_name='suppression_rules')
    op.drop_index(op.f('ix_suppression_rules_scanner_rule_id'), table_name='suppression_rules')
    op.drop_index(op.f('ix_suppression_rules_pattern_hash'), table_name='suppression_rules')
    op.drop_index(op.f('ix_suppression_rules_is_active'), table_name='suppression_rules')
    op.drop_table('suppression_rules')
    # ### end Alembic commands ###
