# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add_custom_detectors

Revision ID: c2d3e4f5g6h7
Revises: a1e2f3c4d5e6
Create Date: 2026-04-11 12:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'c2d3e4f5g6h7'
down_revision: Union[str, None] = 'b7d9e1f2a3c4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if 'custom_detectors' in inspector.get_table_names():
        # Initial-schema migration already created the table from
        # the SQLAlchemy model; nothing to do here.
        return
    op.create_table(
        'custom_detectors',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),

        # Rule definition (maps to SecretRule dataclass)
        sa.Column('rule_id', sa.String(255), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('secret_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False, server_default='high'),
        sa.Column('pattern', sa.Text(), nullable=False),
        sa.Column('keywords', postgresql.JSONB(), server_default='[]'),
        sa.Column('confidence', sa.Float(), server_default='0.9'),
        sa.Column('description', sa.Text(), server_default=''),
        sa.Column('fix_hint', sa.Text(), server_default=''),
        sa.Column('cwe', sa.String(20), server_default='CWE-798'),
        sa.Column('multiline', sa.Boolean(), server_default='false'),

        # Management
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('test_cases', postgresql.JSONB(), server_default='[]'),
        sa.Column('match_count', sa.Integer(), server_default='0'),

        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'rule_id', name='uq_custom_detectors_tenant_rule_id'),
    )
    # Idempotent index creates — initial-schema may have created
    # them via the model already.
    op.execute("CREATE INDEX IF NOT EXISTS ix_custom_detectors_tenant_id ON custom_detectors (tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_custom_detectors_is_enabled ON custom_detectors (is_enabled)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_custom_detectors_rule_id ON custom_detectors (rule_id)")


def downgrade() -> None:
    op.drop_index('ix_custom_detectors_rule_id', table_name='custom_detectors')
    op.drop_index('ix_custom_detectors_is_enabled', table_name='custom_detectors')
    op.drop_index('ix_custom_detectors_tenant_id', table_name='custom_detectors')
    op.drop_table('custom_detectors')
