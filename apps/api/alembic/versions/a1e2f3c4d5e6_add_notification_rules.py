# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add_notification_rules

Revision ID: a1e2f3c4d5e6
Revises: f3bcd877ef7f
Create Date: 2026-04-04 12:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'a1e2f3c4d5e6'
down_revision: Union[str, None] = 'f3bcd877ef7f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    has_table = 'notification_rules' in inspector.get_table_names()
    if has_table:
        # Initial-schema already created the table; ensure any
        # composite indexes from this migration are also present.
        op.execute("CREATE INDEX IF NOT EXISTS ix_notification_rules_tenant_id ON notification_rules (tenant_id)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_notification_rules_event_type ON notification_rules (event_type)")
        return
    op.create_table(
        'notification_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('severity_threshold', sa.String(30), server_default='all', nullable=True),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'event_type', name='uq_tenant_event_type'),
    )
    op.create_index('ix_notification_rules_tenant_id', 'notification_rules', ['tenant_id'])


def downgrade() -> None:
    op.drop_index('ix_notification_rules_tenant_id', table_name='notification_rules')
    op.drop_table('notification_rules')
