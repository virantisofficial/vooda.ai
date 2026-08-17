# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add_repository_scan_mode

Revision ID: b7d9e1f2a3c4
Revises: a1e2f3c4d5e6
Create Date: 2026-04-04 14:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b7d9e1f2a3c4'
down_revision: Union[str, None] = 'a1e2f3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Idempotent column adds — initial-schema migration may already
    # have created these from the model definition.
    op.execute("ALTER TABLE repositories ADD COLUMN IF NOT EXISTS scan_mode VARCHAR(20) NOT NULL DEFAULT 'vooda'")
    op.execute("ALTER TABLE repositories ADD COLUMN IF NOT EXISTS scanner_integration_id UUID")
    op.execute("ALTER TABLE repositories ADD COLUMN IF NOT EXISTS scanner_project_key VARCHAR(255)")
    # Add the FK constraint only if it isn't already present. Wrap
    # in a DO $$ block so duplicate_object errors don't propagate.
    op.execute("""
        DO $$ BEGIN
            ALTER TABLE repositories
                ADD CONSTRAINT fk_repositories_scanner_integration
                FOREIGN KEY (scanner_integration_id)
                REFERENCES integration_configs (id);
        EXCEPTION
            WHEN duplicate_object THEN NULL;
            WHEN duplicate_table THEN NULL;
        END $$;
    """)


def downgrade() -> None:
    op.drop_column('repositories', 'scanner_project_key')
    op.drop_column('repositories', 'scanner_integration_id')
    op.drop_column('repositories', 'scan_mode')
