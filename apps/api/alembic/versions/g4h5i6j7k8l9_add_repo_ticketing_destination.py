# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add ticketing_integration_id on repositories — per-repo Jira board mapping

Revision ID: g4h5i6j7k8l9
Revises: f3bcd877ef7f
Create Date: 2026-04-27 06:30:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'g4h5i6j7k8l9'
down_revision: Union[str, None] = 'f3bcd877ef7f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add per-repository ticketing destination override.

    Lets dev teams say "findings from this repo file to this Jira
    board" — overrides the integration's scope_level routing.
    Multiple repos can point at the same integration row (the
    `Repo A, C → JIRA A` case from the user's UX request 2026-04-27).

    NULL means "no override" — fall back to scope_level routing
    (organization-wide / business_unit / project-bound boards).
    """
    # Idempotent column add — initial-schema migration may have
    # already created the column from the SQLAlchemy model.
    op.execute("ALTER TABLE repositories ADD COLUMN IF NOT EXISTS ticketing_integration_id UUID")
    op.execute("""
        DO $$ BEGIN
            ALTER TABLE repositories
                ADD CONSTRAINT fk_repositories_ticketing_integration
                FOREIGN KEY (ticketing_integration_id)
                REFERENCES integration_configs (id)
                ON DELETE SET NULL;
        EXCEPTION
            WHEN duplicate_object THEN NULL;
            WHEN duplicate_table THEN NULL;
        END $$;
    """)


def downgrade() -> None:
    op.drop_column('repositories', 'ticketing_integration_id')
