# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add target_repository_id + target_business_unit_id on scan_sources — per-source scope

Revision ID: h5i6j7k8l9m0
Revises: g4h5i6j7k8l9
Create Date: 2026-04-29 06:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'h5i6j7k8l9m0'
down_revision: Union[str, None] = 'g4h5i6j7k8l9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Per-source scope binding for non-git sources.

    Sources (Slack, S3, Confluence, etc.) historically scanned org-
    wide and produced findings with repository_id = NULL. That meant
    source findings bypassed every per-repo feature: the per-repo
    ticketing destination shipped earlier today, BU-scoped access
    grants, repository-aware dashboards, etc.

    These two columns let the user bind a configured Source to a
    specific Repository or Business Unit at create / edit time. The
    worker normalizer reads them when creating findings:
      - target_repository_id set  → finding.repository_id = that repo
      - else target_business_unit_id set → finding.business_unit_id
        is populated via the BU
      - else  → org-wide (NULL on both, current behavior)

    Both nullable + ON DELETE SET NULL — preserves backward compat
    (existing rows are NULL = org-wide, no migration needed) and
    prevents orphaned references when a repo or BU is deleted.

    Bug fix / feature 2026-04-29.
    """
    # Idempotent — initial-schema may have created these from model.
    op.execute("ALTER TABLE scan_sources ADD COLUMN IF NOT EXISTS target_repository_id UUID")
    op.execute("ALTER TABLE scan_sources ADD COLUMN IF NOT EXISTS target_business_unit_id UUID")
    op.execute("""
        DO $$ BEGIN
            ALTER TABLE scan_sources
                ADD CONSTRAINT fk_scan_sources_target_repository
                FOREIGN KEY (target_repository_id)
                REFERENCES repositories (id)
                ON DELETE SET NULL;
        EXCEPTION
            WHEN duplicate_object THEN NULL;
            WHEN duplicate_table THEN NULL;
        END $$;
    """)
    op.execute("""
        DO $$ BEGIN
            ALTER TABLE scan_sources
                ADD CONSTRAINT fk_scan_sources_target_business_unit
                FOREIGN KEY (target_business_unit_id)
                REFERENCES business_units (id)
                ON DELETE SET NULL;
        EXCEPTION
            WHEN duplicate_object THEN NULL;
            WHEN duplicate_table THEN NULL;
        END $$;
    """)


def downgrade() -> None:
    op.drop_column('scan_sources', 'target_business_unit_id')
    op.drop_column('scan_sources', 'target_repository_id')
