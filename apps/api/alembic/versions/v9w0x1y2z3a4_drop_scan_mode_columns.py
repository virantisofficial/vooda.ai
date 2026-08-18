# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""drop scan_mode + scanner_integration_id + scanner_project_key from repositories

Revision ID: v9w0x1y2z3a4
Revises: u8v9w0x1y2z3
Create Date: 2026-05-16 13:00:00.000000

Why
---
The defect-import surface was removed in commit 3fac398.  This
migration finishes the job at the schema level — the three columns
that backed it on the `repositories` table now have zero readers and
zero writers, but the original `scan_mode` column was declared
``NOT NULL`` with a Python-side default of ``'vooda'``.  Because the
SQLAlchemy model no longer maps that column, INSERTs from
``create_repository()`` don't supply a value and Postgres rejects
them with ``NotNullViolationError`` (caught during smoke-testing —
adding a new repo via /api/v1/repositories was returning HTTP 500).

Three options were on the table:

  1. Re-introduce a server-side DEFAULT on the column.  Keeps the
     orphan column.  Half-measure.
  2. Re-map the column on the SQLAlchemy side.  Conflicts with the
     "remove completely" direction the user asked for.
  3. Drop the columns.  Removes the schema/code mismatch entirely,
     completes the deletion.

Going with (3).  Any existing repository rows that had
``scan_mode='import'`` become regular Vooda repos at the schema level
— there's no code path that distinguishes them anymore anyway, so the
column carried no useful information after the previous commit.

Columns dropped
---------------
  - repositories.scan_mode                  VARCHAR(20)  NOT NULL  DEFAULT 'vooda'
  - repositories.scanner_integration_id     UUID         FK→integration_configs.id
  - repositories.scanner_project_key        VARCHAR(255) NULL

The FK constraint on scanner_integration_id is named by Postgres
convention; ``op.drop_column`` drops the column and any constraints
attached to it.

The downgrade re-creates the columns with their original definitions
but does not restore data — there is no source of truth for what value
each row should hold (the orphan rows would have arbitrarily landed in
'import' or 'vooda' anyway).  ``scan_mode`` is recreated with the
original ``NOT NULL DEFAULT 'vooda'`` server-default so existing rows
backfill cleanly.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision = "v9w0x1y2z3a4"
down_revision = "u8v9w0x1y2z3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("repositories", "scanner_project_key")
    op.drop_column("repositories", "scanner_integration_id")
    op.drop_column("repositories", "scan_mode")


def downgrade() -> None:
    op.add_column(
        "repositories",
        sa.Column(
            "scan_mode",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'vooda'"),
        ),
    )
    op.add_column(
        "repositories",
        sa.Column(
            "scanner_integration_id",
            UUID(as_uuid=True),
            sa.ForeignKey("integration_configs.id"),
            nullable=True,
        ),
    )
    op.add_column(
        "repositories",
        sa.Column(
            "scanner_project_key",
            sa.String(length=255),
            nullable=True,
        ),
    )
