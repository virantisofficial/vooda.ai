# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add severity_rank to secret_incidents for atomic escalate-only upsert

Revision ID: d7e8f9a0b1c2
Revises: c6d7e8f9a0b1
Create Date: 2026-05-28 00:00:00.000000

Why
---
Concurrent scans in the same tenant that discover the same credential
both wrote to the shared ``secret_incidents`` aggregate row via an ORM
read-modify-write guarded by ``version_id_col``.  The loser's
version-checked UPDATE matched 0 rows -> StaleDataError -> the whole
scan transaction rolled back (an entire scan's findings lost).  The fix
moves scan ingest to an atomic ``INSERT ... ON CONFLICT DO UPDATE``
(see apps/worker/tasks.py:_upsert_secret_incident).

That upsert needs to merge ``severity_max`` as ESCALATE-ONLY in a
single server-side statement.  A lexical ``GREATEST`` on the string
``severity_max`` is wrong ('high' > 'critical' alphabetically), so we
add a numeric ``severity_rank`` and escalate via
``GREATEST(EXCLUDED.severity_rank, secret_incidents.severity_rank)``.

Backwards-compatibility
-----------------------
Adds one column with a server default of 1, so existing rows backfill
non-NULL at column-add time (Postgres 11+ -> no table rewrite, no long
lock).  We then backfill the real rank from the existing string
``severity_max`` in a single UPDATE.  Nothing FKs the new column.

Downgrade
---------
Drops the helper index and the column.  Safe.
"""
from alembic import op
import sqlalchemy as sa


revision = "d7e8f9a0b1c2"
down_revision = "c6d7e8f9a0b1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # server_default="1" backfills existing rows non-NULL at add time.
    op.add_column(
        "secret_incidents",
        sa.Column(
            "severity_rank",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    # Backfill the numeric rank from the existing string severity.
    op.execute(
        """
        UPDATE secret_incidents SET severity_rank = CASE severity_max
            WHEN 'critical' THEN 5
            WHEN 'high'     THEN 4
            WHEN 'medium'   THEN 3
            WHEN 'low'      THEN 2
            ELSE 1
        END
        """
    )
    # Free win: incident lists sorted by severity desc can use this
    # instead of the lexically-wrong string index on severity_max.
    op.create_index(
        "ix_secret_incidents_tenant_sevrank",
        "secret_incidents",
        ["tenant_id", sa.text("severity_rank DESC")],
    )


def downgrade() -> None:
    op.drop_index("ix_secret_incidents_tenant_sevrank", table_name="secret_incidents")
    op.drop_column("secret_incidents", "severity_rank")
