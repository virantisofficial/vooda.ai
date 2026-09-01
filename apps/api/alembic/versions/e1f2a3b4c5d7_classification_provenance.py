# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""classification_provenance on normalized_findings

Revision ID: e1f2a3b4c5d7
Revises: d0e1f2a3b4c5
Create Date: 2026-09-01 09:00:00.000000

Why
---
``CONFIRMED_*`` asserts that somebody established the verdict, and an
auditor reads it that way. Two paths wrote it without a human: org-wide
learning (removed), and the triage cache, which replays a stored
decision onto a new finding. The replay is worth keeping — re-asking a
person about identical code in the same place is how a queue becomes
unusable — but the new finding claimed a confirmation with nothing on it
pointing back to who made it.

Fix
---
A nullable JSONB column recording mechanism, actor, and the originating
decision or finding. A session-level guard refuses any write of a
``CONFIRMED_*`` value without it.

NULL on existing rows is deliberate. Backfilling would invent an actor
for confirmations whose origin was never recorded — the exact problem
this column exists to prevent. The guard only fires on new writes, so
history stays as it is, honestly unattributed.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "e1f2a3b4c5d7"
down_revision = "d0e1f2a3b4c5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "normalized_findings",
        sa.Column("classification_provenance", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("normalized_findings", "classification_provenance")
