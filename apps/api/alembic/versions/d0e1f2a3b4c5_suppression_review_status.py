# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""review_status on suppression_rules — proposals vs decided rules

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
Create Date: 2026-08-31 10:00:00.000000

Why
---
The learning engine may now write rules derived from AI triage, which
is a guess rather than a confirmed decision. Those must not suppress
anything until a human approves them, so they are stored inactive.

But ``is_active = false`` already means "an admin muted this rule".
Collapsing "never reviewed" into "deliberately switched off" loses the
distinction the reviewer needs: one is a question waiting for an
answer, the other is an answer. Worse, without a durable record of a
*rejected* proposal, every scan would re-derive the same pattern and
re-propose it forever.

Fix
---
A nullable ``review_status``:

  NULL       — an ordinary rule; nobody proposed it (all existing rows)
  'pending'  — proposed by learning, inert until someone decides
  'approved' — a human accepted the proposal; it is live
  'rejected' — a human declined it; kept so learning does not re-propose

NULL for existing rows is deliberate: a manual rule was never a
proposal, and backfilling them to 'approved' would invent a review
that never happened.
"""
from alembic import op
import sqlalchemy as sa


revision = "d0e1f2a3b4c5"
down_revision = "c9d0e1f2a3b4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "suppression_rules",
        sa.Column("review_status", sa.String(length=20), nullable=True),
    )
    # Proposals are read on every scan to decide what NOT to re-propose,
    # and the review queue filters on it. Partial index: the overwhelming
    # majority of rows are NULL and never matched by those queries.
    op.create_index(
        "ix_suppression_rules_review_status",
        "suppression_rules",
        ["tenant_id", "review_status"],
        postgresql_where=sa.text("review_status IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_suppression_rules_review_status", table_name="suppression_rules")
    op.drop_column("suppression_rules", "review_status")
