# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add password_history to users

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-08-12 00:00:00.000000

Why
---
Self-service password change must refuse to reuse a recent password
(documented policy: not one of the last 5). That needs somewhere to keep
the prior hashes. This column stores a JSON array of bcrypt hashes,
oldest-first, capped in application code to the last few.

Column
------
  users.password_history  JSONB  NULL

Nullable so the migration is non-breaking — existing rows read as an empty
history until their owner next changes their password.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "b8c9d0e1f2a3"
down_revision = "a7b8c9d0e1f2"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    cols = [c["name"] for c in sa.inspect(conn).get_columns("users")]
    if "password_history" not in cols:
        op.add_column(
            "users",
            sa.Column("password_history", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        )


def downgrade():
    conn = op.get_bind()
    cols = [c["name"] for c in sa.inspect(conn).get_columns("users")]
    if "password_history" in cols:
        op.drop_column("users", "password_history")
