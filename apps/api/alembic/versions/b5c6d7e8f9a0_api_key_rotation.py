# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""api_keys: rotation tracking columns

Revision ID: b5c6d7e8f9a0
Revises: a4b5c6d7e8f9
Create Date: 2026-05-24 17:00:00.000000

Why
---
Sprint 2 of the API-key audit follow-up adds a key-rotation flow with
a grace period.  Enterprise customers expect zero-downtime rotation:

    1. operator clicks "Rotate" on a live key
    2. server issues a brand-new key (returned once)
    3. the old key keeps working for ``grace_period_days`` (default 7)
       so CI pipelines have a window to redeploy with the new key
    4. once the grace window passes the old key auto-expires via the
       existing ``expires_at`` check in ``_authenticate_api_key``

Two new columns capture the linkage so the UI + audit log can show
"key X was rotated TO key Y on date Z" and prevent chained rotations
(rotating an already-rotated key would compound grace periods and
create confusing "key X → Y → Z" trails).

Columns
-------
  api_keys.rotated_at      TIMESTAMP WITH TIME ZONE  NULL
      When the rotation happened.  NULL = key has never been rotated.

  api_keys.rotated_to_id   UUID  NULL  FK → api_keys.id
      The successor key issued by the rotation.  Lets the UI render a
      "Rotated → [new key name]" hint on the soon-to-expire row and
      a "Rotated from [old key name]" hint on the fresh row.

  api_keys.rotation_grace_until  TIMESTAMP WITH TIME ZONE  NULL
      Convenience column — equals ``expires_at`` at rotation time and
      is preserved even if the operator later edits ``expires_at`` for
      another reason.  Used by the UI to label the row "Rotated;
      expires in 4 days" rather than the generic "Expires …" line.

Why three columns instead of one JSONB
--------------------------------------
The query "find all keys currently in their rotation grace window"
benefits from an indexed ``rotation_grace_until > NOW()`` predicate.
JSONB extraction would defeat the index.  Three nullable columns
cost less than the indexable read pattern we get in return.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "b5c6d7e8f9a0"
down_revision = "a4b5c6d7e8f9"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "api_keys",
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "api_keys",
        sa.Column(
            "rotated_to_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("api_keys.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "api_keys",
        sa.Column(
            "rotation_grace_until", sa.DateTime(timezone=True), nullable=True
        ),
    )
    # Index the grace-window query — operators reading
    # "GET /api-keys?status=rotating" should not seq-scan.
    op.create_index(
        "ix_api_keys_rotation_grace_until",
        "api_keys",
        ["rotation_grace_until"],
        postgresql_where=sa.text("rotation_grace_until IS NOT NULL"),
    )


def downgrade():
    op.drop_index("ix_api_keys_rotation_grace_until", table_name="api_keys")
    op.drop_column("api_keys", "rotation_grace_until")
    op.drop_column("api_keys", "rotated_to_id")
    op.drop_column("api_keys", "rotated_at")
