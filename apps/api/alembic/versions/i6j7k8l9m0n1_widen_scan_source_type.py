# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""widen scan_sources.source_type from VARCHAR(20) → VARCHAR(40)

The 2026-04-30 enterprise expansion introduced longer source_type
identifiers (`onedrive_sharepoint`, `container_registry`,
`github_issues`) that don't fit comfortably in 20 chars. Widening
to 40 leaves headroom for future additions without another
migration.

Postgres VARCHAR widening is an in-place metadata-only change —
no table rewrite, no row scan, safe to ship anytime.

Revision ID: i6j7k8l9m0n1
Revises: h5i6j7k8l9m0
Create Date: 2026-04-30 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "i6j7k8l9m0n1"
down_revision: Union[str, None] = "h5i6j7k8l9m0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Idempotency guard added 2026-05-04 audit pass.
    # The initial-schema migration creates `scan_sources.source_type`
    # at width 40 directly from the SQLAlchemy model (which is the
    # current source of truth). Re-running this VARCHAR widening on
    # an already-wide column is a Postgres no-op, but we explicitly
    # check and skip to keep the migration log clean and avoid any
    # risk of `ALTER COLUMN ... TYPE` conflicts on managed Postgres
    # services that surface odd errors on no-op DDL.
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    cols = {c["name"]: c for c in inspector.get_columns("scan_sources")}
    src_col = cols.get("source_type")
    # SQLAlchemy returns the column type as a sa.String/VARCHAR object;
    # `.length` is the configured width. If we can't read it for any
    # reason (custom type, missing column on a partially-migrated
    # DB), fall through to the alter — Postgres will tell us.
    current_len = getattr(getattr(src_col, "type", None), "length", None) if src_col else None
    if current_len is not None and current_len >= 40:
        return  # Already at target width; nothing to do.
    op.alter_column(
        "scan_sources",
        "source_type",
        existing_type=sa.String(length=20),
        type_=sa.String(length=40),
        existing_nullable=False,
    )


def downgrade() -> None:
    # Downgrade truncates if any row already uses a longer name; the
    # `USING` clause asks Postgres to truncate on cast. Don't run
    # this downgrade after enterprise sources have been used.
    op.alter_column(
        "scan_sources",
        "source_type",
        existing_type=sa.String(length=40),
        type_=sa.String(length=20),
        existing_nullable=False,
        postgresql_using="substring(source_type, 1, 20)",
    )
