# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""record the rule pack a branch checkpoint was scanned with

Revision ID: k7f8a9b0c1d2
Revises: j6e7f8a9b0c1
Create Date: 2026-09-20 12:00:00.000000

An incremental scan examines only the files that changed since the
checkpoint, so a detection rule added or edited afterwards was never
applied to anything else — the new rule silently covered only recent
commits until someone happened to run a full re-scan.

Storing the rule pack fingerprint alongside the watermark lets the scan
notice that the rules have moved and walk every file once, the same way
the file-level cache already invalidates itself on a pack change.

NULL means "unknown" (rows written before this migration, and fresh
installs' first scan). The worker treats NULL as "do not force" so a
deploy does not stampede every repository into a full scan at once;
the next scan writes the current pack and the check is live from then
on.
"""
from alembic import op
import sqlalchemy as sa


revision = "k7f8a9b0c1d2"
down_revision = "j6e7f8a9b0c1"
branch_labels = None
depends_on = None

TABLE = "repo_branch_checkpoints"
COLUMN = "rule_pack_version"


def _has_column(bind) -> bool:
    insp = sa.inspect(bind)
    if not insp.has_table(TABLE):
        return False
    return COLUMN in {c["name"] for c in insp.get_columns(TABLE)}


def upgrade() -> None:
    bind = op.get_bind()
    if not sa.inspect(bind).has_table(TABLE):
        # Table arrives with the initial create_all on a fresh install.
        return
    if _has_column(bind):
        return
    op.add_column(TABLE, sa.Column(COLUMN, sa.String(length=64), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    if _has_column(bind):
        op.drop_column(TABLE, COLUMN)
