# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""repo_branch_checkpoints: per-branch incremental scan watermarks

Revision ID: p3q4r5s6t7u8
Revises: o2p3q4r5s6t7
Create Date: 2026-05-06 04:30:00.000000

Why
---
``repositories.last_scanned_commit`` is a single SHA per repo. That
breaks for any team that scans more than one branch:

  Engineer A scans ``main``    → checkpoint = abc123
  Engineer B scans ``feature`` → checkpoint = def456 (overwrites abc!)
  Engineer A re-scans ``main`` → diff = def456..main_HEAD (CROSS-BRANCH)

The diff in the third step crosses branches: it walks every file
that differs between feature/HEAD and main/HEAD, which is a much
larger and semantically wrong set. The user gets findings from files
the feature branch added that were never on main.

Fix
---
Track the checkpoint per ``(repository_id, branch)`` in a dedicated
table. The worker resolves the branch at scan start
(``job.config["branch"]`` from webhooks, ``repo.default_branch`` for
manual scans), reads the row for that pair, and writes the new HEAD
back to that same pair on success.

The legacy ``repositories.last_scanned_commit`` column is left in
place — populated alongside the new table for backwards compat with
any tool that reads it directly. A future migration can drop it once
we're confident nothing depends on it.

Schema notes
------------
- ``UNIQUE(repository_id, branch)`` enforces one checkpoint per
  branch pair. Upserts via ``ON CONFLICT``.
- ``branch`` is TEXT not VARCHAR(N) because branch names can be
  arbitrary git refs (no real upper bound — the spec allows up to
  the OS path limit). 1024 is generous; the index is fine for that
  width because it sits behind the (repository_id, branch) PK.
- No FK on ``repository_id`` — same pattern as ``file_scan_cache``.
  We clean up explicitly in the repo-delete handler so the row count
  stays bounded by tenant size.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "p3q4r5s6t7u8"
down_revision: Union[str, None] = "o2p3q4r5s6t7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS repo_branch_checkpoints (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            repository_id UUID NOT NULL,
            branch VARCHAR(1024) NOT NULL,
            last_scanned_commit VARCHAR(40) NOT NULL,
            last_scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_repo_branch_checkpoint
                UNIQUE (repository_id, branch)
        )
        """
    )
    # Repo-scoped lookup is the dominant access pattern (worker reads
    # the row at scan start). Tenant-scoped queries (admin dashboards
    # listing all checkpoints across a tenant) are rare enough that
    # the standard tenant_id column index suffices.
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_repo_branch_checkpoints_repo "
        "ON repo_branch_checkpoints (repository_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_repo_branch_checkpoints_tenant "
        "ON repo_branch_checkpoints (tenant_id)"
    )

    # Backfill the new table from the legacy single-checkpoint column
    # so the first scan after this migration deploys still benefits
    # from the existing watermark. Any repo whose ``last_scanned_commit``
    # is NULL is skipped — it would have been a full scan anyway.
    op.execute(
        """
        INSERT INTO repo_branch_checkpoints (
            tenant_id, repository_id, branch, last_scanned_commit, last_scanned_at
        )
        SELECT
            tenant_id,
            id,
            COALESCE(default_branch, 'main'),
            last_scanned_commit,
            now()
          FROM repositories
         WHERE last_scanned_commit IS NOT NULL
        ON CONFLICT (repository_id, branch) DO NOTHING
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_repo_branch_checkpoints_tenant")
    op.execute("DROP INDEX IF EXISTS ix_repo_branch_checkpoints_repo")
    op.execute("DROP TABLE IF EXISTS repo_branch_checkpoints")
