# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""repositories: add last_scanned_commit for incremental scans

Revision ID: m0n1o2p3q4r5
Revises: l9m0n1o2p3q4
Create Date: 2026-05-05 09:00:00.000000

Why
---
Manual / scheduled scans previously re-walked the entire repository
filesystem every time (`scanner.scan_directory(repo_path)` in
`apps/worker/tasks.py:_run_scan_job`). The webhook scan path already
supports incremental scans via `scan_diff(repo_path, base_sha,
head_sha)` — it just needs a per-repository checkpoint to know what
the previous scan covered.

This migration adds:
  - ``repositories.last_scanned_commit`` (VARCHAR(40), nullable):
    SHA of the commit at which the most recent successful scan
    finished. NULL on freshly-imported repos so the first scan always
    runs as a full scan.

The worker reads this column at the start of each scan and routes
through the existing `scan_diff` engine path when:
  - the repo is git-backed (has a URL),
  - last_scanned_commit is set and resolvable in the cloned repo,
  - the scan_type is "standalone" (HEAD scan),
  - the scan was not triggered with ``config.force_full == true``.

After a successful scan the worker writes the new HEAD SHA back to
this column, so the next scan only walks the diff.

Schema change is metadata-only (no row rewrite, no scan). Safe on a
live database. Idempotent via ``ADD COLUMN IF NOT EXISTS``.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "m0n1o2p3q4r5"
down_revision: Union[str, None] = "l9m0n1o2p3q4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE repositories "
        "ADD COLUMN IF NOT EXISTS last_scanned_commit VARCHAR(40)"
    )
    # Partial index: only repos that have been scanned at least once
    # ever read this column. Keeps the index small on tenants with
    # thousands of newly-imported, never-scanned repos.
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_repositories_last_scanned_commit "
        "ON repositories (last_scanned_commit) "
        "WHERE last_scanned_commit IS NOT NULL"
    )


def downgrade() -> None:
    op.execute(
        "DROP INDEX IF EXISTS ix_repositories_last_scanned_commit"
    )
    op.execute(
        "ALTER TABLE repositories "
        "DROP COLUMN IF EXISTS last_scanned_commit"
    )
