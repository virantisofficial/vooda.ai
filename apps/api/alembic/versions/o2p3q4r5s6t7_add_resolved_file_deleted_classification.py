# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add RESOLVED_FILE_DELETED classification value

Revision ID: o2p3q4r5s6t7
Revises: n1o2p3q4r5s6
Create Date: 2026-05-06 04:00:00.000000

Why
---
Incremental scans (``scan_diff(base, head)``) walk only files that
were Added/Copied/Modified/Renamed in the diff
(``--diff-filter=ACMR``). Deleted files are intentionally excluded —
the engine has nothing to scan in a file that no longer exists.

But the existing ``NormalizedFinding`` rows for that path stay in the
DB forever. From the user's POV, a high-severity finding silently
lingers in the dashboard long after the secret-bearing file was
deleted. Worse, MTTR / SLA metrics keep counting the finding as
"open" because no automated path closes it.

Fix
---
After every incremental scan, the worker enumerates the diff's
deleted entries (``--diff-filter=D``) and marks every finding whose
``file_path`` matches as ``RESOLVED_FILE_DELETED``. Audit trail
(``last_seen_at``, ``resolved_at`` etc.) is preserved; the row stays
in the DB for compliance, but it's filtered out of the default
"active findings" views.

This migration adds the new enum value. ``ALTER TYPE ... ADD VALUE``
runs in an autocommit block (Postgres 11–15 reject it inside a txn)
and is idempotent via ``IF NOT EXISTS``.

Both case variants are added so legacy callers that bind the
lowercase form (e.g. raw SQL inserts from a future migration) don't
break.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "o2p3q4r5s6t7"
down_revision: Union[str, None] = "n1o2p3q4r5s6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        # Uppercase — the form SQLAlchemy persists today.
        op.execute(
            "ALTER TYPE classification ADD VALUE IF NOT EXISTS 'RESOLVED_FILE_DELETED'"
        )
        # Lowercase — defensive belt + braces for legacy raw-SQL paths.
        op.execute(
            "ALTER TYPE classification ADD VALUE IF NOT EXISTS 'resolved_file_deleted'"
        )


def downgrade() -> None:
    """No-op (Postgres can't DROP VALUE without recreating the type).

    Same rationale as ``k8l9m0n1o2p3``: enum values are additive in
    Postgres, and dropping one would require a destructive table
    rewrite. Leave the values in place; future code paths that don't
    reference them are unaffected.
    """
    pass
