# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""sources: weekly full-sync sweep + RESOLVED_ITEM_DELETED tombstones

Revision ID: q4r5s6t7u8v9
Revises: p3q4r5s6t7u8
Create Date: 2026-05-07 09:00:00.000000

Why
---
Source-scan adapters (Slack, Jira, Confluence, S3, …) currently run
incrementally via per-source ``sync_state`` watermarks. That covers
the fast path well, but it has 3 production-grade gaps:

  1. **Watermark drift** — if an adapter writes back a malformed cursor
     or the upstream API format changes, future polls return 0 items
     forever and nobody notices.
  2. **Deletion blindness** — a deleted Slack message / closed Jira
     issue keeps its finding open forever; no event surfaces the
     deletion to the polling consumer.
  3. **First-scan recovery** — a partial first scan (rate-limited
     halfway through) advances the watermark; subsequent scans only
     see "after that broken point" and the unscanned tail is silently
     skipped.

Industry pattern (GitGuardian / Nightfall / Cyera): a periodic
**full-sync sweep** (typically weekly) that ignores the watermark and
re-walks the entire source. Items present in the DB but not seen in
the sweep are tombstoned; the watermark is then re-anchored at the
sweep's HEAD timestamp. This catches all 3 gaps with one mechanism.

This migration adds:
  - ``Classification.RESOLVED_ITEM_DELETED`` — applied by the sweep
    when an item that previously yielded a finding is no longer
    returned by the source. Distinct from ``RESOLVED_FILE_DELETED``
    (repo-side) so dashboards / SLA reporting can tell apart "git
    file removed in a commit" from "Slack message deleted by user".
  - ``scan_sources.last_full_sweep_at`` — when the source last had a
    full sweep run. The weekly Beat task uses this to find sources
    overdue for a sweep (NULL or older than 7 days).

The weekly Beat task itself, the worker logic, and the
``force_full`` dispatch wiring all land in code (no schema change
needed for those).
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "q4r5s6t7u8v9"
down_revision: Union[str, None] = "p3q4r5s6t7u8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1) Add the new Classification enum value. ``ALTER TYPE ... ADD
    # VALUE`` runs in an autocommit block (Postgres 11-15 reject it
    # inside a txn) and is idempotent via ``IF NOT EXISTS``. Both case
    # variants added — same belt-and-braces pattern as prior enum
    # migrations (k8l9m0n1o2p3, o2p3q4r5s6t7).
    with op.get_context().autocommit_block():
        op.execute(
            "ALTER TYPE classification ADD VALUE IF NOT EXISTS 'RESOLVED_ITEM_DELETED'"
        )
        op.execute(
            "ALTER TYPE classification ADD VALUE IF NOT EXISTS 'resolved_item_deleted'"
        )

    # 2) Track when the source last had a full sweep run.
    # NULL on existing rows → sweep treats them as overdue and runs
    # the first sweep on the next Beat tick. Defensive on cold start.
    op.execute(
        "ALTER TABLE scan_sources "
        "ADD COLUMN IF NOT EXISTS last_full_sweep_at TIMESTAMPTZ"
    )

    # Partial index — only sources that have HAD a sweep need to be
    # filtered by it (the cold-start NULLs are rare and short-lived).
    # Saves index size on tenants with thousands of sources.
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_scan_sources_last_full_sweep "
        "ON scan_sources (last_full_sweep_at) "
        "WHERE last_full_sweep_at IS NOT NULL"
    )


def downgrade() -> None:
    """Drop the new column + index. Enum value cannot be removed (Postgres
    has no DROP VALUE) — same rationale as o2p3q4r5s6t7's downgrade."""
    op.execute("DROP INDEX IF EXISTS ix_scan_sources_last_full_sweep")
    op.execute(
        "ALTER TABLE scan_sources "
        "DROP COLUMN IF EXISTS last_full_sweep_at"
    )
