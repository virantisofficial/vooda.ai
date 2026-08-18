# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""scan_jobs.heartbeat_at — liveness column for the stall-based watchdog

Revision ID: f9a0b1c2d3e4
Revises: e8f9a0b1c2d3
Create Date: 2026-05-30 11:10:00.000000

Why
---
Sprint G-2.  The stale-scan watchdog previously keyed off
``scan_jobs.created_at`` (total AGE), which force-failed legitimately
long large-repo scans — a regression (aws-cdk ran ~15.4 min and was
killed mid-AI-triage by the 15-min age threshold).  Real scan time is
unbounded by design (repo size, history depth, finding count), so no
fixed AGE cap can distinguish "deadlocked" from "slow but progressing".

This column lets the worker emit a liveness heartbeat at every progress
point (each phase transition, each storing chunk-commit, each AI-triage
batch).  The watchdog then reaps a scan only when
``COALESCE(heartbeat_at, created_at)`` has been stale for
STALE_SCAN_THRESHOLD_MINUTES (default 15m) — i.e. it measures *lack of
progress*, not *age* — with a separate multi-hour absolute backstop on
created_at for the pathological heartbeating-but-wedged case.

Column notes
------------
  heartbeat_at : nullable timestamptz.  NULL until the first heartbeat
                 and for rows created before this column existed; the
                 watchdog's COALESCE falls back to created_at in that
                 case, so old/unstamped rows keep the previous (now
                 4h-backstop) semantics rather than being treated as
                 instantly stale.

Deliberately UN-indexed: written very frequently (once per chunk/phase)
and only ever read inside the tiny ``status IN (pending,running,
analyzing)`` candidate set the watchdog already filters to, so an index
would be pure write overhead with no read benefit.

Additive nullable column with no default => Postgres applies it as a
metadata-only change (no full-table rewrite, no long lock), safe on a
large scan_jobs table.
"""
from alembic import op
import sqlalchemy as sa


revision = "f9a0b1c2d3e4"
down_revision = "e8f9a0b1c2d3"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "scan_jobs",
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade():
    op.drop_column("scan_jobs", "heartbeat_at")
