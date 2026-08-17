# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""scan_phase_events — append-only per-phase scan timeline

Revision ID: e8f9a0b1c2d3
Revises: d7e8f9a0b1c2
Create Date: 2026-05-28 09:00:00.000000

Why
---
Sprint S / WS-1.  Persists one row per scan phase transition so the
live progress drawer's "Recent Activity" timeline can be seeded from
the backend (survives refresh / drawer-reopen / scan completion)
instead of being rebuilt client-side from only the messages that
arrived since the drawer opened.

The table is append-only by contract and is deliberately EXCLUDED from
the audit retention sweeper (see routers/audit.py) — it's operational
telemetry, not a compliance audit log, and operators reviewing a
months-old failed scan still want its phase history.

Column notes
------------
  total_steps : canonical phase denominator written once per scan, so
                the UI never shows the [6/7]-then-[7/8] drift observed
                in production.
  phase_label : redacted before insert (WS-6) — never contains a secret.
  status      : mirror of the scan's status at the moment of the event.

Index on (scan_job_id, created_at) drives the ordered timeline read.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "e8f9a0b1c2d3"
down_revision = "d7e8f9a0b1c2"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scan_phase_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("step", sa.Integer(), nullable=False),
        sa.Column("total_steps", sa.Integer(), nullable=False),
        sa.Column("phase_label", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("progress_pct", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("stats_snapshot", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index(
        "ix_scan_phase_events_job_created",
        "scan_phase_events",
        ["scan_job_id", "created_at"],
    )


def downgrade():
    op.drop_index("ix_scan_phase_events_job_created", table_name="scan_phase_events")
    op.drop_table("scan_phase_events")
