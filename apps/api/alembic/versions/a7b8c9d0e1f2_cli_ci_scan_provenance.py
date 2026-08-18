# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""P0 two-way sync: CLI/CI scan_type + provenance columns

Revision ID: a7b8c9d0e1f2
Revises: f9a0b1c2d3e4
Create Date: 2026-05-31

Additive + NON-BREAKING (P0 CLI/CI sync):
  - ALTER TYPE scantype ADD VALUE 'CLI', 'CI' — Vooda's own client-side scans
    synced back via the new import endpoint. Distinct from third-party 'IMPORT'.
    (DB enum stores member NAMES, which are uppercase — hence 'CLI'/'CI'.)
  - Add nullable provenance columns to scan_jobs: commit_sha, branch, actor,
    ci_provider, ci_pipeline_url, idempotency_key. Server-side scans
    (webhook/scheduled/manual) leave them NULL and keep using config JSONB
    exactly as before — nothing in the existing pipeline reads these.
  - Partial-unique index (tenant_id, idempotency_key) WHERE idempotency_key
    IS NOT NULL, so CI retries (same import) collapse to one scan_job and never
    double-create. Partial so the millions of NULL-key server scans are not
    constrained.

No backfill; no change to existing rows, queries, or the scan/dedup pipeline.
"""
from alembic import op
import sqlalchemy as sa


revision = "a7b8c9d0e1f2"
down_revision = "f9a0b1c2d3e4"
branch_labels = None
depends_on = None


def upgrade():
    # PostgreSQL 16 permits ALTER TYPE ... ADD VALUE inside a transaction as
    # long as the new value isn't USED in the same transaction (it isn't here —
    # we only add columns). IF NOT EXISTS makes the migration idempotent/re-runnable.
    op.execute("ALTER TYPE scantype ADD VALUE IF NOT EXISTS 'CLI'")
    op.execute("ALTER TYPE scantype ADD VALUE IF NOT EXISTS 'CI'")

    op.add_column("scan_jobs", sa.Column("commit_sha", sa.String(length=64), nullable=True))
    op.add_column("scan_jobs", sa.Column("branch", sa.String(length=255), nullable=True))
    op.add_column("scan_jobs", sa.Column("actor", sa.String(length=255), nullable=True))
    op.add_column("scan_jobs", sa.Column("ci_provider", sa.String(length=50), nullable=True))
    op.add_column("scan_jobs", sa.Column("ci_pipeline_url", sa.Text(), nullable=True))
    op.add_column("scan_jobs", sa.Column("idempotency_key", sa.String(length=64), nullable=True))

    op.create_index(
        "uq_scan_jobs_tenant_idempotency",
        "scan_jobs",
        ["tenant_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )


def downgrade():
    op.drop_index("uq_scan_jobs_tenant_idempotency", table_name="scan_jobs")
    for col in (
        "idempotency_key",
        "ci_pipeline_url",
        "ci_provider",
        "actor",
        "branch",
        "commit_sha",
    ):
        op.drop_column("scan_jobs", col)
    # NOTE: PostgreSQL cannot DROP a value from an enum type, so 'CLI'/'CI'
    # remain in scantype after downgrade (harmless, unused). Intentional.
