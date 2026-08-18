# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""perf indexes — apply add_indexes.sql via CREATE INDEX CONCURRENTLY

Revision ID: j7k8l9m0n1o2
Revises: 7a9c4e2b1d8f, i6j7k8l9m0n1
Create Date: 2026-05-03 14:30:00.000000

Why this migration exists
-------------------------
``infra/scripts/add_indexes.sql`` previously had to be applied
manually after deployment because:

  1. CREATE INDEX CONCURRENTLY cannot run inside a transaction —
     Alembic's online mode wraps every migration in a txn by default.
  2. Re-running the .sql file via psql works but isn't tracked in
     ``alembic_version``, so deployments couldn't tell whether the
     indexes were already in place.

This migration solves both:
  - Wraps each CONCURRENT statement in
    ``op.get_context().autocommit_block()`` which exits the
    surrounding txn so CONCURRENTLY is legal.
  - Lives in the alembic version chain so ``alembic upgrade heads``
    automatically applies it on every deploy. Idempotent thanks to
    ``IF NOT EXISTS``.

Also acts as the merge point for the two existing heads
(``7a9c4e2b1d8f`` from rotation events + ``i6j7k8l9m0n1`` from the
scan_sources widening), so post-deploy there's exactly ONE head.

CONCURRENT indexes don't lock the table for writes — safe to apply
to a live production database.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "j7k8l9m0n1o2"
down_revision: Union[str, Sequence[str], None] = ("7a9c4e2b1d8f", "i6j7k8l9m0n1")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Index DDL pulled from infra/scripts/add_indexes.sql. Keep the two
# in sync — the SQL file remains as a manual-recovery tool that ops
# can run against a database without going through Alembic.
_INDEX_STATEMENTS: list[str] = [
    # Composite index for finding list queries (most common query)
    """CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_severity_class
       ON normalized_findings (tenant_id, severity, classification)
       WHERE is_suppressed = false""",

    # Composite for repo-scoped finding queries
    """CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_repo_created
       ON normalized_findings (repository_id, created_at DESC)
       WHERE is_suppressed = false""",

    # Composite for scan job finding queries
    """CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_scan_job
       ON normalized_findings (scan_job_id, severity)""",

    # Index for correlation group lookups
    """CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_correlation
       ON normalized_findings (correlation_group_id)
       WHERE correlation_group_id IS NOT NULL""",

    # Index for finding decisions (calibration queries)
    """CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_decisions_finding_action
       ON finding_decisions (finding_id, action)""",

    # Index for audit events
    """CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_tenant_created
       ON audit_events (tenant_id, created_at DESC)""",

    # Index for scan jobs by repo
    """CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scans_repo_created
       ON scan_jobs (repository_id, created_at DESC)""",

    # Index for suppression rules
    """CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_suppressions_rule_pattern
       ON suppression_rules (scanner_rule_id, pattern_hash)
       WHERE is_active = true""",
]


def upgrade() -> None:
    # autocommit_block() exits the surrounding Alembic transaction so
    # each CONCURRENT statement runs in its own implicit txn — the
    # only way Postgres allows CREATE INDEX CONCURRENTLY.
    #
    # We loop over the statements one at a time so a failure on
    # statement N doesn't leave statements 1..N-1 silently rolled
    # back (they wouldn't be — autocommit makes each one durable —
    # but the explicit loop makes the failure point obvious in
    # alembic's output).
    for stmt in _INDEX_STATEMENTS:
        with op.get_context().autocommit_block():
            op.execute(stmt)


def downgrade() -> None:
    # Mirror upgrade with DROP INDEX CONCURRENTLY IF EXISTS. Same
    # autocommit block pattern.
    for name in (
        "idx_findings_tenant_severity_class",
        "idx_findings_repo_created",
        "idx_findings_scan_job",
        "idx_findings_correlation",
        "idx_decisions_finding_action",
        "idx_audit_tenant_created",
        "idx_scans_repo_created",
        "idx_suppressions_rule_pattern",
    ):
        with op.get_context().autocommit_block():
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}")
