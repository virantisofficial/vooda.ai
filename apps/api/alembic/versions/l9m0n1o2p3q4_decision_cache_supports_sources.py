# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""decision_cache: nullable repository_id + add scan_source_id

Revision ID: l9m0n1o2p3q4
Revises: k8l9m0n1o2p3
Create Date: 2026-05-04 10:00:00.000000

Why
---
The AI triage pipeline writes a row into ``finding_decision_cache``
after classifying each finding (so cache hits skip the AI call on
re-scan). The schema was ``repository_id NOT NULL`` because every
finding used to have a parent repo. After the source-scan work
shipped earlier in 2026, source-scan findings (``slack://`` /
``jira://`` / ``s3://`` etc.) carry ``repository_id = NULL`` instead.

When AI triage finally started running for source findings (after
the 4-blocker fix landed in ``apps/worker/tasks.py`` 2026-05-04),
the cache write raised ``NotNullViolationError: null value in
column "repository_id"``, the surrounding transaction rolled back,
and the AI classification was lost — even though the model had
returned a perfectly good ``likely_true_positive`` verdict.

This migration:
  1. Drops the NOT NULL constraint on ``finding_decision_cache.repository_id``.
  2. Adds ``scan_source_id`` (nullable, FK → scan_sources.id) so the
     cache can partition by source the same way it partitions by
     repository for git findings.

Both changes are metadata-only (no table rewrite, no row scan).
Safe on a live database. Idempotent via ``ALTER COLUMN ... DROP NOT
NULL`` (no-op when already nullable) and ``ADD COLUMN IF NOT EXISTS``.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "l9m0n1o2p3q4"
down_revision: Union[str, None] = "k8l9m0n1o2p3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Postgres ``ALTER COLUMN ... DROP NOT NULL`` is idempotent —
    # applying it to an already-nullable column is a metadata-only
    # no-op. No need to wrap in a guard.
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "ALTER COLUMN repository_id DROP NOT NULL"
    )
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "ADD COLUMN IF NOT EXISTS scan_source_id UUID"
    )
    # FK constraint — wrapped in DO $$ ... $$ so re-running on an
    # already-migrated DB doesn't raise duplicate_object.
    op.execute("""
        DO $$ BEGIN
            ALTER TABLE finding_decision_cache
                ADD CONSTRAINT fk_decision_cache_scan_source
                FOREIGN KEY (scan_source_id) REFERENCES scan_sources (id);
        EXCEPTION
            WHEN duplicate_object THEN NULL;
            WHEN duplicate_table THEN NULL;
        END $$;
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_finding_decision_cache_scan_source_id "
        "ON finding_decision_cache (scan_source_id)"
    )


def downgrade() -> None:
    """Re-add NOT NULL on repository_id + drop scan_source_id.

    Only safe to run if every cache row has a non-null
    ``repository_id``. On a database that has accumulated source-scan
    cache entries, the NOT NULL re-add will raise. We don't try to
    handle that here — if you genuinely need to roll back, manually
    DELETE source-scan cache rows first.
    """
    op.execute(
        "DROP INDEX IF EXISTS ix_finding_decision_cache_scan_source_id"
    )
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "DROP CONSTRAINT IF EXISTS fk_decision_cache_scan_source"
    )
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "DROP COLUMN IF EXISTS scan_source_id"
    )
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "ALTER COLUMN repository_id SET NOT NULL"
    )
