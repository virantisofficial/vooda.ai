# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""finding_decision_cache: ON DELETE CASCADE on scan_source_id + repository_id

Revision ID: r5s6t7u8v9w0
Revises: q4r5s6t7u8v9
Create Date: 2026-05-09 01:50:00.000000

Why
---
Production bug 2026-05-09: deleting a scan_source through the API
returns HTTP 500 with ``ForeignKeyViolationError`` because the
``finding_decision_cache`` table has a NO ACTION FK to
``scan_sources.id`` (and the same shape against ``repositories.id``).

Customers couldn't delete a connected Slack / Confluence / Jira / S3
source after running any scan against it — the AI-triage decision
cache rows for findings tied to that source held a hard reference,
and DELETE on the parent table aborted the transaction. The same
hazard applied to repositories: the moment a repo accumulated any
triage history, it could not be removed without manual SQL.

There were ALSO two duplicate FK constraints on
``scan_source_id`` (``finding_decision_cache_scan_source_id_fkey``
and ``fk_decision_cache_scan_source``) — a result of one older
schema definition and a later partial-migration rename that didn't
drop the original. Doubling the constraint just doubled the failure
path.

Fix
---
1. Drop both duplicate ``scan_source_id`` FKs and recreate one with
   ON DELETE CASCADE.
2. Drop and recreate the ``repository_id`` FK with the same.
3. Decision-cache rows are derived state — losing them on parent
   delete is correct (the cache rebuilds itself on the next AI-triage
   run for the new findings; nothing audit-worthy lives only here).

This intentionally diverges from the classic "preserve history"
pattern because finding_decision_cache is a per-(rule, file, snippet)
optimization keyed on the source/repo. When the source/repo is gone,
the cache rows for that key are unreachable anyway.
"""

from alembic import op


revision = "r5s6t7u8v9w0"
down_revision = "q4r5s6t7u8v9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop both existing scan_source_id FKs (one of them is the
    # legacy duplicate). use IF EXISTS so this migration is safe to
    # run on instances that already had the duplicate cleaned up.
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "DROP CONSTRAINT IF EXISTS finding_decision_cache_scan_source_id_fkey"
    )
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "DROP CONSTRAINT IF EXISTS fk_decision_cache_scan_source"
    )

    # Recreate the scan_source_id FK with CASCADE.
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "ADD CONSTRAINT finding_decision_cache_scan_source_id_fkey "
        "FOREIGN KEY (scan_source_id) REFERENCES scan_sources(id) "
        "ON DELETE CASCADE"
    )

    # Same fix for repository_id (currently NO ACTION; same blast
    # radius if a repository with prior scan history is deleted).
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "DROP CONSTRAINT IF EXISTS finding_decision_cache_repository_id_fkey"
    )
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "ADD CONSTRAINT finding_decision_cache_repository_id_fkey "
        "FOREIGN KEY (repository_id) REFERENCES repositories(id) "
        "ON DELETE CASCADE"
    )


def downgrade() -> None:
    # Restore NO ACTION semantics. We don't recreate the duplicate
    # ``fk_decision_cache_scan_source`` constraint on downgrade —
    # carrying the duplicate forward was always a bug, downgrade is
    # the right time to leave it dead.
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "DROP CONSTRAINT IF EXISTS finding_decision_cache_scan_source_id_fkey"
    )
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "ADD CONSTRAINT finding_decision_cache_scan_source_id_fkey "
        "FOREIGN KEY (scan_source_id) REFERENCES scan_sources(id)"
    )
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "DROP CONSTRAINT IF EXISTS finding_decision_cache_repository_id_fkey"
    )
    op.execute(
        "ALTER TABLE finding_decision_cache "
        "ADD CONSTRAINT finding_decision_cache_repository_id_fkey "
        "FOREIGN KEY (repository_id) REFERENCES repositories(id)"
    )
