# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""file_scan_cache: per-file content+rule-version cache for fast re-scans

Revision ID: n1o2p3q4r5s6
Revises: m0n1o2p3q4r5
Create Date: 2026-05-05 11:00:00.000000

Why
---
Incremental scanning (the previous migration) skips files that haven't
changed BETWEEN COMMITS. But the production-grade ask is broader:

1. Re-scan with no commit changes should be near-instant (without
   sacrificing correctness when rules update).
2. Custom-rule additions must invalidate the cache automatically.
3. Engine version bumps must invalidate the cache automatically.
4. AI / scanner settings changes that affect output must invalidate.

This is exactly the pattern Snyk Code, SonarQube, and GitHub Advanced
Security use: cache the **per-file scanner output** keyed by
``(content_sha, rule_pack_version)``. On re-scan:

  - Hash each file's content
  - Look up ``(repository_id, file_path, content_sha,
    rule_pack_version)`` in this table
  - If hit: deserialize the cached findings, skip the rule engine
    entirely for that file
  - If miss: run the rule engine, store the new entry

This gives us:
  - **Correctness**: rule pack bump = different ``rule_pack_version`` =
    cache miss = full re-scan with new rules
  - **Speed**: 99 % of files don't change between scans, so a no-change
    re-scan finishes in seconds
  - **Auditability**: every scan still produces a ``scan_jobs`` row, just
    with ``files_cached=N, files_scanned=0`` in the stats blob
  - **No silent skips**: unlike a naive ``HEAD == checkpoint`` short
    circuit, a rule update on Day N+1 automatically reflects in the
    Day N+2 re-scan

Schema notes
------------
- ``content_sha`` is the SHA-256 of the file's UTF-8 bytes (same shape
  the engine reads via ``open(..., "r", errors="ignore")``).
- ``rule_pack_version`` is a SHA-256 over the sorted, normalized rule
  set (built-in + custom for the tenant). Computed in
  ``services/secret_scan/engine.py`` and exposed via
  ``SecretScanner.rule_pack_version``.
- ``findings_json`` stores the list of ``ParsedFinding`` objects
  (``dataclasses.asdict`` round-trip) for that file. JSONB so we can
  query into the cache for analytics if needed.
- ``UNIQUE(repository_id, file_path, content_sha, rule_pack_version)``
  enforces the cache key invariant. ``ON CONFLICT (...) DO UPDATE``
  in the worker keeps ``last_used_at`` warm without doubling rows.
- Per-tenant scoping prevents cross-tenant cache leaks: the unique
  constraint already partitions on ``repository_id``, but
  ``tenant_id`` lives on the row for fast cleanup queries
  (``DELETE WHERE tenant_id = :t AND last_used_at < :ttl``).

The schema is deliberately decoupled from ``finding_decision_cache``
(the AI-triage cache) — that one keys on ``stability_id + code_hash``
and stores classification verdicts, this one keys on
``content_sha + rule_pack_version`` and stores raw scanner output. They
serve different layers of the pipeline.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "n1o2p3q4r5s6"
down_revision: Union[str, None] = "m0n1o2p3q4r5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS file_scan_cache (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            repository_id UUID NOT NULL,
            file_path VARCHAR(2000) NOT NULL,
            content_sha VARCHAR(64) NOT NULL,
            rule_pack_version VARCHAR(64) NOT NULL,
            scan_scope VARCHAR(32) NOT NULL DEFAULT 'standard',
            findings_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            findings_count INTEGER NOT NULL DEFAULT 0,
            scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_file_scan_cache_key
                UNIQUE (repository_id, file_path, content_sha, rule_pack_version, scan_scope)
        )
        """
    )

    # Lookup index on the cache key — covers the WHERE clause used by
    # FileScanCache.lookup_batch (``IN (file_path, content_sha)`` with
    # repo + rule pack version pinned).
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_file_scan_cache_lookup "
        "ON file_scan_cache (repository_id, rule_pack_version, scan_scope, file_path, content_sha)"
    )

    # Tenant-scoped cleanup index — used by TTL-based eviction queries
    # ``DELETE FROM file_scan_cache WHERE tenant_id = :t AND last_used_at < :ttl``.
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_file_scan_cache_tenant_ttl "
        "ON file_scan_cache (tenant_id, last_used_at)"
    )

    # Repo-scoped cleanup — when a repository is deleted we drop its
    # cache rows in the same transaction (tasks.py / repositories.py
    # delete handler).
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_file_scan_cache_repo "
        "ON file_scan_cache (repository_id)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_file_scan_cache_repo")
    op.execute("DROP INDEX IF EXISTS ix_file_scan_cache_tenant_ttl")
    op.execute("DROP INDEX IF EXISTS ix_file_scan_cache_lookup")
    op.execute("DROP TABLE IF EXISTS file_scan_cache")
