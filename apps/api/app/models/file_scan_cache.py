# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
File Scan Cache — per-file rule-engine output keyed by content + rule pack.

This is the speed-without-sacrificing-correctness layer for re-scans.

Layered with the existing ``finding_decision_cache``:
  - ``finding_decision_cache`` caches the AI triage VERDICT
    (likely_tp / likely_fp / etc.) keyed on
    ``(stability_id, code_hash)``. It avoids re-running the LLM on
    findings the AI already classified.
  - ``file_scan_cache`` (this table) caches the raw RULE-ENGINE OUTPUT
    keyed on ``(content_sha, rule_pack_version, scan_scope)``. It
    avoids re-running 883 regex rules on a file whose bytes haven't
    changed since the rule pack was last bumped.

Together they shorten a no-source-change re-scan from ~30 s to ~1-2 s
without ever silently skipping a rule update — bumping the rule pack
forces every cache row to miss until each file is re-scanned with the
new rules.
"""

from sqlalchemy import Column, String, Integer, DateTime, UniqueConstraint, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TenantMixin


class FileScanCache(Base, UUIDMixin, TenantMixin):
    """Cached per-file scanner findings.

    The cache key is ``(repository_id, file_path, content_sha,
    rule_pack_version, scan_scope)`` — every component must match
    exactly for a cache hit. Any drift in any component (file edited,
    rule added, scope widened) produces a miss and triggers a fresh
    scan, which then UPDATES the row via ``ON CONFLICT`` (no row
    explosion on busy repos).
    """

    __tablename__ = "file_scan_cache"

    # ── Cache key ────────────────────────────────────────────────────
    # Repo scope — when the user deletes a repo we drop its cache rows
    # in the same transaction (services/secret_scan/file_cache.py
    # invalidate_repo).
    repository_id = Column(UUID(as_uuid=True), nullable=False)
    # Path relative to repo root. 2000 chars covers Linux's PATH_MAX +
    # nested monorepo depths comfortably.
    file_path = Column(String(2000), nullable=False)
    # SHA-256 hex of the file's UTF-8-decoded content (matches what the
    # engine reads via ``open(path, "r", errors="ignore")``).
    content_sha = Column(String(64), nullable=False)
    # SHA-256 hex of the active rule pack at scan time. Includes both
    # built-in rules and the tenant's custom detectors. See
    # ``services/secret_scan/engine.py:SecretScanner.rule_pack_version``.
    rule_pack_version = Column(String(64), nullable=False)
    # The scan scope (`standard` / `wide` / etc.) influences which
    # extensions the engine even opens. Different scope = potentially
    # different file set = different scan = different cache key.
    scan_scope = Column(String(32), nullable=False, default="standard")

    # ── Cached payload ────────────────────────────────────────────────
    # Serialized list of ``ParsedFinding`` (via ``dataclasses.asdict``).
    # The cache helper round-trips this through
    # ``ParsedFinding(**entry)`` on read. Stored in JSONB so we can
    # query in (e.g. for cache-poisoning audits) without a migration.
    findings_json = Column(JSONB, nullable=False, default=list)
    # Denormalised count for fast aggregate queries (cache hit rate
    # dashboards) without unpacking the JSONB.
    findings_count = Column(Integer, nullable=False, default=0)

    # ── Audit fields ──────────────────────────────────────────────────
    # When this entry was first written (= when the rule engine last
    # ran on this content/rule combo).
    scanned_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    # Bumped on every cache hit so a TTL-based cleanup job can evict
    # rows that haven't been touched in N days. Without this you'd
    # accumulate cache rows for files long since deleted from any
    # branch and never know to drop them.
    last_used_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        # Mirrors the SQL constraint added by the migration. Declared
        # here so SQLAlchemy autogenerate is in sync with reality.
        UniqueConstraint(
            "repository_id", "file_path", "content_sha",
            "rule_pack_version", "scan_scope",
            name="uq_file_scan_cache_key",
        ),
        # Lookup index — covers the WHERE clause used by the cache
        # helper's batch-lookup query.
        Index(
            "ix_file_scan_cache_lookup",
            "repository_id", "rule_pack_version", "scan_scope",
            "file_path", "content_sha",
        ),
        # TTL eviction by tenant.
        Index("ix_file_scan_cache_tenant_ttl", "tenant_id", "last_used_at"),
        # Repo-scoped cleanup on repository delete.
        Index("ix_file_scan_cache_repo", "repository_id"),
    )
