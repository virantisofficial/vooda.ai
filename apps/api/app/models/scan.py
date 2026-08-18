# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, Enum as SAEnum, Text, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
import enum

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, enum.Enum):
    STANDALONE = "standalone"
    HISTORY = "history"
    IMPORT = "import"          # third-party results imported (e.g. external SARIF)
    HYBRID = "hybrid"
    SOURCE_SCAN = "source_scan"
    # P0 two-way sync — Vooda's OWN scanner run client-side and synced back.
    # Distinct from IMPORT (which is third-party tool output) so the UI can
    # badge "CLI" vs "CI" vs "Imported".
    CLI = "cli"               # `vooda scan` from a developer machine
    CI = "ci"                 # `vooda monitor` from a CI/CD pipeline


class ScanJob(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "scan_jobs"

    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=True, index=True)
    scan_source_id = Column(UUID(as_uuid=True), ForeignKey("scan_sources.id"), nullable=True, index=True)
    snapshot_id = Column(UUID(as_uuid=True), ForeignKey("repository_snapshots.id"), nullable=True)
    scanner_id = Column(UUID(as_uuid=True), ForeignKey("scanners.id"), nullable=True)
    initiated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)  # Null for webhook/system-triggered scans

    scan_type = Column(SAEnum(ScanType), nullable=False)
    status = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    progress_pct = Column(Integer, default=0)
    status_message = Column(Text, nullable=True)

    config = Column(JSONB, default=dict)  # scan config overrides
    stats = Column(JSONB, default=dict)  # findings_count, fp_count, etc.
    error_detail = Column(Text, nullable=True)
    celery_task_id = Column(String(255), nullable=True)  # for task revocation/cancel

    # Sprint G-2 — liveness heartbeat. The worker stamps this with now()
    # at every progress point (each phase transition, each storing
    # chunk-commit, each AI-triage batch). The stale-scan watchdog reaps
    # a scan only when COALESCE(heartbeat_at, created_at) has gone stale
    # (no progress for STALE_SCAN_THRESHOLD_MINUTES, default 15m), so a
    # slow-but-progressing large-repo scan is never force-failed while a
    # genuinely deadlocked one is reaped fast. NULL until the first
    # heartbeat (and for rows created before this column existed), in
    # which case the watchdog falls back to created_at. Deliberately
    # un-indexed: written very frequently, read only inside the tiny
    # status.in_(non_terminal) candidate set, so an index would be pure
    # write overhead.
    heartbeat_at = Column(DateTime(timezone=True), nullable=True)

    # ── P0 two-way CLI/CI sync — first-class provenance ──────────────────
    # Additive + nullable. Server-side scans (webhook/scheduled/manual) leave
    # these NULL and keep using the `config` JSONB exactly as before — nothing
    # in the existing pipeline reads these. The CLI/CI SARIF-import path
    # populates them so a CI scan carries queryable git/pipeline context the
    # UI scan-detail header can render. `actor` is self-reported by the CI
    # runner and is UNTRUSTED (display only — never used for authz; the
    # authenticated API key is the real identity).
    commit_sha = Column(String(64), nullable=True)
    branch = Column(String(255), nullable=True)
    actor = Column(String(255), nullable=True)
    ci_provider = Column(String(50), nullable=True)       # github_actions, gitlab_ci, ...
    ci_pipeline_url = Column(Text, nullable=True)
    # Idempotency for CI retries / at-least-once runners: a re-POST of the same
    # import (same key) returns the existing scan_job instead of double-creating.
    # Enforced by a partial-unique index (tenant_id, idempotency_key) — see migration.
    idempotency_key = Column(String(64), nullable=True)

    repository = relationship("Repository", back_populates="scan_jobs")
    artifacts = relationship("ScanArtifact", back_populates="scan_job", cascade="all, delete-orphan")


class ScanPhaseEvent(Base, UUIDMixin, TimestampMixin):
    """Append-only per-phase event log for a scan (Sprint S / WS-1).

    Why this exists
    ---------------
    Before this table, scan progress lived only in ``scan_jobs.status_message``
    — a single field overwritten on every phase transition.  The live
    progress drawer therefore could only show messages that arrived
    AFTER the operator opened it; closing/refreshing reset the timeline,
    and a completed scan showed no history at all.

    This table persists one row per phase transition so the full
    lifecycle (queued → clone → analyze → scan → AI-triage → store →
    verify → done) is queryable forever and survives refresh.

    Immutability (WS-8)
    -------------------
    Append-only by contract.  The retention sweeper
    (``/audit/enforce-retention``) MUST exclude this table — see the
    guard in routers/audit.py.  Rows are never UPDATEd or DELETEd
    except by tenant cascade when the parent scan_job is deleted.

    Redaction (WS-6)
    ----------------
    ``phase_label`` is redacted via ``packages.common.logging_config
    ._redact_string`` BEFORE insert in the worker's ``_emit_phase``
    helper — a secret scanner must never persist the secrets it finds
    into its own audit log.
    """
    __tablename__ = "scan_phase_events"

    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    step = Column(Integer, nullable=False)              # e.g. 4
    total_steps = Column(Integer, nullable=False)        # canonical denominator (fixes /7-vs-/8 drift)
    phase_label = Column(Text, nullable=False)           # redacted human-readable phase text
    status = Column(String(20), nullable=False)          # running | analyzing | completed | failed | cancelled
    progress_pct = Column(Integer, nullable=False, default=0)
    stats_snapshot = Column(JSONB, nullable=True)        # optional per-phase counters

    scan_job = relationship("ScanJob", backref="phase_events")


class ScanArtifact(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "scan_artifacts"

    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_type = Column(String(50), nullable=False)  # sarif, json, xml, log, report
    storage_path = Column(String(1024), nullable=False)
    size_bytes = Column(Integer, default=0)
    metadata_ = Column("metadata", JSONB, default=dict)

    scan_job = relationship("ScanJob", back_populates="artifacts")


class Scanner(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "scanners"

    name = Column(String(100), nullable=False)  # checkmarx, fortify, snyk, etc.
    version = Column(String(50), nullable=True)
    scanner_type = Column(String(50), nullable=False)  # sast, dast, sca, secret, iac
    config = Column(JSONB, default=dict)
    is_active = Column(Boolean, default=True)
