# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, Boolean, ForeignKey, Integer, Enum as SAEnum, Text, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
import enum

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class RepoSourceType(str, enum.Enum):
    GIT_URL = "git_url"
    UPLOAD = "upload"
    ARCHIVE = "archive"
    SCANNER_IMPORT = "scanner_import"


class Repository(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "repositories"

    name = Column(String(255), nullable=False)
    url = Column(String(1024), nullable=True)
    source_type = Column(SAEnum(RepoSourceType), nullable=False)
    default_branch = Column(String(100), default="main")
    is_active = Column(Boolean, default=True, nullable=False)
    languages = Column(JSONB, default=list)
    frameworks = Column(JSONB, default=list)
    metadata_ = Column("metadata", JSONB, default=dict)
    business_unit_id = Column(UUID(as_uuid=True), ForeignKey("business_units.id"), nullable=True, index=True)


    # Per-repository ticketing destination — points at a specific
    # IntegrationConfig (Jira / ServiceNow / Linear / custom). When
    # set, the dispatcher routes every finding from this repo to
    # ONLY that integration, overriding the integration's
    # scope_level (organization / business_unit / project).
    # Multiple repos can point at the same integration — the
    # "Repo A, C → JIRA A" case from the user's UX request
    # 2026-04-27. NULL means no override; falls back to scope_level
    # routing.
    ticketing_integration_id = Column(UUID(as_uuid=True), ForeignKey("integration_configs.id", ondelete="SET NULL"), nullable=True)

    # Incremental-scan checkpoint. SHA of the commit at which the most
    # recent successful HEAD scan finished. The worker uses this as
    # the `base_sha` for `scan_diff(...)` so subsequent scans only
    # walk files changed since the last run. NULL on freshly-imported
    # repos (first scan is always a full scan). Reset to NULL when
    # the user explicitly requests a `force_full` scan via the UI or
    # API config payload — this triggers a full re-walk and a fresh
    # checkpoint at the new HEAD.
    last_scanned_commit = Column(String(40), nullable=True)

    # ── Per-repo scan toggles (migration u8v9w0x1y2z3) ──
    # GitGuardian / Snyk / GHAS all expose per-repo push vs PR scan
    # toggles.  Defaults preserve existing scan behaviour for every
    # repo at migration time (both TRUE).  Worker checks these flags
    # in services/webhooks/receiver.py before dispatching the scan.
    push_scan_enabled = Column(Boolean, default=True, nullable=False, server_default="true")
    pr_scan_enabled = Column(Boolean, default=True, nullable=False, server_default="true")

    # ── Webhook health (migration u8v9w0x1y2z3) ──
    # When the most recent webhook event arrived, what kind it was,
    # and whether it succeeded.  Drives the 3-state webhook health
    # badge on the repository list view (green ≤ 7d, yellow ≤ 30d,
    # red > 30d or last_status=failed).  Written by
    # services/webhooks/receiver.py on every event delivery.
    last_webhook_event_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_webhook_event_type = Column(String(20), nullable=True)  # push / pull_request / merge_request
    last_webhook_event_status = Column(String(20), nullable=True)  # success / failed

    # ── Branch monitoring (migration w0x1y2z3a4b5) ──
    # List of fnmatch glob patterns that gate which branches trigger
    # a scan on webhook delivery.  NULL or empty → scan everything
    # (preserves the pre-w0x1y2z3a4b5 "scan all branches" behaviour
    # so existing repos aren't silently throttled by the migration).
    # See services/secret_scan/branch_filter.py for the matching
    # logic.  Examples: ["main"], ["main", "release/*"], ["*"].
    branch_patterns = Column(JSONB, nullable=True)

    snapshots = relationship("RepositorySnapshot", back_populates="repository", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="repository")


class RepositorySnapshot(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "repository_snapshots"

    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    branch = Column(String(255), nullable=False)
    commit_sha = Column(String(40), nullable=True)
    storage_path = Column(String(1024), nullable=False)
    file_count = Column(Integer, default=0)
    total_size_bytes = Column(Integer, default=0)
    file_index = Column(JSONB, default=dict)  # path -> {lang, size, hash}
    analysis_result = Column(JSONB, default=dict)  # languages, frameworks, configs detected

    repository = relationship("Repository", back_populates="snapshots")
