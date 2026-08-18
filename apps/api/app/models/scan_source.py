# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, Boolean, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


# Valid source types (not a DB enum — stored as varchar). Original 7
# (Google Drive removed 2026-05-14 alongside Chat/Docs — OAuth ops-side
# setup overhead didn't pay off at current demand level) + 7 enterprise
# additions added 2026-04-30 to close the M365 + DevSecOps coverage
# gap vs peers.
# Community edition source types. Two whole categories are Enterprise-only
# and deliberately excluded here:
#   - Collaboration: slack, ms_teams, mattermost
#   - Docs & Wikis:  confluence, notion, sharepoint_pages
# The create endpoint validates against this set, so those types can't be
# configured or scanned in the community edition. (onedrive_sharepoint stays
# — it is a Cloud Storage source, not Docs & Wikis.)
SCAN_SOURCE_TYPES = {
    # Issue Tracking (community edition ships the top 3; GitHub Issues,
    # Linear, Asana, and Bitbucket Issues are enterprise-only sources.
    # GitHub secrets are still caught via the normal git repository scan.)
    "jira", "servicenow", "azure_devops",
    # Cloud Storage (community edition ships the big-3 object stores;
    # Box and OneDrive / SharePoint are enterprise-only sources.)
    "s3", "gcs", "azure_blob",
    # DevOps
    "docker_image", "cicd_logs", "container_registry", "terraform_state",
    # APIs / SaaS
    "postman", "salesforce",
}

# Friendly-name aliases. The canonical type is what's stored in the
# DB (the right side); the left side is what we accept as input from
# clients written against the documented "Microsoft Teams" name etc.
# Resolved server-side so existing callers using the canonical name
# keep working unchanged. Bug fix 2026-05-08.
SCAN_SOURCE_TYPE_ALIASES = {
    "atlassian_jira": "jira",
    "aws_s3": "s3",
}


def normalize_source_type(value: str) -> str:
    """Resolve a user-supplied source_type string to its canonical key.

    Returns the value unchanged if it's already canonical.
    Returns the alias target if the value is a known alias.
    Returns the value unchanged if it's neither — caller validates
    against ``SCAN_SOURCE_TYPES``.
    """
    if not value:
        return value
    v = value.strip().lower()
    if v in SCAN_SOURCE_TYPES:
        return v
    return SCAN_SOURCE_TYPE_ALIASES.get(v, v)
SCAN_SCHEDULES = {"on_demand", "hourly", "daily", "weekly"}


class ScanSource(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """A non-git source that can be scanned for secrets (Slack, Confluence, S3, etc.)."""
    __tablename__ = "scan_sources"

    name = Column(String(255), nullable=False)
    # Widened from VARCHAR(20) → VARCHAR(40) to fit the longer
    # source_type names introduced 2026-04-30 (`onedrive_sharepoint`
    # is 19 chars and gets dangerously close; `container_registry` is
    # 18). Migration is non-destructive — Postgres VARCHAR widening is
    # an in-place metadata change.
    source_type = Column(String(40), nullable=False, index=True)
    integration_config_id = Column(UUID(as_uuid=True), ForeignKey("integration_configs.id"), nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    scan_schedule = Column(String(20), default="on_demand", nullable=False)

    # Source-specific config: channel list, bucket name, space key, image tag, etc.
    config = Column(JSONB, default=dict)

    # Incremental sync state: cursors, timestamps, version numbers per sub-resource
    sync_state = Column(JSONB, default=dict)

    # Per-source scope — binds this source's findings to a specific
    # Repository or Business Unit. When NULL (default), findings are
    # org-wide (the original behaviour). Set so that:
    #   - target_repository_id     → every finding from this source
    #     gets repository_id = that repo (per-repo ticketing
    #     destination, BU access grants, etc. all then apply)
    #   - target_business_unit_id  → finding picks up the BU instead
    # Use one or the other, not both. UI enforces the exclusivity;
    # the worker honours target_repository_id first if both happen
    # to be set. Bug fix / feature 2026-04-29.
    target_repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="SET NULL"), nullable=True)
    target_business_unit_id = Column(UUID(as_uuid=True), ForeignKey("business_units.id", ondelete="SET NULL"), nullable=True)

    # Tracking
    last_scan_at = Column(DateTime(timezone=True), nullable=True)
    # When the source last had a FULL sweep run (force_full=true,
    # ignoring sync_state watermark). The weekly Beat task uses this
    # to find sources overdue for a sweep — NULL or older than 7
    # days. Distinct from last_scan_at because incremental scans
    # don't satisfy the sweep's role of catching watermark drift,
    # deleted items, and partial-first-scan recovery.
    last_full_sweep_at = Column(DateTime(timezone=True), nullable=True)
    stats = Column(JSONB, default=dict)  # items_scanned, findings_count, last_duration_s

    # ── Convenience accessors over stats JSONB ────────────────────
    # The worker stamps stats["last_scan_status"] (success|failed) and
    # stats["last_error"] on every scan attempt — preflight, in-flight,
    # post-scan — so the UI has one place to read "what happened on
    # the last attempt?" without cracking the JSONB blob in JS.
    # Pydantic's from_attributes=True picks up these properties as if
    # they were columns. Bug fix 2026-05-08 — before, scan failures
    # were invisible at the API/UI level even though the worker
    # logged them.
    @property
    def last_scan_status(self) -> str | None:
        return (self.stats or {}).get("last_scan_status") if isinstance(self.stats, dict) else None

    @property
    def last_scan_error(self) -> str | None:
        return (self.stats or {}).get("last_error") if isinstance(self.stats, dict) else None
