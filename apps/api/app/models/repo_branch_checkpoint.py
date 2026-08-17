# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Per-(repo, branch) incremental-scan checkpoints.

The single ``repositories.last_scanned_commit`` column was a footgun
on any repo with more than one actively-scanned branch — a feature-
branch scan would overwrite the main branch's watermark, and the
next ``main`` scan would walk a cross-branch diff. This table is
the per-branch home for the watermark.

The legacy column is still populated alongside this table for
backwards compat. Worker reads from this table first; falls back to
the legacy column only if no row exists yet.
"""

from sqlalchemy import Column, String, DateTime, UniqueConstraint, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TenantMixin


class RepoBranchCheckpoint(Base, UUIDMixin, TenantMixin):
    """One row per ``(repository_id, branch)`` pair."""

    __tablename__ = "repo_branch_checkpoints"

    repository_id = Column(UUID(as_uuid=True), nullable=False)
    # Branch name as written in git refs. 1024 is generous — git
    # itself permits ref names up to the OS path limit, but the
    # practical limit is well under this in any sane setup.
    branch = Column(String(1024), nullable=False)
    # SHA of the commit at which the most recent successful scan
    # finished for this (repo, branch) pair. Used as the ``base_sha``
    # for the next ``scan_diff(base, head)`` invocation on this branch.
    last_scanned_commit = Column(String(40), nullable=False)
    # When the checkpoint was last advanced. Useful for "stale repo"
    # dashboards (last scanned > 30 days ago) and for TTL-based
    # cleanup if a tenant churns through hundreds of feature branches.
    last_scanned_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (
        UniqueConstraint(
            "repository_id", "branch",
            name="uq_repo_branch_checkpoint",
        ),
        Index("ix_repo_branch_checkpoints_repo", "repository_id"),
        Index("ix_repo_branch_checkpoints_tenant", "tenant_id"),
    )
