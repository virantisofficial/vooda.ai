# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class MetricSnapshot(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "metric_snapshots"

    snapshot_type = Column(String(50), nullable=False, index=True)  # daily, weekly, scan_summary
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=True)
    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=True)
    data = Column(JSONB, nullable=False)  # flexible metric data
