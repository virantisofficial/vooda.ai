# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, Boolean, UniqueConstraint

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class NotificationRule(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """
    Centralized notification rules — controls WHICH events trigger notifications
    and at what severity threshold, independent of delivery channels.

    One rule per (tenant_id, event_type). Channels (Slack, Teams, etc.) only
    define WHERE to deliver; this table defines WHAT to deliver.
    """
    __tablename__ = "notification_rules"

    event_type = Column(String(50), nullable=False)          # scan_complete, critical_finding, etc.
    severity_threshold = Column(String(30), default="all")   # all, critical, high_and_above
    is_enabled = Column(Boolean, default=True, nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "event_type", name="uq_tenant_event_type"),
    )
