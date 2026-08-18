# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class IntegrationConfig(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "integration_configs"

    name = Column(String(100), nullable=False)
    integration_type = Column(String(50), nullable=False)  # scanner, notification, ticketing, scm
    provider = Column(String(50), nullable=False)  # checkmarx, jira, slack, github, etc.
    config = Column(JSONB, default=dict)  # connection details (encrypted at rest in prod)
    is_active = Column(Boolean, default=True, nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=True)

    # ── Notification scoping ────────────────────────────────────
    # NULL = org-wide (only org-level admins see / receive)
    # Set = scoped to that BU or project
    business_unit_id = Column(UUID(as_uuid=True), ForeignKey("business_units.id"), nullable=True, index=True)
    # scope_level: "organization" | "business_unit" | "project"
    # Determines who can manage this config and who receives alerts
    scope_level = Column(String(20), nullable=True)  # mirrors AccessLevel values
