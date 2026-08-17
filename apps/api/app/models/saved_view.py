# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class SavedView(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "saved_views"

    name = Column(String(100), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    view_type = Column(String(50), default="findings")  # findings, projects
    filters = Column(JSONB, nullable=False)  # {severity, classification, repository_id, search, tags, assigned_to, ...}
    is_default = Column(String(10), default="false")  # "true" if this is the user's default view
