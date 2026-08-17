# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, Boolean, Text
from sqlalchemy.dialects.postgresql import JSONB

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class RoleDefinition(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """Custom role definitions with configurable permissions."""
    __tablename__ = "role_definitions"

    name = Column(String(100), nullable=False)          # Display name
    slug = Column(String(100), nullable=False)          # Unique key (admin, developer, etc.)
    description = Column(Text, nullable=True)
    color = Column(String(50), default="slate")         # UI color theme
    permissions = Column(JSONB, default=list)            # List of permission keys
    is_builtin = Column(Boolean, default=False)          # Built-in roles can't be deleted
    is_active = Column(Boolean, default=True)
