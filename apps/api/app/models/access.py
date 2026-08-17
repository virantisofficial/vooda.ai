# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Access Control Models — Business Units and User Access Grants.

Supports three levels of access:
- Organization: user sees all BUs and all projects
- Business Unit: user sees all projects within that BU
- Project: user sees only that specific project

Admin role users always have organization-level access.
"""

from sqlalchemy import Column, String, Boolean, ForeignKey, Text, Enum as SAEnum
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import enum

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class BusinessUnit(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "business_units"

    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    parent_id = Column(UUID(as_uuid=True), ForeignKey("business_units.id"), nullable=True)  # for sub-BUs
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    children = relationship("BusinessUnit", back_populates="parent", cascade="all")
    parent = relationship("BusinessUnit", back_populates="children", remote_side="BusinessUnit.id")


class AccessLevel(str, enum.Enum):
    ORGANIZATION = "organization"
    BUSINESS_UNIT = "business_unit"
    PROJECT = "project"


class AccessRole(str, enum.Enum):
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class UserAccessGrant(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "user_access_grants"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    access_level = Column(SAEnum(AccessLevel, values_callable=lambda x: [e.value for e in x]), nullable=False)

    # Scope — set based on access_level
    business_unit_id = Column(UUID(as_uuid=True), ForeignKey("business_units.id"), nullable=True, index=True)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=True, index=True)

    # Role within this scope
    role = Column(SAEnum(AccessRole, values_callable=lambda x: [e.value for e in x]), default=AccessRole.MEMBER, nullable=False)
