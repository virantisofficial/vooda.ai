# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""API Key model for CI/CD and programmatic access."""

import secrets
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime, timezone, timedelta

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


def generate_api_key() -> str:
    """Generate a secure API key with vooda_ prefix."""
    return f"vooda_{secrets.token_urlsafe(32)}"


class APIKey(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "api_keys"

    name = Column(String(255), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True, index=True)
    key_prefix = Column(String(20), nullable=False)  # first 8 chars for display
    scopes = Column(JSONB, default=list)  # ["scan", "findings", "gate", "reports"]
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    # Rotation tracking (migration b5c6d7e8f9a0).  When the operator
    # rotates a key, the OLD row gets these set + expires_at moved to
    # ``now + grace_period_days``.  The successor key is brand-new with
    # rotated_at = NULL.  See routers/api_keys.py:rotate_api_key for
    # the full state machine + invariants.
    rotated_at = Column(DateTime(timezone=True), nullable=True)
    rotated_to_id = Column(
        UUID(as_uuid=True),
        ForeignKey("api_keys.id", ondelete="SET NULL"),
        nullable=True,
    )
    rotation_grace_until = Column(DateTime(timezone=True), nullable=True)
    # Source-IP allowlist (migration c6d7e8f9a0b1).  NULL or [] = no
    # restriction (auth behaves as before the migration).  Non-empty
    # list of CIDR strings = source IP MUST fall inside at least one
    # block or _authenticate_api_key raises 403.  Both IPv4 and IPv6
    # are supported; the list is validated at write-time so the auth
    # path can assume well-formed CIDR strings.
    allowed_ip_cidrs = Column(JSONB, nullable=True)
