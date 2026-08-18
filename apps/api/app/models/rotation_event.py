# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class CredentialRotationEvent(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """Records every active→inactive transition of a verified credential.

    This is an append-only audit table — one row per rotation event.
    It feeds:

    * **Mean Time To Rotation (MTTR)** dashboard metric
    * Compliance audit trail (proof that leaks were remediated)
    * Customer rotation SLA reporting

    Design notes
    ------------
    ``first_seen_active_at`` is the earliest timestamp at which this
    specific credential (keyed by ``secret_hash``) was seen active by
    the verifier. The worker maintains it in ``source_metadata`` once
    the credential first verifies live; it is never overwritten while
    the credential remains active, so ``time_to_rotation_s`` measures
    the real elapsed time between leak-visible-and-live and leak-
    rotated, not the time between last-check-and-rotation.

    ``rotated_at`` is the timestamp at which the transition to
    ``inactive`` was observed — this is a **lower bound** on the true
    rotation moment (customer may have rotated slightly earlier; we
    only learn about it on our next verification pass for that hash).
    """

    __tablename__ = "credential_rotation_events"

    # Link back to the finding that triggered detection; nullable
    # because findings can be deleted / merged and we still want the
    # audit record to persist.
    finding_id = Column(
        UUID(as_uuid=True),
        ForeignKey("normalized_findings.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    repository_id = Column(UUID(as_uuid=True), nullable=True, index=True)

    provider = Column(String(64), nullable=False, index=True)
    # sha256-hex of the secret value; safe to store, never the secret itself
    secret_hash = Column(String(128), nullable=False, index=True)

    first_seen_active_at = Column(DateTime(timezone=True), nullable=False)
    rotated_at = Column(DateTime(timezone=True), nullable=False)
    # Pre-computed for index-free dashboard queries. Seconds between
    # first_seen_active_at and rotated_at. Capped at INT4 (~68 years).
    time_to_rotation_s = Column(Integer, nullable=False)

    # "live" when detected on a direct verifier call, "cache" when
    # detected via Redis cache hit for the same secret_hash.
    detected_via = Column(String(16), nullable=False, default="live")

    # Free-form extras: prior verification_details, risk_level, etc.
    extra = Column("extra_data", JSONB, default=dict, nullable=False)

    __table_args__ = (
        # Tenant dashboards filter by tenant_id + rotated_at range
        Index("ix_rotation_events_tenant_rotated_at",
              "tenant_id", "rotated_at"),
        # For computing per-provider MTTR
        Index("ix_rotation_events_tenant_provider",
              "tenant_id", "provider"),
    )
