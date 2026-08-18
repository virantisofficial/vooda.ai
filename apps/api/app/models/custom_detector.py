# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Custom Detector model — stores user-defined secret detection regex rules.

Enterprise admins define org-specific patterns (e.g. mycompany_sk_[a-zA-Z0-9]{32})
without touching code. Custom detectors are loaded at scan time and merged with
the 415+ built-in rules.
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class CustomDetector(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "custom_detectors"
    __table_args__ = (
        UniqueConstraint("tenant_id", "rule_id", name="uq_custom_detectors_tenant_rule_id"),
    )

    # ── Rule definition (maps 1:1 to SecretRule dataclass) ──
    rule_id = Column(String(255), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    secret_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False, default="high")
    pattern = Column(Text, nullable=False)
    keywords = Column(JSONB, default=list)
    confidence = Column(Float, default=0.9)
    description = Column(Text, default="")
    fix_hint = Column(Text, default="")
    cwe = Column(String(20), default="CWE-798")
    multiline = Column(Boolean, default=False)

    # ── Management ──
    is_enabled = Column(Boolean, default=True, nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), nullable=False)
    test_cases = Column(JSONB, default=list)     # [{input: str, should_match: bool}]
    match_count = Column(Integer, default=0)      # lifetime matches across scans
