# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
AI Engine Settings — global configuration for how the AI processes findings.
Stored per-tenant. One active settings record per tenant.
"""

from sqlalchemy import Column, String, Float, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class AIEngineSettings(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "ai_engine_settings"

    # Context Extraction: "full", "smart", "minimal"
    context_mode = Column(String(20), default="smart", nullable=False)

    # Finding Analysis: "individual", "batch_similar"
    analysis_mode = Column(String(20), default="batch_similar", nullable=False)

    # Token Optimization
    skip_ai_for_info = Column(Boolean, default=True)  # Don't spend tokens on info-level findings
    ai_confidence_threshold = Column(Float, default=0.6)  # Below this → "needs review"
    max_tokens_per_finding = Column(Integer, default=4096)

    # Batch settings
    batch_size = Column(Integer, default=5)
    max_concurrent = Column(Integer, default=10)
    rate_limit_rpm = Column(Integer, default=60)

    # Scan pipeline settings
    auto_verify_credentials = Column(Boolean, default=True)    # Auto-verify secrets during scan
    deprioritize_test_files = Column(String(20), default="normal")  # normal, deprioritize, exclude
    scan_scope = Column(String(20), default="standard")        # standard, extended, minimal
