# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, Float, ForeignKey, Enum as SAEnum, Text
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
import enum

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin


class PatchStatus(str, enum.Enum):
    DRAFT = "draft"
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"


class RemediationPlan(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_plans"

    finding_id = Column(UUID(as_uuid=True), ForeignKey("normalized_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    generated_by = Column(String(50), nullable=False)  # ai_model identifier

    vulnerability_summary = Column(Text, nullable=False)
    root_cause = Column(Text, nullable=False)
    fix_rationale = Column(Text, nullable=False)
    developer_notes = Column(JSONB, default=list)
    validation_steps = Column(JSONB, default=list)
    risk_of_breakage = Column(String(20), default="unknown")
    confidence_score = Column(Float, nullable=True)
    metadata_ = Column("metadata", JSONB, default=dict)

    finding = relationship("NormalizedFinding", back_populates="remediation_plans")
    patches = relationship("RemediationPatch", back_populates="plan", cascade="all, delete-orphan")


class RemediationPatch(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_patches"

    plan_id = Column(UUID(as_uuid=True), ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False, index=True)

    patch_diff = Column(Text, nullable=False)
    files_changed = Column(JSONB, default=list)
    status = Column(SAEnum(PatchStatus), default=PatchStatus.DRAFT, nullable=False)
    confidence_score = Column(Float, nullable=True)
    safety_score = Column(Float, nullable=True)
    pr_url = Column(String(1024), nullable=True)
    metadata_ = Column("metadata", JSONB, default=dict)

    plan = relationship("RemediationPlan", back_populates="patches")


class ReviewFeedback(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "review_feedback"

    finding_id = Column(UUID(as_uuid=True), ForeignKey("normalized_findings.id"), nullable=True, index=True)
    patch_id = Column(UUID(as_uuid=True), ForeignKey("remediation_patches.id"), nullable=True, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    feedback_type = Column(String(50), nullable=False)  # approval, rejection, comment, correction
    comment = Column(Text, nullable=True)
    rating = Column(String(20), nullable=True)  # helpful, not_helpful, incorrect
    metadata_ = Column("metadata", JSONB, default=dict)
