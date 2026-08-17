# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Finding Decision Cache — stores AI and user decisions keyed by Stability ID.
Enables carrying forward triage decisions across scans without re-running AI.
"""

from sqlalchemy import Column, String, Float, Integer, ForeignKey, Text, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime, timezone

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class FindingDecisionCache(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "finding_decision_cache"

    stability_id = Column(String(20), nullable=False, index=True)
    # Nullable so source-scan findings (Slack/Jira/S3/etc., where
    # `repository_id` is None and the parent is `scan_source_id`) can
    # cache their AI decisions too. Bug fix 2026-05-04 — without this,
    # AI triage on any source-scan finding raised NotNullViolation
    # mid-flush, the txn rolled back, and the classification was lost.
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=True, index=True)
    # Optional source scope — populated for source-scan findings so
    # the cache can be partitioned by source the same way it's
    # partitioned by repo for code findings.
    scan_source_id = Column(UUID(as_uuid=True), ForeignKey("scan_sources.id"), nullable=True, index=True)

    # The cached decision
    classification = Column(String(50), nullable=False)  # likely_tp, likely_fp, confirmed_fp, etc.
    ai_confidence = Column(Float, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    exploitability_score = Column(Float, nullable=True)
    true_positive_reasons = Column(JSONB, default=list)
    false_positive_reasons = Column(JSONB, default=list)
    compensating_controls = Column(JSONB, default=list)
    ai_evidence_refs = Column(JSONB, default=list)

    # Decision source
    decided_by = Column(String(20), nullable=False)  # "ai" or "user"
    decided_by_user_id = Column(UUID(as_uuid=True), nullable=True)
    source_scan_job_id = Column(UUID(as_uuid=True), nullable=True)

    # Code hash — to detect when code changes and invalidate
    code_hash = Column(String(16), nullable=False)

    # Pattern hash — for cross-repo learning
    pattern_hash = Column(String(16), nullable=True, index=True)

    # Tracking
    hit_count = Column(Integer, default=1)
    last_hit_at = Column(DateTime(timezone=True), nullable=True)

    # Finding metadata (for reference)
    rule_id = Column(String(255), nullable=True)
    file_path = Column(String(1024), nullable=True)
    function_name = Column(String(255), nullable=True)
    cwe = Column(String(20), nullable=True)
    finding_title = Column(Text, nullable=True)
