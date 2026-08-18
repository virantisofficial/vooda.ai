# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Suppression Rule model — stores learned and manual suppression patterns.

Learned rules are auto-created by the org-wide learning engine.
Manual rules can be created by admins to suppress specific scanner rules.
All suppressions are auditable and reversible.
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
import enum

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class SuppressionType(str, enum.Enum):
    LEARNED = "learned"        # Auto-created by org-wide learning
    MANUAL = "manual"          # Created by admin
    SCANNER_RULE = "scanner_rule"  # Suppress a specific scanner rule globally


class SuppressionRule(Base, UUIDMixin, TimestampMixin, TenantMixin):
    __tablename__ = "suppression_rules"

    # Rule identity
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    suppression_type = Column(String(50), nullable=False, default="learned")

    # Match criteria
    scanner_rule_id = Column(String(255), nullable=True, index=True)  # match on scanner rule
    pattern_hash = Column(String(64), nullable=True, index=True)     # match on normalized code pattern
    vulnerability_category = Column(String(255), nullable=True)       # match on category
    cwe = Column(String(20), nullable=True)                          # match on CWE
    file_path_pattern = Column(String(1024), nullable=True)          # glob pattern for file paths

    # Learning evidence
    evidence_count = Column(Integer, default=0)                # how many FP decisions led to this
    evidence_repo_count = Column(Integer, default=0)           # across how many repos
    evidence_finding_ids = Column(JSONB, default=list)         # sample finding IDs that proved this pattern is FP
    confidence = Column(Float, default=0.8)                    # how confident we are this should be suppressed
    sample_code = Column(Text, nullable=True)                  # sample code snippet that triggers this

    # State
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    created_by = Column(String(100), default="system_learning")  # "system_learning" or user email

    # Stats
    times_applied = Column(Integer, default=0)  # how many times this rule suppressed a finding
