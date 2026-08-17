# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from apps.api.app.models.user import User, UserRole, Tenant
from apps.api.app.models.repository import Repository, RepositorySnapshot
from apps.api.app.models.scan import ScanJob, ScanArtifact, Scanner
from apps.api.app.models.finding import (
    ImportedFinding,
    NormalizedFinding,
    FindingEvidence,
    FindingDecision,
    SecretIncident,
)
from apps.api.app.models.remediation import RemediationPlan, RemediationPatch, ReviewFeedback
# Policy model removed 2026-05-16 alongside the governance product surfaces.
# SLA windows are hardcoded defaults (critical=7d, high=30d, medium=90d,
# low=180d) — see apps/api/app/routers/reports.py.
from apps.api.app.models.audit import AuditEvent
from apps.api.app.models.integration import IntegrationConfig
from apps.api.app.models.notification import Notification
from apps.api.app.models.notification_delivery import NotificationDelivery
from apps.api.app.models.metrics import MetricSnapshot
from apps.api.app.models.ai_model import AIModelConfig
from apps.api.app.models.role_definition import RoleDefinition
from apps.api.app.models.suppression import SuppressionRule
# Per-repo / org-wide scanner-rule muting.  Proactive (pre-persist) counterpart
# to SuppressionRule (post-finding triage).  See models/rule_override.py.
from apps.api.app.models.rule_override import RuleOverride
from apps.api.app.models.api_key import APIKey
from apps.api.app.models.saved_view import SavedView
from apps.api.app.models.notification_rule import NotificationRule
# Governance models (nhi, agent, supply_chain, policy_dsl, federation,
# migration, quantum) removed 2026-05-16 alongside the corresponding product
# surfaces — the secret-scanner core does not need them.  The DB tables remain
# in place via existing migrations; SQLAlchemy no longer registers them on
# Base.metadata so they will not be touched by future autogenerate runs.
from apps.api.app.models.access import (
    BusinessUnit, UserAccessGrant,
)
from apps.api.app.models.custom_detector import CustomDetector
from apps.api.app.models.scan_source import ScanSource
from apps.api.app.models.rotation_event import CredentialRotationEvent
# ── Added 2026-05-04 audit pass ──
# Both of these were on disk but never imported here. SQLAlchemy
# only registers a model on `Base.metadata` when its module is
# imported, so Base.metadata.create_all() in the initial-schema
# migration silently SKIPPED these tables. On a fresh-DB deploy
# the next migration that referenced them (l9m0n1o2p3q4 ALTERs
# finding_decision_cache; older code paths read
# ai_engine_settings) blew up with `relation "..." does not exist`.
# Importing them here registers them on Base.metadata so the
# initial-schema migration creates the tables on every fresh deploy.
from apps.api.app.models.decision_cache import FindingDecisionCache
from apps.api.app.models.ai_engine_settings import AIEngineSettings
# File-level scanner-output cache (rule-version-aware). Sits in front
# of SecretScanner and lets a re-scan with no source changes finish
# in seconds without ever silently skipping a rule update.
from apps.api.app.models.file_scan_cache import FileScanCache
# Per-(repo, branch) incremental-scan checkpoint. Replaces the
# single ``repositories.last_scanned_commit`` column for any repo
# scanned across multiple branches.
from apps.api.app.models.repo_branch_checkpoint import RepoBranchCheckpoint

__all__ = [
    "User", "UserRole", "Tenant",
    "Repository", "RepositorySnapshot",
    "ScanJob", "ScanArtifact", "Scanner",
    "ImportedFinding", "NormalizedFinding", "FindingEvidence", "FindingDecision", "SecretIncident",
    "RemediationPlan", "RemediationPatch", "ReviewFeedback",
    "AuditEvent", "IntegrationConfig", "Notification", "MetricSnapshot",
    "AIModelConfig", "RoleDefinition", "SuppressionRule", "RuleOverride", "APIKey", "NotificationRule",
    "BusinessUnit", "UserAccessGrant",
    "CustomDetector",
    "ScanSource",
    "CredentialRotationEvent",
    "SavedView",
    "FindingDecisionCache",
    "AIEngineSettings",
    "FileScanCache",
    "RepoBranchCheckpoint",
]
