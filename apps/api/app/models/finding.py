# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, Integer, Float, ForeignKey, Enum as SAEnum, Text, Boolean, DateTime, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
import enum

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Classification(str, enum.Enum):
    LIKELY_TRUE_POSITIVE = "likely_true_positive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    NEEDS_REVIEW = "needs_review"
    CONFIRMED_TRUE_POSITIVE = "confirmed_true_positive"
    CONFIRMED_FALSE_POSITIVE = "confirmed_false_positive"
    ACCEPTED_RISK = "accepted_risk"
    NOT_ENOUGH_EVIDENCE = "not_enough_evidence"
    # ── Closure states added 2026-05-04 ──
    # `ROTATED` — the credential was rotated / revoked at the
    # provider; the finding is closed but the audit trail (when it
    # was first seen + how long it took to rotate) is preserved.
    # Distinct from CONFIRMED_FALSE_POSITIVE because the secret WAS
    # real — MTTR metrics + compliance reporting depend on the
    # distinction.
    ROTATED = "rotated"
    # `TEST_CREDENTIAL` — intentional test/mock value (e.g.
    # `sk_test_...` Stripe keys, AWS IAM users tagged for fixtures).
    # Functionally similar to CONFIRMED_FALSE_POSITIVE but kept
    # separate because "this is a real secret intentionally placed
    # in a test fixture" is different from "this isn't a secret at
    # all" — important when triaging a peer's repo where you can't
    # tell if a key is genuinely test-only or a developer mistake.
    TEST_CREDENTIAL = "test_credential"
    # `RESOLVED_FILE_DELETED` — automatic closure: the finding's
    # source file was removed in a subsequent commit. The secret is
    # no longer in the working tree, so the finding is no longer
    # actionable. Distinct from CONFIRMED_FALSE_POSITIVE (the secret
    # was real but the file/secret no longer exists) and ROTATED
    # (the credential was actively rotated at the provider). Set by
    # the worker's deleted-file tombstone pass after each
    # incremental scan. Useful for audit / MTTR metrics: knowing a
    # finding closed by file-deletion vs rotation tells different
    # stories about how teams react to secret leaks.
    RESOLVED_FILE_DELETED = "resolved_file_deleted"
    # `RESOLVED_ITEM_DELETED` — source-side equivalent of
    # RESOLVED_FILE_DELETED. Applied by the weekly source full-sync
    # sweep when an item that previously yielded a finding (a Slack
    # message, Jira issue, Confluence page, S3 object, …) is no
    # longer returned by the source. Distinct from
    # RESOLVED_FILE_DELETED so dashboards / SLA reporting can tell
    # apart "git file removed in a commit" from "user deleted the
    # Slack message". Both close the finding without inflating MTTR.
    RESOLVED_ITEM_DELETED = "resolved_item_deleted"
    # `RESOLVED_REPO_REMOVED` — closure applied when the parent
    # repository is permanently deleted from Vooda by an admin.  The
    # finding is no longer trackable because Vooda lost visibility,
    # NOT because the credential was rotated or the leak was cleaned.
    # Distinguished from RESOLVED_FILE_DELETED so MTTR / SLA dashboards
    # can exclude admin-deletes from remediation-rate calculations
    # (otherwise nuking a repo would falsely inflate "fixed" metrics).
    # Compliance reporting can still surface these as "credential may
    # still be live, ownership transferred outside Vooda."
    RESOLVED_REPO_REMOVED = "resolved_repo_removed"
    # `RESOLVED_SOURCE_REMOVED` — source-side equivalent for scan
    # sources (Slack / Confluence / Jira / S3 / …).  Same operational
    # meaning as RESOLVED_REPO_REMOVED: admin action, NOT a cleanup
    # outcome.  Kept distinct so dashboards can break down deletions
    # by scope.
    RESOLVED_SOURCE_REMOVED = "resolved_source_removed"


class ReviewStatus(str, enum.Enum):
    UNREVIEWED = "unreviewed"
    IN_REVIEW = "in_review"
    REVIEWED = "reviewed"
    DISPUTED = "disputed"


class RemediationStatus(str, enum.Enum):
    NONE = "none"
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PATCH_GENERATED = "patch_generated"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"


class ImportedFinding(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """Raw finding as received from an external scanner."""
    __tablename__ = "imported_findings"

    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False, index=True)
    scanner_name = Column(String(100), nullable=False, index=True)
    scanner_rule_id = Column(String(255), nullable=True)
    external_id = Column(String(255), nullable=True)

    raw_data = Column(JSONB, nullable=False)  # preserve original payload
    parser_used = Column(String(100), nullable=False)  # which parser adapter
    parse_errors = Column(JSONB, default=list)

    # Pre-normalization extracted fields
    title = Column(Text, nullable=True)
    severity = Column(String(50), nullable=True)
    file_path = Column(String(1024), nullable=True)
    line_start = Column(Integer, nullable=True)
    cwe = Column(String(20), nullable=True)
    category = Column(String(255), nullable=True)


class NormalizedFinding(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """Canonical finding model — the heart of the platform.

    Concurrency
    -----------
    Carries a ``version`` column wired into SQLAlchemy's optimistic
    locking via ``__mapper_args__["version_id_col"]``.  Every flush
    that mutates the row bumps ``version`` and adds it to the UPDATE
    WHERE clause; a concurrent write that loaded the same row at the
    older version then races to write will fail with
    :class:`sqlalchemy.exc.StaleDataError` (zero rows matched).  The
    triage routers catch that and return ``HTTP 409 Conflict`` so the
    UI can reload and surface the stale-edit to the user.  Added
    2026-05-19 to close the silent-overwrite race documented in the
    Track-A product audit.
    """
    __tablename__ = "normalized_findings"

    # Linkage
    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False, index=True)
    imported_finding_id = Column(UUID(as_uuid=True), ForeignKey("imported_findings.id"), nullable=True)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=True, index=True)
    scan_source_id = Column(UUID(as_uuid=True), ForeignKey("scan_sources.id"), nullable=True, index=True)

    # Scanner metadata
    scanner_name = Column(String(100), nullable=False, index=True)
    scanner_rule_id = Column(String(255), nullable=True)
    external_finding_id = Column(String(255), nullable=True)

    # Finding identity
    title = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    vulnerability_category = Column(String(255), nullable=False, index=True)
    cwe = Column(String(20), nullable=True, index=True)
    cve = Column(String(30), nullable=True)

    # Severity and scoring
    severity = Column(SAEnum(Severity), nullable=False, index=True)
    confidence = Column(Float, default=0.5)
    exploitability_score = Column(Float, nullable=True)
    business_risk_score = Column(Float, nullable=True)

    # Location
    branch = Column(String(255), nullable=True)
    commit_sha = Column(String(40), nullable=True)
    file_path = Column(String(1024), nullable=False, index=True)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    function_name = Column(String(255), nullable=True)
    class_name = Column(String(255), nullable=True)
    module_name = Column(String(255), nullable=True)

    # Code context
    code_snippet = Column(Text, nullable=True)
    source_metadata = Column(JSONB, default=dict)  # taint source info
    sink_metadata = Column(JSONB, default=dict)    # taint sink info
    trace = Column(JSONB, default=list)            # dataflow trace steps

    # AI classification
    classification = Column(SAEnum(Classification), default=Classification.NEEDS_REVIEW, nullable=False, index=True)
    ai_explanation = Column(Text, nullable=True)
    ai_confidence = Column(Float, nullable=True)
    ai_evidence_refs = Column(JSONB, default=list)
    true_positive_reasons = Column(JSONB, default=list)
    false_positive_reasons = Column(JSONB, default=list)
    compensating_controls = Column(JSONB, default=list)

    # Status
    review_status = Column(SAEnum(ReviewStatus), default=ReviewStatus.UNREVIEWED, nullable=False, index=True)

    # How the current classification was established: mechanism, actor,
    # and the originating decision. Required whenever `classification`
    # is a CONFIRMED_* value, because that word asserts somebody decided
    # — a session guard refuses the write otherwise. NULL on anything
    # weaker, and on rows that predate the column.
    # See apps/api/app/core/classification_provenance.py
    classification_provenance = Column(JSONB, nullable=True)
    remediation_status = Column(SAEnum(RemediationStatus), default=RemediationStatus.NONE, nullable=False, index=True)
    is_suppressed = Column(Boolean, default=False)
    suppression_reason = Column(String(255), nullable=True)

    # Assignment
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    assigned_at = Column(DateTime(timezone=True), nullable=True)

    # Tags
    tags = Column(JSONB, default=list)  # ["sprint-42", "auth-team", etc.]

    # Stability & Cache
    stability_id = Column(String(20), nullable=True, index=True)
    code_hash = Column(String(16), nullable=True)
    cache_hit = Column(Boolean, default=False)
    cache_source = Column(String(20), nullable=True)

    # Cross-scan tracking
    last_seen_scan_job_id = Column(UUID(as_uuid=True), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    first_seen_at = Column(DateTime(timezone=True), nullable=True)
    scan_count = Column(Integer, default=1)

    # Dedup
    fingerprint = Column(String(64), nullable=True, index=True)

    # Optimistic-lock counter (see class docstring).  Defaults to 1 on
    # INSERT, auto-incremented on UPDATE via SQLAlchemy's version_id_col.
    # The DB-level default keeps backfilled rows non-NULL after the
    # migration without requiring a separate UPDATE pass.
    version = Column(Integer, nullable=False, default=1, server_default="1")

    # Correlation (Phase 2.2)
    correlation_group_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    correlated_finding_ids = Column(JSONB, default=list)  # IDs of correlated findings
    aggregate_confidence = Column(Float, nullable=True)   # boosted confidence from multi-scanner
    is_correlation_primary = Column(Boolean, default=True) # primary finding in a correlation group

    # ── Case-B aggregation: incident this occurrence belongs to ──
    # NULL for non-secret findings (no secret_hash).  When set, the
    # parent ``SecretIncident`` carries the credential-level state
    # (classification, rotation_status, validation_status) and this
    # finding carries the LOCATION-level state (file_path,
    # line_start, code cleanup status, etc.).
    incident_id = Column(
        UUID(as_uuid=True),
        ForeignKey("secret_incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # SQLAlchemy's built-in optimistic-lock plumbing.  Once
    # ``version_id_col`` is set, the session adds the current version
    # to every UPDATE's WHERE clause and bumps it automatically; if no
    # rows match, StaleDataError is raised and the transaction must
    # roll back.  ``version_id_generator=False`` lets the DB default
    # handle the initial value and SQLAlchemy increment the rest.
    __mapper_args__ = {"version_id_col": version}

    # Relations
    evidence = relationship("FindingEvidence", back_populates="finding", cascade="all, delete-orphan")
    decisions = relationship("FindingDecision", back_populates="finding", cascade="all, delete-orphan")
    remediation_plans = relationship("RemediationPlan", back_populates="finding", cascade="all, delete-orphan")
    incident = relationship("SecretIncident", back_populates="occurrences", foreign_keys=[incident_id])


class FindingEvidence(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "finding_evidence"

    finding_id = Column(UUID(as_uuid=True), ForeignKey("normalized_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(50), nullable=False)  # code_context, config, framework_detection, sanitizer, etc.
    file_path = Column(String(1024), nullable=True)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    content = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)
    metadata_ = Column("metadata", JSONB, default=dict)

    finding = relationship("NormalizedFinding", back_populates="evidence")


class FindingDecision(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "finding_decisions"

    finding_id = Column(UUID(as_uuid=True), ForeignKey("normalized_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    action = Column(String(50), nullable=False)  # approve, reject, mark_fp, mark_tp, accept_risk, request_review
    previous_classification = Column(String(50), nullable=True)
    new_classification = Column(String(50), nullable=True)
    comment = Column(Text, nullable=True)
    metadata_ = Column("metadata", JSONB, default=dict)

    finding = relationship("NormalizedFinding", back_populates="decisions")


class SecretIncident(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """First-class entity for a unique credential exposure.

    Concurrency
    -----------
    Same optimistic-lock pattern as :class:`NormalizedFinding`: a
    ``version`` column wired into SQLAlchemy's ``version_id_col``
    auto-increments on every flush.  Triage routers catch
    :class:`StaleDataError` and return ``HTTP 409 Conflict`` so a
    user whose draft was overwritten by another reviewer's save sees
    a "stale, reload" prompt instead of silent data loss.  Added
    2026-05-19 alongside the matching column on NormalizedFinding.

    Column-ownership contract (two writers, two strategies)
    -------------------------------------------------------
    This row is written by two kinds of writer that MUST own disjoint
    columns:

      * Interactive human triage (``PATCH /incidents/{id}``) uses the
        optimistic ``version`` lock above and owns the DISPOSITION
        columns: ``classification``, ``review_status``, ``assigned_to``,
        ``rotation_status``.
      * Autonomous scan ingest writes via an atomic
        ``INSERT ... ON CONFLICT DO UPDATE``
        (``apps/worker/tasks.py:_upsert_secret_incident``) that
        deliberately BYPASSES ``version_id_col`` and owns only:
        identity (``tenant_id``, ``secret_hash``), denormalized display
        (``title``, ``secret_type``, ``masked_value``), and the
        monotonic aggregates (``severity_max`` / ``severity_rank``,
        ``last_seen_at``, ``validation_status``, ``occurrence_count``).

    The ingest upsert does NOT bump ``version`` and does NOT touch a
    disposition column; the human PATCH path does NOT touch an aggregate
    column.  That disjointness is what lets a scan's severity merge and
    a reviewer's edit race on the same row without a semantic conflict
    (or a spurious 409).  Using ``version_id_col`` on the *autonomous*
    writer is what caused a whole-scan rollback bug — two concurrent
    scans, same credential, loser's ``StaleDataError`` poisoned the
    session and discarded the entire scan's findings — fixed by moving
    ingest to the atomic upsert.  Do not re-introduce it there.

    One SecretIncident represents the credential itself; its
    NormalizedFinding "occurrences" represent the individual leaked
    locations (files, commits, pages, channels).  Matches what
    GitGuardian / Wiz / TruffleHog all ship as their primary entity.

    Triage decisions live on the incident (one credential = one
    decision); per-location cleanup status lives on the occurrence
    (each file needs its own git scrub).
    """
    __tablename__ = "secret_incidents"

    # The natural key has to be a real UNIQUE constraint, not just an
    # index, and it has to carry this exact name — two things depend on
    # it by name at runtime and at migration time:
    #   * ``_upsert_secret_incident`` (apps/worker/tasks.py) targets
    #     ``constraint="uq_secret_incidents_tenant_hash"`` in its
    #     INSERT ... ON CONFLICT DO UPDATE.
    #   * migration s6t7u8v9w0x1's backfill uses
    #     ``ON CONFLICT (tenant_id, secret_hash)``.
    # The initial-schema migration builds every table with
    # ``Base.metadata.create_all()``, so on a FRESH database this class
    # is what supplies the constraint. While it was declared as a plain
    # ``index=True`` on secret_hash alone, fresh installs got no unique
    # constraint at all: migrations aborted with "there is no unique or
    # exclusion constraint matching the ON CONFLICT specification", and
    # had they passed, every scan ingest would have failed the same way.
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "secret_hash", name="uq_secret_incidents_tenant_hash"
        ),
    )

    # Natural key — unique per tenant (enforced by __table_args__ above)
    secret_hash = Column(String(128), nullable=False, index=True)

    # Display fields (denormalized from latest occurrence)
    title = Column(Text, nullable=False)
    secret_type = Column(String(255), nullable=True)
    masked_value = Column(String(255), nullable=True)

    # Aggregate state
    severity_max = Column(String(20), nullable=False, index=True)
    # Numeric mirror of ``severity_max`` so the scan-ingest upsert can do
    # an atomic escalate-only merge via ``GREATEST(EXCLUDED.severity_rank,
    # secret_incidents.severity_rank)``.  Lexical GREATEST on the string
    # column would be wrong ('high' > 'critical' alphabetically).  Kept in
    # sync with ``severity_max`` by the ingest upsert; backfilled by
    # migration d7e8f9a0b1c2.  critical=5 / high=4 / medium=3 / low=2 / info=1.
    severity_rank = Column(Integer, nullable=False, default=1, server_default="1")
    occurrence_count = Column(Integer, nullable=False, default=1)

    # Credential-level triage state
    classification = Column(String(40), nullable=False, default="needs_review", index=True)
    review_status = Column(String(40), nullable=False, default="unreviewed")

    # Live-validation against the provider's API
    validation_status = Column(String(50), nullable=True)
    last_validated_at = Column(DateTime(timezone=True), nullable=True)

    # Rotation lifecycle (credential-level)
    rotation_status = Column(String(50), nullable=True)
    rotated_at = Column(DateTime(timezone=True), nullable=True)

    # Assignment + tags
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    tags = Column(JSONB, default=list)

    # Cross-scan tracking
    first_seen_at = Column(DateTime(timezone=True), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)

    # AI metadata (denormalized for fast incident-list render)
    ai_explanation = Column(Text, nullable=True)
    ai_confidence = Column(Float, nullable=True)

    # Optimistic-lock counter (see class docstring).
    version = Column(Integer, nullable=False, default=1, server_default="1")

    # Relations
    occurrences = relationship(
        "NormalizedFinding",
        back_populates="incident",
        foreign_keys="NormalizedFinding.incident_id",
    )

    __mapper_args__ = {"version_id_col": version}


# Importing the models is enough to arm the provenance guard; nothing
# can reach a session without going through here first.
from apps.api.app.core import classification_provenance as _cp  # noqa: E402,F401
