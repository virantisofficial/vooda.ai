# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from pydantic import BaseModel, Field, field_validator
from uuid import UUID
from datetime import datetime
from typing import Optional


class FindingListItem(BaseModel):
    id: UUID
    title: str
    vulnerability_category: str
    cwe: Optional[str] = None
    severity: str
    classification: str
    review_status: str
    remediation_status: str
    scanner_name: str
    file_path: str
    line_start: Optional[int]
    confidence: float
    ai_confidence: Optional[float]
    code_snippet: Optional[str] = None
    assigned_to: Optional[UUID] = None
    source_metadata: Optional[dict] = None
    # See _none_tags_to_empty in FindingDetail — same DB column nullable
    # vs schema list-required mismatch applies to the list endpoint too.
    tags: Optional[list[str]] = None
    cache_hit: bool = False
    cache_source: Optional[str] = None
    # Optimistic-lock counter.  The UI echoes this back as
    # ``expected_version`` on PATCH so concurrent triage edits surface
    # as HTTP 409 rather than silently overwriting each other.  See the
    # NormalizedFinding model docstring and main.py's StaleDataError
    # handler for the full mechanism.
    version: int = 1
    # Incident this occurrence belongs to.  NULL for non-secret findings
    # (anything without a secret_hash).  The UI uses this to group by
    # incident and to look up incident-level state (rotation_status,
    # validation_status, occurrence_count across all locations).
    incident_id: Optional[UUID] = None
    # True when the parent (repo OR scan_source) is archived.  Lets the
    # FE render an inline "Archived source" badge when archived-source
    # findings are surfaced (via bypass routes or the include_archived_sources
    # toggle).  Industry pattern — every commercial peer (GitGuardian,
    # Wiz, Snyk, Orca, Aikido, TruffleHog Enterprise) signals archived
    # parent state inline on finding rows so analysts know at a glance
    # this is "paused data" vs an active finding.
    is_archived_parent: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("tags", mode="before")
    @classmethod
    def _none_tags_to_empty(cls, v):
        return v if v is not None else []


class FindingDetail(BaseModel):
    id: UUID
    scan_job_id: UUID
    # Source-scan findings (Slack/Jira/S3/etc.) have
    # `repository_id = None` because their parent is `scan_source_id`
    # instead. Schema must accept None or every source-finding detail
    # request 500s with `UUID input should be a string, bytes or
    # UUID object [input_value=None]` — discovered 2026-05-04 when
    # the side panel stopped opening on Slack-found credentials.
    repository_id: Optional[UUID] = None
    # The companion source-side parent. Set for findings produced by
    # source scans, NULL for git-scan findings. Exposing it on the
    # detail response lets the FE link back to the right source page.
    scan_source_id: Optional[UUID] = None
    scanner_name: str
    scanner_rule_id: Optional[str]
    external_finding_id: Optional[str]

    title: str
    description: Optional[str]
    vulnerability_category: str
    cwe: Optional[str]
    cve: Optional[str]
    severity: str
    confidence: float
    exploitability_score: Optional[float]
    business_risk_score: Optional[float]

    branch: Optional[str]
    commit_sha: Optional[str]
    file_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    function_name: Optional[str]
    class_name: Optional[str]
    code_snippet: Optional[str]

    classification: str
    ai_explanation: Optional[str]
    ai_confidence: Optional[float]
    true_positive_reasons: list[str]
    false_positive_reasons: list[str]
    compensating_controls: list[str]

    review_status: str
    remediation_status: str
    is_suppressed: bool

    source_metadata: Optional[dict] = None
    sink_metadata: Optional[dict] = None

    assigned_to: Optional[UUID] = None
    # The DB column allows NULL; Pydantic's default-of-[] does NOT permit
    # explicit None inputs, so a route returning the raw column value would
    # 500 with `Input should be a valid list`. Accept None here and coerce
    # to an empty list via the validator below — caught 2026-04-25 when
    # the /findings/{id} detail page silently failed because the frontend
    # `.catch(() => {})` swallowed the 500.
    tags: Optional[list[str]] = None
    stability_id: Optional[str] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    scan_count: int = 0
    cache_hit: bool = False
    cache_source: Optional[str] = None

    evidence: list[dict] = []
    decisions: list[dict] = []
    remediation_plans: list[dict] = []

    # Optimistic-lock counter.  Mirrors the field on FindingListItem;
    # repeated here so the detail GET also returns it.  Defaults to 1
    # so existing rows backfilled by the DB default deserialize cleanly.
    version: int = 1

    # Same `is_archived_parent` signal as FindingListItem — see note
    # there.  Drives the "Archived source" indicator in the detail panel
    # so users on bypass routes (repo-detail, source-detail) know why
    # they're seeing an archived parent's data.
    is_archived_parent: bool = False

    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("tags", mode="before")
    @classmethod
    def _none_tags_to_empty(cls, v):
        return v if v is not None else []


class TriageRequest(BaseModel):
    # Allowed: mark_fp, mark_tp, accept_risk, request_review, add_comment.
    # ``add_comment`` is the no-op classification used by the /comment
    # endpoint when the operator just wants to leave a note without
    # changing the finding's review_status — required because this
    # request model is shared between /triage and /comment.
    action: str = Field(
        ...,
        examples=["mark_fp", "mark_tp", "accept_risk", "request_review", "add_comment"],
        description=(
            "Triage decision OR ``add_comment`` for the /comment endpoint "
            "(comment-only, leaves classification untouched)."
        ),
    )
    comment: Optional[str] = Field(
        None, examples=["Hard-coded test fixture; safe to ignore."],
    )
    # Provenance marker — when the action came from a SuggestionChip
    # click (gap #6) the frontend sets this to "suggestion_placeholder",
    # "suggestion_test_file", "suggestion_git_history".  Surfaced in
    # the audit metadata `via` field so the History tab can render
    # signal-confirmed actions distinctly from manual triage.
    source: Optional[str] = None
    # Optimistic-lock token from the row the client loaded.  When set,
    # a mismatch with the current row triggers HTTP 409 so the user
    # can reload instead of overwriting another reviewer's save.
    # Optional for backwards compatibility with non-UI callers.
    expected_version: Optional[int] = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "action": "mark_fp",
                    "comment": "Test fixture used in CI snapshot tests.",
                },
                {
                    "action": "add_comment",
                    "comment": "Coordinated with #infra-sec on Slack — will rotate this week.",
                },
            ],
        },
    }


class RemediateRequest(BaseModel):
    auto_apply: bool = False


class ApprovalRequest(BaseModel):
    action: str  # approve, reject
    comment: Optional[str] = None


class FindingFilters(BaseModel):
    severity: Optional[list[str]] = None
    classification: Optional[list[str]] = None
    review_status: Optional[list[str]] = None
    scanner_name: Optional[str] = None
    repository_id: Optional[UUID] = None
    category: Optional[str] = None
    search: Optional[str] = None
    page: int = 1
    page_size: int = 50
