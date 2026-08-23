# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from pydantic import BaseModel, HttpUrl, field_validator
from uuid import UUID
from datetime import datetime
from typing import Optional


class RepositoryCreate(BaseModel):
    name: str
    url: Optional[str] = None
    source_type: str = "git_url"
    default_branch: str = "main"
    auth: Optional[dict] = None  # {token, username, password} — stored encrypted in metadata
    provider: Optional[str] = None  # github, gitlab, bitbucket, generic
    # Per-repo ticketing destination (FK to integration_configs).
    # Lets dev teams pick which Jira board catches this repo's
    # findings at create time — no go-back-and-edit step. NULL =
    # use the integration's own scope routing.
    ticketing_integration_id: Optional[UUID] = None


class RepositoryResponse(BaseModel):
    id: UUID
    name: str
    url: Optional[str]
    source_type: str
    default_branch: str
    is_active: bool
    languages: list[str]
    frameworks: list[str]
    business_unit_id: Optional[UUID] = None
    # Per-repo Jira board override — see Repository model. Returned
    # so the FE can show the current mapping in the Repositories list
    # row + pre-select it in the edit modal's "Ticketing destination"
    # picker.
    ticketing_integration_id: Optional[UUID] = None
    created_at: datetime
    # Surfaced separately rather than exposing the full metadata blob —
    # the FE only needs to know "is this archived?" to show the badge
    # + Unarchive action.  False (not null) when the key is absent.
    is_archived: bool = False
    # Per-repo scan toggles + webhook health (migration u8v9w0x1y2z3).
    # Drives the list-view webhook-health badge and the detail-view
    # "Webhook & PR Scans" Settings section.  push_scan_enabled and
    # pr_scan_enabled default to True at the DB level so existing
    # tenants keep their scanning behaviour after the migration.
    push_scan_enabled: bool = True
    pr_scan_enabled: bool = True
    last_webhook_event_at: Optional[datetime] = None
    last_webhook_event_type: Optional[str] = None
    last_webhook_event_status: Optional[str] = None
    # List of fnmatch globs that gate which branches trigger a scan
    # on webhook delivery.  NULL → scan every branch (preserves the
    # pre-w0x1y2z3a4b5 default).  See services/secret_scan/branch_filter.py.
    branch_patterns: Optional[list[str]] = None

    model_config = {"from_attributes": True}


class ScanConfigUpdate(BaseModel):
    """PATCH body for /repositories/{id}/scan-config — per-repo push/PR
    scan toggle + branch-pattern changes.  All fields optional so the
    FE can update them independently without echoing the others."""
    push_scan_enabled: Optional[bool] = None
    pr_scan_enabled: Optional[bool] = None
    # ``[]`` (empty list) is treated as ``None`` server-side — "monitor
    # nothing" doesn't make sense; the FE should send a non-empty list
    # to restrict, or ``None`` to reset to "all branches".
    branch_patterns: Optional[list[str]] = None


class ScanRequest(BaseModel):
    # Scan type:
    #   "standalone" — default, scans HEAD of the repo's default branch
    #   "history"    — full git-history scan across all commits
    #   "import"     — set automatically for repos with scan_mode="import"
    scan_type: str = "standalone"
    # Free-form config passed through to the worker. Recognized keys:
    #   skip_ai (bool)     — skip AI triage even if a provider is configured
    #   force_full (bool)  — bypass the incremental checkpoint and re-walk
    #                        every file from scratch
    #   branch (str)       — webhook payloads pass the pushed branch here;
    #                        manual triggers normally leave it unset and
    #                        inherit the repo's default_branch
    config: dict = {}


class ScanJobResponse(BaseModel):
    # ── NULL-tolerant JSONB fields ───────────────────────────────────
    # `scan_jobs.config` and `.stats` are NULLABLE in Postgres with no
    # server default, while both are typed as `dict` here. A default
    # (`= {}`) only covers a MISSING field — an explicit None still
    # fails validation, and FastAPI validates the WHOLE response list,
    # so a single NULL jsonb column would fail the entire request.
    #
    # Coerced before validation rather than typed Optional, so callers
    # keep the simple `dict` contract and never have to null-check.
    @field_validator("stats", "config", mode="before")
    @classmethod
    def _null_jsonb_to_empty_dict(cls, v):
        return {} if v is None else v

    id: UUID
    repository_id: UUID
    scan_type: str
    status: str
    progress_pct: int
    status_message: Optional[str]
    # WS-3′ — the machine-useful failure reason (never empty for a FAILED
    # scan: falls back to the exception type, or an actionable hint for
    # timeouts). Exposed so the drawer + /scan-jobs page can show WHY a
    # scan failed instead of a bare red badge. Already redacted (WS-6).
    error_detail: Optional[str] = None
    stats: dict = {}
    # The trigger-time config (skip_ai, force_full, branch, etc.).
    # Exposed so the scan-card UI can distinguish a user-requested
    # AI skip from a missing-provider state — both would otherwise
    # show as ``stats.ai_triaged=0`` with no other signal.  Added
    # 2026-05-24 (Vooda Scan Intelligence audit follow-up).
    config: dict = {}
    created_at: datetime
    updated_at: datetime
    # Sprint G-2 — the worker stamps this at every REAL progress point
    # (phase transition, storing chunk-commit, each completed AI-triage
    # batch). Exposed so the drawer/page can show scan-PROGRESS liveness
    # ("last progress 8s ago") and a stall warning — distinct from the
    # WS-connection "Live" chip, which only means the socket is up and so
    # stays green even on a wedged scan. Null until the first heartbeat
    # and for rows created before G-2.
    heartbeat_at: Optional[datetime] = None

    # ── P0 two-way sync — first-class provenance (CLI/CI scans) ──
    # Populated only for scan_type cli|ci (a `vooda scan` / `vooda monitor`
    # synced from a dev machine or CI pipeline); NULL for server-side scans.
    # Exposed so the scan-detail header can badge "CLI"/"CI" and render the
    # git/pipeline context (commit, branch, who ran it, which CI, a link to
    # the pipeline run). ``actor`` is self-reported by the runner and is
    # UNTRUSTED — display only, never used for authz.
    commit_sha: Optional[str] = None
    branch: Optional[str] = None
    actor: Optional[str] = None
    ci_provider: Optional[str] = None
    ci_pipeline_url: Optional[str] = None

    model_config = {"from_attributes": True}


class ScanPhaseEventResponse(BaseModel):
    """One row of the append-only per-phase scan timeline (Sprint S / WS-1).

    Drives the live progress drawer's "Recent Activity" timeline and the
    /scan-jobs/{id} page so both survive refresh / reopen / completion.
    ``total_steps`` is the canonical denominator (no /7-vs-/8 drift) and
    ``progress_pct`` is monotonic.  ``phase_label`` is already redacted
    (WS-6) before it was persisted.
    """
    id: UUID
    scan_job_id: UUID
    step: int
    total_steps: int
    phase_label: str
    status: str
    progress_pct: int
    stats_snapshot: Optional[dict] = None
    created_at: datetime

    model_config = {"from_attributes": True}
