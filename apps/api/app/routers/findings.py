# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.core.classification_provenance import (
    MECHANISM_BULK_TRIAGE,
    MECHANISM_HUMAN_TRIAGE,
    set_classification,
)
from apps.api.app.models.finding import (
    NormalizedFinding,
    FindingEvidence,
    FindingDecision,
    Classification,
    ReviewStatus,
)
from apps.api.app.models.remediation import RemediationPlan
from apps.api.app.schemas.finding import (
    FindingListItem,
    FindingDetail,
    TriageRequest,
    RemediateRequest,
    ApprovalRequest,
)

router = APIRouter()


async def _get_finding_with_access_check(finding_id: UUID, db: AsyncSession, user) -> NormalizedFinding:
    """Load a finding and verify the user has access to its repository."""
    result = await db.execute(
        select(NormalizedFinding).where(
            NormalizedFinding.id == finding_id,
            NormalizedFinding.tenant_id == user.tenant_id,
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    from apps.api.app.core.access_control import can_access_repository
    if not await can_access_repository(db, user, finding.repository_id):
        raise HTTPException(status_code=403, detail="Access denied")
    return finding


@router.get("/tags")
async def list_tags(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return all unique tags used across findings with counts.

    Defensive filter: `jsonb_typeof(tags) = 'array'` excludes rows
    where tags is the JSON `null` literal or any other non-array
    scalar — without this guard, jsonb_array_elements_text crashes
    with `cannot extract elements from a scalar` (Postgres error
    surfaced as a 500 to the UI). Bug fix 2026-04-27.
    """
    from sqlalchemy import text
    result = await db.execute(text("""
        SELECT tag, COUNT(*) as cnt
        FROM normalized_findings, jsonb_array_elements_text(tags) AS tag
        WHERE tenant_id = :tid
          AND tags IS NOT NULL
          AND jsonb_typeof(tags) = 'array'
        GROUP BY tag ORDER BY cnt DESC LIMIT 50
    """), {"tid": str(user.tenant_id)})
    return [{"tag": row[0], "count": row[1]} for row in result.all()]


@router.get("")
async def list_findings(
    severity: Optional[str] = Query(None),
    classification: Optional[str] = Query(None),
    review_status: Optional[str] = Query(None),
    remediation_status: Optional[str] = Query(None),
    scanner_name: Optional[str] = Query(None),
    repository_id: Optional[UUID] = Query(None),
    # Filter findings by their scan-source (Slack / Confluence / Jira / S3 / …).
    # Two flavours: ``scan_source_id`` for an exact source row, or
    # ``source_type`` for a category-level filter ("show me everything
    # from any Confluence connection"). Both join via the
    # NormalizedFinding.scan_source_id FK; ``source_type`` resolves
    # through the scan_sources table. Bug fix 2026-05-08 — before, the
    # router silently ignored these params and returned every finding
    # in the tenant, which broke the Findings-by-source UX.
    scan_source_id: Optional[UUID] = Query(None),
    source_type: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    # Filter by source_metadata.validation_status — added 2026-04-25 to
    # support the Dashboard "Active Credentials" Quick Action and any
    # downstream tools that need a definitive view of verifier-confirmed
    # live credentials (validation_status = "active"). Lives in JSONB so
    # we filter via the literal_column expression below rather than a
    # column-level == comparison.
    validation_status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: Optional[str] = Query("priority"),  # priority(default): Confirmed-TP→Likely-TP→Needs-Review→Likely-FP→Confirmed-FP, then severity; also: created_at, severity, classification, ai_confidence, title
    sort_dir: Optional[str] = Query("desc"),  # asc, desc
    # Findings from archived repositories are excluded from the default
    # list — same pattern as GitGuardian/Wiz/Snyk where archived sources
    # disappear from the active risk surface but stay queryable.  Set
    # ?include_archived_sources=true to surface them; rendering them
    # with an "Archived source" badge is the FE's responsibility.
    # When `repository_id` is provided explicitly, the filter is
    # bypassed — the user is intentionally looking at one repo, even if
    # that repo is archived (repo-detail page needs this).
    include_archived_sources: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Base filter with access control
    from apps.api.app.core.access_control import get_accessible_repo_ids
    base_filter = NormalizedFinding.tenant_id == user.tenant_id
    conditions = [base_filter]

    # Apply access control — limit to accessible repos
    accessible = await get_accessible_repo_ids(db, user)
    if accessible is not None:
        conditions.append(NormalizedFinding.repository_id.in_(accessible))

    if severity:
        conditions.append(NormalizedFinding.severity == severity)
    if classification:
        conditions.append(NormalizedFinding.classification == classification)
    if review_status:
        conditions.append(NormalizedFinding.review_status == review_status)
    if remediation_status:
        conditions.append(NormalizedFinding.remediation_status == remediation_status)
    if scanner_name:
        conditions.append(NormalizedFinding.scanner_name == scanner_name)
    if repository_id:
        conditions.append(NormalizedFinding.repository_id == repository_id)
    if scan_source_id:
        conditions.append(NormalizedFinding.scan_source_id == scan_source_id)
    if source_type:
        # source_type is a category filter — resolve to the set of
        # scan_source_ids of that type within this tenant, then filter.
        # Honours the same canonical/alias resolution as the rest of
        # the source-type API surface so callers can pass either form
        # ("microsoft_teams" or "ms_teams"). Two-step lookup keeps the
        # route fast (sub-query plan stays cheap when scan_sources is
        # small relative to normalized_findings).
        from apps.api.app.models.scan_source import ScanSource, normalize_source_type
        canonical = normalize_source_type(source_type)
        sub = select(ScanSource.id).where(
            ScanSource.tenant_id == user.tenant_id,
            ScanSource.source_type == canonical,
        ).scalar_subquery()
        conditions.append(NormalizedFinding.scan_source_id.in_(sub))
    if tag:
        conditions.append(NormalizedFinding.tags.contains([tag]))
    if validation_status:
        from sqlalchemy import literal_column
        conditions.append(
            literal_column("source_metadata->>'validation_status'") == validation_status
        )

    # ── Archive filter ─────────────────────────────────────────────
    # Default: hide findings whose parent (repo OR source) is archived.
    # "Archived" is unified across two storage shapes:
    #   - Repository:  metadata.archived == true
    #   - ScanSource:  is_active == false
    # Both mean "preserved, scanning paused, reversible".  Bypassed when
    # the caller explicitly filters by `repository_id` or `scan_source_id`
    # (detail pages legitimately need to show archived-parent findings)
    # or sets `include_archived_sources=true` (the FE toggle).
    if not include_archived_sources and not repository_id and not scan_source_id:
        from sqlalchemy import literal_column, and_
        from apps.api.app.models.repository import Repository
        from apps.api.app.models.scan_source import ScanSource as ScanSourceModel
        archived_repo_ids = select(Repository.id).where(
            Repository.tenant_id == user.tenant_id,
            literal_column("repositories.metadata->>'archived'") == "true",
        ).scalar_subquery()
        archived_source_ids = select(ScanSourceModel.id).where(
            ScanSourceModel.tenant_id == user.tenant_id,
            ScanSourceModel.is_active == False,  # noqa: E712
        ).scalar_subquery()
        conditions.append(
            and_(
                or_(
                    NormalizedFinding.repository_id.is_(None),
                    ~NormalizedFinding.repository_id.in_(archived_repo_ids),
                ),
                or_(
                    NormalizedFinding.scan_source_id.is_(None),
                    ~NormalizedFinding.scan_source_id.in_(archived_source_ids),
                ),
            )
        )
    if search:
        # Search across title, file_path, and scanner_rule_id so typing e.g.
        # "test" surfaces findings in test files, not just those with "test"
        # in their title.
        like = f"%{search}%"
        conditions.append(
            or_(
                NormalizedFinding.title.ilike(like),
                NormalizedFinding.file_path.ilike(like),
                NormalizedFinding.scanner_rule_id.ilike(like),
            )
        )

    # Count total
    from sqlalchemy import func as sa_func, literal_column
    count_query = select(sa_func.count(NormalizedFinding.id)).where(*conditions)
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Count UNIQUE credentials (grouped by secret_hash). The UI's
    # "Grouped" toggle collapses occurrences of the same secret to one
    # row, but the visible count is then per-PAGE which is misleading
    # ("40 unique" on page 1 even though there are 47 unique across the
    # full filtered set). Returning the global unique count here lets
    # the UI show the correct number regardless of pagination.
    #
    # Findings without a secret_hash (e.g. non-secret rules) each count
    # as their own "unique" — fall back to the finding id so each one
    # is distinct, matching the UI's grouping logic
    # (`hash = sm.secret_hash || f.id`).
    from sqlalchemy import cast, String
    unique_count_query = select(
        sa_func.count(
            sa_func.distinct(
                sa_func.coalesce(
                    literal_column("source_metadata->>'secret_hash'"),
                    cast(NormalizedFinding.id, String),
                )
            )
        )
    ).where(*conditions)
    unique_result = await db.execute(unique_count_query)
    unique_count = unique_result.scalar() or 0

    # Sort
    SORT_MAP = {
        "created_at": NormalizedFinding.created_at,
        "severity": NormalizedFinding.severity,
        "classification": NormalizedFinding.classification,
        "ai_confidence": NormalizedFinding.ai_confidence,
        "title": NormalizedFinding.title,
        "remediation_status": NormalizedFinding.remediation_status,
    }
    if sort_by == "priority":
        # Actionability order (the DEFAULT): classification confidence FIRST —
        # Confirmed-TP -> Likely-TP -> Needs-Review -> Likely-FP -> Confirmed-FP
        # — then severity (Critical->Info), then newest. NOTHING is filtered out:
        # the FP tiers simply sink to the bottom, so a real secret the AI
        # mislabels FP is still on the page, just lower (recall-safe). The order
        # is classification-PRIMARY on purpose: confirmed noise sinks below an
        # un-reviewed finding regardless of its nominal severity.
        from sqlalchemy import case as _case
        _class_pri = _case(
            (NormalizedFinding.classification == "CONFIRMED_TRUE_POSITIVE", 1),
            (NormalizedFinding.classification == "LIKELY_TRUE_POSITIVE", 2),
            (NormalizedFinding.classification == "NEEDS_REVIEW", 3),
            (NormalizedFinding.classification == "LIKELY_FALSE_POSITIVE", 4),
            (NormalizedFinding.classification == "CONFIRMED_FALSE_POSITIVE", 5),
            else_=3,  # unknown / not-yet-triaged -> needs-review tier (never bury it)
        )
        _sev_pri = _case(
            (NormalizedFinding.severity == "CRITICAL", 1),
            (NormalizedFinding.severity == "HIGH", 2),
            (NormalizedFinding.severity == "MEDIUM", 3),
            (NormalizedFinding.severity == "LOW", 4),
            else_=5,
        )
        order_clauses = [_class_pri.asc(), _sev_pri.asc(), NormalizedFinding.created_at.desc()]
    else:
        sort_col = SORT_MAP.get(sort_by, NormalizedFinding.created_at)
        order_clauses = [sort_col.asc() if sort_dir == "asc" else sort_col.desc()]

    # Query
    query = (
        select(NormalizedFinding)
        .where(*conditions)
        .order_by(*order_clauses)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(query)
    findings = result.scalars().all()

    # ── Resolve is_archived_parent per finding ─────────────────────
    # Bulk-fetch the set of archived parents (repos + sources) for the
    # tenant once, then membership-check per finding.  Avoids the N+1
    # join we'd get with `selectinload`.  Cheap because both sets are
    # typically tiny (archived = small fraction of total).
    from sqlalchemy import literal_column
    from apps.api.app.models.repository import Repository as Repo
    from apps.api.app.models.scan_source import ScanSource as Src
    archived_repos_rows = await db.execute(
        select(Repo.id).where(
            Repo.tenant_id == user.tenant_id,
            literal_column("repositories.metadata->>'archived'") == "true",
        )
    )
    archived_repo_ids: set = {row[0] for row in archived_repos_rows.all()}
    archived_sources_rows = await db.execute(
        select(Src.id).where(
            Src.tenant_id == user.tenant_id,
            Src.is_active == False,  # noqa: E712
        )
    )
    archived_source_ids: set = {row[0] for row in archived_sources_rows.all()}

    items = []
    for f in findings:
        is_archived_parent = (
            (f.repository_id is not None and f.repository_id in archived_repo_ids)
            or (f.scan_source_id is not None and f.scan_source_id in archived_source_ids)
        )
        # Construct via model_validate so all the from_attributes plumbing
        # keeps working, then set the derived field on the dumped dict.
        item = FindingListItem.model_validate(f, from_attributes=True).model_dump()
        item["is_archived_parent"] = is_archived_parent
        items.append(item)

    # Return paginated response with metadata
    return {
        "items": items,
        "total": total,
        # Global count of distinct credentials matching the filter set
        # (deduplicated by source_metadata.secret_hash, with the
        # finding id as the fallback key for non-secret findings).
        # The UI displays this as "N unique" alongside the total.
        "unique_count": unique_count,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
    }


@router.get("/{finding_id}", response_model=FindingDetail)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    finding = await _get_finding_with_access_check(finding_id, db, user)

    # Load related data
    evidence_result = await db.execute(
        select(FindingEvidence).where(FindingEvidence.finding_id == finding.id)
    )
    decisions_result = await db.execute(
        select(FindingDecision)
        .where(FindingDecision.finding_id == finding.id)
        .order_by(FindingDecision.created_at.desc())
    )
    plans_result = await db.execute(
        select(RemediationPlan).where(RemediationPlan.finding_id == finding.id)
    )

    # Resolve user names for decisions
    from apps.api.app.models.user import User as UserModel
    decision_list = decisions_result.scalars().all()
    user_ids = list(set(d.user_id for d in decision_list))
    user_map = {}
    if user_ids:
        users_result = await db.execute(
            select(UserModel).where(UserModel.id.in_(user_ids))
        )
        user_map = {u.id: u.full_name for u in users_result.scalars().all()}

    # Derive is_archived_parent — one cheap check per parent type.
    # Single-row endpoint, so just SELECT the relevant parent's archive
    # state rather than bulk-fetching (the list endpoint above batches).
    is_archived_parent = False
    if finding.repository_id is not None:
        from sqlalchemy import literal_column
        from apps.api.app.models.repository import Repository as Repo
        repo_archived = await db.execute(
            select(literal_column("metadata->>'archived'"))
            .where(Repo.id == finding.repository_id, Repo.tenant_id == user.tenant_id)
        )
        is_archived_parent = repo_archived.scalar() == "true"
    elif finding.scan_source_id is not None:
        from apps.api.app.models.scan_source import ScanSource as Src
        src_active = await db.execute(
            select(Src.is_active).where(Src.id == finding.scan_source_id, Src.tenant_id == user.tenant_id)
        )
        val = src_active.scalar()
        is_archived_parent = val is False

    finding_dict = {
        **{c.name: getattr(finding, c.name) for c in finding.__table__.columns},
        "is_archived_parent": is_archived_parent,
        "evidence": [
            {"type": e.evidence_type, "file": e.file_path, "summary": e.summary, "content": e.content}
            for e in evidence_result.scalars().all()
        ],
        "decisions": [
            {
                "action": d.action,
                "comment": d.comment,
                "created_at": str(d.created_at),
                "user_name": user_map.get(d.user_id, "Unknown"),
                "user_id": str(d.user_id),
                "previous_classification": d.previous_classification,
                "new_classification": d.new_classification,
            }
            for d in decision_list
        ],
        "remediation_plans": [],
    }

    # Load full remediation plans with patches
    from apps.api.app.models.remediation import RemediationPatch
    plans = plans_result.scalars().all()
    for p in plans:
        patches_r = await db.execute(
            select(RemediationPatch).where(RemediationPatch.plan_id == p.id).order_by(RemediationPatch.created_at.desc())
        )
        patches = patches_r.scalars().all()
        plan_data = {
            "id": str(p.id),
            "summary": p.vulnerability_summary,
            "root_cause": p.root_cause,
            "fix_rationale": p.fix_rationale,
            "confidence": p.confidence_score,
            "risk_of_breakage": p.risk_of_breakage,
            "developer_notes": p.developer_notes or [],
            "validation_steps": p.validation_steps or [],
            "generated_by": p.generated_by,
            "patch_diff": patches[0].patch_diff if patches else None,
            "files_changed": patches[0].files_changed if patches else [],
            "patch_status": patches[0].status.value if patches and hasattr(patches[0].status, 'value') else (patches[0].status if patches else None),
            "safety_score": patches[0].safety_score if patches else None,
            "pr_url": patches[0].pr_url if patches else None,
        }
        finding_dict["remediation_plans"].append(plan_data)

    return finding_dict


@router.post("/{finding_id}/triage")
async def triage_finding(
    finding_id: UUID,
    body: TriageRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    finding = await _get_finding_with_access_check(finding_id, db, user)

    # ── Optimistic-lock check ────────────────────────────────────
    # When the client passes ``expected_version``, reject the write
    # if the row has moved on since they loaded it.  Returns 409
    # with the live version so the UI can refetch and re-prompt.
    # Omitted version => legacy last-write-wins (preserved for CI
    # scripts / integrations not yet aware of the protocol).
    if body.expected_version is not None and body.expected_version != finding.version:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "stale_version",
                "message": "Finding was modified by another reviewer; reload and retry.",
                "current_version": finding.version,
                "expected_version": body.expected_version,
            },
        )

    action_map = {
        "mark_fp": Classification.CONFIRMED_FALSE_POSITIVE,
        "mark_tp": Classification.CONFIRMED_TRUE_POSITIVE,
        "accept_risk": Classification.ACCEPTED_RISK,
        "reopen": Classification.NEEDS_REVIEW,
        "request_review": None,
        # ── Closure-state actions added 2026-05-04 ──
        # The findings UI dropdown has exposed these two buttons for
        # months but they silently fell through to None (no class
        # change, no audit trail beyond the action string). Wired up
        # alongside the corresponding enum values + DB migration
        # k8l9m0n1o2p3. See the migration's docstring for the
        # full backstory.
        "mark_rotated": Classification.ROTATED,
        "mark_test": Classification.TEST_CREDENTIAL,
    }

    new_class = action_map.get(body.action)
    old_class = finding.classification

    decision = FindingDecision(
        finding_id=finding.id,
        user_id=user.id,
        action=body.action,
        previous_classification=old_class.value if old_class else None,
        new_classification=new_class.value if new_class else None,
        comment=body.comment,
    )
    db.add(decision)

    if new_class:
        # The decision row created above IS the provenance; recording it
        # on the finding means a confirmed verdict can be attributed
        # without joining, and lets the guard verify the write.
        set_classification(
            finding, new_class,
            mechanism=MECHANISM_HUMAN_TRIAGE,
            actor=user.id,
            decision_id=decision.id,
        )
    finding.review_status = ReviewStatus.REVIEWED

    # ── Case-B: cascade triage UP to the parent incident ──
    # Per-finding triage is a decision about the CREDENTIAL, not just
    # this one location.  Apply the same classification + review_status
    # to the parent SecretIncident so other occurrences of the same
    # credential (and the /incidents view) stay in sync.  Also cascade
    # to all SIBLING occurrences so the legacy per-finding views keep
    # working until the UI fully migrates to the incident-primary
    # surface.  Without this, triaging from /findings leaves /incidents
    # stale.
    if new_class and finding.incident_id is not None:
        from apps.api.app.models.finding import SecretIncident
        from sqlalchemy import update as sa_update
        # Lowercase enum-value form — matches how SecretIncident stores
        # its VARCHAR classification (see migration s6t7u8v9w0x1).
        inc_class = new_class.value
        await db.execute(
            sa_update(SecretIncident)
            .where(
                SecretIncident.id == finding.incident_id,
                SecretIncident.tenant_id == user.tenant_id,
            )
            .values(classification=inc_class, review_status="reviewed")
        )
        # Cascade to sibling occurrences (other findings of the same
        # incident).  Excludes the current finding because it was
        # already set above.
        await db.execute(
            sa_update(NormalizedFinding)
            .where(
                NormalizedFinding.incident_id == finding.incident_id,
                NormalizedFinding.tenant_id == user.tenant_id,
                NormalizedFinding.id != finding.id,
            )
            .values(classification=new_class, review_status=ReviewStatus.REVIEWED)
        )

    await db.flush()

    # Store user decision in cache for future scans
    try:
        from services.normalization.decision_cache import store_user_decision_in_cache
        if new_class and finding.stability_id:
            await store_user_decision_in_cache(db, finding, new_class.value, user.id)
            await db.flush()
    except Exception:
        pass  # Don't fail triage if cache store fails

    # Trigger async recalibration in background
    try:
        from apps.worker.tasks import recalibrate_tenant
        recalibrate_tenant.delay(str(user.tenant_id))
    except Exception:
        pass

    from apps.api.app.core.audit import log_audit
    # Carry the provenance marker into the audit metadata so the
    # History tab can render SuggestionChip-driven actions distinctly
    # from manual triage.  `source` defaults to None — we coerce to
    # "manual" on the metadata side so the JSON shape is always
    # populated (easier downstream filtering).
    await log_audit(
        db, user, "finding_triaged", "finding", finding_id,
        f"Action: {body.action}, classification: {finding.classification.value}"
        + (f", via: {body.source}" if body.source else ""),
        metadata={
            "action": body.action,
            "classification": finding.classification.value,
            "comment": body.comment,
            "via": body.source or "manual",
        },
    )

    return {"status": "ok", "classification": finding.classification.value}


# ── Bulk triage ──────────────────────────────────────────────────────
#
# Replaces the fan-out pattern the UI used to do (JS Promise.all of
# N triageFinding() calls — one HTTP round trip per finding).  At
# 500 selected findings on a typical install that was 500 × ~50ms =
# 25s wall-clock with no transactional guarantee.  Single-call
# version moves the work server-side and gives us one audit summary
# entry instead of 500 individual ones.
#
# Action vocabulary matches the single-finding /triage endpoint
# exactly so the Findings drawer + the bulk bar commit identical
# state for the same action keyword.

_BULK_FINDING_ACTION_MAP: dict = {
    "mark_fp": Classification.CONFIRMED_FALSE_POSITIVE,
    "mark_tp": Classification.CONFIRMED_TRUE_POSITIVE,
    "accept_risk": Classification.ACCEPTED_RISK,
    "reopen": Classification.NEEDS_REVIEW,
    "mark_rotated": Classification.ROTATED,
    "mark_test": Classification.TEST_CREDENTIAL,
}


class BulkFindingTriageRequest(BaseModel):
    finding_ids: list[UUID]
    action: str
    comment: Optional[str] = None

    @field_validator("finding_ids")
    @classmethod
    def _non_empty(cls, v: list[UUID]) -> list[UUID]:
        if not v:
            raise ValueError("finding_ids cannot be empty")
        if len(v) > 500:
            raise ValueError("Up to 500 findings per bulk-triage request")
        return v

    @field_validator("action")
    @classmethod
    def _known_action(cls, v: str) -> str:
        if v not in _BULK_FINDING_ACTION_MAP:
            raise ValueError(
                f"Unknown action '{v}'. Must be one of: "
                + ", ".join(sorted(_BULK_FINDING_ACTION_MAP.keys()))
            )
        return v


class BulkFindingTriageResponse(BaseModel):
    updated: int       # findings whose classification was actually changed
    unchanged: int     # findings already in the requested classification
    not_found: int     # finding_ids that didn't resolve to a tenant row
    incidents_cascaded: int  # parent SecretIncident rows updated
    siblings_cascaded: int   # sibling occurrence rows updated


@router.post("/bulk-triage", response_model=BulkFindingTriageResponse)
async def bulk_triage_findings(
    body: BulkFindingTriageRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Apply the same triage action to N findings in one transaction.

    Behaviour per finding:
      1. Skip if not in tenant (not_found)
      2. Skip if already in the requested classification (unchanged)
      3. Update classification + review_status
      4. Cascade to parent SecretIncident (Case-B), same as single-
         finding triage does
      5. Cascade to sibling occurrences
      6. Write a FindingDecision row (powers the per-finding History
         tab — keeps lockstep with the single-triage path)
      7. Write an audit entry with via="bulk_triage"

    Notes:
      - Does NOT call the decision-cache store_user_decision_in_cache
        path per finding — that's a hot path that recomputes
        stability-based decision caching and is expensive at N=500.
        Tenant-level recalibration (kicked once at the end) covers
        the same purpose for bulk operations.
      - Does NOT write a FindingDecision for the `mark_rotated`
        cascade through to siblings — only the directly-selected
        findings get decision rows.  Siblings inherit via the bulk
        UPDATE but their History tab will not show the action (same
        behaviour as the single-finding path).
    """
    from apps.api.app.core.audit import log_audit
    from apps.api.app.models.finding import FindingDecision, SecretIncident
    from sqlalchemy import update as sa_update

    new_class: Classification = _BULK_FINDING_ACTION_MAP[body.action]

    rows = await db.execute(
        select(NormalizedFinding).where(
            NormalizedFinding.id.in_(body.finding_ids),
            NormalizedFinding.tenant_id == user.tenant_id,
        )
    )
    findings = list(rows.scalars().all())
    found_ids = {f.id for f in findings}
    not_found = len(body.finding_ids) - len(found_ids)

    updated = 0
    unchanged = 0
    incidents_cascaded = 0
    siblings_cascaded = 0

    # Group findings by incident_id so we cascade once per parent
    # incident instead of N times (matters when the user bulk-triages
    # 200 findings that all belong to 5 incidents).
    incident_to_findings: dict = {}
    for f in findings:
        if f.classification == new_class:
            unchanged += 1
            continue
        if f.incident_id:
            incident_to_findings.setdefault(f.incident_id, []).append(f)
        else:
            incident_to_findings.setdefault(None, []).append(f)

    for f in findings:
        if f.classification == new_class:
            continue  # already counted as unchanged above
        old_class = f.classification

        # FindingDecision row — feeds the per-finding History timeline.
        db.add(FindingDecision(
            finding_id=f.id,
            user_id=user.id,
            action=body.action,
            previous_classification=old_class.value if old_class else None,
            new_classification=new_class.value,
            comment=body.comment,
        ))

        set_classification(
            f, new_class,
            mechanism=MECHANISM_BULK_TRIAGE,
            actor=user.id,
        )
        f.review_status = ReviewStatus.REVIEWED
        updated += 1

    # Cascade to parent SecretIncident + sibling occurrences, one
    # round-trip per affected incident.
    inc_class_str = new_class.value  # lowercase for SecretIncident.classification (VARCHAR)
    for incident_id, sel_findings in incident_to_findings.items():
        if incident_id is None:
            continue
        # Update parent incident.
        inc_result = await db.execute(
            sa_update(SecretIncident)
            .where(
                SecretIncident.id == incident_id,
                SecretIncident.tenant_id == user.tenant_id,
            )
            .values(classification=inc_class_str, review_status="reviewed")
        )
        incidents_cascaded += inc_result.rowcount or 0

        # Cascade to siblings (other findings in the same incident
        # that weren't part of this bulk request).
        selected_ids = {f.id for f in sel_findings}
        sib_result = await db.execute(
            sa_update(NormalizedFinding)
            .where(
                NormalizedFinding.incident_id == incident_id,
                NormalizedFinding.tenant_id == user.tenant_id,
                ~NormalizedFinding.id.in_(selected_ids),
            )
            .values(classification=new_class, review_status=ReviewStatus.REVIEWED)
        )
        siblings_cascaded += sib_result.rowcount or 0

    # One audit summary entry — the per-finding FindingDecision rows
    # already provide the detailed trail; this gives the audit page a
    # single line about the bulk op for "show me bulk actions this
    # week" queries.
    await log_audit(
        db, user, "findings_bulk_triaged", "finding",
        resource_id=None,
        detail=(
            f"action={body.action}; updated={updated}; "
            f"unchanged={unchanged}; not_found={not_found}; "
            f"incidents_cascaded={incidents_cascaded}; "
            f"siblings_cascaded={siblings_cascaded}"
            + (f"; comment={body.comment[:200]!r}" if body.comment else "")
        ),
        metadata={
            "action": body.action,
            "finding_ids": [str(i) for i in body.finding_ids],
            "updated": updated,
            "unchanged": unchanged,
            "not_found": not_found,
            "incidents_cascaded": incidents_cascaded,
            "siblings_cascaded": siblings_cascaded,
            "comment": body.comment,
            "via": "bulk_triage",
        },
    )

    # Background recalibration — same trigger the single-triage path
    # uses, fired once for the whole bulk operation instead of N
    # times.  Idempotent and fail-safe.
    try:
        from apps.worker.tasks import recalibrate_tenant
        recalibrate_tenant.delay(str(user.tenant_id))
    except Exception:
        pass

    await db.commit()

    return BulkFindingTriageResponse(
        updated=updated,
        unchanged=unchanged,
        not_found=not_found,
        incidents_cascaded=incidents_cascaded,
        siblings_cascaded=siblings_cascaded,
    )


@router.post("/{finding_id}/verify")
async def verify_finding_credential(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Manually trigger credential verification for a finding."""
    result = await db.execute(
        select(NormalizedFinding).where(
            NormalizedFinding.id == finding_id,
            NormalizedFinding.tenant_id == user.tenant_id,
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    sm = finding.source_metadata or finding.raw_data or {}

    from services.secret_verification.verifier import verify_finding as _verify, SUPPORTED_PROVIDERS
    provider = (sm.get("provider") or "").lower()
    if provider not in SUPPORTED_PROVIDERS:
        return {"status": "unsupported", "message": f"No verifier for provider: {provider}"}

    verification = await _verify(sm)
    if verification:
        updated_sm = dict(sm)
        updated_sm["validation_status"] = verification.status
        updated_sm["verification_details"] = verification.details
        updated_sm["verification_permissions"] = verification.permissions

        # Auto-run Blast Radius analysis if credential is active
        blast_radius = None
        if verification.status == "active":
            from services.secret_verification.blast_radius import analyze_blast_radius
            br_result = await analyze_blast_radius(updated_sm)
            if br_result:
                updated_sm["blast_radius"] = br_result.to_dict()
                blast_radius = br_result.to_dict()

        finding.source_metadata = updated_sm
        await db.commit()
        return {
            "status": verification.status,
            "details": verification.details,
            "permissions": verification.permissions,
            "provider": verification.provider,
            "blast_radius": blast_radius,
        }

    return {"status": "error", "message": "Verification failed"}


@router.get("/{finding_id}/blast-radius")
async def get_blast_radius(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get blast radius analysis for a finding. Returns cached result or runs fresh analysis."""
    result = await db.execute(
        select(NormalizedFinding).where(
            NormalizedFinding.id == finding_id,
            NormalizedFinding.tenant_id == user.tenant_id,
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    sm = finding.source_metadata or {}

    # Return cached blast radius if available
    cached = sm.get("blast_radius")
    if cached:
        return cached

    # Run fresh analysis if credential was verified as active
    if sm.get("validation_status") != "active":
        return {"error": "Blast radius requires an active (verified) credential. Run verification first."}

    from services.secret_verification.blast_radius import analyze_blast_radius
    br_result = await analyze_blast_radius(sm)
    if br_result:
        updated_sm = dict(sm)
        updated_sm["blast_radius"] = br_result.to_dict()
        finding.source_metadata = updated_sm
        await db.commit()
        return br_result.to_dict()

    return {"error": "Blast radius analysis not available for this provider"}


@router.post("/{finding_id}/remediate")
async def request_remediation(
    finding_id: UUID,
    body: RemediateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    finding = await _get_finding_with_access_check(finding_id, db, user)

    from apps.worker.tasks import generate_remediation
    generate_remediation.delay(str(finding.id))

    finding.remediation_status = "pending"
    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "remediation_requested", "finding", finding_id, f"Remediation requested for {finding.title[:60]}")

    return {"status": "remediation_requested"}


@router.post("/{finding_id}/approve")
async def approve_patch(
    finding_id: UUID,
    body: ApprovalRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    finding = await _get_finding_with_access_check(finding_id, db, user)

    decision = FindingDecision(
        finding_id=finding.id,
        user_id=user.id,
        action=f"patch_{body.action}",
        comment=body.comment,
    )
    db.add(decision)

    if body.action == "approve":
        finding.remediation_status = "approved"
        # Dispatch PR creation task
        from apps.worker.tasks import create_fix_pr
        create_fix_pr.delay(str(finding.id))
    elif body.action == "reject":
        finding.remediation_status = "rejected"

    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, f"patch_{body.action}", "finding", finding_id, f"Patch {body.action}d: {body.comment or ''}")

    return {"status": body.action, "pr_creating": body.action == "approve"}


@router.post("/batch-remediate")
async def batch_remediate_findings(
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate AI remediation for multiple findings at once."""
    finding_ids = body.get("finding_ids", [])
    repository_id = body.get("repository_id")
    if not finding_ids or not repository_id:
        raise HTTPException(status_code=400, detail="finding_ids and repository_id required")

    # Access control — verify user can access this repository
    from apps.api.app.core.access_control import can_access_repository
    if not await can_access_repository(db, user, repository_id):
        raise HTTPException(status_code=403, detail="Access denied")

    from apps.worker.tasks import batch_remediate
    batch_remediate.delay(repository_id, finding_ids, str(user.tenant_id))

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "batch_remediation", "finding", repository_id, f"Batch remediation for {len(finding_ids)} findings")

    return {"status": "batch_remediation_started", "findings": len(finding_ids)}


@router.post("/{finding_id}/comment")
async def add_comment(
    finding_id: UUID,
    body: TriageRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Add a standalone comment to a finding without changing its classification."""
    finding = await _get_finding_with_access_check(finding_id, db, user)

    decision = FindingDecision(
        finding_id=finding.id,
        user_id=user.id,
        action="comment",
        previous_classification=finding.classification.value if hasattr(finding.classification, 'value') else str(finding.classification),
        new_classification=finding.classification.value if hasattr(finding.classification, 'value') else str(finding.classification),
        comment=body.comment or "",
    )
    db.add(decision)
    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "comment_added", "finding", finding_id, f"Comment on finding")

    return {"status": "ok", "comment_saved": True}


@router.post("/{finding_id}/assign")
async def assign_finding(
    finding_id: UUID,
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Assign a finding to a user."""
    finding = await _get_finding_with_access_check(finding_id, db, user)

    from datetime import datetime, timezone
    assignee_id = body.get("user_id")
    finding.assigned_to = assignee_id
    finding.assigned_at = datetime.now(timezone.utc) if assignee_id else None
    await db.flush()

    # Audit
    decision = FindingDecision(
        finding_id=finding.id, user_id=user.id, action="assign",
        comment=f"Assigned to {body.get('user_name', assignee_id or 'unassigned')}",
    )
    db.add(decision)
    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "finding_assigned", "finding", finding_id, f"Assigned to {body.get('user_name', assignee_id or 'unassigned')}")

    return {"status": "ok", "assigned_to": str(assignee_id) if assignee_id else None}


@router.post("/{finding_id}/tags")
async def update_tags(
    finding_id: UUID,
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update tags on a finding."""
    finding = await _get_finding_with_access_check(finding_id, db, user)

    tags = body.get("tags", [])
    if not isinstance(tags, list):
        raise HTTPException(status_code=400, detail="Tags must be a list")
    # Sanitize: lowercase, strip, max 20 tags, max 50 chars each
    clean_tags = list(set([t.strip().lower()[:50] for t in tags if isinstance(t, str) and t.strip()]))[:20]
    finding.tags = clean_tags
    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "tags_updated", "finding", finding_id, f"Tags updated: {body.get('tags', [])}")

    return {"status": "ok", "tags": clean_tags}


@router.post("/{finding_id}/mark-false-positive")
async def mark_false_positive(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return await triage_finding(
        finding_id,
        TriageRequest(action="mark_fp"),
        db=db,
        user=user,
    )
