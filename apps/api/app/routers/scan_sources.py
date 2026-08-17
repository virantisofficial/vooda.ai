# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Scan Sources API — manage non-git sources (Slack, Confluence, S3, etc.)."""

from datetime import datetime, timedelta, timezone
from uuid import UUID
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func


# ── Stale-source derivation ─────────────────────────────────────────
# Expected interval per schedule.  on_demand sources never become
# stale (they only run when explicitly triggered).  We allow 2× the
# nominal interval before flagging — a daily schedule that missed
# one run is noise; missing two days in a row is signal.
_STALE_THRESHOLDS: dict[str, timedelta] = {
    "hourly": timedelta(hours=2),
    "daily": timedelta(days=2),
    "weekly": timedelta(weeks=2),
}


def _compute_is_stale(
    last_scan_at: Optional[datetime],
    scan_schedule: Optional[str],
    is_active: bool,
) -> bool:
    """Return True when a source on a recurring schedule hasn't scanned
    within 2× its expected interval.

    Inactive sources are never stale (they're deliberately paused).
    on_demand sources are never stale (no implied cadence).  Sources
    that have never scanned ARE stale once they've been active for
    long enough — but we can't tell that from this signature alone;
    treat "never scanned" as stale to surface mis-configured sources
    that the scheduler is silently failing to pick up.
    """
    if not is_active:
        return False
    threshold = _STALE_THRESHOLDS.get(scan_schedule or "")
    if threshold is None:
        return False  # on_demand or unknown schedule — no implied cadence
    if last_scan_at is None:
        return True  # active + recurring + never run = silent failure
    now = datetime.now(timezone.utc)
    # Be defensive about naive timestamps from older rows.
    if last_scan_at.tzinfo is None:
        last_scan_at = last_scan_at.replace(tzinfo=timezone.utc)
    return (now - last_scan_at) > threshold

logger = structlog.get_logger(__name__)

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.scan_source import ScanSource, SCAN_SOURCE_TYPES, normalize_source_type
from apps.api.app.models.integration import IntegrationConfig
from apps.api.app.models.repository import Repository
from apps.api.app.models.access import BusinessUnit
from apps.api.app.schemas.scan_source import (
    ScanSourceCreate, ScanSourceUpdate, ScanSourceResponse, SOURCE_TYPE_SCHEMAS,
    get_default_schedule,
)

router = APIRouter()


async def _validate_target_scope(
    db: AsyncSession,
    tenant_id: UUID,
    target_repository_id: Optional[UUID],
    target_business_unit_id: Optional[UUID],
) -> None:
    """Validate per-source scope binding.

    - Both NULL  → org-wide (allowed, default)
    - Only one set → must belong to tenant
    - Both set     → repository wins (worker honours that), but we still
                     validate both exist + belong to tenant so the saved
                     state is coherent. UI is expected to enforce
                     exclusivity at the form level.
    """
    if target_repository_id is not None:
        result = await db.execute(
            select(Repository).where(
                Repository.id == target_repository_id,
                Repository.tenant_id == tenant_id,
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="target_repository_id not found")

    if target_business_unit_id is not None:
        result = await db.execute(
            select(BusinessUnit).where(
                BusinessUnit.id == target_business_unit_id,
                BusinessUnit.tenant_id == tenant_id,
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="target_business_unit_id not found")


@router.get("/types")
async def list_source_types():
    """Return available source types with their config schemas.

    Enriches each entry with `default_schedule` so the frontend can
    pre-fill the Schedule dropdown when a user picks a source type.
    Without this, every new source would land on "on_demand" — the
    legacy default — which means "scans never run automatically."
    See schemas/scan_source.py for the per-category defaults.
    """
    enriched = {
        key: {**schema, "default_schedule": get_default_schedule(key)}
        for key, schema in SOURCE_TYPE_SCHEMAS.items()
        if key in SCAN_SOURCE_TYPES  # Enterprise-only types excluded in community
    }
    return enriched


@router.post("", response_model=ScanSourceResponse)
async def create_scan_source(
    data: ScanSourceCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create a new scan source linked to an integration config."""
    # Resolve friendly aliases (microsoft_teams → ms_teams, etc.)
    # before validating; clients writing against the docs use the
    # alias names. Bug fix 2026-05-08.
    data.source_type = normalize_source_type(data.source_type)
    # Validate source type
    if data.source_type not in SCAN_SOURCE_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid source type: {data.source_type}. Valid: {sorted(SCAN_SOURCE_TYPES)}")

    # Validate integration config exists and belongs to tenant
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == data.integration_config_id,
            IntegrationConfig.tenant_id == user.tenant_id,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration config not found")

    # Validate per-source scope binding (target_repository_id / target_business_unit_id)
    await _validate_target_scope(
        db, user.tenant_id, data.target_repository_id, data.target_business_unit_id
    )

    # Resolve scan_schedule: explicit value wins; None means "give me
    # the smart default for this source category."  This is what
    # closes the "new sources land on on_demand and never auto-scan"
    # footgun — see DEFAULT_SCHEDULE_BY_SOURCE_TYPE in
    # schemas/scan_source.py.  Existing sources are never touched;
    # only fresh CREATEs go through this resolution.
    resolved_schedule = (
        data.scan_schedule
        if data.scan_schedule
        else get_default_schedule(data.source_type)
    )

    source = ScanSource(
        name=data.name,
        source_type=data.source_type,
        integration_config_id=data.integration_config_id,
        scan_schedule=resolved_schedule,
        config=data.config,
        target_repository_id=data.target_repository_id,
        target_business_unit_id=data.target_business_unit_id,
        tenant_id=user.tenant_id,
    )
    db.add(source)
    await db.commit()
    await db.refresh(source)
    return source


@router.get("")
async def list_scan_sources(
    source_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List scan sources with optional type filter and pagination."""
    base = select(ScanSource).where(ScanSource.tenant_id == user.tenant_id)

    # Allow alias names in the filter (microsoft_teams → ms_teams).
    if source_type:
        canonical = normalize_source_type(source_type)
        if canonical in SCAN_SOURCE_TYPES:
            base = base.where(ScanSource.source_type == canonical)

    # Count
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0

    # Paginate
    base = base.order_by(ScanSource.created_at.desc())
    base = base.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(base)
    items = result.scalars().all()

    # ── Embed recent-scan summary per source ─────────────────────
    # Frontend renders an activity-dot strip on each connected
    # source card (last 5 scans, colored by outcome). Doing this
    # in one batched query is much cheaper than N+1 round-trips
    # from the FE. Limit 5 per source to bound payload size.
    from apps.api.app.models.scan import ScanJob, ScanStatus
    recent_by_source: dict[str, list[dict]] = {}
    if items:
        source_ids = [s.id for s in items]
        # Window function: rank scans within each source by created_at
        # DESC, keep only the top 5. PostgreSQL native, no app-side
        # iteration. Cheap on the existing scan_jobs.scan_source_id index.
        from sqlalchemy import select as sa_select, func as sa_func
        rn = sa_func.row_number().over(
            partition_by=ScanJob.scan_source_id,
            order_by=ScanJob.created_at.desc(),
        ).label("rn")
        sub = sa_select(
            ScanJob.id, ScanJob.scan_source_id, ScanJob.status,
            ScanJob.stats, ScanJob.created_at, ScanJob.error_detail, rn,
        ).where(ScanJob.scan_source_id.in_(source_ids)).subquery()
        recent_q = sa_select(sub).where(sub.c.rn <= 5).order_by(
            sub.c.scan_source_id, sub.c.created_at.desc()
        )
        recent_rows = (await db.execute(recent_q)).all()
        for row in recent_rows:
            sid = str(row.scan_source_id)
            recent_by_source.setdefault(sid, []).append({
                "id": str(row.id),
                "status": row.status.value if hasattr(row.status, "value") else str(row.status),
                "findings_total": (row.stats or {}).get("findings_total", 0) if isinstance(row.stats, dict) else 0,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "error": (row.error_detail or "")[:140] if row.error_detail else None,
            })

    response_items = []
    for s in items:
        item = ScanSourceResponse.model_validate(s).model_dump()
        item["recent_scans"] = recent_by_source.get(str(s.id), [])
        # Surface staleness here so the FE doesn't need to know schedule
        # intervals.  Drives the amber "needs attention" pip on cards
        # and the optional "Stale only" filter chip.
        item["is_stale"] = _compute_is_stale(s.last_scan_at, s.scan_schedule, s.is_active)
        response_items.append(item)

    return {
        "items": response_items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


@router.get("/{source_id}", response_model=ScanSourceResponse)
async def get_scan_source(
    source_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanSource).where(ScanSource.id == source_id, ScanSource.tenant_id == user.tenant_id)
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Scan source not found")
    # ScanSourceResponse pulls is_stale from the ORM row by default
    # (which has no such attribute → False).  Re-validate via dict so
    # we can inject the computed staleness for parity with the list
    # endpoint and the detail-drawer.
    payload = ScanSourceResponse.model_validate(source).model_dump()
    payload["is_stale"] = _compute_is_stale(
        source.last_scan_at, source.scan_schedule, source.is_active,
    )
    return payload


@router.put("/{source_id}", response_model=ScanSourceResponse)
async def update_scan_source(
    source_id: UUID,
    data: ScanSourceUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update a scan source.

    Audit-logging behaviour mirrors the repository archive/unarchive
    contract:
      - When `is_active` flips True → False we emit `source_archived`
        and stamp `sync_state.archived_at` + `sync_state.archived_by`.
      - When `is_active` flips False → True we emit `source_unarchived`
        and clear those keys.
    These two events are the single source of truth for compliance
    reviewers ("who archived source X, when?") and back the
    Archived-since-N-days query.

    `archived_at` / `archived_by` are stored inside `sync_state` so we
    don't need a schema migration to ship parity with repos.  The
    sub-keys are namespaced clearly so they can't collide with
    scan-engine sync state.
    """
    from apps.api.app.core.audit import log_audit
    from datetime import datetime, timezone

    result = await db.execute(
        select(ScanSource).where(ScanSource.id == source_id, ScanSource.tenant_id == user.tenant_id)
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Scan source not found")

    # Snapshot the prior state so we can detect the archive transition
    # AFTER the field assignments below.
    previous_is_active = source.is_active

    if data.name is not None:
        source.name = data.name
    if data.is_active is not None:
        source.is_active = data.is_active
    if data.scan_schedule is not None:
        source.scan_schedule = data.scan_schedule
    if data.config is not None:
        source.config = data.config

    # Per-source scope: PATCH semantics — fields default to None if
    # omitted by the client, so we only touch them when present in
    # the raw request body. `model_fields_set` is Pydantic v2's
    # "what did the client actually send" introspection.
    sent = data.model_fields_set
    if "target_repository_id" in sent or "target_business_unit_id" in sent:
        new_repo_id = data.target_repository_id if "target_repository_id" in sent else source.target_repository_id
        new_bu_id = data.target_business_unit_id if "target_business_unit_id" in sent else source.target_business_unit_id
        await _validate_target_scope(db, user.tenant_id, new_repo_id, new_bu_id)
        if "target_repository_id" in sent:
            source.target_repository_id = data.target_repository_id
        if "target_business_unit_id" in sent:
            source.target_business_unit_id = data.target_business_unit_id

    # ── Archive lifecycle: audit + metadata stamps ─────────────────
    # Detect transitions only (avoids double-logging on no-op PUTs).
    if data.is_active is not None and previous_is_active != source.is_active:
        sync_state = dict(source.sync_state or {})
        if source.is_active is False:
            # ARCHIVED — stamp who/when so compliance can answer
            # "show me sources archived in the last 30 days".
            sync_state["archived_at"] = datetime.now(timezone.utc).isoformat()
            sync_state["archived_by"] = str(user.id)
            source.sync_state = sync_state
            await log_audit(
                db, user, "source_archived", "scan_source", source_id,
                f"Archived source '{source.name}' ({source.source_type}) — scanning paused, findings preserved",
                request=request,
                metadata={"source_name": source.name, "source_type": source.source_type},
            )
        else:
            # UNARCHIVED — clear the archive markers.
            sync_state.pop("archived_at", None)
            sync_state.pop("archived_by", None)
            source.sync_state = sync_state
            await log_audit(
                db, user, "source_unarchived", "scan_source", source_id,
                f"Unarchived source '{source.name}' ({source.source_type}) — scanning resumed",
                request=request,
                metadata={"source_name": source.name, "source_type": source.source_type},
            )

    await db.commit()
    await db.refresh(source)
    return source


@router.get("/{source_id}/delete-preview")
async def get_source_delete_preview(
    source_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Impact preview for permanent source delete — see the
    repositories router's get_delete_preview for the design rationale.
    Mirrors that response shape so the FE modal renders identically
    regardless of scope.
    """
    from sqlalchemy import func as sa_func, literal_column, and_
    from apps.api.app.models.finding import NormalizedFinding, SecretIncident
    from apps.api.app.models.scan import ScanJob

    source_q = await db.execute(
        select(ScanSource).where(
            ScanSource.id == source_id,
            ScanSource.tenant_id == user.tenant_id,
        )
    )
    source = source_q.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Scan source not found")

    findings_q = await db.execute(
        select(sa_func.count(NormalizedFinding.id)).where(
            NormalizedFinding.scan_source_id == source_id,
            NormalizedFinding.tenant_id == user.tenant_id,
        )
    )
    findings_count = findings_q.scalar() or 0

    active_q = await db.execute(
        select(sa_func.count(NormalizedFinding.id)).where(
            NormalizedFinding.scan_source_id == source_id,
            NormalizedFinding.tenant_id == user.tenant_id,
            literal_column("source_metadata->>'validation_status'") == "active",
        )
    )
    active_credentials = active_q.scalar() or 0

    touched_q = await db.execute(
        select(NormalizedFinding.incident_id).where(
            NormalizedFinding.scan_source_id == source_id,
            NormalizedFinding.incident_id.isnot(None),
        ).distinct()
    )
    touched_ids = [row[0] for row in touched_q.all()]
    incidents_affected = len(touched_ids)
    will_survive = 0
    if touched_ids:
        survive_q = await db.execute(
            select(NormalizedFinding.incident_id).where(
                NormalizedFinding.incident_id.in_(touched_ids),
                NormalizedFinding.tenant_id == user.tenant_id,
                # Elsewhere = a different scan source, OR a repository.
                ~(NormalizedFinding.scan_source_id == source_id),
            ).distinct()
        )
        will_survive = len(set(row[0] for row in survive_q.all()))
    will_close = incidents_affected - will_survive

    scan_q = await db.execute(
        select(sa_func.count(ScanJob.id)).where(ScanJob.scan_source_id == source_id)
    )
    scan_history_count = scan_q.scalar() or 0

    return {
        "scope": "scan_source",
        "id": str(source_id),
        "name": source.name,
        "source_type": source.source_type,
        "findings_count": findings_count,
        "incidents_affected": incidents_affected,
        "incidents_will_close": will_close,
        "incidents_will_survive": will_survive,
        "active_credentials": active_credentials,
        "scan_history_count": scan_history_count,
    }


@router.delete("/{source_id}")
async def delete_scan_source(
    source_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Permanent delete of a scan source.

    Symmetric with the repositories router's delete_repository — same
    cascade discipline, same audit-trail expectations, same
    incident-aware orphan handling.

    Order of operations is significant:
      1) Snapshot the cleanup counts BEFORE any destruction so the
         audit log entry has accurate "how many records destroyed"
         numbers (the same numbers the FE preview showed the user).
      2) Capture the set of incident_ids tied to this source's
         findings so we can revisit them AFTER the finding deletes
         to decide closure vs. survive.
      3) Delete child rows in FK-dependency order.
      4) For incidents that lost ALL their occurrences in step 3,
         mark them closed with classification = resolved_source_removed
         — preserves the row for compliance / dashboards.
      5) Delete the source row itself.
      6) Audit log entry.
      7) Commit.

    Wrapped in a single transaction so partial failures roll back the
    whole operation — never leave a half-deleted source behind.
    """
    from sqlalchemy import delete as sa_delete, func as sa_func, text, literal_column, update as sa_update
    from apps.api.app.models.scan import ScanJob
    from apps.api.app.models.finding import NormalizedFinding, SecretIncident
    from apps.api.app.core.audit import log_audit

    result = await db.execute(
        select(ScanSource).where(ScanSource.id == source_id, ScanSource.tenant_id == user.tenant_id)
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Scan source not found")

    source_name = source.name
    source_type = source.source_type
    sid_text = str(source_id)

    # ── 1. Snapshot counts (for audit log) ─────────────────────────
    counts_q = await db.execute(
        select(sa_func.count(NormalizedFinding.id)).where(
            NormalizedFinding.scan_source_id == source_id,
        )
    )
    findings_count = counts_q.scalar() or 0
    active_q = await db.execute(
        select(sa_func.count(NormalizedFinding.id)).where(
            NormalizedFinding.scan_source_id == source_id,
            literal_column("source_metadata->>'validation_status'") == "active",
        )
    )
    active_credentials = active_q.scalar() or 0

    # ── 2. Capture touched incidents BEFORE the finding cascade ────
    touched_q = await db.execute(
        select(NormalizedFinding.incident_id).where(
            NormalizedFinding.scan_source_id == source_id,
            NormalizedFinding.incident_id.isnot(None),
        ).distinct()
    )
    touched_incident_ids = [row[0] for row in touched_q.all()]

    # ── 3. Cascade delete child rows ───────────────────────────────
    # FK topology for a scan_source:
    #   scan_sources  ← scan_jobs ← (normalized_findings, imported_findings,
    #                                metric_snapshots, policy_evaluation_results,
    #                                scan_artifacts [CASCADE])
    #   scan_sources  ← finding_decision_cache [CASCADE]
    #   normalized_findings ← (finding_evidence, finding_decisions,
    #                          remediation_plans) [all CASCADE]
    #                       ← credential_rotation_events [SET NULL —
    #                          preserved as historical rotation audit]
    #                       ← quantum_assessments, review_feedback
    #                          [NO ACTION — explicit cleanup]
    # Order: scan_job-children → normalized_findings → scan_jobs →
    # scan_sources (cascades finding_decision_cache).

    # Find scan_jobs for this source so we can clean their non-cascading
    # children before deleting the jobs themselves.
    scan_job_ids_q = await db.execute(
        select(ScanJob.id).where(ScanJob.scan_source_id == source_id)
    )
    scan_job_ids = [row[0] for row in scan_job_ids_q.all()]

    if scan_job_ids:
        # Children of scan_jobs that DON'T cascade. policy_evaluation_results
        # is from a removed product line and no longer exists; the
        # existence filter drops it so this delete does not 500 on it.
        from apps.api.app.routers.repositories import _existing_tables

        scan_job_subq = "SELECT id FROM scan_jobs WHERE scan_source_id = :sid"
        _cands = ("imported_findings", "metric_snapshots", "policy_evaluation_results")
        _present = await _existing_tables(db, _cands)
        for tbl in _cands:
            if tbl not in _present:
                continue
            await db.execute(
                text(f"DELETE FROM {tbl} WHERE scan_job_id IN ({scan_job_subq})"),
                {"sid": sid_text},
            )

    # Children of normalized_findings that DON'T cascade.  Both tables
    # are typically empty for source-scan paths today, but the cleanup
    # makes future migrations safe and matches the repo path's discipline.
    if findings_count:
        finding_subq = "SELECT id FROM normalized_findings WHERE scan_source_id = :sid"
        for tbl in ("quantum_assessments", "review_feedback"):
            await db.execute(
                text(f"DELETE FROM {tbl} WHERE finding_id IN ({finding_subq})"),
                {"sid": sid_text},
            )

    # Findings (cascades finding_evidence/decisions/remediation; SET NULLs
    # credential_rotation_events.finding_id to preserve historical audit).
    await db.execute(
        sa_delete(NormalizedFinding).where(NormalizedFinding.scan_source_id == source_id)
    )
    # Scan jobs (cascades scan_artifacts).
    await db.execute(
        sa_delete(ScanJob).where(ScanJob.scan_source_id == source_id)
    )

    # ── 4. Orphan-incident handling ────────────────────────────────
    # For each incident that had occurrences in this source: check if
    # any occurrences remain.  Zero → close with the source-removed
    # classification (preserves audit trail).  Non-zero → recompute
    # aggregate stats (occurrence_count, last_seen_at, severity_max).
    if touched_incident_ids:
        # Recompute occurrence_count per touched incident.
        remaining_q = await db.execute(
            select(
                NormalizedFinding.incident_id,
                sa_func.count(NormalizedFinding.id),
                sa_func.max(NormalizedFinding.last_seen_at),
            )
            .where(NormalizedFinding.incident_id.in_(touched_incident_ids))
            .group_by(NormalizedFinding.incident_id)
        )
        remaining_by_inc = {row[0]: (row[1], row[2]) for row in remaining_q.all()}

        # Orphaned incidents — no remaining occurrences.
        orphan_ids = [iid for iid in touched_incident_ids if iid not in remaining_by_inc]
        if orphan_ids:
            await db.execute(
                sa_update(SecretIncident)
                .where(SecretIncident.id.in_(orphan_ids))
                .values(
                    classification="resolved_source_removed",
                    review_status="reviewed",
                    occurrence_count=0,
                )
            )

        # Surviving incidents — recompute their stats.
        for inc_id, (cnt, last_seen) in remaining_by_inc.items():
            await db.execute(
                sa_update(SecretIncident)
                .where(SecretIncident.id == inc_id)
                .values(occurrence_count=cnt, last_seen_at=last_seen)
            )

    incidents_closed = len([
        iid for iid in touched_incident_ids
        if iid not in remaining_by_inc
    ]) if touched_incident_ids else 0
    incidents_survived = len([
        iid for iid in touched_incident_ids
        if iid in remaining_by_inc
    ]) if touched_incident_ids else 0

    # ── 5. Delete the source row itself ────────────────────────────
    await db.delete(source)
    await db.flush()

    # ── 6. Audit log ───────────────────────────────────────────────
    # Capture cleanup counts in the audit-event detail so compliance
    # / SOC2 reviewers can trace what was destroyed and when.
    await log_audit(
        db, user, "source_deleted", "scan_source", source_id,
        (
            f"Deleted source '{source_name}' ({source_type}). "
            f"Findings: {findings_count} · Incidents closed: {incidents_closed} "
            f"· Incidents survived: {incidents_survived} · Active creds: {active_credentials}"
        ),
        request=request,
        metadata={
            "source_name": source_name,
            "source_type": source_type,
            "findings_deleted": findings_count,
            "incidents_closed": incidents_closed,
            "incidents_survived": incidents_survived,
            "active_credentials_at_delete": active_credentials,
        },
    )

    # ── 7. Commit (single transaction) ─────────────────────────────
    await db.commit()
    return {
        "status": "deleted",
        "findings_deleted": findings_count,
        "incidents_closed": incidents_closed,
        "incidents_survived": incidents_survived,
        "active_credentials_at_delete": active_credentials,
    }


@router.post("/{source_id}/scan")
async def trigger_source_scan(
    source_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Trigger a scan of this non-git source."""
    result = await db.execute(
        select(ScanSource).where(ScanSource.id == source_id, ScanSource.tenant_id == user.tenant_id)
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Scan source not found")
    if not source.is_active:
        raise HTTPException(status_code=400, detail="Scan source is disabled")

    # Opportunistic concurrency check — surface 409 to the user
    # *before* dispatching a Celery task that would just skip
    # itself anyway. The worker still re-checks under lock so this
    # is purely a UX improvement; the real correctness boundary is
    # the SETNX inside _run_source_scan.
    try:
        from services.source_scanners.concurrency import is_locked
        if await is_locked(str(source.id)):
            raise HTTPException(
                status_code=409,
                detail="A scan is already in progress for this source. Wait for it to complete or check the recent scans list.",
            )
    except HTTPException:
        raise
    except Exception:
        # Lock-probe failures are best-effort; carry on with dispatch.
        # Worker still enforces the lock on its end.
        pass

    # Create scan job. Per-source scope (target_repository_id /
    # target_business_unit_id) is inherited onto the job so any
    # downstream finding-creation path that copies job.repository_id
    # picks it up automatically. target_repository_id wins if both
    # are set (matches model docstring + UI exclusivity).
    from apps.api.app.models.scan import ScanJob, ScanType, ScanStatus
    job_config: dict = {"source_type": source.source_type}
    if source.target_business_unit_id:
        job_config["target_business_unit_id"] = str(source.target_business_unit_id)
    scan_job = ScanJob(
        repository_id=source.target_repository_id,  # may be None = org-wide / BU-scoped
        scan_source_id=source.id,
        scan_type=ScanType.SOURCE_SCAN,
        status=ScanStatus.PENDING,
        initiated_by=user.id,
        tenant_id=user.tenant_id,
        config=job_config,
    )
    db.add(scan_job)
    await db.commit()
    await db.refresh(scan_job)

    # Dispatch Celery task
    try:
        from apps.worker.celery_app import celery_app
        celery_app.send_task(
            "apps.worker.tasks.run_source_scan",
            args=[str(scan_job.id), str(source.id)],
        )
    except Exception:
        pass  # Worker may not be running in dev

    return {
        "scan_job_id": str(scan_job.id),
        "status": "dispatched",
        "source_id": str(source.id),
        "source_type": source.source_type,
    }


@router.post("/{source_id}/test")
async def test_source_connection(
    source_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Test connection to the source using its STORED credentials.

    Used by the FE's Edit dialog when the user clicks "Test Connection"
    without filling in the credential fields — the most common flow for
    re-testing an already-connected source.  The companion
    ``/scan-sources/test-connection`` endpoint handles the inline-creds
    case (new sources + token rotation).
    """
    result = await db.execute(
        select(ScanSource).where(ScanSource.id == source_id, ScanSource.tenant_id == user.tenant_id)
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Scan source not found")

    # Load integration config for credentials
    int_result = await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.id == source.integration_config_id)
    )
    integration = int_result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration config not found")

    # Decrypt the stored credential bag before handing it to the adapter.
    # IntegrationConfig.config is encrypted at rest; the inline-creds
    # endpoint receives raw values from the user, so the adapter's
    # contract is "plaintext credentials" — symmetric encryption here.
    from packages.common.encryption import decrypt_config_dict
    decrypted_creds = decrypt_config_dict(dict(integration.config or {}))

    try:
        from services.source_scanners.factory import create_source_adapter
        adapter = create_source_adapter(
            source_type=source.source_type,
            config=source.config or {},
            credentials=decrypted_creds,
        )
        result = await adapter.test_connection()
        # Structured log line — same shape as the inline-creds endpoint
        # so operators can grep `event=test_connection_result` across
        # both flows uniformly.  Includes ``via=stored`` so an operator
        # can split stored-cred tests from inline-cred tests when
        # triaging.
        details = (result or {}).get("details") or {}
        logger.info(
            "test_connection_result",
            source_type=source.source_type,
            status=(result or {}).get("status"),
            error_code=details.get("code"),
            error_title=(result or {}).get("title"),
            trace_id=details.get("trace_id"),
            user_id=str(user.id),
            source_id=str(source_id),
            via="stored",
        )
        return result
    except Exception as e:
        logger.warning(
            "test_connection_unhandled_exception",
            source_type=source.source_type,
            exception_type=type(e).__name__,
            exception=str(e)[:200],
            user_id=str(user.id),
            source_id=str(source_id),
            via="stored",
        )
        return {"status": "error", "message": str(e)}


@router.post("/test-connection")
async def test_unsaved_source_connection(
    payload: dict,
    user: User = Depends(get_current_user),
):
    """Test connection BEFORE the source is saved.

    The Connect Source modal calls this so users can validate their
    credentials WITHOUT first creating an integration_config + source
    pair (and then having to delete them on failure). Mirrors the
    shape of ``test_source_connection`` above but takes the source
    type, scan-config, and raw credentials in the request body.

    Why this exists separately from the legacy
    ``/integrations/test`` endpoint: that one validates against
    PROVIDER_SCHEMAS (outbound notification config — Slack expects
    ``webhook_url``, etc.) while source-scan adapters need the
    inbound shape (Slack expects ``bot_token``). Reusing the wrong
    endpoint surfaced confusing "Missing required field: Webhook URL"
    errors on the Slack source form (bug 2026-05-07).

    Body:
      {
        "source_type": "slack" | "jira" | ...,
        "credentials": { "bot_token": "xoxb-...", ... },
        "config":      { "channels": "#eng,#sec", ... }   # optional
      }

    Returns the adapter's ``test_connection()`` result verbatim:
      { "status": "success" | "error", "message": "...", "details": {...} }
    """
    source_type = (payload or {}).get("source_type")
    credentials = (payload or {}).get("credentials") or {}
    config      = (payload or {}).get("config") or {}

    if not source_type:
        raise HTTPException(status_code=400, detail="source_type is required")
    if not credentials:
        # Empty credentials guaranteed to fail the upstream auth call;
        # short-circuit here so the user gets a useful error without
        # the extra round-trip to the provider's API.
        return {"status": "error", "message": "Credentials are required"}

    # Resolve friendly aliases ("microsoft_teams" → "ms_teams" etc.)
    # before handing off to the factory. Lets clients use the names
    # documented in the user-facing docs without each call site
    # learning the canonical DB key. Bug fix 2026-05-08.
    from apps.api.app.models.scan_source import normalize_source_type
    source_type = normalize_source_type(source_type)

    try:
        from services.source_scanners.factory import create_source_adapter
        adapter = create_source_adapter(
            source_type=source_type,
            config=config,
            credentials=credentials,
        )
    except Exception as e:
        # Adapter init failures (unknown source_type, missing required
        # credential field at the dataclass level, etc.) — surface as
        # a clear 400 rather than letting it bubble up as a 500.
        raise HTTPException(status_code=400, detail=f"Adapter init failed: {e}")

    try:
        result = await adapter.test_connection()
        # Emit a structured log line for every test-connection call so
        # operators can watch the classifier outcomes in real time
        # without having to read response bodies. The `details.code`
        # field is the stable error code (e.g. atlassian.auth.token_invalid)
        # — present whenever the adapter went through the new
        # IntegrationError pipeline. Falls back to "legacy" for any
        # adapter that hasn't been migrated yet.
        details = (result or {}).get("details") or {}
        # We log `title` alongside `error_code` so operators (or Claude
        # in real-time monitoring sessions) can spot a misclassified
        # error at a glance — code + headline together make it obvious
        # whether the right branch fired.  Title is bounded at 80 chars
        # by the IntegrationError model so the log line stays compact.
        logger.info(
            "test_connection_result",
            source_type=source_type,
            status=(result or {}).get("status"),
            error_code=details.get("code"),
            error_title=(result or {}).get("title"),
            trace_id=details.get("trace_id"),
            user_id=str(user.id),
        )
        return result
    except Exception as e:
        # Network errors / unexpected adapter exceptions — keep the
        # response shape identical to the success path so the UI's
        # status/message rendering doesn't have to special-case.
        logger.warning(
            "test_connection_unhandled_exception",
            source_type=source_type,
            exception_type=type(e).__name__,
            exception=str(e)[:200],
            user_id=str(user.id),
        )
        return {"status": "error", "message": str(e)[:500]}


@router.get("/{source_id}/scans")
async def list_source_scans(
    source_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List scan jobs for this source."""
    from apps.api.app.models.scan import ScanJob

    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.scan_source_id == source_id, ScanJob.tenant_id == user.tenant_id)
        .order_by(ScanJob.created_at.desc())
        .limit(20)
    )
    jobs = result.scalars().all()
    return [
        {
            "id": str(j.id),
            "status": j.status.value if hasattr(j.status, "value") else str(j.status),
            "progress_pct": j.progress_pct,
            "stats": j.stats or {},
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "updated_at": j.updated_at.isoformat() if j.updated_at else None,
        }
        for j in jobs
    ]
