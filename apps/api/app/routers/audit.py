# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from typing import Optional
import io
import csv

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, delete

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.audit import AuditEvent

router = APIRouter()

# ── Dashboard "Recent Activity" noise denylist ──────────────────────────────
# These categories stay in the FULL audit log (compliance/forensics, viewable
# at /settings/admin?tab=audit) but are filtered OUT of the dashboard feed via
# ?exclude_noise=true, so the dashboard surfaces security-relevant activity
# (findings, incidents, scans, remediations) instead of auth churn and watchdog
# reaps. A denylist (not allowlist) so genuinely-new event types still surface
# on the dashboard by default — we only ever hide the known-noisy categories.
_NOISE_RESOURCE_TYPES = {"auth"}  # login_success / login_failed / logout
_NOISE_ACTIONS = {"scan_watchdog_failed", "notification_dead_lettered"}  # system-internal


@router.get("")
async def list_audit_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    days: Optional[int] = Query(None, description="Filter to last N days"),
    exclude_noise: bool = Query(False, description="Drop auth + system-internal events (dashboard feed)"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = select(AuditEvent).where(AuditEvent.tenant_id == user.tenant_id)

    if action:
        query = query.where(AuditEvent.action == action)
    if resource_type:
        query = query.where(AuditEvent.resource_type == resource_type)
    if exclude_noise:
        query = query.where(
            AuditEvent.resource_type.notin_(_NOISE_RESOURCE_TYPES),
            AuditEvent.action.notin_(_NOISE_ACTIONS),
        )
    if search:
        query = query.where(or_(
            AuditEvent.detail.ilike(f"%{search}%"),
            AuditEvent.action.ilike(f"%{search}%"),
            AuditEvent.resource_type.ilike(f"%{search}%"),
        ))
    if days:
        from datetime import datetime, timezone, timedelta
        since = datetime.now(timezone.utc) - timedelta(days=days)
        query = query.where(AuditEvent.created_at >= since)

    query = query.order_by(AuditEvent.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    events = result.scalars().all()

    # Resolve user names
    from apps.api.app.models.user import User as UserModel
    user_ids = list(set(e.user_id for e in events if e.user_id))
    user_map = {}
    if user_ids:
        users_r = await db.execute(select(UserModel).where(UserModel.id.in_(user_ids)))
        user_map = {u.id: u.full_name for u in users_r.scalars().all()}

    return [
        {
            "id": str(e.id),
            "action": e.action,
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "detail": e.detail,
            "user_id": str(e.user_id) if e.user_id else None,
            "user_name": user_map.get(e.user_id, "System"),
            "ip_address": e.ip_address,
            "created_at": str(e.created_at),
        }
        for e in events
    ]


@router.get("/export")
async def export_audit_csv(
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    days: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export audit events as CSV. Supports same filters as list endpoint."""
    query = select(AuditEvent).where(AuditEvent.tenant_id == user.tenant_id)
    if action:
        query = query.where(AuditEvent.action == action)
    if resource_type:
        query = query.where(AuditEvent.resource_type == resource_type)
    if search:
        query = query.where(or_(
            AuditEvent.detail.ilike(f"%{search}%"),
            AuditEvent.action.ilike(f"%{search}%"),
        ))
    if days:
        from datetime import datetime, timezone, timedelta
        query = query.where(AuditEvent.created_at >= datetime.now(timezone.utc) - timedelta(days=days))

    query = query.order_by(AuditEvent.created_at.desc()).limit(10000)
    result = await db.execute(query)
    events = result.scalars().all()

    # Resolve user names
    from apps.api.app.models.user import User as UserModel
    user_ids = list(set(e.user_id for e in events if e.user_id))
    user_map = {}
    if user_ids:
        users_r = await db.execute(select(UserModel).where(UserModel.id.in_(user_ids)))
        user_map = {u.id: u.full_name for u in users_r.scalars().all()}

    # Build CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "User", "Action", "Resource Type", "Resource ID", "Detail", "IP Address"])
    for e in events:
        writer.writerow([
            str(e.created_at), user_map.get(e.user_id, "System"), e.action,
            e.resource_type, e.resource_id or "", e.detail or "", e.ip_address or "",
        ])

    output.seek(0)
    from datetime import datetime, timezone
    filename = f"vooda_audit_log_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.post("/enforce-retention")
async def enforce_retention(
    retention_days: int = Query(..., ge=1, description="Delete events older than N days"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Enforce audit log retention — delete events older than the specified days.

    Scope contract (WS-8 — append-only telemetry exemption)
    -------------------------------------------------------
    This sweep is DELIBERATELY scoped to ``audit_events`` only.  Other
    operational telemetry — most importantly ``scan_phase_events`` (the
    append-only per-phase scan timeline) — must NEVER be added to this
    purge.  That table is append-only by contract: an operator reviewing
    a months-old failed scan still needs its full phase history, and it
    holds no compliance-audit data subject to a retention window.  Rows
    there are removed only by tenant cascade when the parent ``scan_job``
    is deleted.  If you ever generalize this endpoint to sweep additional
    tables, keep ``scan_phase_events`` excluded.
    """
    from apps.api.app.core.audit import log_audit
    from datetime import datetime, timezone, timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    # Count before delete
    count_r = await db.execute(
        select(func.count(AuditEvent.id)).where(
            AuditEvent.tenant_id == user.tenant_id,
            AuditEvent.created_at < cutoff,
        )
    )
    count = count_r.scalar() or 0

    if count > 0:
        await db.execute(
            delete(AuditEvent).where(
                AuditEvent.tenant_id == user.tenant_id,
                AuditEvent.created_at < cutoff,
            )
        )
        await log_audit(db, user, "retention_enforced", "audit", detail=f"Purged {count} events older than {retention_days} days")

    return {"purged": count, "retention_days": retention_days, "cutoff": str(cutoff)}


@router.get("/stats")
async def audit_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Audit log statistics — total events, by action, by resource type."""
    total_r = await db.execute(
        select(func.count(AuditEvent.id)).where(AuditEvent.tenant_id == user.tenant_id)
    )
    by_action = await db.execute(
        select(AuditEvent.action, func.count(AuditEvent.id))
        .where(AuditEvent.tenant_id == user.tenant_id)
        .group_by(AuditEvent.action)
        .order_by(func.count(AuditEvent.id).desc())
    )
    by_resource = await db.execute(
        select(AuditEvent.resource_type, func.count(AuditEvent.id))
        .where(AuditEvent.tenant_id == user.tenant_id)
        .group_by(AuditEvent.resource_type)
        .order_by(func.count(AuditEvent.id).desc())
    )

    from datetime import datetime, timezone, timedelta
    last_24h = await db.execute(
        select(func.count(AuditEvent.id)).where(
            AuditEvent.tenant_id == user.tenant_id,
            AuditEvent.created_at >= datetime.now(timezone.utc) - timedelta(hours=24),
        )
    )

    return {
        "total_events": total_r.scalar() or 0,
        "events_last_24h": last_24h.scalar() or 0,
        "by_action": {a: c for a, c in by_action.all()},
        "by_resource_type": {r: c for r, c in by_resource.all()},
    }
