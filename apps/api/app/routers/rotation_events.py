# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Rotation-event / MTTR endpoints.

Exposes the append-only ``credential_rotation_events`` table behind two
tenant-scoped read endpoints:

* ``GET /rotation-events``         — paginated list of rotation events
* ``GET /rotation-events/summary`` — aggregate MTTR + rotation counts

Both filter by tenant via the authenticated user. Optional query params
let the UI slice by provider, repository, or time window for dashboards.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.rotation_event import CredentialRotationEvent


router = APIRouter()


@router.get("/rotation-events")
async def list_rotation_events(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    provider: Optional[str] = Query(None, description="Filter by provider (e.g. 'github')"),
    repository_id: Optional[UUID] = Query(None, description="Filter by repository"),
    days: int = Query(30, ge=1, le=365, description="Lookback window in days"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Paginated list of rotation events for the authenticated tenant."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    filters = [
        CredentialRotationEvent.tenant_id == user.tenant_id,
        CredentialRotationEvent.rotated_at >= cutoff,
    ]
    if provider:
        filters.append(CredentialRotationEvent.provider == provider.lower())
    if repository_id:
        filters.append(CredentialRotationEvent.repository_id == repository_id)

    total_stmt = (
        select(func.count(CredentialRotationEvent.id)).where(and_(*filters))
    )
    total = (await db.execute(total_stmt)).scalar() or 0

    stmt = (
        select(CredentialRotationEvent)
        .where(and_(*filters))
        .order_by(CredentialRotationEvent.rotated_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(stmt)).scalars().all()

    return {
        "total": total,
        "events": [
            {
                "id": str(r.id),
                "finding_id": str(r.finding_id) if r.finding_id else None,
                "repository_id": str(r.repository_id) if r.repository_id else None,
                "provider": r.provider,
                "secret_hash_prefix": (r.secret_hash or "")[:12],
                "first_seen_active_at": r.first_seen_active_at.isoformat(),
                "rotated_at": r.rotated_at.isoformat(),
                "time_to_rotation_s": r.time_to_rotation_s,
                "detected_via": r.detected_via,
            }
            for r in rows
        ],
    }


@router.get("/rotation-events/summary")
async def rotation_summary(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    days: int = Query(30, ge=1, le=365),
):
    """Aggregate rotation metrics.

    Returns total count, mean / median / p90 time-to-rotation in seconds,
    and a per-provider breakdown. Values are computed in-Postgres so
    this remains cheap even across large rotation histories.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Overall totals + percentiles via SQL
    overall_stmt = select(
        func.count(CredentialRotationEvent.id).label("count"),
        func.avg(CredentialRotationEvent.time_to_rotation_s).label("mean_s"),
        func.percentile_cont(0.5)
            .within_group(CredentialRotationEvent.time_to_rotation_s)
            .label("median_s"),
        func.percentile_cont(0.9)
            .within_group(CredentialRotationEvent.time_to_rotation_s)
            .label("p90_s"),
    ).where(
        and_(
            CredentialRotationEvent.tenant_id == user.tenant_id,
            CredentialRotationEvent.rotated_at >= cutoff,
        )
    )
    overall = (await db.execute(overall_stmt)).one()

    # Per-provider breakdown
    per_prov_stmt = (
        select(
            CredentialRotationEvent.provider,
            func.count(CredentialRotationEvent.id).label("count"),
            func.avg(CredentialRotationEvent.time_to_rotation_s).label("mean_s"),
        )
        .where(
            and_(
                CredentialRotationEvent.tenant_id == user.tenant_id,
                CredentialRotationEvent.rotated_at >= cutoff,
            )
        )
        .group_by(CredentialRotationEvent.provider)
        .order_by(func.count(CredentialRotationEvent.id).desc())
    )
    per_provider = (await db.execute(per_prov_stmt)).all()

    def _to_int(v):
        return int(v) if v is not None else 0

    return {
        "window_days": days,
        "total_rotations": _to_int(overall.count),
        "mttr_mean_s": _to_int(overall.mean_s),
        "mttr_median_s": _to_int(overall.median_s),
        "mttr_p90_s": _to_int(overall.p90_s),
        "by_provider": [
            {
                "provider": row.provider,
                "count": _to_int(row.count),
                "mean_s": _to_int(row.mean_s),
            }
            for row in per_provider
        ],
    }
