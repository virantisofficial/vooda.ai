# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Flat scan-job access by id (Sprint S / WS-4).

The rest of the scan API is nested under the repository
(``/repositories/{repo_id}/scans/{scan_id}``), which is the natural
shape for the repo detail page.  But two callers only have a scan id:

  * the standalone ``/scan-jobs/{id}`` page (deep-link / bookmark), and
  * external API consumers that the docs tell to poll
    ``GET /api/v1/scan-jobs/{id}`` until ``status=completed`` — an
    endpoint that was documented but never actually implemented.

This router closes that gap.  Authorization is tenant-scoped: a job is
only visible when ``scan_jobs.tenant_id == user.tenant_id`` (404
otherwise, so a cross-tenant id is indistinguishable from a missing
one).  The per-phase timeline lives at the existing repo-scoped
endpoint; this page resolves ``repository_id`` from the job record and
reuses it.
"""
import json
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.scan import ScanJob
from apps.api.app.schemas.repository import ScanJobResponse, ScanPhaseEventResponse
from apps.api.app.models.scan import ScanPhaseEvent

router = APIRouter()


async def _get_job_tenant_scoped(scan_id: UUID, db: AsyncSession, user: User) -> ScanJob:
    result = await db.execute(
        select(ScanJob).where(
            ScanJob.id == scan_id,
            ScanJob.tenant_id == user.tenant_id,
        )
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.get("/{scan_id}", response_model=ScanJobResponse)
async def get_scan_job(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Detailed scan-job record by id (tenant-scoped).

    Matches the long-documented ``GET /api/v1/scan-jobs/{id}`` polling
    endpoint.  Returns status / progress_pct / status_message / stats so
    a deep-linked page or a CI poller can track a scan without knowing
    its repository id.
    """
    return await _get_job_tenant_scoped(scan_id, db, user)


@router.get("/{scan_id}/events", response_model=list[ScanPhaseEventResponse])
async def get_scan_job_events(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Append-only per-phase timeline for a scan, by id (WS-1 + WS-7).

    Flat twin of ``/repositories/{repo_id}/scans/{scan_id}/events`` for
    callers that only hold a scan id.  Same append-only,
    already-redacted rows, oldest-first, driven by
    ix_scan_phase_events_job_created.  Tenant ownership is enforced via
    the parent job before any event is exposed.
    """
    await _get_job_tenant_scoped(scan_id, db, user)
    result = await db.execute(
        select(ScanPhaseEvent)
        .where(ScanPhaseEvent.scan_job_id == scan_id)
        .order_by(ScanPhaseEvent.created_at.asc())
    )
    return result.scalars().all()


@router.get("/{scan_id}/events/export")
async def export_scan_events(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Download the full scan timeline + job summary as JSON (WS-10).

    For offline audit / archival / attaching to an incident ticket. The
    in-app timeline (/events) is paginatable UI data; this is the whole
    record in one file. Tenant-scoped; every field is already redacted
    (phase_label + error_detail go through WS-6 before persist).
    """
    job = await _get_job_tenant_scoped(scan_id, db, user)
    result = await db.execute(
        select(ScanPhaseEvent)
        .where(ScanPhaseEvent.scan_job_id == scan_id)
        .order_by(ScanPhaseEvent.created_at.asc())
    )
    events = result.scalars().all()

    payload = {
        "schema_version": 1,
        "exported_at": datetime.now(timezone.utc),
        "scan_job": {
            "id": job.id,
            "repository_id": job.repository_id,
            "scan_type": job.scan_type,
            "status": job.status,
            "progress_pct": job.progress_pct,
            "status_message": job.status_message,
            "error_detail": job.error_detail,
            "stats": job.stats,
            "created_at": job.created_at,
            "updated_at": job.updated_at,
        },
        "events": [
            {
                "step": e.step,
                "total_steps": e.total_steps,
                "phase_label": e.phase_label,
                "status": e.status,
                "progress_pct": e.progress_pct,
                "stats_snapshot": e.stats_snapshot,
                "created_at": e.created_at,
            }
            for e in events
        ],
    }
    # default=str serialises UUID + datetime + Enum deterministically.
    body = json.dumps(payload, indent=2, default=str)
    filename = f"vooda_scan_{scan_id}_events.json"
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
