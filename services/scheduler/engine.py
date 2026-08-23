# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Scan Scheduler — manages recurring scan schedules for repositories.

Supports: daily, weekly, on-demand, on-PR triggers.
Uses Celery Beat for periodic task execution.
"""

import structlog
from uuid import UUID
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

logger = structlog.get_logger()

SCHEDULE_OPTIONS = {
    "on_demand": {"label": "On Demand", "description": "Scan only when manually triggered"},
    # `hourly` is honored for ScanSources (collaboration tools) only —
    # it doesn't make sense for code repos which churn at a slower cadence
    # and where webhook-driven scanning covers near-real-time anyway.
    "hourly":   {"label": "Hourly",  "description": "Scan once per hour", "cron": "0 * * * *"},
    "daily":    {"label": "Daily",   "description": "Scan once per day at configured time", "cron": "0 2 * * *"},
    "weekly":   {"label": "Weekly",  "description": "Scan once per week on Monday", "cron": "0 2 * * 1"},
    "on_push":  {"label": "On Push", "description": "Scan on every push to default branch (requires webhook)"},
    "on_pr":    {"label": "On Pull Request", "description": "Scan when a PR is opened (requires webhook)"},
}

# Per-schedule "is this overdue?" check, keyed off the last-run
# timestamp the scheduler stamps on each entity. Centralised here so
# we tune cadence in one place; both the repository path and the
# scan_source path call into _is_due.
_SCHEDULE_INTERVAL_SECONDS = {
    "hourly": 3_600,       # 1 hour
    "daily":  86_400,      # 24 hours
    "weekly": 604_800,     # 7 days
}


def _is_due(schedule: str, last_run_iso: str | None) -> bool:
    interval = _SCHEDULE_INTERVAL_SECONDS.get(schedule)
    if interval is None:
        return False
    if not last_run_iso:
        return True
    try:
        last_dt = datetime.fromisoformat(last_run_iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return True
    return (datetime.now(timezone.utc) - last_dt).total_seconds() > interval


async def get_scheduled_repos(db: AsyncSession) -> list[dict]:
    """Get all repositories with active scan schedules.

    Skips archived repos (`metadata_.archived == true`) — the archive
    contract is "pause scanning, preserve data".  Without this filter
    archiving would be cosmetic only, defeating the point.
    """
    from apps.api.app.models.repository import Repository

    result = await db.execute(
        select(Repository).where(Repository.is_active == True)
    )
    repos = result.scalars().all()

    scheduled = []
    for repo in repos:
        meta = repo.metadata_ or {}
        if meta.get("archived") is True:
            continue
        schedule = meta.get("scan_schedule", "on_demand")
        if schedule in ("daily", "weekly"):
            scheduled.append({
                "repo_id": str(repo.id),
                "tenant_id": str(repo.tenant_id),
                "name": repo.name,
                "schedule": schedule,
                "last_scan": meta.get("last_scheduled_scan"),
            })

    return scheduled


async def run_scheduled_scans(db: AsyncSession) -> int:
    """Check both repositories AND scan_sources, trigger scans for
    everything overdue. Called every 5 minutes by Celery Beat.

    Repositories use the `metadata_.scan_schedule` field; scan_sources
    use the `scan_schedule` column. Both go through `_is_due` for the
    overdue check so we tune cadence in one place.
    """
    repo_count = await _trigger_due_repositories(db)
    source_count = await _trigger_due_sources(db)
    if repo_count or source_count:
        logger.info(
            "scheduled_scans_dispatched",
            repos=repo_count, sources=source_count,
        )
    return repo_count + source_count


async def _trigger_due_repositories(db: AsyncSession) -> int:
    from apps.api.app.models.repository import Repository
    from apps.api.app.models.scan import ScanJob, ScanType, ScanStatus
    from apps.api.app.models.user import User

    repos = await get_scheduled_repos(db)
    triggered = 0
    now = datetime.now(timezone.utc)

    for repo_info in repos:
        repo_id = UUID(repo_info["repo_id"])
        tenant_id = UUID(repo_info["tenant_id"])
        schedule = repo_info["schedule"]
        last_scan = repo_info.get("last_scan")

        if not _is_due(schedule, last_scan):
            continue

        user_result = await db.execute(
            select(User).where(User.tenant_id == tenant_id, User.is_active == True).limit(1)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            continue

        scan_job = ScanJob(
            repository_id=repo_id,
            tenant_id=tenant_id,
            initiated_by=user.id,
            scan_type=ScanType.STANDALONE,
            status=ScanStatus.PENDING,
            config={"triggered_by": "scheduler", "schedule": schedule},
        )
        db.add(scan_job)
        await db.flush()

        repo_result = await db.execute(select(Repository).where(Repository.id == repo_id))
        repo = repo_result.scalar_one_or_none()
        if repo:
            meta = repo.metadata_ or {}
            meta["last_scheduled_scan"] = now.isoformat()
            repo.metadata_ = meta

        from apps.worker.tasks import run_scan_job
        # Store the Celery task id — the cancel endpoint is guarded by
        # `if job.celery_task_id:`, so a scan dispatched without it can
        # NEVER be revoked: cancelling flips the row to CANCELLED while
        # the worker keeps scanning, and the still-held repo lock makes
        # every subsequent Run Scan coalesce. Scheduled scans missed this
        # for their whole existence (the API paths always set it).
        _task = run_scan_job.delay(str(scan_job.id))
        scan_job.celery_task_id = _task.id
        triggered += 1

        logger.info("scheduled_repo_scan_triggered", repo=repo_info["name"], schedule=schedule)

    await db.commit()
    return triggered


async def _trigger_due_sources(db: AsyncSession) -> int:
    """Periodic scan dispatch for ScanSources (Slack / Jira / S3 / …).

    Picks every active source whose `scan_schedule` is hourly / daily /
    weekly and whose `last_scan_at` is overdue per `_is_due`. Dispatches
    `run_source_scan` exactly the way the API's manual trigger does,
    inheriting `target_repository_id` onto the ScanJob so per-repo
    routing keeps working.
    """
    from apps.api.app.models.scan_source import ScanSource
    from apps.api.app.models.scan import ScanJob, ScanType, ScanStatus
    from apps.api.app.models.user import User

    result = await db.execute(
        select(ScanSource).where(
            ScanSource.is_active == True,
            ScanSource.scan_schedule.in_(("hourly", "daily", "weekly")),
        )
    )
    sources = result.scalars().all()
    triggered = 0
    now = datetime.now(timezone.utc)

    for source in sources:
        last_iso = source.last_scan_at.isoformat() if source.last_scan_at else None
        if not _is_due(source.scan_schedule, last_iso):
            continue

        # Pick a system user from the source's tenant for audit
        # attribution. Same pattern the repo path uses.
        user_result = await db.execute(
            select(User).where(User.tenant_id == source.tenant_id, User.is_active == True).limit(1)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            continue

        # Mirror trigger_source_scan in apps/api/app/routers/scan_sources.py:
        # repository_id inherits from target_repository_id; BU goes into
        # config when no repo binding. Keeps per-repo ticketing routing
        # consistent between manual and scheduled triggers.
        job_config: dict = {
            "source_type": source.source_type,
            "triggered_by": "scheduler",
            "schedule": source.scan_schedule,
        }
        if source.target_business_unit_id:
            job_config["target_business_unit_id"] = str(source.target_business_unit_id)

        scan_job = ScanJob(
            repository_id=source.target_repository_id,
            scan_source_id=source.id,
            scan_type=ScanType.SOURCE_SCAN,
            status=ScanStatus.PENDING,
            initiated_by=user.id,
            tenant_id=source.tenant_id,
            config=job_config,
        )
        db.add(scan_job)
        await db.flush()

        from apps.worker.tasks import run_source_scan
        # Same reason as the repo path above — without celery_task_id the
        # cancel endpoint cannot revoke this task.
        _task = run_source_scan.delay(str(scan_job.id), str(source.id))
        scan_job.celery_task_id = _task.id
        triggered += 1

        logger.info(
            "scheduled_source_scan_triggered",
            source=source.name, schedule=source.scan_schedule,
        )

    await db.commit()
    return triggered
