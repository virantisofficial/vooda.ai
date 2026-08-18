# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Reporting Service — generates scan summary metrics and stores snapshots.
"""

from uuid import UUID
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

import structlog

logger = structlog.get_logger()


async def generate_scan_metrics(
    db: AsyncSession,
    scan_job_id: UUID,
    tenant_id: UUID,
    repository_id: UUID,
) -> dict:
    """
    Generate summary metrics for a completed scan and store as MetricSnapshot.
    Called after scan completion in the worker pipeline.
    """
    from apps.api.app.models.finding import NormalizedFinding, Classification
    from apps.api.app.models.metrics import MetricSnapshot

    # Count by severity
    severity_counts = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = await db.execute(
            select(func.count(NormalizedFinding.id)).where(
                NormalizedFinding.scan_job_id == scan_job_id,
                NormalizedFinding.severity == sev,
            )
        )
        severity_counts[sev] = cnt.scalar() or 0

    # Count by classification
    classification_counts = {}
    for cls in ["likely_true_positive", "likely_false_positive", "needs_review",
                "confirmed_true_positive", "confirmed_false_positive", "accepted_risk"]:
        cnt = await db.execute(
            select(func.count(NormalizedFinding.id)).where(
                NormalizedFinding.scan_job_id == scan_job_id,
                NormalizedFinding.classification == cls,
            )
        )
        classification_counts[cls] = cnt.scalar() or 0

    # Count by category (top 10)
    cat_result = await db.execute(
        select(NormalizedFinding.vulnerability_category, func.count(NormalizedFinding.id))
        .where(NormalizedFinding.scan_job_id == scan_job_id)
        .group_by(NormalizedFinding.vulnerability_category)
        .order_by(func.count(NormalizedFinding.id).desc())
        .limit(10)
    )
    top_categories = {cat: count for cat, count in cat_result.all()}

    # Total
    total_result = await db.execute(
        select(func.count(NormalizedFinding.id)).where(
            NormalizedFinding.scan_job_id == scan_job_id,
        )
    )
    total = total_result.scalar() or 0

    # FP rate
    fp_count = (
        classification_counts.get("likely_false_positive", 0) +
        classification_counts.get("confirmed_false_positive", 0)
    )
    fp_rate = round(fp_count / max(total, 1), 4)

    metrics_data = {
        "scan_job_id": str(scan_job_id),
        "repository_id": str(repository_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": total,
        "by_severity": severity_counts,
        "by_classification": classification_counts,
        "top_categories": top_categories,
        "false_positive_rate": fp_rate,
        "false_positive_count": fp_count,
        "true_positive_count": (
            classification_counts.get("likely_true_positive", 0) +
            classification_counts.get("confirmed_true_positive", 0)
        ),
    }

    # Store as MetricSnapshot
    snapshot = MetricSnapshot(
        tenant_id=tenant_id,
        snapshot_type="scan_summary",
        repository_id=repository_id,
        scan_job_id=scan_job_id,
        data=metrics_data,
    )
    db.add(snapshot)
    await db.flush()

    logger.info(
        "metrics_snapshot_created",
        scan_job_id=str(scan_job_id),
        total=total,
        fp_rate=fp_rate,
    )

    return metrics_data
