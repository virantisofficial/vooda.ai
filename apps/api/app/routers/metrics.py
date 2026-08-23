# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.finding import NormalizedFinding, Severity, Classification
from apps.api.app.models.scan import ScanJob

router = APIRouter()


# Classifications that mean "settled — no longer live risk". Everything
# NOT in this set counts as open, so a newly added classification is
# treated as open work until someone decides otherwise; the failure mode
# of a wrong guess here is over-reporting, never a false all-clear.
_CLOSED_CLASSIFICATIONS = (
    Classification.LIKELY_FALSE_POSITIVE,
    Classification.CONFIRMED_FALSE_POSITIVE,
    Classification.TEST_CREDENTIAL,
    Classification.ROTATED,
    Classification.ACCEPTED_RISK,
    Classification.RESOLVED_FILE_DELETED,
    Classification.RESOLVED_ITEM_DELETED,
    Classification.RESOLVED_REPO_REMOVED,
    Classification.RESOLVED_SOURCE_REMOVED,
)


async def _build_finding_filters(db, user, include_archived_sources: bool = False, open_only: bool = False):
    """Build base filters for findings scoped to user's accessible repos.

    By default, findings from archived sources are excluded so the
    dashboard KPIs reflect the active risk surface — same pattern as
    GitGuardian/Wiz/Snyk.  Pass `include_archived_sources=True` to
    bypass (used for "historical / paused" toggles).

    `open_only=True` additionally narrows to findings that still
    represent live, actionable risk: anything a human or the AI has
    already settled (false positive, test credential, rotated, resolved,
    accepted risk) and anything suppressed is excluded. NEEDS_REVIEW is
    deliberately KEPT — an un-adjudicated finding is open work, and
    dropping it would report "all clear" whenever triage fails, which is
    the one direction a security dashboard must never be wrong in.

    Endpoints that measure DETECTION or TRIAGE behaviour (scanner
    comparison, AI accuracy) must NOT pass it: excluding false positives
    from an FP-rate calculation forces the answer to zero.

    "Archived source" is unified across two storage shapes:
      - Repository:    `metadata.archived == true`
      - ScanSource:    `is_active == false`
    Both mean "preserved data, scanning paused, reversible".  The FE
    surfaces a single "Archive" concept across both entity types; this
    filter mirrors that by excluding findings from either kind.
    """
    from apps.api.app.core.access_control import get_accessible_repo_ids
    from sqlalchemy import literal_column, or_, and_
    from apps.api.app.models.repository import Repository
    from apps.api.app.models.scan_source import ScanSource

    conditions = [NormalizedFinding.tenant_id == user.tenant_id]
    accessible = await get_accessible_repo_ids(db, user)
    if accessible is not None:
        conditions.append(NormalizedFinding.repository_id.in_(accessible))

    if not include_archived_sources:
        archived_repo_ids = select(Repository.id).where(
            Repository.tenant_id == user.tenant_id,
            literal_column("repositories.metadata->>'archived'") == "true",
        ).scalar_subquery()
        archived_source_ids = select(ScanSource.id).where(
            ScanSource.tenant_id == user.tenant_id,
            ScanSource.is_active == False,  # noqa: E712 — SQLAlchemy needs ==
        ).scalar_subquery()
        # Hide a finding when EITHER its repo is archived OR its source
        # is archived.  Findings with repository_id=NULL bypass the repo
        # check; findings with scan_source_id=NULL bypass the source
        # check.  AND combination: a finding survives only if neither
        # of its parents is archived.
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

    if open_only:
        conditions.append(
            ~NormalizedFinding.classification.in_(_CLOSED_CLASSIFICATIONS)
        )
        conditions.append(
            or_(
                NormalizedFinding.is_suppressed.is_(None),
                NormalizedFinding.is_suppressed == False,  # noqa: E712
            )
        )
    return conditions


@router.get("/overview")
async def metrics_overview(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    days: Optional[int] = Query(
        None,
        ge=1,
        le=365,
        description=(
            "Window size in days.  When provided, all counts (total / by_severity / "
            "by_classification / scans) are restricted to findings/scans created "
            "within the last N days.  When omitted, returns all-time counts (legacy "
            "behaviour — preserves backward compat for any caller that doesn't pass "
            "the param)."
        ),
    ),
    with_delta: bool = Query(
        False,
        description=(
            "When true (and `days` is set), also returns the equivalent metrics for "
            "the immediately preceding window of the same size — used by the "
            "dashboard KPI tiles to render \"↑ 12% vs prev 30d\" delta badges "
            "without a second round-trip."
        ),
    ),
):
    tenant = user.tenant_id
    # Two scopes, deliberately:
    #   `conditions`      — OPEN findings. Everything the dashboard
    #                       presents as risk (the headline, the severity
    #                       mix, the remediation denominators) counts
    #                       these, so the tiles reconcile with each other.
    #   `all_conditions`  — every detection, settled or not. Used only to
    #                       report detection volume and how much of it
    #                       triage removed, which is the denominator that
    #                       makes the noise rate meaningful.
    conditions = await _build_finding_filters(db, user, open_only=True)
    all_conditions = await _build_finding_filters(db, user)

    # Time-window filter — drives the dashboard's range picker.
    # The dashboard sends ?days=7 / 30 / 90 / 365 to scope all KPIs to
    # the matching window.  Computed once here and applied to BOTH the
    # findings counts and the scan counts so the entire response is
    # consistent.
    if days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        conditions.append(NormalizedFinding.created_at >= cutoff)
        all_conditions.append(NormalizedFinding.created_at >= cutoff)

    total = await db.execute(
        select(func.count(NormalizedFinding.id)).where(*conditions)
    )
    by_severity = await db.execute(
        select(NormalizedFinding.severity, func.count(NormalizedFinding.id))
        .where(*conditions)
        .group_by(NormalizedFinding.severity)
    )
    # Classification breakdown stays UNFILTERED — filtering a breakdown by
    # classification would erase the categories it exists to show.
    by_classification = await db.execute(
        select(NormalizedFinding.classification, func.count(NormalizedFinding.id))
        .where(*all_conditions)
        .group_by(NormalizedFinding.classification)
    )
    detected_total = await db.execute(
        select(func.count(NormalizedFinding.id)).where(*all_conditions)
    )

    # Remediation coverage over the SAME open+window scope as the
    # headline, so the Auto-Fix tile's percentage divides like by like.
    # The standalone /remediation endpoint counts patches across all
    # findings all-time; dividing that by an open, windowed denominator
    # inflates the percentage and can push it past 100%.
    from apps.api.app.models.finding import RemediationStatus
    from apps.api.app.models.remediation import RemediationPlan, RemediationPatch

    # "Covered" is a claim that a fix was DRAFTED, so it is counted from
    # the patch artifacts themselves, not from `remediation_status` — a
    # status flag can exist without the artifact behind it, and a patch
    # with an empty diff is not a draft either.
    _has_real_patch = (
        select(RemediationPlan.finding_id)
        .join(RemediationPatch, RemediationPatch.plan_id == RemediationPlan.id)
        .where(func.length(func.coalesce(RemediationPatch.patch_diff, "")) > 20)
        .scalar_subquery()
    )
    _covered_q = await db.execute(
        select(func.count(NormalizedFinding.id)).where(
            *conditions,
            NormalizedFinding.id.in_(_has_real_patch),
        )
    )
    _applied_q = await db.execute(
        select(func.count(NormalizedFinding.id)).where(
            *conditions,
            NormalizedFinding.id.in_(_has_real_patch),
            NormalizedFinding.remediation_status.in_([
                RemediationStatus.APPROVED,
                RemediationStatus.APPLIED,
            ]),
        )
    )
    # Review-queue size under the same scope, so the quick-action chip
    # agrees with the queue it links to (the unfiltered classification
    # breakdown includes suppressed rows; the queue does not).
    _needs_review_q = await db.execute(
        select(func.count(NormalizedFinding.id)).where(
            *conditions,
            NormalizedFinding.classification == Classification.NEEDS_REVIEW,
        )
    )

    # Scans also need repo filtering
    from apps.api.app.core.access_control import get_accessible_repo_ids
    accessible = await get_accessible_repo_ids(db, user)
    scan_conditions = [ScanJob.tenant_id == tenant]
    if accessible is not None:
        scan_conditions.append(ScanJob.repository_id.in_(accessible))
    if days is not None:
        # Same window applied to scans — keeps the response coherent
        # (you can't have "5 findings in last 7d but 0 scans in last 7d").
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        scan_conditions.append(ScanJob.created_at >= cutoff)
    total_scans = await db.execute(
        select(func.count(ScanJob.id)).where(*scan_conditions)
    )

    # Credential verification counts
    from sqlalchemy import literal_column
    active_secrets = await db.execute(
        select(func.count(NormalizedFinding.id)).where(
            *conditions,
            literal_column("source_metadata->>'validation_status'") == "active",
        )
    )
    inactive_secrets = await db.execute(
        select(func.count(NormalizedFinding.id)).where(
            *conditions,
            literal_column("source_metadata->>'validation_status'") == "inactive",
        )
    )

    _open = total.scalar() or 0
    _detected = detected_total.scalar() or 0
    response = {
        # OPEN findings — the headline, and the denominator every other
        # risk tile reconciles against.
        "total_findings": _open,
        # Detection volume and how much triage removed. Reported so the
        # UI can show "N detected · M filtered as noise" without implying
        # that settled findings are outstanding work.
        "detected_total": _detected,
        "filtered_as_noise": max(_detected - _open, 0),
        "remediation_covered": _covered_q.scalar() or 0,
        "remediation_applied": _applied_q.scalar() or 0,
        "needs_review_open": _needs_review_q.scalar() or 0,
        "total_scans": total_scans.scalar() or 0,
        "by_severity": {str(s): c for s, c in by_severity.all()},
        "by_classification": {str(s): c for s, c in by_classification.all()},
        "active_secrets": active_secrets.scalar() or 0,
        "inactive_secrets": inactive_secrets.scalar() or 0,
    }

    # ── Previous-period comparison (delta badges) ─────────────────────
    # Only computed when caller asks for it AND a window is set — comparing
    # all-time vs all-time is meaningless.  Runs the same five queries
    # against the prior window of the same size (e.g. days 31-60 ago for a
    # 30d view).  The dashboard then computes (curr - prev) / prev as the
    # percent change displayed in each KPI tile's delta badge.
    if with_delta and days is not None:
        # Re-derive the base (unwindowed) conditions; we don't want the
        # current-window cutoff carried over into the prev-window query.
        # Same open-only scope as the current window — a delta between two
        # differently-scoped counts is not a delta.
        prev_conditions = await _build_finding_filters(db, user, open_only=True)
        now = datetime.now(timezone.utc)
        prev_start = now - timedelta(days=days * 2)
        prev_end = now - timedelta(days=days)
        prev_conditions.append(NormalizedFinding.created_at >= prev_start)
        prev_conditions.append(NormalizedFinding.created_at < prev_end)

        prev_total = await db.execute(
            select(func.count(NormalizedFinding.id)).where(*prev_conditions)
        )
        prev_by_severity = await db.execute(
            select(NormalizedFinding.severity, func.count(NormalizedFinding.id))
            .where(*prev_conditions)
            .group_by(NormalizedFinding.severity)
        )
        prev_active = await db.execute(
            select(func.count(NormalizedFinding.id)).where(
                *prev_conditions,
                literal_column("source_metadata->>'validation_status'") == "active",
            )
        )
        response["previous_period"] = {
            "total_findings": prev_total.scalar() or 0,
            "by_severity": {str(s): c for s, c in prev_by_severity.all()},
            "active_secrets": prev_active.scalar() or 0,
        }

    return response


@router.get("/findings-by-category")
async def findings_by_category(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    days: Optional[int] = Query(None, ge=1, le=365),
):
    """Findings grouped by source category — drives the dashboard's
    "Findings by Source" bar chart.

    Categorisation rule:
      - Finding with `repository_id` set  →  "Code Repos"
      - Finding with `scan_source_id` set →  ScanSource.source_type mapped
                                              to its category via the
                                              SOURCE_TYPE_TO_CATEGORY table

    Severity counts are returned per category so the FE can render the
    bar fill colour as a severity-blended hue (critical-weighted).
    """
    from sqlalchemy import literal_column
    from apps.api.app.models.scan_source import ScanSource

    # Source-type → category mapping.  Kept in sync with the FE's
    # SourceCategory union (apps/web/src/app/sources/page.tsx).  When a
    # new source_type is added there it MUST land here too — otherwise
    # its findings fall into "Other".
    SOURCE_TYPE_TO_CATEGORY = {
        "slack": "Collaboration",
        "ms_teams": "Collaboration",
        "mattermost": "Collaboration",
        "confluence": "Docs & Wikis",
        "notion": "Docs & Wikis",
        "sharepoint_pages": "Docs & Wikis",
        "jira": "Issue Tracking",
        "github_issues": "Issue Tracking",
        "servicenow": "Issue Tracking",
        "azure_devops": "Issue Tracking",
        "linear": "Issue Tracking",
        "asana": "Issue Tracking",
        "bitbucket_issues": "Issue Tracking",
        "s3": "Cloud Storage",
        "onedrive_sharepoint": "Cloud Storage",
        "azure_blob": "Cloud Storage",
        "gcs": "Cloud Storage",
        "box": "Cloud Storage",
        "docker_image": "DevOps",
        "cicd_logs": "DevOps",
        "container_registry": "DevOps",
        "postman": "APIs",
        "salesforce": "CRM & Support",
    }

    conditions = await _build_finding_filters(db, user, open_only=True)
    if days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        conditions.append(NormalizedFinding.created_at >= cutoff)

    # ── Bucket 1: findings tied to a Git repository → Code Repos ─────
    code_q = await db.execute(
        select(NormalizedFinding.severity, func.count(NormalizedFinding.id))
        .where(*conditions, NormalizedFinding.repository_id.isnot(None))
        .group_by(NormalizedFinding.severity)
    )
    code_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    code_total = 0
    for sev, count in code_q.all():
        sev_name = (sev.value if hasattr(sev, "value") else str(sev)).split(".")[-1].lower()
        if sev_name in code_severity:
            code_severity[sev_name] = count
        code_total += count

    # ── Bucket 2: findings tied to a ScanSource → group by category ──
    source_q = await db.execute(
        select(
            ScanSource.source_type,
            NormalizedFinding.severity,
            func.count(NormalizedFinding.id),
        )
        .join(ScanSource, NormalizedFinding.scan_source_id == ScanSource.id)
        .where(*conditions, NormalizedFinding.scan_source_id.isnot(None))
        .group_by(ScanSource.source_type, NormalizedFinding.severity)
    )

    # Aggregate per category.  Unknown source_types fall into "Other"
    # (they won't show on the chart unless they exceed the visible
    # threshold).
    category_data: dict[str, dict] = {}
    if code_total > 0:
        category_data["Code Repos"] = {
            "category": "Code Repos",
            "count": code_total,
            "severity": code_severity,
        }

    for source_type, sev, count in source_q.all():
        category = SOURCE_TYPE_TO_CATEGORY.get(source_type, "Other")
        if category not in category_data:
            category_data[category] = {
                "category": category,
                "count": 0,
                "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            }
        category_data[category]["count"] += count
        sev_name = (sev.value if hasattr(sev, "value") else str(sev)).split(".")[-1].lower()
        if sev_name in category_data[category]["severity"]:
            category_data[category]["severity"][sev_name] += count

    # Sort by count desc — the FE renders top 5 then folds the tail into
    # "+N other".  Returning sorted lets the FE skip its own sort.
    sorted_categories = sorted(
        category_data.values(),
        key=lambda c: c["count"],
        reverse=True,
    )
    total = sum(c["count"] for c in sorted_categories)

    return {
        "categories": sorted_categories,
        "total": total,
        "period_days": days,
    }


@router.get("/top-leaking-repos")
async def top_leaking_repos(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    days: Optional[int] = Query(None, ge=1, le=365),
    limit: int = Query(7, ge=1, le=20),
):
    """Top N repositories ranked by total finding count.  Includes
    per-severity breakdown so the FE can render colour-coded badges
    alongside the absolute count and a proportional bar.
    """
    from apps.api.app.models.repository import Repository

    conditions = await _build_finding_filters(db, user, open_only=True)
    conditions.append(NormalizedFinding.repository_id.isnot(None))
    if days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        conditions.append(NormalizedFinding.created_at >= cutoff)

    # ── Coverage stats (scan-scope context for the dashboard card) ───
    #   total_configured — repos under management for this tenant
    #   total_scanned    — repos with >=1 completed scan (fleet coverage)
    #   total_leaking    — distinct repos with findings matching the filter
    # Computed BEFORE the early-return so even the empty state reports scope: a
    # dashboard with 0 monitored repos must read as "nothing watched", not
    # "all clear". total_leaking spans ALL leaking repos, not just the top-N.
    from apps.api.app.models.scan import ScanJob, ScanStatus
    _tenant = user.tenant_id
    total_configured = (await db.execute(
        select(func.count(Repository.id)).where(Repository.tenant_id == _tenant)
    )).scalar() or 0
    total_scanned = (await db.execute(
        select(func.count(func.distinct(ScanJob.repository_id)))
        .where(ScanJob.tenant_id == _tenant, ScanJob.status == ScanStatus.COMPLETED)
    )).scalar() or 0
    total_leaking = (await db.execute(
        select(func.count(func.distinct(NormalizedFinding.repository_id))).where(*conditions)
    )).scalar() or 0
    coverage = {
        "total_configured": total_configured,
        "total_scanned": total_scanned,
        "total_leaking": total_leaking,
    }

    # ── Pass 1: rank repos by total finding count ────────────────────
    rank_q = await db.execute(
        select(
            NormalizedFinding.repository_id,
            func.count(NormalizedFinding.id).label("cnt"),
        )
        .where(*conditions)
        .group_by(NormalizedFinding.repository_id)
        .order_by(func.count(NormalizedFinding.id).desc())
        .limit(limit)
    )
    ranked = rank_q.all()
    if not ranked:
        return {"repos": [], "max_count": 0, "period_days": days, "coverage": coverage}
    top_ids = [r[0] for r in ranked]

    # ── Pass 2: severity breakdown for the top-N repos ───────────────
    sev_q = await db.execute(
        select(
            NormalizedFinding.repository_id,
            NormalizedFinding.severity,
            func.count(NormalizedFinding.id),
        )
        .where(*conditions, NormalizedFinding.repository_id.in_(top_ids))
        .group_by(NormalizedFinding.repository_id, NormalizedFinding.severity)
    )
    severity_by_repo: dict = {}
    for repo_id, sev, count in sev_q.all():
        if repo_id not in severity_by_repo:
            severity_by_repo[repo_id] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        sev_name = (sev.value if hasattr(sev, "value") else str(sev)).split(".")[-1].lower()
        if sev_name in severity_by_repo[repo_id]:
            severity_by_repo[repo_id][sev_name] = count

    # ── Pass 3: repo names + providers for display ───────────────────
    # The Repository model exposes the git provider via `source_type`
    # (an enum: github / gitlab / bitbucket / bare).  We surface it as
    # "provider" in the response so the FE can render the matching
    # icon without knowing the column name.
    repo_q = await db.execute(
        select(Repository.id, Repository.name, Repository.source_type)
        .where(Repository.id.in_(top_ids))
    )
    repo_meta = {}
    for repo_id, name, st in repo_q.all():
        provider = st.value if hasattr(st, "value") else (str(st).split(".")[-1] if st else "unknown")
        repo_meta[repo_id] = {"name": name, "provider": provider.lower()}

    repos = []
    max_count = ranked[0][1] if ranked else 0
    for repo_id, count in ranked:
        meta = repo_meta.get(repo_id, {"name": "Unknown", "provider": "unknown"})
        repos.append({
            "repository_id": str(repo_id),
            "name": meta["name"],
            "provider": meta["provider"],
            "count": count,
            "severity": severity_by_repo.get(repo_id, {"critical": 0, "high": 0, "medium": 0, "low": 0}),
        })

    return {
        "repos": repos,
        "max_count": max_count,
        "period_days": days,
        "coverage": coverage,
    }


@router.get("/findings")
async def findings_metrics(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    conditions = await _build_finding_filters(db, user, open_only=True)
    by_category = await db.execute(
        select(NormalizedFinding.vulnerability_category, func.count(NormalizedFinding.id))
        .where(*conditions)
        .group_by(NormalizedFinding.vulnerability_category)
        .order_by(func.count(NormalizedFinding.id).desc())
        .limit(20)
    )
    by_scanner = await db.execute(
        select(NormalizedFinding.scanner_name, func.count(NormalizedFinding.id))
        .where(*conditions)
        .group_by(NormalizedFinding.scanner_name)
    )
    fp_conditions = list(conditions) + [NormalizedFinding.classification.in_([
        Classification.LIKELY_FALSE_POSITIVE,
        Classification.CONFIRMED_FALSE_POSITIVE,
    ])]
    fp_rate = await db.execute(
        select(func.count(NormalizedFinding.id)).where(*fp_conditions)
    )
    total = await db.execute(
        select(func.count(NormalizedFinding.id)).where(*conditions)
    )
    t = total.scalar() or 1
    fp = fp_rate.scalar() or 0

    return {
        "by_category": {c: n for c, n in by_category.all()},
        "by_scanner": {s: n for s, n in by_scanner.all()},
        "false_positive_rate": round(fp / t, 4),
    }


@router.get("/remediation")
async def remediation_metrics(
    repository_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from datetime import datetime, timezone
    from apps.api.app.models.repository import Repository
    from apps.api.app.models.user import User as UserModel
    from apps.api.app.core.access_control import get_accessible_repo_ids, can_access_repository

    # Normalize repository_id (may be Query(None) when called internally)
    if repository_id is not None and not isinstance(repository_id, UUID):
        try:
            repository_id = UUID(str(repository_id)) if str(repository_id) not in ('None', '') else None
        except (ValueError, AttributeError):
            repository_id = None

    if repository_id:
        if not await can_access_repository(db, user, repository_id):
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Access denied")

    conditions = [NormalizedFinding.tenant_id == user.tenant_id, NormalizedFinding.is_suppressed == False]
    if repository_id:
        conditions.append(NormalizedFinding.repository_id == repository_id)
    else:
        accessible = await get_accessible_repo_ids(db, user)
        if accessible is not None:
            conditions.append(NormalizedFinding.repository_id.in_(accessible))

    # By status
    by_status = await db.execute(
        select(NormalizedFinding.remediation_status, func.count(NormalizedFinding.id))
        .where(*conditions)
        .group_by(NormalizedFinding.remediation_status)
    )
    status_counts = {}
    for s, c in by_status.all():
        label = s.value.lower() if hasattr(s, "value") else str(s).split(".")[-1].lower()
        status_counts[label] = c

    # By severity × remediation status
    by_sev = await db.execute(
        select(NormalizedFinding.severity, NormalizedFinding.remediation_status, func.count(NormalizedFinding.id))
        .where(*conditions)
        .group_by(NormalizedFinding.severity, NormalizedFinding.remediation_status)
    )
    severity_breakdown: dict[str, dict] = {}
    for sev, rem, c in by_sev.all():
        sev_name = sev.value.lower() if hasattr(sev, "value") else str(sev).split(".")[-1].lower()
        rem_name = rem.value.lower() if hasattr(rem, "value") else str(rem).split(".")[-1].lower()
        if sev_name not in severity_breakdown:
            severity_breakdown[sev_name] = {}
        severity_breakdown[sev_name][rem_name] = c

    # Total with patches
    patched = status_counts.get("patch_generated", 0) + status_counts.get("approved", 0) + status_counts.get("applied", 0)
    total = sum(status_counts.values())

    # ── Actionable findings: awaiting approval, stalled, unassigned ──
    now = datetime.now(timezone.utc)
    actionable_statuses = ["pending", "in_progress", "patch_generated"]
    actionable_q = select(NormalizedFinding).where(
        *conditions,
        NormalizedFinding.remediation_status.in_(actionable_statuses),
        NormalizedFinding.classification.notin_(["confirmed_false_positive", "likely_false_positive"]),
    ).order_by(NormalizedFinding.severity, NormalizedFinding.created_at).limit(200)

    result = await db.execute(actionable_q)
    actionable_findings = result.scalars().all()

    # Pre-fetch repo names
    repo_ids = {f.repository_id for f in actionable_findings if f.repository_id}
    repo_name_map = {}
    if repo_ids:
        repos_r = await db.execute(select(Repository.id, Repository.name).where(Repository.id.in_(repo_ids)))
        repo_name_map = {str(r[0]): r[1] for r in repos_r.all()}

    # Pre-fetch assignee names
    assigned_ids = {f.assigned_to for f in actionable_findings if f.assigned_to}
    user_name_map = {}
    if assigned_ids:
        users_r = await db.execute(select(UserModel.id, UserModel.full_name).where(UserModel.id.in_(assigned_ids)))
        user_name_map = {str(r[0]): r[1] for r in users_r.all()}

    # Categorize into actionable buckets
    awaiting_approval = []  # patch_generated — needs someone to approve
    stalled = []            # pending/in_progress for > 7 days
    unassigned = []         # actionable but no owner

    for f in actionable_findings:
        sev = f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).split(".")[-1].lower()
        rem = f.remediation_status.value.lower() if hasattr(f.remediation_status, "value") else str(f.remediation_status).split(".")[-1].lower()
        age = (now - (f.created_at.replace(tzinfo=timezone.utc) if f.created_at.tzinfo is None else f.created_at)).days if f.created_at else 0
        assignee = user_name_map.get(str(f.assigned_to), None) if f.assigned_to else None
        repo_name = repo_name_map.get(str(f.repository_id), "")
        line = f.line_start if hasattr(f, "line_start") and f.line_start else None
        file_loc = f.file_path or ""
        if line:
            file_loc = f"{file_loc}:{line}"

        entry = {
            "id": str(f.id), "title": f.title[:60], "severity": sev,
            "status": rem.replace("_", " "), "age_days": age,
            "file": file_loc[:60], "repo_name": repo_name,
            "assignee": assignee or "Unassigned",
        }

        if rem == "patch_generated":
            awaiting_approval.append(entry)
        if rem in ("pending", "in_progress") and age > 7:
            stalled.append(entry)
        if not f.assigned_to:
            unassigned.append(entry)

    # Sort: worst severity first, then oldest
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for lst in [awaiting_approval, stalled, unassigned]:
        lst.sort(key=lambda x: (sev_order.get(x["severity"], 5), -x["age_days"]))

    return {
        "by_remediation_status": status_counts,
        "by_severity": severity_breakdown,
        "total_findings": total,
        "patched": patched,
        "patch_rate": round(patched / max(total, 1) * 100, 1),
        "pending_review": status_counts.get("pending", 0),
        "in_progress": status_counts.get("in_progress", 0),
        "awaiting_approval": awaiting_approval[:20],
        "awaiting_approval_count": len(awaiting_approval),
        "stalled": stalled[:20],
        "stalled_count": len(stalled),
        "unassigned": unassigned[:20],
        "unassigned_count": len(unassigned),
    }


@router.get("/trends")
async def finding_trends(
    days: int = 30,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Finding count trends over time — total, by severity, new vs resolved."""
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import cast, Date, case, literal_column

    since = datetime.now(timezone.utc) - timedelta(days=days)
    conditions = await _build_finding_filters(db, user, open_only=True)
    time_conditions = list(conditions) + [NormalizedFinding.created_at >= since]

    # Daily total
    daily = await db.execute(
        select(
            cast(NormalizedFinding.created_at, Date).label("date"),
            func.count(NormalizedFinding.id),
        )
        .where(*time_conditions)
        .group_by(cast(NormalizedFinding.created_at, Date))
        .order_by(cast(NormalizedFinding.created_at, Date))
    )
    daily_counts = [{"date": str(d), "count": c} for d, c in daily.all()]

    # Daily by severity
    daily_sev = await db.execute(
        select(
            cast(NormalizedFinding.created_at, Date).label("date"),
            NormalizedFinding.severity,
            func.count(NormalizedFinding.id),
        )
        .where(*time_conditions)
        .group_by(cast(NormalizedFinding.created_at, Date), NormalizedFinding.severity)
        .order_by(cast(NormalizedFinding.created_at, Date))
    )
    severity_trend: dict[str, dict] = {}
    for d, sev, c in daily_sev.all():
        ds = str(d)
        if ds not in severity_trend:
            severity_trend[ds] = {"date": ds, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        sev_name = sev.value.lower() if hasattr(sev, "value") else str(sev).lower()
        for key in ["critical", "high", "medium", "low", "info"]:
            if key in sev_name:
                severity_trend[ds][key] = c
                break

    # Period summary
    total_new = sum(d["count"] for d in daily_counts)
    prev_since = since - timedelta(days=days)
    prev_conditions = list(conditions) + [
        NormalizedFinding.created_at >= prev_since,
        NormalizedFinding.created_at < since,
    ]
    prev_r = await db.execute(select(func.count(NormalizedFinding.id)).where(*prev_conditions))
    prev_count = prev_r.scalar() or 0
    change_pct = round(((total_new - prev_count) / max(prev_count, 1)) * 100, 1)

    return {
        "period_days": days,
        "daily_counts": daily_counts,
        "severity_trend": list(severity_trend.values()),
        "period_summary": {
            "new_findings": total_new,
            "previous_period": prev_count,
            "change_pct": change_pct,
            "trend": "increasing" if change_pct > 10 else "decreasing" if change_pct < -10 else "stable",
        },
    }


# AI-triage accuracy is a PER-FINDING measure: the AI makes one prediction per
# finding, the human reaches one final verdict per finding — no matter how many
# times they flip. Counting raw FindingDecision rows is wrong twice (double-counts
# mind-changes; a re-decision's previous_classification is a prior HUMAN state, not
# the AI's). These pure helpers collapse decisions to one record per finding and
# are unit-tested in tests/test_ai_accuracy_per_finding.py.
_AI_TP_CLASSES = {"likely_true_positive", "confirmed_true_positive"}
_AI_FP_CLASSES = {"likely_false_positive", "confirmed_false_positive"}


def _per_finding_verdicts(decision_rows):
    """Collapse decision rows to ONE record per finding.

    decision_rows: iterable of (finding_id, action, previous_classification,
    severity, vulnerability_category), ORDERED by (finding_id, created_at ASC).
    AI verdict = the EARLIEST decision's previous_classification (the state before
    any human touched the finding); human verdict = the LATEST decision's action.
    Returns {finding_id: {"ai_pred": "tp"|"fp"|None, "human": "tp"|"fp",
    "sev": ..., "cat": ...}}.
    """
    per_finding: dict = {}
    for fid, action, prev, sev, cat in decision_rows:
        rec = per_finding.get(fid)
        if rec is None:
            ai = (prev or "").lower()
            ai_pred = "tp" if ai in _AI_TP_CLASSES else ("fp" if ai in _AI_FP_CLASSES else None)
            rec = {"ai_pred": ai_pred, "human": None, "sev": sev, "cat": cat}
            per_finding[fid] = rec
        rec["human"] = "tp" if action == "mark_tp" else "fp"  # latest action wins
    return per_finding


def _accuracy_of(records):
    """(confirmed, correct) over the findings where the AI made a TP/FP call.

    A finding the AI never predicted on (ai_pred is None) is not an accuracy data
    point and is excluded from both numerator and denominator.
    """
    scored = [r for r in records if r["ai_pred"] is not None]
    return len(scored), sum(1 for r in scored if r["ai_pred"] == r["human"])


@router.get("/ai-accuracy")
async def ai_accuracy_metrics(
    repository_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """AI triage accuracy — detailed breakdown with actionable tables."""
    from apps.api.app.models.finding import FindingDecision
    from apps.api.app.models.repository import Repository
    from apps.api.app.core.access_control import get_accessible_repo_ids, can_access_repository

    # Normalize repository_id
    if repository_id is not None and not isinstance(repository_id, UUID):
        try:
            repository_id = UUID(str(repository_id)) if str(repository_id) not in ('None', '') else None
        except (ValueError, AttributeError):
            repository_id = None

    if repository_id:
        if not await can_access_repository(db, user, repository_id):
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Access denied")

    conditions = [NormalizedFinding.tenant_id == user.tenant_id, NormalizedFinding.is_suppressed == False]
    if repository_id:
        conditions.append(NormalizedFinding.repository_id == repository_id)
    else:
        accessible = await get_accessible_repo_ids(db, user)
        if accessible is not None:
            conditions.append(NormalizedFinding.repository_id.in_(accessible))

    # Total AI-triaged findings
    ai_conditions = list(conditions) + [NormalizedFinding.ai_confidence.isnot(None)]
    ai_triaged = await db.execute(
        select(func.count(NormalizedFinding.id)).where(*ai_conditions)
    )

    # ── Per-FINDING AI accuracy (2026-06-13) ─────────────────────────────
    # The AI makes ONE prediction per finding; the human reaches ONE final
    # verdict per finding — regardless of how many times they change their mind.
    # Counting raw FindingDecision rows is wrong twice over: it double-counts
    # mind-changes (2 findings + a flip = 3 rows → /3 → 33%), AND a re-decision's
    # previous_classification is the prior HUMAN state, not the AI's verdict. So
    # aggregate per finding: AI verdict = the EARLIEST decision's
    # previous_classification (the state before any human touched it); human
    # verdict = the LATEST decision's action.
    base_join_conds = list(conditions)
    _dec_rows = await db.execute(
        select(
            FindingDecision.finding_id,
            FindingDecision.action,
            FindingDecision.previous_classification,
            NormalizedFinding.severity,
            NormalizedFinding.vulnerability_category,
        )
        .join(NormalizedFinding, FindingDecision.finding_id == NormalizedFinding.id)
        .where(*base_join_conds, FindingDecision.action.in_(["mark_fp", "mark_tp"]))
        .order_by(FindingDecision.finding_id, FindingDecision.created_at)
    )
    per_finding = _per_finding_verdicts(_dec_rows.all())

    total_triaged = ai_triaged.scalar() or 0
    total_confirmed, correct = _accuracy_of(per_finding.values())
    accuracy = round(correct / max(total_confirmed, 1), 4)

    # ── Confidence distribution ──
    conf_buckets = {"low": 0, "medium": 0, "high": 0, "very_high": 0}  # 0-25, 25-50, 50-75, 75-100
    conf_q = await db.execute(
        select(NormalizedFinding.ai_confidence)
        .where(*ai_conditions)
    )
    for (c,) in conf_q.all():
        if c is None:
            continue
        if c < 0.25:
            conf_buckets["low"] += 1
        elif c < 0.50:
            conf_buckets["medium"] += 1
        elif c < 0.75:
            conf_buckets["high"] += 1
        else:
            conf_buckets["very_high"] += 1

    # ── Accuracy by severity (per-finding, from the same aggregation) ──
    sev_accuracy = {}
    for sev_val in ["critical", "high", "medium", "low"]:
        sc, sx = _accuracy_of([r for r in per_finding.values()
                               if (r["sev"] or "").lower() == sev_val])
        sev_accuracy[sev_val] = {
            "confirmed": sc,
            "correct": sx,
            "accuracy_pct": round(sx / max(sc, 1) * 100, 1),
        }

    # ── Accuracy by vulnerability category (top 10, per-finding) ──
    _cat_groups: dict = {}
    for r in per_finding.values():
        _cat_groups.setdefault(r["cat"], []).append(r)
    by_category = []
    for cat, recs in _cat_groups.items():
        cc, cx = _accuracy_of(recs)
        if cc == 0:
            continue
        by_category.append({
            "category": cat or "Unknown",
            "confirmed": cc,
            "correct": cx,
            "accuracy_pct": round(cx / max(cc, 1) * 100, 1),
        })
    by_category.sort(key=lambda x: x["confirmed"], reverse=True)
    by_category = by_category[:10]

    # ── Low confidence findings needing review ──
    low_conf_q = await db.execute(
        select(NormalizedFinding).where(
            *conditions,
            NormalizedFinding.ai_confidence.isnot(None),
            NormalizedFinding.ai_confidence < 0.5,
            NormalizedFinding.review_status == "unreviewed",
            NormalizedFinding.classification.notin_(["confirmed_false_positive", "confirmed_true_positive"]),
        ).order_by(NormalizedFinding.severity, NormalizedFinding.ai_confidence).limit(100)
    )
    low_conf_findings = low_conf_q.scalars().all()

    # Pre-fetch repo names for low-conf findings
    repo_ids = {f.repository_id for f in low_conf_findings if f.repository_id}
    repo_name_map = {}
    if repo_ids:
        repos_r = await db.execute(select(Repository.id, Repository.name).where(Repository.id.in_(repo_ids)))
        repo_name_map = {str(r[0]): r[1] for r in repos_r.all()}

    low_confidence = []
    for f in low_conf_findings:
        sev = f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).split(".")[-1].lower()
        cls = f.classification.value if hasattr(f.classification, "value") else str(f.classification).split(".")[-1]
        line = f.line_start if hasattr(f, "line_start") and f.line_start else None
        file_loc = f.file_path or ""
        if line:
            file_loc = f"{file_loc}:{line}"
        low_confidence.append({
            "id": str(f.id), "title": f.title[:60], "severity": sev,
            "ai_confidence": round(f.ai_confidence, 2) if f.ai_confidence else 0,
            "classification": cls.replace("_", " "),
            "repo_name": repo_name_map.get(str(f.repository_id), ""),
            "file": file_loc[:60],
        })

    # ── High-confidence unreviewed (auto-close candidates) ──
    high_conf_unreviewed_q = await db.execute(
        select(func.count(NormalizedFinding.id)).where(
            *conditions,
            NormalizedFinding.ai_confidence >= 0.9,
            NormalizedFinding.review_status == "unreviewed",
            NormalizedFinding.classification.in_(["likely_false_positive"]),
        )
    )
    high_conf_fp_count = high_conf_unreviewed_q.scalar() or 0

    # ── Disagreements (AI wrong) ──
    disagree_tp_q = await db.execute(
        select(NormalizedFinding).join(FindingDecision, FindingDecision.finding_id == NormalizedFinding.id)
        .where(
            *base_join_conds,
            NormalizedFinding.classification.in_(["likely_false_positive", "confirmed_false_positive"]),
            FindingDecision.action == "mark_tp",
        ).limit(20)
    )
    disagree_fp_q = await db.execute(
        select(NormalizedFinding).join(FindingDecision, FindingDecision.finding_id == NormalizedFinding.id)
        .where(
            *base_join_conds,
            NormalizedFinding.classification.in_(["likely_true_positive", "confirmed_true_positive"]),
            FindingDecision.action == "mark_fp",
        ).limit(20)
    )
    disagreements = []
    for f in list(disagree_tp_q.scalars().all()) + list(disagree_fp_q.scalars().all()):
        sev = f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).split(".")[-1].lower()
        cls = f.classification.value if hasattr(f.classification, "value") else str(f.classification).split(".")[-1]
        line = f.line_start if hasattr(f, "line_start") and f.line_start else None
        file_loc = f.file_path or ""
        if line:
            file_loc = f"{file_loc}:{line}"
        disagreements.append({
            "id": str(f.id), "title": f.title[:60], "severity": sev,
            "ai_said": cls.replace("_", " "),
            "ai_confidence": round(f.ai_confidence, 2) if f.ai_confidence else 0,
            "repo_name": repo_name_map.get(str(f.repository_id), ""),
            "file": file_loc[:60],
        })
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    disagreements.sort(key=lambda x: sev_order.get(x["severity"], 5))

    return {
        "ai_triaged_findings": total_triaged,
        "user_confirmed_decisions": total_confirmed,
        "ai_correct": correct,
        "accuracy": accuracy,
        "accuracy_pct": f"{accuracy * 100:.1f}%",
        "confidence_distribution": conf_buckets,
        "by_severity": sev_accuracy,
        "by_category": by_category[:10],
        "low_confidence": low_confidence[:20],
        "low_confidence_count": len(low_confidence),
        "high_conf_fp_unreviewed": high_conf_fp_count,
        "disagreements": disagreements[:20],
        "disagreement_count": len(disagreements),
    }


@router.get("/mttr")
async def mttr_metrics(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Server-side MTTR — avoids loading all findings client-side."""
    from datetime import datetime, timezone
    # Deliberately NOT open_only: MTTR measures findings that completed
    # remediation. A finding that finished its lifecycle (patched, then
    # rotated/resolved) is exactly the population this averages over —
    # the open-only scope would remove it and hollow the metric out.
    conditions = await _build_finding_filters(db, user)

    # MTTR averages over findings that were actually RESOLVED: the fix
    # landed (applied) or the finding reached a resolved classification
    # (rotated, file/item/repo/source removed). Draft and approved
    # patches are excluded — a drafted fix has remediated nothing.
    #
    # updated_at - created_at is an approximation (updated_at can be
    # touched by later events), but for a terminal-state finding the
    # last touch is close to the resolution itself.
    from sqlalchemy import or_ as _or
    resolved_conds = list(conditions) + [
        _or(
            NormalizedFinding.remediation_status == "applied",
            NormalizedFinding.classification.in_([
                Classification.ROTATED,
                Classification.RESOLVED_FILE_DELETED,
                Classification.RESOLVED_ITEM_DELETED,
                Classification.RESOLVED_REPO_REMOVED,
                Classification.RESOLVED_SOURCE_REMOVED,
            ]),
        ),
    ]

    avg_q = await db.execute(
        select(
            func.count(NormalizedFinding.id),
            func.avg(
                func.extract("epoch", NormalizedFinding.updated_at)
                - func.extract("epoch", NormalizedFinding.created_at)
            ),
        ).where(*resolved_conds)
    )
    row = avg_q.one()
    count = row[0] or 0
    avg_seconds = row[1] or 0
    avg_hours = round(avg_seconds / 3600, 1) if count > 0 else None

    return {
        "resolved_count": count,
        "avg_hours": avg_hours,
        "display": (
            f"{round(avg_hours)} hours" if avg_hours is not None and avg_hours < 24
            else f"{round(avg_hours / 24)} days" if avg_hours is not None
            else None
        ),
    }


@router.get("/findings-breakdown")
async def findings_breakdown(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Pre-computed breakdowns by provider, validation_status, detection_method
    from source_metadata JSONB — avoids loading all findings client-side."""
    from sqlalchemy import literal_column

    conditions = await _build_finding_filters(db, user, open_only=True)

    # Use literal_column for JSONB text extraction to avoid GROUP BY issues
    provider_col = literal_column("source_metadata->>'provider'")
    validation_col = literal_column("source_metadata->>'validation_status'")
    method_col = literal_column("source_metadata->>'detection_method'")

    # By provider
    provider_q = await db.execute(
        select(provider_col.label("val"), func.count(NormalizedFinding.id))
        .where(*conditions)
        .where(provider_col.isnot(None))
        .group_by(provider_col)
        .order_by(func.count(NormalizedFinding.id).desc())
        .limit(20)
    )
    by_provider = {p: c for p, c in provider_q.all() if p}

    # By validation status
    validation_q = await db.execute(
        select(validation_col.label("val"), func.count(NormalizedFinding.id))
        .where(*conditions)
        .where(validation_col.isnot(None))
        .group_by(validation_col)
        .order_by(func.count(NormalizedFinding.id).desc())
    )
    by_validation = {v: c for v, c in validation_q.all() if v}

    # By detection method
    method_q = await db.execute(
        select(method_col.label("val"), func.count(NormalizedFinding.id))
        .where(*conditions)
        .where(method_col.isnot(None))
        .group_by(method_col)
        .order_by(func.count(NormalizedFinding.id).desc())
    )
    by_method = {m: c for m, c in method_q.all() if m}

    return {
        "by_provider": by_provider,
        "by_validation": by_validation,
        "by_method": by_method,
    }


@router.get("/scanner-comparison")
async def scanner_comparison(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Compare detection rates and FP rates across scanners."""
    conditions = await _build_finding_filters(db, user)

    # Findings per scanner
    by_scanner = await db.execute(
        select(NormalizedFinding.scanner_name, func.count(NormalizedFinding.id))
        .where(*conditions)
        .group_by(NormalizedFinding.scanner_name)
    )

    # FP per scanner
    fp_conditions = list(conditions) + [NormalizedFinding.classification.in_(["likely_false_positive", "confirmed_false_positive"])]
    fp_by_scanner = await db.execute(
        select(NormalizedFinding.scanner_name, func.count(NormalizedFinding.id))
        .where(*fp_conditions)
        .group_by(NormalizedFinding.scanner_name)
    )

    scanner_totals = {s: c for s, c in by_scanner.all()}
    scanner_fps = {s: c for s, c in fp_by_scanner.all()}

    comparison = []
    for scanner, total in scanner_totals.items():
        fps = scanner_fps.get(scanner, 0)
        comparison.append({
            "scanner": scanner,
            "total_findings": total,
            "false_positives": fps,
            "true_positives": total - fps,
            "fp_rate": round(fps / max(total, 1), 4),
        })

    return {"scanners": sorted(comparison, key=lambda x: x["total_findings"], reverse=True)}
