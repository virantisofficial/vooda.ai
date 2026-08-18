# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Report generation endpoints — compliance reports, exports.
"""

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.finding import NormalizedFinding

router = APIRouter()


@router.get("/compliance")
async def compliance_report(
    repository_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate compliance summary mapped to OWASP Top 10, CWE Top 25, PCI DSS."""
    from services.reporting.compliance import generate_compliance_summary
    from apps.api.app.core.access_control import get_accessible_repo_ids, can_access_repository

    # Validate access to specific repo if requested
    if repository_id:
        if not await can_access_repository(db, user, repository_id):
            raise HTTPException(status_code=403, detail="Access denied")

    query = select(NormalizedFinding).where(
        NormalizedFinding.tenant_id == user.tenant_id,
        NormalizedFinding.is_suppressed == False,
    )

    # Apply repo-level access control
    if repository_id:
        query = query.where(NormalizedFinding.repository_id == repository_id)
    else:
        accessible = await get_accessible_repo_ids(db, user)
        if accessible is not None:
            query = query.where(NormalizedFinding.repository_id.in_(accessible))

    result = await db.execute(query)
    findings = result.scalars().all()

    findings_data = [
        {
            "cwe": f.cwe,
            "vulnerability_category": f.vulnerability_category,
            "severity": f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).split(".")[-1].lower(),
        }
        for f in findings
    ]

    summary = generate_compliance_summary(findings_data)
    summary["repository_id"] = str(repository_id) if repository_id else "all"
    return summary


@router.get("/owasp")
async def owasp_report(
    repository_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """OWASP Top 10 findings breakdown."""
    from services.reporting.compliance import map_to_owasp, OWASP_TOP_10
    from apps.api.app.core.access_control import get_accessible_repo_ids, can_access_repository

    if repository_id:
        if not await can_access_repository(db, user, repository_id):
            raise HTTPException(status_code=403, detail="Access denied")

    query = select(NormalizedFinding).where(
        NormalizedFinding.tenant_id == user.tenant_id,
        NormalizedFinding.is_suppressed == False,
    )
    if repository_id:
        query = query.where(NormalizedFinding.repository_id == repository_id)
    else:
        accessible = await get_accessible_repo_ids(db, user)
        if accessible is not None:
            query = query.where(NormalizedFinding.repository_id.in_(accessible))

    result = await db.execute(query)
    findings = result.scalars().all()

    # Build OWASP breakdown
    owasp_findings: dict[str, list] = {f"{code}: {info['name']}": [] for code, info in OWASP_TOP_10.items()}
    unmapped = []

    for f in findings:
        mapping = map_to_owasp(f.cwe, f.vulnerability_category)
        if mapping:
            key = f"{mapping['code']}: {mapping['name']}"
            owasp_findings[key].append({
                "id": str(f.id),
                "title": f.title[:80],
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "file": f.file_path,
                "cwe": f.cwe,
            })
        else:
            unmapped.append(str(f.id))

    return {
        "framework": "OWASP Top 10 (2021)",
        "categories": {k: {"count": len(v), "findings": v[:10]} for k, v in owasp_findings.items() if v},
        "unmapped_count": len(unmapped),
        "total_findings": len(findings),
    }


@router.get("/executive")
async def executive_summary(
    days: int = Query(30),
    repository_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Executive summary — high-level security posture."""
    from sqlalchemy import func, cast, Date
    from datetime import datetime, timezone, timedelta
    from apps.api.app.models.scan import ScanJob
    from apps.api.app.models.repository import Repository
    from apps.api.app.models.finding import FindingDecision
    from apps.api.app.core.access_control import get_accessible_repo_ids, can_access_repository

    # Normalize repository_id (may be Query(None) when called internally)
    if repository_id is not None and not isinstance(repository_id, UUID):
        try:
            repository_id = UUID(str(repository_id)) if str(repository_id) not in ('None', '') else None
        except (ValueError, AttributeError):
            repository_id = None

    # Validate access to specific repo if requested
    if repository_id:
        if not await can_access_repository(db, user, repository_id):
            raise HTTPException(status_code=403, detail="Access denied")

    tenant = user.tenant_id
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Build access-controlled conditions
    accessible = await get_accessible_repo_ids(db, user)
    finding_conds = [NormalizedFinding.tenant_id == tenant]
    if repository_id:
        finding_conds.append(NormalizedFinding.repository_id == repository_id)
    elif accessible is not None:
        finding_conds.append(NormalizedFinding.repository_id.in_(accessible))

    total = await db.execute(select(func.count(NormalizedFinding.id)).where(*finding_conds))
    total_count = total.scalar() or 0

    # By severity
    sev_r = await db.execute(
        select(NormalizedFinding.severity, func.count(NormalizedFinding.id))
        .where(*finding_conds)
        .group_by(NormalizedFinding.severity)
    )
    by_severity = {(s.value.lower() if hasattr(s, "value") else str(s).split(".")[-1].lower()): c for s, c in sev_r.all()}

    # By classification
    cls_r = await db.execute(
        select(NormalizedFinding.classification, func.count(NormalizedFinding.id))
        .where(*finding_conds)
        .group_by(NormalizedFinding.classification)
    )
    by_classification = {(s.value.lower().replace("_", " ") if hasattr(s, "value") else str(s).split(".")[-1].lower().replace("_", " ")): c for s, c in cls_r.all()}

    # FP rate
    fp_count = sum(v for k, v in by_classification.items() if "false_positive" in k.lower())
    fp_rate = round(fp_count / max(total_count, 1), 4)

    # Scan stats — extract scalars eagerly to avoid ResourceClosedError
    scans_r = await db.execute(select(func.count(ScanJob.id)).where(ScanJob.tenant_id == tenant))
    scans_count = scans_r.scalar() or 0

    repos_r = await db.execute(select(func.count(Repository.id)).where(Repository.tenant_id == tenant, Repository.is_active == True))
    repos_count = repos_r.scalar() or 0

    # New findings this period
    new_r = await db.execute(
        select(func.count(NormalizedFinding.id))
        .where(NormalizedFinding.tenant_id == tenant, NormalizedFinding.created_at >= since)
    )
    new_count = new_r.scalar() or 0

    # Resolved this period (user decisions)
    resolved_r = await db.execute(
        select(func.count(FindingDecision.id))
        .join(NormalizedFinding, FindingDecision.finding_id == NormalizedFinding.id)
        .where(NormalizedFinding.tenant_id == tenant, FindingDecision.created_at >= since)
    )
    resolved_count = resolved_r.scalar() or 0

    # Security score
    criticals = sum(v for k, v in by_severity.items() if "critical" in k.lower())
    highs = sum(v for k, v in by_severity.items() if "high" in k.lower())
    mediums = sum(v for k, v in by_severity.items() if "medium" in k.lower())
    sec_score = max(5, min(95, 100 - (criticals * 10 + highs * 5 + mediums * 2))) if total_count > 0 else 85
    grade = "A" if sec_score >= 90 else "B+" if sec_score >= 80 else "B" if sec_score >= 70 else "C+" if sec_score >= 60 else "C" if sec_score >= 40 else "D" if sec_score >= 20 else "F"

    total_scans = scans_count
    total_repos = repos_count
    new_period = new_count
    resolved_period = resolved_count

    # ── Top 5 riskiest repos (single query, no nested loops) ──
    top_repos_q = await db.execute(
        select(
            Repository.id, Repository.name,
            func.count(NormalizedFinding.id).label("finding_count"),
        )
        .join(NormalizedFinding, NormalizedFinding.repository_id == Repository.id)
        .where(Repository.tenant_id == tenant, Repository.is_active == True)
        .group_by(Repository.id, Repository.name)
        .order_by(func.count(NormalizedFinding.id).desc())
        .limit(5)
    )
    top_repos_raw = top_repos_q.all()

    # Get severity counts for these repos in one query
    top_repo_ids = [row[0] for row in top_repos_raw]
    repo_severity = {}
    if top_repo_ids:
        sev_q = await db.execute(
            select(
                NormalizedFinding.repository_id,
                NormalizedFinding.severity,
                func.count(NormalizedFinding.id),
            )
            .where(NormalizedFinding.repository_id.in_(top_repo_ids))
            .group_by(NormalizedFinding.repository_id, NormalizedFinding.severity)
        )
        for rid, sev, cnt in sev_q.all():
            sev_str = sev.value if hasattr(sev, "value") else str(sev)
            repo_severity.setdefault(str(rid), {})[sev_str] = cnt

    top_repos = []
    for repo_id, repo_name, finding_count in top_repos_raw:
        rid = str(repo_id)
        sevs = repo_severity.get(rid, {})
        top_repos.append({
            "id": rid, "name": repo_name, "findings": finding_count,
            "critical": sevs.get("critical", 0), "high": sevs.get("high", 0),
        })

    # ── Top vulnerability categories ──────────────────
    cat_q = await db.execute(
        select(NormalizedFinding.vulnerability_category, func.count(NormalizedFinding.id))
        .where(NormalizedFinding.tenant_id == tenant)
        .group_by(NormalizedFinding.vulnerability_category)
        .order_by(func.count(NormalizedFinding.id).desc())
        .limit(10)
    )
    top_categories = [{"category": c, "count": n} for c, n in cat_q.all()]

    # ── Daily trend (new findings per day) ────────────
    daily_q = await db.execute(
        select(
            cast(NormalizedFinding.created_at, Date).label("date"),
            func.count(NormalizedFinding.id),
        )
        .where(NormalizedFinding.tenant_id == tenant, NormalizedFinding.created_at >= since)
        .group_by(cast(NormalizedFinding.created_at, Date))
        .order_by(cast(NormalizedFinding.created_at, Date))
    )
    daily_trend = [{"date": str(d), "count": c} for d, c in daily_q.all()]

    # ── Remediation pipeline ──────────────────────────
    rem_q = await db.execute(
        select(NormalizedFinding.remediation_status, func.count(NormalizedFinding.id))
        .where(NormalizedFinding.tenant_id == tenant)
        .group_by(NormalizedFinding.remediation_status)
    )
    remediation_pipeline = {(s.value.lower().replace("_", " ") if hasattr(s, "value") else str(s).split(".")[-1].lower().replace("_", " ")): c for s, c in rem_q.all()}

    # ── AI performance ────────────────────────────────
    ai_triaged = await db.execute(
        select(func.count(NormalizedFinding.id)).where(
            NormalizedFinding.tenant_id == tenant,
            NormalizedFinding.ai_confidence.isnot(None),
        )
    )
    ai_triaged_count = ai_triaged.scalar() or 0

    user_decisions = await db.execute(
        select(func.count(FindingDecision.id))
        .join(NormalizedFinding, FindingDecision.finding_id == NormalizedFinding.id)
        .where(NormalizedFinding.tenant_id == tenant)
    )
    decision_count = user_decisions.scalar() or 0

    # ── SLA compliance ────────────────────────────────
    from datetime import datetime as dt
    critical_sla_days = 7
    high_sla_days = 30

    overdue_crit_r = await db.execute(
        select(func.count(NormalizedFinding.id)).where(
            NormalizedFinding.tenant_id == tenant,
            NormalizedFinding.severity == "critical",
            NormalizedFinding.classification.notin_(["confirmed_false_positive", "likely_false_positive"]),
            NormalizedFinding.created_at < (datetime.now(timezone.utc) - timedelta(days=critical_sla_days)),
        )
    )
    overdue_crit_count = overdue_crit_r.scalar() or 0

    overdue_high_r = await db.execute(
        select(func.count(NormalizedFinding.id)).where(
            NormalizedFinding.tenant_id == tenant,
            NormalizedFinding.severity == "high",
            NormalizedFinding.classification.notin_(["confirmed_false_positive", "likely_false_positive"]),
            NormalizedFinding.created_at < (datetime.now(timezone.utc) - timedelta(days=high_sla_days)),
        )
    )
    overdue_high_count = overdue_high_r.scalar() or 0

    sla_compliance = {
        "critical_overdue": overdue_crit_count,
        "critical_sla_days": critical_sla_days,
        "high_overdue": overdue_high_count,
        "high_sla_days": high_sla_days,
        "critical_in_compliance": max(0, criticals - overdue_crit_count),
        "high_in_compliance": max(0, highs - overdue_high_count),
    }

    # ── Scan coverage ─────────────────────────────────
    repos_scanned_r = await db.execute(
        select(func.count(func.distinct(ScanJob.repository_id))).where(ScanJob.tenant_id == tenant)
    )
    scan_coverage = round((repos_scanned_r.scalar() or 0) / max(total_repos, 1), 4)

    # ── Posture statement ─────────────────────────────
    if sec_score >= 80:
        posture = "Your security posture is strong. Continue monitoring and addressing findings as they arise."
    elif sec_score >= 60:
        posture = f"Your security posture is moderate. {criticals} critical findings require immediate attention."
    elif sec_score >= 40:
        posture = f"Your security posture needs improvement. {criticals} critical and {highs} high severity findings are open."
    else:
        posture = f"Your security posture is critical. {criticals} critical vulnerabilities require urgent remediation."

    return {
        "period_days": days,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "posture_statement": posture,

        # KPIs
        "total_findings": total_count,
        "new_findings_period": new_period,
        "resolved_period": resolved_period,
        "security_score": sec_score,
        "grade": grade,
        "fp_rate": fp_rate,
        "fp_count": fp_count,
        "total_scans": total_scans,
        "total_repos": total_repos,
        "scan_coverage": scan_coverage,
        "criticals": criticals,
        "highs": highs,

        # Breakdowns
        "by_severity": by_severity,
        "by_classification": by_classification,

        # Sections
        "top_repos": top_repos,
        "top_categories": top_categories,
        "daily_trend": daily_trend,
        "remediation_pipeline": remediation_pipeline,
        "sla_compliance": sla_compliance,

        # AI
        "ai_triaged": ai_triaged_count,
        "user_decisions": decision_count,
        "ai_accuracy": round(decision_count / max(ai_triaged_count, 1), 4) if ai_triaged_count > 0 else None,
    }


@router.get("/aging")
async def vulnerability_aging(
    repository_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """SLA & Aging — combined SLA compliance + age distribution + overdue findings."""
    from datetime import datetime, timezone
    from apps.api.app.core.access_control import get_accessible_repo_ids, can_access_repository
    from apps.api.app.models.repository import Repository

    # Normalize repository_id
    if repository_id is not None and not isinstance(repository_id, UUID):
        try:
            repository_id = UUID(str(repository_id)) if str(repository_id) not in ('None', '') else None
        except (ValueError, AttributeError):
            repository_id = None

    tenant = user.tenant_id

    if repository_id:
        if not await can_access_repository(db, user, repository_id):
            raise HTTPException(status_code=403, detail="Access denied")

    # SLA limits — hardcoded defaults.  The Policy model that backed these was
    # removed 2026-05-16 along with the governance surfaces; these windows are
    # what every existing tenant was on by default.  Override per-tenant SLA
    # settings can be reintroduced as a single config row when needed.
    sla_limits = {
        "critical": 7,
        "high": 30,
        "medium": 90,
        "low": 180,
    }

    # Access control
    accessible = await get_accessible_repo_ids(db, user)
    query = select(NormalizedFinding).where(
        NormalizedFinding.tenant_id == tenant,
        NormalizedFinding.is_suppressed == False,
        NormalizedFinding.classification.notin_(["confirmed_false_positive", "likely_false_positive"]),
    )
    if repository_id:
        query = query.where(NormalizedFinding.repository_id == repository_id)
    elif accessible is not None:
        query = query.where(NormalizedFinding.repository_id.in_(accessible))

    result = await db.execute(query.limit(5000))
    findings = result.scalars().all()

    now = datetime.now(timezone.utc)

    # Buckets with severity breakdown
    bucket_names = ["0-7 days", "8-30 days", "31-90 days", "90+ days"]
    buckets = {b: 0 for b in bucket_names}
    bucket_severity = {b: {"critical": 0, "high": 0, "medium": 0, "low": 0} for b in bucket_names}

    # SLA tracking per severity (all 4 tiers)
    overdue = {"critical": [], "high": [], "medium": [], "low": []}
    in_sla_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    unassigned_overdue = 0

    all_aged = []
    repo_ages: dict[str, list[int]] = {}

    # Pre-fetch repo names
    repo_ids = {f.repository_id for f in findings if f.repository_id}
    repo_name_map = {}
    if repo_ids:
        repos_r = await db.execute(select(Repository.id, Repository.name).where(Repository.id.in_(repo_ids)))
        repo_name_map = {str(r[0]): r[1] for r in repos_r.all()}

    # Pre-fetch user names for assignees
    from apps.api.app.models.user import User as UserModel
    assigned_ids = {f.assigned_to for f in findings if f.assigned_to}
    user_name_map = {}
    if assigned_ids:
        users_r = await db.execute(select(UserModel.id, UserModel.full_name).where(UserModel.id.in_(assigned_ids)))
        user_name_map = {str(r[0]): r[1] for r in users_r.all()}

    for f in findings:
        if f.created_at:
            age = (now - (f.created_at.replace(tzinfo=timezone.utc) if f.created_at.tzinfo is None else f.created_at)).days
        else:
            age = 0

        sev = f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).split(".")[-1].lower()
        line = f.line_start if hasattr(f, "line_start") and f.line_start else None
        file_loc = f.file_path or ""
        if line:
            file_loc = f"{file_loc}:{line}"
        assignee = user_name_map.get(str(f.assigned_to), None) if f.assigned_to else None
        sla_limit = sla_limits.get(sev, 180)
        days_remaining = sla_limit - age
        overdue_by = max(age - sla_limit, 0)
        repo_name = repo_name_map.get(str(f.repository_id), "Unknown")

        # Bucket assignment
        if age <= 7:
            bk = "0-7 days"
        elif age <= 30:
            bk = "8-30 days"
        elif age <= 90:
            bk = "31-90 days"
        else:
            bk = "90+ days"
        buckets[bk] += 1
        if sev in bucket_severity[bk]:
            bucket_severity[bk][sev] += 1

        finding_info = {
            "id": str(f.id), "title": f.title[:60], "age_days": age,
            "file": file_loc[:60], "severity": sev,
            "repo_id": str(f.repository_id), "repo_name": repo_name,
            "assignee": assignee or "Unassigned",
            "sla_days": sla_limit, "days_remaining": days_remaining,
            "overdue_by": overdue_by, "cwe": (f.cwe or ""),
        }

        # SLA tracking
        if sev in total_by_sev:
            total_by_sev[sev] += 1
            if age > sla_limit:
                overdue[sev].append(finding_info)
                if not assignee:
                    unassigned_overdue += 1
            else:
                in_sla_counts[sev] += 1

        all_aged.append(finding_info)

        # Per-repo age tracking
        rid = str(f.repository_id)
        if rid not in repo_ages:
            repo_ages[rid] = []
        repo_ages[rid].append(age)

    total_open = len(findings)
    avg_age = sum(a["age_days"] for a in all_aged) / max(total_open, 1)

    # Sort overdue by overdue_by descending (worst first)
    for sev in overdue:
        overdue[sev].sort(key=lambda x: x["overdue_by"], reverse=True)

    # Top 10 oldest findings
    top_aged = sorted(all_aged, key=lambda x: x["age_days"], reverse=True)[:10]

    # Age by repository
    age_by_repo = []
    for rid, ages in repo_ages.items():
        age_by_repo.append({
            "repo_id": rid,
            "repo_name": repo_name_map.get(rid, "Unknown"),
            "total_findings": len(ages),
            "avg_age_days": round(sum(ages) / len(ages), 1),
            "max_age_days": max(ages),
            "over_30_days": sum(1 for a in ages if a > 30),
            "over_90_days": sum(1 for a in ages if a > 90),
        })
    age_by_repo.sort(key=lambda x: x["avg_age_days"], reverse=True)

    # SLA compliance
    total_applicable = sum(total_by_sev.values())
    total_in_sla = sum(in_sla_counts.values())
    total_overdue = sum(len(b) for b in overdue.values())
    compliance_pct = round(total_in_sla / max(total_applicable, 1) * 100, 1)

    return {
        # SLA section
        "sla_policy": sla_limits,
        "compliance_pct": compliance_pct,
        "total_applicable": total_applicable,
        "in_sla": total_in_sla,
        "total_overdue": total_overdue,
        "unassigned_overdue": unassigned_overdue,
        "by_severity": {
            sev: {"total": total_by_sev[sev], "in_sla": in_sla_counts[sev], "overdue": len(overdue[sev])}
            for sev in ["critical", "high", "medium", "low"]
        },
        # Overdue lists per severity
        "critical_overdue": overdue["critical"][:20],
        "critical_overdue_count": len(overdue["critical"]),
        "high_overdue": overdue["high"][:20],
        "high_overdue_count": len(overdue["high"]),
        "medium_overdue": overdue["medium"][:20],
        "medium_overdue_count": len(overdue["medium"]),
        "low_overdue": overdue["low"][:20],
        "low_overdue_count": len(overdue["low"]),
        # Aging section
        "total_open": total_open,
        "avg_age_days": round(avg_age, 1),
        "buckets": buckets,
        "bucket_severity": bucket_severity,
        "top_aged_findings": top_aged,
        "age_by_repository": age_by_repo[:15],
    }


@router.get("/repo-risk")
async def repository_risk_report(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Per-repository risk scorecard."""
    from sqlalchemy import func
    from apps.api.app.models.repository import Repository
    from apps.api.app.models.scan import ScanJob
    from apps.api.app.core.access_control import get_accessible_repo_ids

    tenant = user.tenant_id

    # Get accessible repos
    accessible = await get_accessible_repo_ids(db, user)
    repo_query = select(Repository).where(Repository.tenant_id == tenant, Repository.is_active == True)
    if accessible is not None:
        repo_query = repo_query.where(Repository.id.in_(accessible))
    repos_r = await db.execute(repo_query)
    repos = repos_r.scalars().all()

    results = []
    for repo in repos:
        # Finding counts
        sev_r = await db.execute(
            select(NormalizedFinding.severity, func.count(NormalizedFinding.id))
            .where(NormalizedFinding.repository_id == repo.id, NormalizedFinding.tenant_id == tenant)
            .group_by(NormalizedFinding.severity)
        )
        by_sev = {(s.value.lower() if hasattr(s, "value") else str(s).split(".")[-1].lower()): c for s, c in sev_r.all()}

        total = sum(by_sev.values())
        criticals = by_sev.get("critical", 0)
        highs = by_sev.get("high", 0)

        # Last scan
        scan_r = await db.execute(
            select(ScanJob).where(ScanJob.repository_id == repo.id)
            .order_by(ScanJob.created_at.desc()).limit(1)
        )
        last_scan = scan_r.scalar_one_or_none()

        score = max(5, min(100, 100 - (criticals * 15 + highs * 7 + total))) if total > 0 else 100

        results.append({
            "id": str(repo.id),
            "name": repo.name,
            "url": repo.url,
            "languages": repo.languages or [],
            "frameworks": repo.frameworks or [],
            "total_findings": total,
            "by_severity": by_sev,
            "criticals": criticals,
            "highs": highs,
            "risk_score": score,
            "grade": "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D" if score >= 20 else "F",
            "last_scan": str(last_scan.created_at) if last_scan else None,
            "last_scan_status": last_scan.status.value if last_scan and hasattr(last_scan.status, "value") else None,
            "default_branch": repo.default_branch,
        })

    results.sort(key=lambda x: x["risk_score"])
    return {"repositories": results}


@router.get("/developer-activity")
async def developer_activity(
    days: int = Query(30),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Developer activity — triage actions per user."""
    from sqlalchemy import func
    from datetime import datetime, timezone, timedelta
    from apps.api.app.models.finding import FindingDecision
    from apps.api.app.models.user import User as UserModel

    tenant = user.tenant_id
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Decisions per user
    decisions_r = await db.execute(
        select(FindingDecision.user_id, FindingDecision.action, func.count(FindingDecision.id))
        .join(NormalizedFinding, FindingDecision.finding_id == NormalizedFinding.id)
        .where(NormalizedFinding.tenant_id == tenant, FindingDecision.created_at >= since)
        .group_by(FindingDecision.user_id, FindingDecision.action)
    )

    user_activity: dict = {}
    for user_id, action, count in decisions_r.all():
        uid = str(user_id)
        if uid not in user_activity:
            user_activity[uid] = {"user_id": uid, "actions": {}, "total": 0}
        user_activity[uid]["actions"][action] = count
        user_activity[uid]["total"] += count

    # Enrich with user names
    if user_activity:
        users_r = await db.execute(
            select(UserModel).where(UserModel.tenant_id == tenant)
        )
        user_map = {str(u.id): u.full_name for u in users_r.scalars().all()}
        for uid, data in user_activity.items():
            data["name"] = user_map.get(uid, "Unknown")

    activity_list = sorted(user_activity.values(), key=lambda x: x["total"], reverse=True)
    return {"period_days": days, "users": activity_list}


@router.get("/sla")
async def sla_compliance(
    repository_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """SLA compliance — alias for the combined SLA & Aging report."""
    return await vulnerability_aging(repository_id=repository_id, db=db, user=user)


# ════════════════════════════════════════════════════════════
#  ENTERPRISE REPORT ENDPOINTS
# ════════════════════════════════════════════════════════════


@router.get("/release-readiness")
async def release_readiness(
    repository_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Release readiness assessment — Go/No-Go decision with security quality gate."""
    from services.reporting.risk_scoring import evaluate_release_readiness
    from apps.api.app.core.access_control import get_accessible_repo_ids, can_access_repository

    # Normalize repository_id (may be Query(None) when called internally)
    if repository_id is not None and not isinstance(repository_id, UUID):
        try:
            repository_id = UUID(str(repository_id)) if str(repository_id) not in ('None', '') else None
        except (ValueError, AttributeError):
            repository_id = None

    if repository_id:
        if not await can_access_repository(db, user, repository_id):
            raise HTTPException(status_code=403, detail="Access denied")

    tenant = user.tenant_id

    # Gate policy — hardcoded defaults.  The Policy model that backed these
    # was removed 2026-05-16 along with the governance surfaces.  These are
    # the conservative defaults from the original Policy seeder.
    gate_policy = {
        "max_critical": 0,
        "max_high": 5,
        "max_medium": 50,
        "block_on_new_critical": True,
        "required_review_pct": 80,
        "min_security_score": 60,
    }

    query = select(NormalizedFinding).where(
        NormalizedFinding.tenant_id == tenant,
        NormalizedFinding.is_suppressed == False,
    )
    if repository_id:
        query = query.where(NormalizedFinding.repository_id == repository_id)
    else:
        accessible = await get_accessible_repo_ids(db, user)
        if accessible is not None:
            query = query.where(NormalizedFinding.repository_id.in_(accessible))

    result = await db.execute(query.limit(5000))
    findings = result.scalars().all()

    findings_data = [
        {
            "severity": f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).split(".")[-1].lower(),
            "classification": f.classification.value.lower() if hasattr(f.classification, "value") else str(f.classification).split(".")[-1].lower(),
            "review_status": f.review_status.value.lower() if hasattr(f.review_status, "value") else str(f.review_status).split(".")[-1].lower(),
            "remediation_status": f.remediation_status.value.lower() if hasattr(f.remediation_status, "value") else str(f.remediation_status).split(".")[-1].lower(),
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "exploitability_score": f.exploitability_score,
            "business_risk_score": f.business_risk_score,
        }
        for f in findings
    ]

    return evaluate_release_readiness(findings_data, gate_policy)


@router.get("/security-debt")
async def security_debt_report(
    repository_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Security debt calculation — estimated remediation effort and cost."""
    from services.reporting.risk_scoring import calculate_security_debt, compute_mttr
    from apps.api.app.core.access_control import get_accessible_repo_ids

    # Normalize repository_id (may be Query(None) when called internally)
    if repository_id is not None and not isinstance(repository_id, UUID):
        try:
            repository_id = UUID(str(repository_id)) if str(repository_id) not in ('None', '') else None
        except (ValueError, AttributeError):
            repository_id = None

    tenant = user.tenant_id
    accessible = await get_accessible_repo_ids(db, user)

    query = select(NormalizedFinding).where(
        NormalizedFinding.tenant_id == tenant,
        NormalizedFinding.is_suppressed == False,
    )
    if repository_id:
        query = query.where(NormalizedFinding.repository_id == repository_id)
    elif accessible is not None:
        query = query.where(NormalizedFinding.repository_id.in_(accessible))

    result = await db.execute(query.limit(5000))
    findings = result.scalars().all()

    findings_data = [
        {
            "severity": f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).split(".")[-1].lower(),
            "classification": f.classification.value.lower() if hasattr(f.classification, "value") else str(f.classification).split(".")[-1].lower(),
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "remediation_status": f.remediation_status.value.lower() if hasattr(f.remediation_status, "value") else str(f.remediation_status).split(".")[-1].lower(),
            "updated_at": f.updated_at.isoformat() if f.updated_at else None,
        }
        for f in findings
    ]

    debt = calculate_security_debt(findings_data)
    mttr = compute_mttr(findings_data)

    return {
        **debt,
        "mttr": mttr,
        "repository_id": str(repository_id) if repository_id else "all",
    }


@router.get("/fix-priority")
async def fix_priority_report(
    repository_id: Optional[UUID] = Query(None),
    top_n: int = Query(20, ge=5, le=50),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Top-N fix prioritisation — what to fix first based on risk, exploitability, and age."""
    from services.reporting.risk_scoring import prioritise_fixes
    from apps.api.app.core.access_control import get_accessible_repo_ids

    # Normalize repository_id (may be Query(None) when called internally)
    if repository_id is not None and not isinstance(repository_id, UUID):
        try:
            repository_id = UUID(str(repository_id)) if str(repository_id) not in ('None', '') else None
        except (ValueError, AttributeError):
            repository_id = None

    # Normalize top_n (may be Query object when called internally)
    if not isinstance(top_n, int):
        try:
            top_n = int(str(top_n))
        except (ValueError, TypeError):
            top_n = 20

    tenant = user.tenant_id
    accessible = await get_accessible_repo_ids(db, user)

    query = select(NormalizedFinding).where(
        NormalizedFinding.tenant_id == tenant,
        NormalizedFinding.is_suppressed == False,
    )
    if repository_id:
        query = query.where(NormalizedFinding.repository_id == repository_id)
    elif accessible is not None:
        query = query.where(NormalizedFinding.repository_id.in_(accessible))

    result = await db.execute(query.order_by(NormalizedFinding.severity).limit(5000))
    findings = result.scalars().all()

    findings_data = [
        {
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).split(".")[-1].lower(),
            "classification": f.classification.value.lower() if hasattr(f.classification, "value") else str(f.classification).split(".")[-1].lower(),
            "cwe": f.cwe,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "exploitability_score": f.exploitability_score,
            "business_risk_score": f.business_risk_score,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in findings
    ]

    return {
        "top_fixes": prioritise_fixes(findings_data, top_n),
        "total_analyzed": len(findings_data),
        "repository_id": str(repository_id) if repository_id else "all",
    }


# Governance report endpoint removed 2026-05-16 — it was a thin wrapper
# around services.reporting.* (compliance, release readiness, security debt,
# MTTR, risk heatmap) presented as a "governance" surface.  Each of those
# helpers remains and is reachable via its own dedicated endpoint
# (/release-readiness, /security-debt, /compliance, /sla, /metrics/...).


@router.get("/developer-report")
async def developer_remediation_report(
    finding_id: Optional[UUID] = Query(None),
    repository_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Developer remediation report — detailed fix guidance for findings."""
    from services.reporting.developer_guidance import get_finding_guidance
    from services.reporting.compliance import generate_per_finding_compliance
    from services.reporting.risk_scoring import compute_cvss_score
    from apps.api.app.core.access_control import get_accessible_repo_ids

    # Normalize repository_id and finding_id (may be Query(None) when called internally)
    if repository_id is not None and not isinstance(repository_id, UUID):
        try:
            repository_id = UUID(str(repository_id)) if str(repository_id) not in ('None', '') else None
        except (ValueError, AttributeError):
            repository_id = None
    if finding_id is not None and not isinstance(finding_id, UUID):
        try:
            finding_id = UUID(str(finding_id)) if str(finding_id) not in ('None', '') else None
        except (ValueError, AttributeError):
            finding_id = None

    tenant = user.tenant_id

    query = select(NormalizedFinding).where(
        NormalizedFinding.tenant_id == tenant,
        NormalizedFinding.is_suppressed == False,
    )
    if finding_id:
        query = query.where(NormalizedFinding.id == finding_id)
    elif repository_id:
        query = query.where(NormalizedFinding.repository_id == repository_id)
    else:
        accessible = await get_accessible_repo_ids(db, user)
        if accessible is not None:
            query = query.where(NormalizedFinding.repository_id.in_(accessible))

    query = query.where(
        NormalizedFinding.classification.notin_(["confirmed_false_positive", "likely_false_positive"])
    ).order_by(NormalizedFinding.severity).limit(50)

    result = await db.execute(query)
    findings = result.scalars().all()

    report_findings = []
    for f in findings:
        sev = f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).split(".")[-1].lower()
        guidance = get_finding_guidance(f.cwe, f.vulnerability_category, sev)
        compliance = generate_per_finding_compliance(f.cwe, f.vulnerability_category)
        cvss = compute_cvss_score(
            sev,
            cwe=f.cwe,
            exploitability_score=f.exploitability_score,
            has_data_flow=bool(f.trace),
        )

        report_findings.append({
            "id": str(f.id),
            "title": f.title,
            "description": f.description,
            "severity": sev,
            "cwe": f.cwe,
            "cve": f.cve,
            "vulnerability_category": f.vulnerability_category,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "function_name": f.function_name,
            "class_name": f.class_name,
            "code_snippet": f.code_snippet,
            "source_metadata": f.source_metadata,
            "sink_metadata": f.sink_metadata,
            "trace": f.trace,
            "cvss": cvss,
            "guidance": guidance,
            "compliance": compliance,
            "ai_confidence": f.ai_confidence,
            "ai_explanation": f.ai_explanation,
            "classification": f.classification.value if hasattr(f.classification, "value") else str(f.classification),
        })

    return {
        "total_findings": len(report_findings),
        "findings": report_findings,
        "repository_id": str(repository_id) if repository_id else "all",
    }


# ── SARIF 2.1.0 export ──────────────────────────────────────────
#
# Why the limit is 25_000 (Track-A P1.1, 2026-05-22)
# ---------------------------------------------------
# Previously hardcoded at 1_000 with no truncation signal — customers
# with bigger scans got partial data and no warning.  Raised to 25_000
# because GitHub Advanced Security's own SARIF upload ceiling is
# 25_000 results per SARIF file (and 10 MB total).  When the cap IS
# hit, the export now sets ``runs[0].invocations[0].properties.
# vooda_truncated_at`` so downstream consumers (and our own CI) can
# detect partial exports.
SARIF_RESULT_HARD_LIMIT = 25_000

# Severity → SARIF level mapping.  GHAS recognises error / warning /
# note / none; everything else gets coerced to warning so we never
# emit invalid SARIF.
_SARIF_SEVERITY_MAP = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "none",
}


def _build_sarif(findings: list, truncated_at: Optional[int] = None) -> dict:
    """Build a SARIF 2.1.0 document from a list of NormalizedFinding
    (or duck-typed equivalents — extracted as a pure function so it
    can be tested against fake findings without a DB session).

    ``truncated_at`` — when set, populates
    ``runs[0].invocations[0].properties.vooda_truncated_at`` with the
    cap that was hit.  Lets consumers (UI, CI, GHAS) detect a partial
    export instead of silently believing they have everything.

    Schema version: SARIF 2.1.0 (OASIS published).
    """
    from packages.common.scanner_branding import get_sarif_tool_info

    sarif_results = []
    rules: dict = {}

    for f in findings:
        rule_id = f.scanner_rule_id or "unknown"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f.vulnerability_category},
            }
            if f.cwe:
                rules[rule_id]["properties"] = {"tags": [f.cwe]}

        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)

        sarif_results.append({
            "ruleId": rule_id,
            "level": _SARIF_SEVERITY_MAP.get(sev, "warning"),
            "message": {"text": f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": f.line_start or 1},
                },
            }],
            "properties": {
                "vooda_classification": (
                    f.classification.value if hasattr(f.classification, "value") else str(f.classification)
                ),
                "vooda_confidence": f.ai_confidence,
            },
        })

    tool_info = get_sarif_tool_info()
    tool_info["driver"]["rules"] = list(rules.values())

    run: dict = {
        "tool": tool_info,
        "results": sarif_results,
    }

    # Truncation signal lives on invocations[].properties so
    # consumers that follow the SARIF spec strictly find it where
    # they look for tool-specific metadata — and GHAS ignores
    # unknown properties cleanly.
    if truncated_at is not None:
        run["invocations"] = [{
            "executionSuccessful": True,
            "properties": {
                "vooda_truncated_at": truncated_at,
                "vooda_truncation_notice": (
                    f"Export was capped at {truncated_at} results to stay within "
                    "GitHub Advanced Security's SARIF upload limit. To get the "
                    "remaining findings, filter by repository_id, scan_job_id, "
                    "or scan_source_id and export per-scope."
                ),
            },
        }]

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


@router.get("/export/sarif")
async def export_sarif(
    repository_id: Optional[UUID] = Query(None),
    scan_job_id: Optional[UUID] = Query(None),
    # Added 2026-05-22 (Track-A P1.1): source-scan findings (Slack,
    # Jira, Confluence, etc.) live on scan_source_id rather than
    # repository_id.  Without this filter, customers exporting per-
    # source got their entire tenant's findings instead.
    scan_source_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export findings as SARIF 2.1.0 format.

    Filters (any combination, all optional):
      * ``repository_id``   — restrict to one repo
      * ``scan_job_id``     — restrict to one scan run
      * ``scan_source_id``  — restrict to one SaaS source adapter
                              (Slack workspace, Jira project, etc.)

    Hard cap of ``SARIF_RESULT_HARD_LIMIT`` (25 000) results per
    response — matches GitHub Advanced Security's own ceiling.  When
    the cap is hit, the SARIF document carries an explicit
    ``vooda_truncated_at`` field under
    ``runs[0].invocations[0].properties`` so consumers can detect
    partial exports rather than silently believing they have all
    findings.
    """
    query = select(NormalizedFinding).where(
        NormalizedFinding.tenant_id == user.tenant_id,
        NormalizedFinding.is_suppressed == False,
    )
    if repository_id:
        query = query.where(NormalizedFinding.repository_id == repository_id)
    if scan_job_id:
        query = query.where(NormalizedFinding.scan_job_id == scan_job_id)
    if scan_source_id:
        query = query.where(NormalizedFinding.scan_source_id == scan_source_id)

    # Fetch one over the cap so we can detect "we hit it" without an
    # extra COUNT(*) round trip.  Trimmed back to the cap below.
    result = await db.execute(query.limit(SARIF_RESULT_HARD_LIMIT + 1))
    fetched = list(result.scalars().all())
    truncated_at: Optional[int] = None
    if len(fetched) > SARIF_RESULT_HARD_LIMIT:
        fetched = fetched[:SARIF_RESULT_HARD_LIMIT]
        truncated_at = SARIF_RESULT_HARD_LIMIT

    sarif = _build_sarif(fetched, truncated_at=truncated_at)

    return JSONResponse(content=sarif, headers={
        "Content-Disposition": "attachment; filename=vooda-findings.sarif",
    })


@router.get("/export/spdx")
async def export_spdx(
    repository_id: Optional[UUID] = Query(None),
    scan_job_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export findings as SPDX 2.3 Security format (JSON-LD)."""
    from datetime import datetime, timezone

    query = select(NormalizedFinding).where(
        NormalizedFinding.tenant_id == user.tenant_id,
        NormalizedFinding.is_suppressed == False,
    )
    if repository_id:
        query = query.where(NormalizedFinding.repository_id == repository_id)
    if scan_job_id:
        query = query.where(NormalizedFinding.scan_job_id == scan_job_id)

    result = await db.execute(query.limit(1000))
    findings = result.scalars().all()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_namespace = f"https://vooda.ai/spdx/{user.tenant_id}"

    # Build SPDX packages (one per unique file with findings)
    packages = {}
    relationships = []
    vulnerabilities = []

    for f in findings:
        file_path = f.file_path or "unknown"
        pkg_id = f"SPDXRef-{file_path.replace('/', '-').replace('.', '-')[:60]}"

        if pkg_id not in packages:
            packages[pkg_id] = {
                "SPDXID": pkg_id,
                "name": file_path.split("/")[-1],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "supplier": "NOASSERTION",
                "comment": f"File: {file_path}",
            }
            relationships.append({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": pkg_id,
            })

        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        cls = f.classification.value if hasattr(f.classification, "value") else str(f.classification)
        sm = f.source_metadata or {}

        vuln_id = f"VOODA-{str(f.id)[:8].upper()}"
        vulnerabilities.append({
            "id": vuln_id,
            "name": f.title or "Secret Finding",
            "description": (f.description or "")[:500],
            "modified": now,
            "published": str(f.created_at)[:19] + "Z" if f.created_at else now,
            "withdrawn": None,
            "ratings": [{
                "method": "other",
                "severity": sev,
                "score": f.ai_confidence or f.confidence or 0,
                "vector": f"CWE:{f.cwe}" if f.cwe else "NOASSERTION",
                "justification": cls,
            }],
            "affects": [{
                "ref": pkg_id,
                "versions": [{"version": "NOASSERTION", "status": "affected"}],
            }],
            "externalReferences": [
                {"type": "cwe", "locator": f"https://cwe.mitre.org/data/definitions/{f.cwe.replace('CWE-','')}.html"} if f.cwe else None,
            ],
            "properties": {
                "vooda:classification": cls,
                "vooda:provider": sm.get("provider", "unknown"),
                "vooda:detection_method": sm.get("detection_method", "unknown"),
                "vooda:file_path": file_path,
                "vooda:line": f.line_start,
                "vooda:masked_value": sm.get("masked_value", "****"),
                "vooda:validation_status": sm.get("validation_status", "not_validated"),
            },
        })
        # Clean None from externalReferences
        vulnerabilities[-1]["externalReferences"] = [r for r in vulnerabilities[-1]["externalReferences"] if r]

    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Vooda Secret Scan Report",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": now,
            "creators": ["Tool: Vooda AI Secret Scanner"],
            "licenseListVersion": "3.19",
        },
        "packages": list(packages.values()),
        "relationships": relationships,
        "vulnerabilities": vulnerabilities,
    }

    return JSONResponse(content=spdx, headers={
        "Content-Disposition": "attachment; filename=vooda-findings.spdx.json",
    })


async def _get_export_context(db, user, report_type: str, days: int, repository_id=None):
    """Get report-specific data + findings for export. Dispatches to the correct report endpoint."""
    report_data = None

    if report_type == "executive":
        report_data = await executive_summary(days=days, repository_id=repository_id, db=db, user=user)
    elif report_type == "compliance":
        report_data = await compliance_report(repository_id=repository_id, db=db, user=user)
    elif report_type == "aging":
        report_data = await vulnerability_aging(repository_id=repository_id, db=db, user=user)
    elif report_type == "repo_risk":
        report_data = await repository_risk_report(db=db, user=user)
    elif report_type == "developer":
        report_data = await developer_activity(days=days, db=db, user=user)
    elif report_type == "sla":
        report_data = await sla_compliance(repository_id=repository_id, db=db, user=user)
    elif report_type == "release_readiness":
        report_data = await release_readiness(repository_id=repository_id, db=db, user=user)
    elif report_type == "security_debt":
        report_data = await security_debt_report(repository_id=repository_id, db=db, user=user)
    elif report_type == "fix_priority":
        report_data = await fix_priority_report(repository_id=repository_id, db=db, user=user)
    elif report_type == "developer_report":
        report_data = await developer_remediation_report(repository_id=repository_id, db=db, user=user)
    elif report_type in ("trends", "remediation", "scanner", "ai"):
        # These come from metrics endpoints — import and call them
        from apps.api.app.routers.metrics import (
            finding_trends, remediation_metrics, scanner_comparison, ai_accuracy_metrics,
        )
        if report_type == "trends":
            report_data = await finding_trends(days=days, db=db, user=user)
        elif report_type == "remediation":
            report_data = await remediation_metrics(repository_id=repository_id, db=db, user=user)
        elif report_type == "scanner":
            report_data = await scanner_comparison(db=db, user=user)
        elif report_type == "ai":
            report_data = await ai_accuracy_metrics(repository_id=repository_id, db=db, user=user)

    # Always include findings
    query = select(NormalizedFinding).where(
        NormalizedFinding.tenant_id == user.tenant_id,
        NormalizedFinding.is_suppressed == False,
    )
    if repository_id:
        query = query.where(NormalizedFinding.repository_id == repository_id)
    result = await db.execute(query.order_by(NormalizedFinding.severity).limit(5000))
    findings = result.scalars().all()
    return report_data, findings


def _write_csv_report_section(writer, report_type: str, data: dict, days: int = 30):
    """Write report-type-specific sections to CSV."""

    if report_type == "executive":
        writer.writerow(["METRIC", "VALUE"])
        writer.writerow(["Security Score", f"{data['security_score']}/100 ({data['grade']})"])
        writer.writerow(["Total Findings", data["total_findings"]])
        writer.writerow(["New This Period", data["new_findings_period"]])
        writer.writerow(["Resolved This Period", data["resolved_period"]])
        writer.writerow(["FP Reduction Rate", f"{data['fp_rate'] * 100:.1f}%"])
        writer.writerow(["Critical Open", data["criticals"]])
        writer.writerow(["High Open", data["highs"]])
        writer.writerow(["Scan Coverage", f"{data['scan_coverage'] * 100:.0f}%"])
        writer.writerow(["Total Scans", data["total_scans"]])
        writer.writerow(["Total Repos", data["total_repos"]])
        writer.writerow([])
        if data.get("top_repos"):
            writer.writerow(["TOP RISKY APPLICATIONS"])
            writer.writerow(["Application", "Findings", "Critical", "High"])
            for repo in data["top_repos"]:
                writer.writerow([repo["name"], repo["findings"], repo["critical"], repo["high"]])
            writer.writerow([])
        if data.get("top_categories"):
            writer.writerow(["TOP VULNERABILITY CATEGORIES"])
            writer.writerow(["Category", "Count"])
            for cat in data["top_categories"]:
                writer.writerow([cat["category"], cat["count"]])
            writer.writerow([])
        # Classification breakdown
        if data.get("by_classification"):
            writer.writerow(["CLASSIFICATION BREAKDOWN"])
            writer.writerow(["Classification", "Count"])
            for cls_name, count in data["by_classification"].items():
                writer.writerow([cls_name.replace("_", " ").title(), count])
            writer.writerow([])

        # Remediation pipeline
        pipeline = data.get("remediation_pipeline", {})
        if pipeline:
            writer.writerow(["REMEDIATION PIPELINE"])
            writer.writerow(["Stage", "Count"])
            for stage, count in pipeline.items():
                writer.writerow([stage.replace("_", " ").title(), count])
            writer.writerow([])

        # AI performance
        writer.writerow(["AI PERFORMANCE"])
        writer.writerow(["Findings Triaged by AI", data.get("ai_triaged", 0)])
        writer.writerow(["User Decisions", data.get("user_decisions", 0)])
        fp_count = data.get("fp_count", 0)
        if fp_count > 0:
            writer.writerow(["Estimated Time Saved", f"{fp_count * 15} min ({fp_count} FPs @ 15 min/review)"])
        writer.writerow([])

        # SLA
        sla = data.get("sla_compliance", {})
        writer.writerow(["SLA COMPLIANCE"])
        writer.writerow([f"Critical ({sla.get('critical_sla_days', 7)}d SLA)", f"Overdue: {sla.get('critical_overdue', 0)}", f"In SLA: {sla.get('critical_in_compliance', 0)}"])
        writer.writerow([f"High ({sla.get('high_sla_days', 30)}d SLA)", f"Overdue: {sla.get('high_overdue', 0)}", f"In SLA: {sla.get('high_in_compliance', 0)}"])
        writer.writerow([])

        # Daily trend
        if data.get("daily_trend"):
            writer.writerow(["FINDING TREND (DAILY)"])
            writer.writerow(["Date", "New Findings"])
            for day in data["daily_trend"]:
                writer.writerow([day["date"], day["count"]])
            writer.writerow([])

    elif report_type == "compliance":
        writer.writerow(["Total Findings Analyzed", data.get("total_findings", 0)])
        writer.writerow([])
        writer.writerow(["COMPLIANCE SCORES"])
        writer.writerow(["Framework", "Score", "Clean / Total", "Status"])
        writer.writerow(["OWASP Top 10", f"{data.get('owasp_score', 0)}%",
                          f"{data.get('owasp_categories_clean', 0)}/{data.get('owasp_categories_total', 0)}",
                          "PASS" if data.get("owasp_score", 0) >= 70 else "NEEDS ATTENTION"])
        writer.writerow(["CWE Top 25", f"{data.get('cwe_top_25_score', 0)}%",
                          f"{25 - data.get('cwe_top_25_matches', 0)}/25",
                          "PASS" if data.get("cwe_top_25_score", 0) >= 70 else "NEEDS ATTENTION"])
        writer.writerow(["PCI DSS 4.0", f"{data.get('pci_dss_score', 0)}%",
                          f"{data.get('pci_dss_requirements_clean', 0)}/{data.get('pci_dss_requirements_total', 0)}",
                          "PASS" if data.get("pci_dss_score", 0) >= 70 else "NEEDS ATTENTION"])
        writer.writerow([])
        # OWASP detail
        owasp = data.get("owasp_top_10", {})
        if owasp:
            writer.writerow(["OWASP TOP 10 DETAIL"])
            writer.writerow(["Category", "Status", "Finding Count", "Critical", "High", "Medium", "Low"])
            for name, info in owasp.items():
                sev = info.get("severity", {})
                writer.writerow([
                    name, "PASS" if info.get("status") == "pass" else "FAIL",
                    info.get("count", 0), sev.get("critical", 0), sev.get("high", 0),
                    sev.get("medium", 0), sev.get("low", 0),
                ])
            writer.writerow([])
        # PCI DSS detail
        pci = data.get("pci_dss", {})
        if pci:
            writer.writerow(["PCI DSS 4.0 DETAIL"])
            writer.writerow(["Requirement", "Status", "Finding Count", "Critical", "High", "Medium", "Low"])
            for name, info in pci.items():
                sev = info.get("severity", {})
                writer.writerow([
                    name, "PASS" if info.get("status") == "pass" else "FAIL",
                    info.get("count", 0), sev.get("critical", 0), sev.get("high", 0),
                    sev.get("medium", 0), sev.get("low", 0),
                ])
            writer.writerow([])
        # CWE Top 25
        cwe_findings = data.get("cwe_top_25_findings", [])
        if cwe_findings:
            seen = set()
            writer.writerow(["CWE TOP 25 MATCHES"])
            writer.writerow(["Rank", "CWE ID", "Name"])
            for m in cwe_findings:
                key = m.get("cwe", "")
                if key not in seen:
                    seen.add(key)
                    writer.writerow([m.get("rank", ""), key, m.get("name", "")])
            writer.writerow([])

    elif report_type in ("aging", "sla"):
        # Combined SLA & Aging CSV
        policy = data.get("sla_policy", {})
        by_sev = data.get("by_severity", {})
        writer.writerow(["SLA & AGING REPORT"])
        writer.writerow([])
        # SLA Policy
        writer.writerow(["SLA POLICY"])
        for sev in ["critical", "high", "medium", "low"]:
            writer.writerow([f"{sev.title()} SLA (days)", policy.get(sev, "")])
        writer.writerow(["Compliance Rate", f"{data.get('compliance_pct', 0)}%"])
        writer.writerow(["Total Applicable", data.get("total_applicable", 0)])
        writer.writerow(["In SLA", data.get("in_sla", 0)])
        writer.writerow(["Total Overdue", data.get("total_overdue", 0)])
        writer.writerow(["Unassigned Overdue", data.get("unassigned_overdue", 0)])
        writer.writerow([])
        # Aging summary
        ninety_plus = data.get("buckets", {}).get("90+ days", 0)
        writer.writerow(["AGING SUMMARY"])
        writer.writerow(["Total Open Findings", data.get("total_open", 0)])
        writer.writerow(["Average Age (days)", data.get("avg_age_days", 0)])
        writer.writerow(["90+ Days Old", ninety_plus])
        writer.writerow([])
        # Age buckets
        writer.writerow(["AGE DISTRIBUTION"])
        writer.writerow(["Bucket", "Count", "Critical", "High", "Medium", "Low"])
        for bucket_name, count in data.get("buckets", {}).items():
            sev = data.get("bucket_severity", {}).get(bucket_name, {})
            writer.writerow([bucket_name, count, sev.get("critical", 0), sev.get("high", 0), sev.get("medium", 0), sev.get("low", 0)])
        writer.writerow([])
        # Age by repo
        if data.get("age_by_repository"):
            writer.writerow(["AGE BY REPOSITORY"])
            writer.writerow(["Repository", "Findings", "Avg Age", "Max Age", ">30 days", ">90 days"])
            for r in data["age_by_repository"]:
                writer.writerow([r.get("repo_name", ""), r["total_findings"], r["avg_age_days"], r["max_age_days"], r["over_30_days"], r["over_90_days"]])
            writer.writerow([])
        # Top oldest
        if data.get("top_aged_findings"):
            writer.writerow(["TOP 10 OLDEST FINDINGS"])
            writer.writerow(["Title", "Severity", "Age (days)", "Project", "Owner", "Location"])
            for f in data["top_aged_findings"]:
                writer.writerow([f.get("title", ""), f.get("severity", ""), f.get("age_days", 0), f.get("repo_name", ""), f.get("assignee", ""), f.get("file", "")])
            writer.writerow([])
        # Overdue per severity
        for sev_key, sev_label in [("critical", "CRITICAL"), ("high", "HIGH"), ("medium", "MEDIUM"), ("low", "LOW")]:
            overdue_list = data.get(f"{sev_key}_overdue", [])
            if overdue_list:
                writer.writerow([f"{sev_label} OVERDUE ({data.get(f'{sev_key}_overdue_count', len(overdue_list))})"])
                writer.writerow(["Title", "Age (days)", "Overdue By", "Project", "Owner", "Location"])
                for f in overdue_list:
                    writer.writerow([f.get("title", ""), f.get("age_days", 0), f.get("overdue_by", 0), f.get("repo_name", ""), f.get("assignee", ""), f.get("file", "")])
                writer.writerow([])

    elif report_type == "trends":
        ps = data.get("period_summary", {})
        writer.writerow(["TREND SUMMARY"])
        writer.writerow(["Period (days)", data.get("period_days", 30)])
        writer.writerow(["New Findings", ps.get("new_findings", 0)])
        writer.writerow(["Previous Period", ps.get("previous_period", 0)])
        writer.writerow(["Change", f"{ps.get('change_pct', 0)}%"])
        writer.writerow(["Trend", ps.get("trend", "stable")])
        writer.writerow([])
        if data.get("daily_counts"):
            writer.writerow(["DAILY FINDING COUNTS"])
            writer.writerow(["Date", "Count"])
            for d in data["daily_counts"]:
                writer.writerow([d["date"], d["count"]])
            writer.writerow([])
        if data.get("severity_trend"):
            writer.writerow(["DAILY SEVERITY BREAKDOWN"])
            writer.writerow(["Date", "Critical", "High", "Medium", "Low", "Info"])
            for d in data["severity_trend"]:
                writer.writerow([d.get("date", ""), d.get("critical", 0), d.get("high", 0), d.get("medium", 0), d.get("low", 0), d.get("info", 0)])
            writer.writerow([])

    elif report_type == "repo_risk":
        writer.writerow(["REPOSITORY RISK SCORECARD"])
        writer.writerow(["Repository", "Grade", "Risk Score", "Total", "Critical", "High", "Languages", "Last Scan"])
        for r in data.get("repositories", []):
            langs = ", ".join(r.get("languages", [])[:5]) or "-"
            writer.writerow([
                r["name"], r.get("grade", ""), r.get("risk_score", 0),
                r["total_findings"], r.get("criticals", 0), r.get("highs", 0),
                langs, r.get("last_scan", "Never"),
            ])
        writer.writerow([])

    elif report_type == "scanner":
        writer.writerow(["SCANNER COMPARISON"])
        writer.writerow(["Scanner", "Total Findings", "True Positives", "False Positives", "FP Rate"])
        for s in data.get("scanners", []):
            writer.writerow([s["scanner"], s["total_findings"], s["true_positives"], s["false_positives"], f"{s['fp_rate'] * 100:.1f}%"])
        writer.writerow([])

    elif report_type == "ai":
        writer.writerow(["AI TRIAGE PERFORMANCE"])
        writer.writerow(["AI-Triaged Findings", data.get("ai_triaged_findings", 0)])
        writer.writerow(["User-Confirmed Decisions", data.get("user_confirmed_decisions", 0)])
        writer.writerow(["AI Correct", data.get("ai_correct", 0)])
        writer.writerow(["Accuracy", data.get("accuracy_pct", "N/A")])
        writer.writerow(["Disagreements", data.get("disagreement_count", 0)])
        writer.writerow(["Low Confidence (Needs Review)", data.get("low_confidence_count", 0)])
        writer.writerow(["High-Conf FP (Auto-Close Candidates)", data.get("high_conf_fp_unreviewed", 0)])
        writer.writerow([])
        conf = data.get("confidence_distribution", {})
        if conf:
            writer.writerow(["CONFIDENCE DISTRIBUTION"])
            writer.writerow(["Range", "Count"])
            writer.writerow(["0-25% (Low)", conf.get("low", 0)])
            writer.writerow(["25-50% (Medium)", conf.get("medium", 0)])
            writer.writerow(["50-75% (High)", conf.get("high", 0)])
            writer.writerow(["75-100% (Very High)", conf.get("very_high", 0)])
            writer.writerow([])
        by_sev = data.get("by_severity", {})
        if by_sev:
            writer.writerow(["ACCURACY BY SEVERITY"])
            writer.writerow(["Severity", "Confirmed", "Correct", "Accuracy"])
            for sev in ["critical", "high", "medium", "low"]:
                if sev in by_sev:
                    s = by_sev[sev]
                    writer.writerow([sev.title(), s.get("confirmed", 0), s.get("correct", 0), f"{s.get('accuracy_pct', 0)}%"])
            writer.writerow([])
        by_cat = data.get("by_category", [])
        if by_cat:
            writer.writerow(["ACCURACY BY CATEGORY"])
            writer.writerow(["Category", "Confirmed", "Correct", "Accuracy"])
            for cat in by_cat:
                writer.writerow([cat.get("category", ""), cat.get("confirmed", 0), cat.get("correct", 0), f"{cat.get('accuracy_pct', 0)}%"])
            writer.writerow([])
        for section_key, section_label in [("low_confidence", "LOW CONFIDENCE — NEEDS REVIEW"), ("disagreements", "AI DISAGREEMENTS")]:
            items = data.get(section_key, [])
            if items:
                writer.writerow([section_label])
                writer.writerow(["Finding", "Severity", "AI Confidence", "Classification/AI Said", "Project", "Location"])
                for item in items:
                    writer.writerow([item.get("title", ""), item.get("severity", "").title(), item.get("ai_confidence", 0), item.get("classification", item.get("ai_said", "")), item.get("repo_name", ""), item.get("file", "")])
                writer.writerow([])

    elif report_type == "remediation":
        writer.writerow(["REMEDIATION SUMMARY"])
        writer.writerow(["Total Findings", data.get("total_findings", 0)])
        writer.writerow(["Patched", data.get("patched", 0)])
        writer.writerow(["Fix Rate", f"{data.get('patch_rate', 0)}%"])
        writer.writerow(["Pending Review", data.get("pending_review", 0)])
        writer.writerow(["Stalled (>7 days)", data.get("stalled_count", 0)])
        writer.writerow(["Unassigned", data.get("unassigned_count", 0)])
        writer.writerow([])
        if data.get("by_remediation_status"):
            writer.writerow(["PIPELINE BY STATUS"])
            writer.writerow(["Status", "Count"])
            for status, count in data["by_remediation_status"].items():
                writer.writerow([status.replace("_", " ").title(), count])
            writer.writerow([])
        if data.get("by_severity"):
            writer.writerow(["PIPELINE BY SEVERITY"])
            header = ["Severity"]
            statuses = set()
            for sev, rem_map in data["by_severity"].items():
                statuses.update(rem_map.keys())
            statuses = sorted(statuses)
            header.extend([s.replace("_", " ").title() for s in statuses])
            writer.writerow(header)
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in data["by_severity"]:
                    row = [sev.title()]
                    for s in statuses:
                        row.append(data["by_severity"][sev].get(s, 0))
                    writer.writerow(row)
            writer.writerow([])
        for section_key, section_label in [("awaiting_approval", "AWAITING APPROVAL"), ("stalled", "STALLED > 7 DAYS"), ("unassigned", "UNASSIGNED")]:
            items = data.get(section_key, [])
            if items:
                writer.writerow([section_label])
                writer.writerow(["Finding", "Severity", "Status", "Age (days)", "Project", "Owner", "Location"])
                for item in items:
                    writer.writerow([item.get("title", ""), item.get("severity", "").title(), item.get("status", ""), item.get("age_days", 0), item.get("repo_name", ""), item.get("assignee", ""), item.get("file", "")])
                writer.writerow([])

    elif report_type == "developer":
        writer.writerow(["DEVELOPER ACTIVITY"])
        writer.writerow([f"Period: Last {data.get('period_days', 30)} days"])
        writer.writerow([])
        writer.writerow(["Developer", "Total Actions", "Mark FP", "Mark TP", "Accept Risk", "Other"])
        for u in data.get("users", []):
            acts = u.get("actions", {})
            mark_fp = acts.get("mark_fp", 0)
            mark_tp = acts.get("mark_tp", 0)
            accept = acts.get("accept_risk", 0)
            other = u.get("total", 0) - mark_fp - mark_tp - accept
            writer.writerow([u.get("name", "Unknown"), u.get("total", 0), mark_fp, mark_tp, accept, max(other, 0)])
        writer.writerow([])

    elif report_type == "release_readiness":
        writer.writerow(["RELEASE READINESS ASSESSMENT"])
        writer.writerow(["Release Status", data.get("release_status", "N/A")])
        writer.writerow(["Security Score", data.get("security_score", 0)])
        writer.writerow(["Open Findings", data.get("open_findings", 0)])
        writer.writerow(["Review Coverage", f"{data.get('review_coverage_pct', 0)}%"])
        writer.writerow(["New Critical (7d)", data.get("new_critical_7d", 0)])
        writer.writerow([])
        sev = data.get("severity_counts", {})
        writer.writerow(["SEVERITY COUNTS"])
        for s, c in sev.items():
            writer.writerow([s.title(), c])
        writer.writerow([])
        violations = data.get("violations", [])
        if violations:
            writer.writerow(["POLICY VIOLATIONS"])
            for v in violations:
                writer.writerow([v])
            writer.writerow([])
        writer.writerow(["Recommendation", data.get("recommendation", "")])
        writer.writerow([])

    elif report_type == "security_debt":
        writer.writerow(["SECURITY DEBT REPORT"])
        writer.writerow(["Total Debt (hours)", data.get("total_hours", 0)])
        writer.writerow(["Estimated Cost (USD)", f"${data.get('total_cost_usd', 0):,.2f}"])
        writer.writerow(["Overdue Debt (hours)", data.get("overdue_hours", 0)])
        writer.writerow(["Overdue Cost (USD)", f"${data.get('overdue_cost_usd', 0):,.2f}"])
        writer.writerow(["Debt Rating", data.get("debt_rating", "")])
        writer.writerow([])
        by_sev = data.get("by_severity", {})
        if by_sev:
            writer.writerow(["DEBT BY SEVERITY"])
            writer.writerow(["Severity", "Hours"])
            for s, h in by_sev.items():
                writer.writerow([s.title(), h])
            writer.writerow([])
        mttr = data.get("mttr", {})
        if mttr:
            writer.writerow(["MTTR METRICS"])
            writer.writerow(["Overall MTTR (days)", mttr.get("mttr_overall_days", 0)])
            writer.writerow(["Fix Rate", f"{mttr.get('fix_rate_pct', 0)}%"])
            writer.writerow(["Total Resolved", mttr.get("total_resolved", 0)])
            writer.writerow(["Total Open", mttr.get("total_open", 0)])
            writer.writerow([])

    elif report_type == "fix_priority":
        writer.writerow(["FIX PRIORITISATION REPORT"])
        writer.writerow(["Total Analyzed", data.get("total_analyzed", 0)])
        writer.writerow([])
        top_fixes = data.get("top_fixes", [])
        if top_fixes:
            writer.writerow(["Rank", "Title", "Severity", "CWE", "File", "Priority Score", "Exploitability", "Age (days)", "Est. Fix (hours)", "Reason"])
            for fix in top_fixes:
                writer.writerow([
                    fix.get("rank", ""), fix.get("title", ""), fix.get("severity", ""),
                    fix.get("cwe", ""), fix.get("file_path", ""), fix.get("priority_score", ""),
                    fix.get("exploitability", ""), fix.get("age_days", ""),
                    fix.get("estimated_fix_hours", ""), fix.get("reason", ""),
                ])
            writer.writerow([])

    # "governance" CSV branch removed 2026-05-16 with the governance surfaces.

    elif report_type == "developer_report":
        writer.writerow(["DEVELOPER REMEDIATION GUIDE"])
        writer.writerow([])
        for df in data.get("findings", []):
            writer.writerow([f"=== {df.get('title', '')} ==="])
            writer.writerow(["Severity", df.get("severity", "")])
            writer.writerow(["CWE", df.get("cwe", "")])
            writer.writerow(["File", df.get("file_path", "")])
            writer.writerow(["Line", df.get("line_start", "")])
            cvss = df.get("cvss", {})
            writer.writerow(["CVSS Score", cvss.get("score", "N/A")])
            writer.writerow(["CVSS Rating", cvss.get("rating", "N/A")])
            guidance = df.get("guidance", {})
            writer.writerow(["Explanation", guidance.get("explanation", "")])
            writer.writerow(["Fix Strategy", guidance.get("fix_strategy", "")])
            writer.writerow(["Fix Difficulty", guidance.get("fix_difficulty", "")])
            writer.writerow(["Est. Fix (min)", guidance.get("estimated_fix_minutes", "")])
            writer.writerow([])


@router.get("/export/csv")
async def export_csv(
    repository_id: Optional[UUID] = Query(None),
    report_type: str = Query("executive"),
    days: int = Query(30),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export findings as CSV with report-specific header sections."""
    from fastapi.responses import StreamingResponse
    from datetime import datetime, timezone
    import csv
    import io

    report_data, findings = await _get_export_context(db, user, report_type, days, repository_id)

    output = io.StringIO()
    writer = csv.writer(output)

    REPORT_TITLES = {
        "executive": "Executive Security Report",
        "compliance": "Compliance Report",
        "aging": "SLA & Aging Report",
        "trends": "Finding Trends Report",
        "repo_risk": "Repository Risk Report",
        "scanner": "Scanner Comparison Report",
        "ai": "AI Performance Report",
        "remediation": "Remediation Report",
        "developer": "Developer Activity Report",
        "sla": "SLA & Aging Report",
        "release_readiness": "Release Readiness Assessment",
        "security_debt": "Security Debt Report",
        "fix_priority": "Fix Prioritisation Report",
        "developer_report": "Developer Remediation Guide",
    }
    title = REPORT_TITLES.get(report_type, "Security Report")
    writer.writerow([f"VOODA AI - {title}"])
    writer.writerow([f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"])
    writer.writerow([])

    if report_data:
        _write_csv_report_section(writer, report_type, report_data, days)

    # Findings detail
    writer.writerow(["FINDINGS DETAIL"])
    writer.writerow([
        "ID", "Title", "Severity", "Classification", "CWE", "Category",
        "File", "Line", "Scanner", "AI Confidence", "Review Status", "Remediation Status",
    ])

    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        cls = f.classification.value if hasattr(f.classification, "value") else str(f.classification)
        rev = f.review_status.value if hasattr(f.review_status, "value") else str(f.review_status)
        rem = f.remediation_status.value if hasattr(f.remediation_status, "value") else str(f.remediation_status)
        writer.writerow([
            str(f.id)[:8], f.title[:120], sev, cls, f.cwe or "",
            f.vulnerability_category, f.file_path, f.line_start or "",
            f.scanner_name, f.ai_confidence or "", rev, rem,
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=vooda-{report_type}-report.csv"},
    )


@router.get("/export/json")
async def export_json(
    repository_id: Optional[UUID] = Query(None),
    report_type: str = Query("executive"),
    days: int = Query(30),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export report as JSON with report-specific data + findings."""
    from datetime import datetime, timezone

    report_data, findings = await _get_export_context(db, user, report_type, days, repository_id)

    REPORT_TITLES = {
        "executive": "Executive Security Report",
        "compliance": "Compliance Report",
        "aging": "SLA & Aging Report",
        "trends": "Finding Trends Report",
        "repo_risk": "Repository Risk Report",
        "scanner": "Scanner Comparison Report",
        "ai": "AI Performance Report",
        "remediation": "Remediation Report",
        "developer": "Developer Activity Report",
        "sla": "SLA & Aging Report",
        "release_readiness": "Release Readiness Assessment",
        "security_debt": "Security Debt Report",
        "fix_priority": "Fix Prioritisation Report",
        "developer_report": "Developer Remediation Guide",
    }

    data = {
        "export_type": f"vooda_{report_type}_report",
        "report_title": REPORT_TITLES.get(report_type, "Security Report"),
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
    }

    # Include report-specific data under its own key
    if report_data:
        data["report_data"] = report_data

    data["findings"] = []
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        cls = f.classification.value if hasattr(f.classification, "value") else str(f.classification)
        data["findings"].append({
            "id": str(f.id),
            "title": f.title,
            "description": f.description or "",
            "severity": sev,
            "classification": cls,
            "cwe": f.cwe,
            "category": f.vulnerability_category,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "scanner": f.scanner_name,
            "rule_id": f.scanner_rule_id,
            "ai_confidence": f.ai_confidence,
            "ai_explanation": f.ai_explanation,
            "exploitability_score": f.exploitability_score,
            "review_status": f.review_status.value if hasattr(f.review_status, "value") else str(f.review_status),
            "remediation_status": f.remediation_status.value if hasattr(f.remediation_status, "value") else str(f.remediation_status),
            "code_snippet": f.code_snippet,
            "created_at": str(f.created_at) if f.created_at else None,
        })

    return JSONResponse(content=data, headers={
        "Content-Disposition": f"attachment; filename=vooda-{report_type}-report.json",
    })


@router.get("/export/pdf")
async def export_pdf(
    repository_id: Optional[UUID] = Query(None),
    report_type: str = Query("executive"),
    days: int = Query(30),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export report as PDF with report-specific sections."""
    from datetime import datetime, timezone
    from fastapi.responses import StreamingResponse

    report_data, findings = await _get_export_context(db, user, report_type, days, repository_id)
    # Limit findings for PDF (tables get long)
    findings = findings[:100]

    REPORT_TITLES = {
        "executive": "Executive Security Report",
        "compliance": "Compliance Report",
        "aging": "SLA & Aging Report",
        "trends": "Finding Trends Report",
        "repo_risk": "Repository Risk Report",
        "scanner": "Scanner Comparison Report",
        "ai": "AI Performance Report",
        "remediation": "Remediation Report",
        "developer": "Developer Activity Report",
        "sla": "SLA & Aging Report",
        "release_readiness": "Release Readiness Assessment",
        "security_debt": "Security Debt Report",
        "fix_priority": "Fix Prioritisation Report",
        "developer_report": "Developer Remediation Guide",
    }
    pdf_title = REPORT_TITLES.get(report_type, "Security Report")

    try:
        from fpdf import FPDF
        import io
        import math

        W = 190  # usable page width
        SEV_COLORS = {"critical": (239, 68, 68), "high": (249, 115, 22), "medium": (234, 179, 8), "low": (34, 197, 94), "info": (107, 114, 128)}
        BRAND_CYAN = (34, 211, 238)
        BRAND_DARK = (15, 23, 42)
        GRAY_50 = (248, 250, 252)
        GRAY_100 = (241, 245, 249)
        GRAY_600 = (100, 116, 139)
        WHITE = (255, 255, 255)

        class VoodaPDF(FPDF):
            _row_idx = 0

            def header(self):
                if self.page_no() == 1:
                    return  # cover page has custom header
                self.set_fill_color(*BRAND_DARK)
                self.rect(0, 0, 210, 18, "F")
                self.set_font("Helvetica", "B", 9)
                self.set_text_color(*WHITE)
                self.set_xy(10, 5)
                self.cell(0, 8, f"VOODA AI  |  {pdf_title}")
                # Accent bar under header
                self.set_fill_color(*BRAND_CYAN)
                self.rect(0, 18, 210, 1.5, "F")
                self.set_y(23)

            def footer(self):
                self.set_y(-12)
                self.set_font("Helvetica", "", 7)
                self.set_text_color(*GRAY_600)
                self.cell(95, 8, f"Confidential  |  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
                self.cell(95, 8, f"Page {self.page_no()}/{{nb}}", align="R")

            def section_title(self, title):
                # Force page break if too close to bottom
                if self.get_y() > 260:
                    self.add_page()
                self.ln(2)
                self.set_draw_color(*BRAND_CYAN)
                self.set_line_width(0.6)
                self.line(self.get_x(), self.get_y(), self.get_x() + 25, self.get_y())
                self.set_line_width(0.2)
                self.ln(2)
                self.set_font("Helvetica", "B", 12)
                self.set_text_color(*BRAND_DARK)
                self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
                self.ln(1)

            def kv_row(self, key, value, bold=False):
                self.set_font("Helvetica", "", 9)
                self.set_text_color(*GRAY_600)
                self.cell(70, 6, key)
                self.set_text_color(*BRAND_DARK)
                self.set_font("Helvetica", "B" if bold else "", 9)
                self.cell(0, 6, str(value), new_x="LMARGIN", new_y="NEXT")

            def kpi_card(self, x, y, w, h, label, value, sub="", color=BRAND_CYAN):
                """Draw a KPI card with colored top accent."""
                self.set_fill_color(255, 255, 255)
                self.set_draw_color(226, 232, 240)
                self.rect(x, y, w, h, "FD")
                # Color accent bar at top
                self.set_fill_color(*color)
                self.rect(x, y, w, 2.5, "F")
                # Value — auto-shrink font if too wide
                val_str = str(value)
                font_size = 16
                self.set_font("Helvetica", "B", font_size)
                while self.get_string_width(val_str) > w - 6 and font_size > 8:
                    font_size -= 1
                    self.set_font("Helvetica", "B", font_size)
                self.set_xy(x + 2, y + 5)
                self.set_text_color(*BRAND_DARK)
                self.cell(w - 4, 8, val_str, align="C")
                # Label
                self.set_xy(x + 2, y + 14)
                self.set_font("Helvetica", "", 7)
                self.set_text_color(*GRAY_600)
                self.cell(w - 4, 5, label, align="C")
                # Sub
                if sub:
                    self.set_xy(x + 2, y + 19)
                    self.set_font("Helvetica", "", 6)
                    self.cell(w - 4, 4, sub, align="C")

            def score_gauge(self, x, y, radius, score, label=""):
                """Draw a circular donut score gauge using filled dots along arc."""
                import math
                sweep = max(score / 100 * 360, 1)
                dot_r = radius * 0.14  # thickness of the ring
                # Background track — full 360 gray ring
                self.set_fill_color(220, 225, 230)
                self.set_draw_color(220, 225, 230)
                steps_bg = 72
                for i in range(steps_bg):
                    angle = math.radians(-90 + 360 * i / steps_bg)
                    dx = x + radius * math.cos(angle)
                    dy = y + radius * math.sin(angle)
                    self.circle(dx, dy, dot_r, style="F")
                # Score arc overlay — colored dots
                if score > 0:
                    if score >= 70:
                        arc_color = (34, 197, 94)  # green
                    elif score >= 40:
                        arc_color = (234, 179, 8)  # yellow
                    else:
                        arc_color = (239, 68, 68)  # red
                    self.set_fill_color(*arc_color)
                    self.set_draw_color(*arc_color)
                    steps_arc = max(int(sweep / 3), 18)
                    for i in range(steps_arc + 1):
                        angle = math.radians(-90 + sweep * i / steps_arc)
                        dx = x + radius * math.cos(angle)
                        dy = y + radius * math.sin(angle)
                        self.circle(dx, dy, dot_r, style="F")
                self.set_line_width(0.2)
                self.set_draw_color(0, 0, 0)
                # Score text centered in circle
                self.set_font("Helvetica", "B", 11)
                self.set_text_color(*BRAND_DARK)
                tw = self.get_string_width(f"{score}%")
                self.set_xy(x - tw / 2, y - 3.5)
                self.cell(tw, 7, f"{score}%", align="C")
                # Label below circle
                if label:
                    self.set_font("Helvetica", "B", 7)
                    self.set_text_color(*GRAY_600)
                    self.set_xy(x - radius - 5, y + radius + 3)
                    self.cell(radius * 2 + 10, 5, label, align="C")

            def progress_bar(self, x, y, w, h, pct, color=BRAND_CYAN, bg=(230, 230, 230)):
                """Draw a horizontal progress bar."""
                self.set_fill_color(*bg)
                self.rect(x, y, w, h, "F")
                fill_w = max(w * min(pct, 100) / 100, 0)
                if fill_w > 0:
                    self.set_fill_color(*color)
                    self.rect(x, y, fill_w, h, "F")

            def badge(self, x, y, text, color=(34, 197, 94), text_color=WHITE):
                """Draw a small colored badge."""
                self.set_fill_color(*color)
                tw = self.get_string_width(text) + 6
                self.rect(x, y, tw, 5, "F")
                self.set_xy(x, y)
                self.set_font("Helvetica", "B", 7)
                self.set_text_color(*text_color)
                self.cell(tw, 5, text, align="C")

        def _table_header(pdf, cols):
            """cols = [(label, width), ...] or [(label, width, align), ...]"""
            pdf._row_idx = 0
            pdf._col_aligns = []
            pdf.set_fill_color(*BRAND_DARK)
            pdf.set_text_color(*WHITE)
            pdf.set_font("Helvetica", "B", 8)
            for col in cols:
                label, w = col[0], col[1]
                align = col[2] if len(col) > 2 else "C"
                pdf._col_aligns.append(align)
                pdf.cell(w, 7, label, border=0, fill=True, align=align)
            pdf.cell(0, 7, "", new_x="LMARGIN", new_y="NEXT")

        def _table_row(pdf, cells, sev_hint=None):
            pdf._row_idx += 1
            if pdf._row_idx % 2 == 0:
                pdf.set_fill_color(*GRAY_50)
            else:
                pdf.set_fill_color(*WHITE)
            pdf.set_text_color(30, 30, 30)
            pdf.set_font("Helvetica", "", 7.5)
            col_aligns = getattr(pdf, "_col_aligns", [])
            for idx, cell_data in enumerate(cells):
                val, w = cell_data[0], cell_data[1]
                # Per-cell align override > column default > "C"
                if len(cell_data) > 2:
                    align = cell_data[2]
                elif idx < len(col_aligns):
                    align = col_aligns[idx]
                else:
                    align = "C"
                text = str(val)
                pad = 4 if align == "L" else 2
                while pdf.get_string_width(text) > w - pad and len(text) > 3:
                    text = text[:-1]
                if len(text) < len(str(val)):
                    text = text.rstrip() + ".."
                pdf.cell(w, 6, text, border=0, fill=True, align=align)
            pdf.cell(0, 6, "", new_x="LMARGIN", new_y="NEXT")

        def _ensure_space(pdf, needed_mm):
            """Force a page break if not enough vertical space remains."""
            if pdf.get_y() + needed_mm > 297 - 18:  # page height minus bottom margin
                pdf.add_page()

        def _bar_chart(pdf, items, max_w=110, bar_h=5, label_w=50):
            """Draw horizontal bar chart. items = [(label, value, color), ...]"""
            if not items:
                return
            _ensure_space(pdf, (bar_h + 2) * min(len(items), 3) + 4)
            max_val = max(v for _, v, _ in items) or 1
            for label, val, color in items:
                _ensure_space(pdf, bar_h + 4)
                pdf.set_font("Helvetica", "", 7.5)
                pdf.set_text_color(*GRAY_600)
                # Truncate label to fit label_w
                trunc = label
                while pdf.get_string_width(trunc) > label_w - 2 and len(trunc) > 3:
                    trunc = trunc[:-1]
                if len(trunc) < len(label):
                    trunc = trunc.rstrip() + ".."
                pdf.cell(label_w, bar_h + 2, trunc)
                # bar
                bar_w = max(val / max_val * max_w, 1) if val > 0 else 0
                bx, by = pdf.get_x(), pdf.get_y() + 1
                pdf.set_fill_color(230, 235, 240)
                pdf.rect(bx, by, max_w, bar_h, "F")
                if bar_w > 0:
                    pdf.set_fill_color(*color)
                    pdf.rect(bx, by, bar_w, bar_h, "F")
                # count
                pdf.set_xy(bx + max_w + 2, by - 1)
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(*BRAND_DARK)
                pdf.cell(20, bar_h + 2, str(val), new_x="LMARGIN", new_y="NEXT")

        def _mini_bar_chart(pdf, data_points, x, y, w, h, color=BRAND_CYAN):
            """Draw a mini bar chart (sparkline-like)."""
            if not data_points:
                return
            _ensure_space(pdf, h + 10)
            n = len(data_points)
            max_val = max(data_points) or 1
            # Draw subtle background
            pdf.set_fill_color(245, 247, 250)
            pdf.rect(x, y, w, h, "F")
            # Draw horizontal grid lines
            pdf.set_draw_color(230, 233, 238)
            pdf.set_line_width(0.1)
            for gi in range(1, 4):
                gy = y + h * gi / 4
                pdf.line(x, gy, x + w, gy)
            # Draw baseline
            pdf.set_draw_color(210, 215, 220)
            pdf.line(x, y + h, x + w, y + h)
            pdf.set_line_width(0.2)
            # Bars — edge-to-edge with 1px gap
            gap = 0.5
            bar_w = max((w - gap * (n - 1)) / n, 1.5)
            for i, val in enumerate(data_points):
                bar_h_actual = max((val / max_val) * (h - 3), 0.5) if val > 0 else 0.5
                bx = x + i * (bar_w + gap)
                by = y + h - bar_h_actual
                pdf.set_fill_color(*color)
                pdf.rect(bx, by, bar_w, bar_h_actual, "F")

        pdf = VoodaPDF()
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(auto=True, margin=18)

        # ═══════════════════════════════════════════════
        # COVER PAGE
        # ═══════════════════════════════════════════════
        pdf.add_page()
        # Dark background
        pdf.set_fill_color(*BRAND_DARK)
        pdf.rect(0, 0, 210, 297, "F")
        # Accent line
        pdf.set_draw_color(*BRAND_CYAN)
        pdf.set_line_width(2)
        pdf.line(20, 80, 80, 80)
        pdf.set_line_width(0.2)
        # Brand
        pdf.set_xy(20, 90)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*BRAND_CYAN)
        pdf.cell(0, 8, "VOODA AI")
        # Title
        pdf.set_xy(20, 105)
        pdf.set_font("Helvetica", "B", 32)
        pdf.set_text_color(*WHITE)
        pdf.multi_cell(170, 14, pdf_title)
        # Date
        pdf.set_xy(20, 160)
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(148, 163, 184)
        pdf.cell(0, 8, datetime.now(timezone.utc).strftime("%B %d, %Y"))
        # Subtitle
        pdf.set_xy(20, 175)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, "AI-Powered Security Analysis Platform")
        # Footer text
        pdf.set_xy(20, 260)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, "CONFIDENTIAL  |  Generated automatically by Vooda AI")

        d = report_data or {}

        # ═══════════════════════════════════════════════
        # REPORT CONTENT
        # ═══════════════════════════════════════════════
        pdf.add_page()

        if report_type == "executive":
            # --- Posture banner
            pdf.set_fill_color(240, 249, 255)
            pdf.set_draw_color(*BRAND_CYAN)
            pdf.set_line_width(0.5)
            bx, by = 10, pdf.get_y()
            pdf.rect(10, by, W, 14, "FD")
            pdf.set_line_width(0.2)
            pdf.set_fill_color(*BRAND_CYAN)
            pdf.rect(10, by, 3, 14, "F")
            pdf.set_xy(16, by + 2)
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(30, 64, 100)
            pdf.multi_cell(W - 10, 5, d.get("posture_statement", ""))
            pdf.ln(4)

            # KPI Cards row
            card_w = 44
            card_h = 26
            _ensure_space(pdf, card_h + 8)
            y0 = pdf.get_y()
            cards = [
                (f"{d['security_score']}", "Security Score", f"Grade: {d['grade']}", (34, 197, 94) if d['security_score'] >= 70 else (239, 68, 68)),
                (str(d['total_findings']), "Total Findings", f"+{d['new_findings_period']} new", BRAND_CYAN),
                (f"{d['fp_rate'] * 100:.0f}%", "FP Rate", f"{d.get('fp_count', 0)} false positives", (234, 179, 8)),
                (str(d['criticals']), "Critical Open", f"{d['highs']} high", (239, 68, 68)),
            ]
            for i, (val, label, sub, color) in enumerate(cards):
                pdf.kpi_card(10 + i * (card_w + 3), y0, card_w, card_h, label, val, sub, color)
            pdf.set_y(y0 + card_h + 5)

            # Severity Distribution — bar chart
            pdf.section_title("Severity Distribution")
            sev_items = []
            for sev_name in ["critical", "high", "medium", "low", "info"]:
                count = sum(v for k, v in d.get("by_severity", {}).items() if sev_name in k.lower())
                if count > 0:
                    sev_items.append((sev_name.upper(), count, SEV_COLORS.get(sev_name, (100, 100, 100))))
            _bar_chart(pdf, sev_items, label_w=28)
            pdf.ln(3)

            # Classification — bar chart
            if d.get("by_classification"):
                pdf.section_title("Classification Breakdown")
                cls_colors = {
                    "true": (34, 197, 94), "false": (107, 114, 128), "needs": (234, 179, 8), "accepted": (59, 130, 246),
                }
                cls_items = []
                for cls_name, count in d["by_classification"].items():
                    color = (100, 116, 139)
                    for key, c in cls_colors.items():
                        if key in cls_name.lower():
                            color = c
                            break
                    cls_items.append((cls_name.replace("_", " ").title(), count, color))
                _bar_chart(pdf, cls_items, label_w=55)
                pdf.ln(3)

            # Top Repos table
            if d.get("top_repos"):
                pdf.section_title("Top Risky Applications")
                _table_header(pdf, [("Application", 60, "L"), ("Findings", 30), ("Critical", 30), ("High", 30)])
                for repo in d["top_repos"]:
                    _table_row(pdf, [(repo["name"][:30], 60), (repo["findings"], 30), (repo["critical"], 30), (repo["high"], 30)])
                pdf.ln(3)

            # Top Categories — numbered with bars
            if d.get("top_categories"):
                pdf.section_title("Top Vulnerability Categories")
                cat_items = [(f"{i}. {cat['category']}", cat["count"], BRAND_CYAN) for i, cat in enumerate(d["top_categories"][:8], 1)]
                _bar_chart(pdf, cat_items, max_w=90, bar_h=5, label_w=70)
                pdf.ln(3)

            # Remediation Pipeline — progress style
            pdf.section_title("Remediation Pipeline")
            pipeline = d.get("remediation_pipeline", {})
            total_p = max(sum(pipeline.values()), 1)
            stage_colors = [(34, 197, 94), (59, 130, 246), (139, 92, 246), (234, 179, 8), (249, 115, 22)]
            stages = [
                ("Open", sum(v for k, v in pipeline.items() if "none" in k.lower())),
                ("Pending", sum(v for k, v in pipeline.items() if "pending" in k.lower() and "none" not in k.lower())),
                ("Patch Gen", sum(v for k, v in pipeline.items() if "patch" in k.lower())),
                ("Approved", sum(v for k, v in pipeline.items() if "approved" in k.lower())),
                ("Applied", sum(v for k, v in pipeline.items() if "applied" in k.lower())),
            ]
            for i, (label, count) in enumerate(stages):
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(*GRAY_600)
                pdf.cell(25, 7, label)
                pct = count / total_p * 100
                bx = pdf.get_x()
                by = pdf.get_y() + 1.5
                pdf.progress_bar(bx, by, 120, 4, pct, stage_colors[i % len(stage_colors)])
                pdf.set_xy(bx + 122, by - 1.5)
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(*BRAND_DARK)
                pdf.cell(20, 7, str(count), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

            # SLA badges
            sla = d.get("sla_compliance", {})
            pdf.section_title("SLA Compliance")
            crit_over = sla.get("critical_overdue", 0)
            high_over = sla.get("high_overdue", 0)
            for label, overdue, sla_days in [("Critical", crit_over, sla.get("critical_sla_days", 7)), ("High", high_over, sla.get("high_sla_days", 30))]:
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*GRAY_600)
                pdf.cell(50, 7, f"{label} ({sla_days}d SLA)")
                bx = pdf.get_x()
                by = pdf.get_y() + 1
                if overdue == 0:
                    pdf.badge(bx, by, "ALL IN SLA", (34, 197, 94))
                else:
                    pdf.badge(bx, by, f"{overdue} OVERDUE", (239, 68, 68))
                pdf.ln(7)
            pdf.ln(3)

            # AI Performance
            pdf.section_title("AI Performance")
            pdf.kv_row("Findings Triaged by AI", str(d.get("ai_triaged", 0)))
            pdf.kv_row("User Decisions", str(d.get("user_decisions", 0)))
            fp_count = d.get("fp_count", 0)
            if fp_count > 0:
                pdf.kv_row("Estimated Time Saved", f"{fp_count * 15} min ({fp_count} FPs @ 15 min/review)")
            pdf.ln(3)

            # Mini trend chart
            if d.get("daily_trend"):
                _ensure_space(pdf, 40)
                pdf.section_title("Finding Trend")
                counts = [day["count"] for day in d["daily_trend"][-14:]]
                cx, cy = pdf.get_x(), pdf.get_y()
                _mini_bar_chart(pdf, counts, cx, cy, 180, 25, BRAND_CYAN)
                pdf.set_y(cy + 28)
                # Date range labels
                pdf.set_font("Helvetica", "", 6)
                pdf.set_text_color(*GRAY_600)
                dates = d["daily_trend"][-14:]
                if dates:
                    pdf.cell(90, 4, dates[0]["date"])
                    pdf.cell(90, 4, dates[-1]["date"], align="R", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(3)

        elif report_type == "compliance":
            # Score gauges
            _ensure_space(pdf, 50)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*GRAY_600)
            pdf.cell(0, 6, f"Total Findings Analyzed: {d.get('total_findings', 0)}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)
            y0 = pdf.get_y()
            gauges = [
                (d.get("owasp_score", 0), "OWASP Top 10", f"{d.get('owasp_categories_clean', 0)}/{d.get('owasp_categories_total', 0)} clean"),
                (d.get("cwe_top_25_score", 0), "CWE Top 25", f"{25 - d.get('cwe_top_25_matches', 0)}/25 clean"),
                (d.get("pci_dss_score", 0), "PCI DSS 4.0", f"{d.get('pci_dss_requirements_clean', 0)}/{d.get('pci_dss_requirements_total', 0)} clean"),
            ]
            for i, (score, label, sub) in enumerate(gauges):
                cx = 42 + i * 63
                pdf.score_gauge(cx, y0 + 15, 12, score, label)
                pdf.set_font("Helvetica", "", 6)
                pdf.set_text_color(*GRAY_600)
                pdf.set_xy(cx - 18, y0 + 36)
                pdf.cell(36, 4, sub, align="C")
            pdf.set_y(y0 + 46)

            # OWASP detail with PASS/FAIL badges
            owasp = d.get("owasp_top_10", {})
            if owasp:
                pdf.section_title("OWASP Top 10 Detail")
                _table_header(pdf, [("Category", 75, "L"), ("Status", 20), ("Count", 18), ("Critical", 22), ("High", 20), ("Medium", 22)])
                for name, info in owasp.items():
                    sev = info.get("severity", {})
                    status = "PASS" if info.get("status") == "pass" else "FAIL"
                    _table_row(pdf, [
                        (name, 75), (status, 20), (info.get("count", 0), 18),
                        (sev.get("critical", 0), 22), (sev.get("high", 0), 20), (sev.get("medium", 0), 22),
                    ])
                pdf.ln(3)

            pci = d.get("pci_dss", {})
            if pci:
                pdf.section_title("PCI DSS 4.0 Detail")
                _table_header(pdf, [("Requirement", 95, "L"), ("Status", 22), ("Count", 20), ("Critical", 22), ("High", 22)])
                for name, info in pci.items():
                    sev = info.get("severity", {})
                    status = "PASS" if info.get("status") == "pass" else "FAIL"
                    _table_row(pdf, [
                        (name, 95), (status, 22), (info.get("count", 0), 20),
                        (sev.get("critical", 0), 22), (sev.get("high", 0), 22),
                    ])
                pdf.ln(3)

            # CWE Top 25
            cwe_findings = d.get("cwe_top_25_findings", [])
            if cwe_findings:
                seen = set()
                unique_cwes = []
                for m in cwe_findings:
                    key = m.get("cwe", "")
                    if key not in seen:
                        seen.add(key)
                        unique_cwes.append(m)
                pdf.section_title(f"CWE Top 25 Matches ({len(unique_cwes)} of 25 found)")
                _table_header(pdf, [("Rank", 18), ("CWE ID", 35), ("Name", 130, "L")])
                for m in unique_cwes:
                    _table_row(pdf, [(m.get("rank", ""), 18), (m.get("cwe", ""), 35), (m.get("name", ""), 130)])
                pdf.ln(3)

        elif report_type in ("aging", "sla"):
            # Combined SLA & Aging PDF
            policy = d.get("sla_policy", {})
            by_sev = d.get("by_severity", {})
            ninety_plus = d.get("buckets", {}).get("90+ days", 0)
            comp_pct = d.get("compliance_pct", 0)

            # SLA Policy reference
            _ensure_space(pdf, 10)
            pdf.set_font("Helvetica", "I", 7.5)
            pdf.set_text_color(*GRAY_600)
            pol_parts = [f"{sev.title()}: {days}d" for sev, days in policy.items()]
            pdf.cell(0, 5, f"SLA Policy: {' | '.join(pol_parts)}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

            # KPI cards — 6 compact
            _ensure_space(pdf, 30)
            y0 = pdf.get_y()
            card_w = 30
            card_h = 22
            cards = [
                (f"{comp_pct}%", "Compliance", "", (34, 197, 94) if comp_pct >= 80 else (239, 68, 68)),
                (str(d.get("total_overdue", 0)), "Overdue", f"{d.get('unassigned_overdue', 0)} unassigned", (239, 68, 68) if d.get("total_overdue", 0) > 0 else (34, 197, 94)),
                (str(d.get("total_open", 0)), "Open", "", BRAND_CYAN),
                (f"{d.get('avg_age_days', 0)}d", "Avg Age", "", (234, 179, 8) if d.get("avg_age_days", 0) > 30 else BRAND_CYAN),
                (str(ninety_plus), "90+ Days", "", (239, 68, 68) if ninety_plus > 0 else (34, 197, 94)),
                (str(d.get("unassigned_overdue", 0)), "Unassigned", "", (239, 68, 68) if d.get("unassigned_overdue", 0) > 0 else (34, 197, 94)),
            ]
            for i, (val, label, sub, color) in enumerate(cards):
                pdf.kpi_card(10 + i * (card_w + 3), y0, card_w, card_h, label, val, sub, color)
            pdf.set_y(y0 + card_h + 5)

            # Compliance by severity bar
            if by_sev:
                pdf.section_title("SLA Compliance by Severity")
                sev_items = []
                for sev in ["critical", "high", "medium", "low"]:
                    info = by_sev.get(sev, {})
                    total = info.get("total", 0)
                    in_s = info.get("in_sla", 0)
                    pct = round(in_s / max(total, 1) * 100)
                    sev_items.append((f"{sev.upper()} ({in_s}/{total})", pct, SEV_COLORS.get(sev, (100, 100, 100))))
                _bar_chart(pdf, sev_items, label_w=40)
                pdf.ln(3)

            # Age distribution bar chart
            pdf.section_title("Age Distribution")
            bucket_items = []
            bucket_colors = [BRAND_CYAN, (59, 130, 246), (234, 179, 8), (239, 68, 68)]
            for i, (bucket_name, count) in enumerate(d.get("buckets", {}).items()):
                bucket_items.append((bucket_name, count, bucket_colors[i % len(bucket_colors)]))
            _bar_chart(pdf, bucket_items, label_w=30)
            pdf.ln(3)

            # Age by repository
            if d.get("age_by_repository"):
                pdf.section_title("Age by Repository")
                _table_header(pdf, [("Repository", 50, "L"), ("Findings", 25), ("Avg Age", 25), ("Max Age", 25), (">30d", 20), (">90d", 20)])
                for r in d["age_by_repository"][:15]:
                    _table_row(pdf, [
                        (r.get("repo_name", "")[:25], 50), (r["total_findings"], 25),
                        (r["avg_age_days"], 25), (r["max_age_days"], 25),
                        (r["over_30_days"], 20), (r["over_90_days"], 20),
                    ])
                pdf.ln(3)

            # Top 10 oldest
            if d.get("top_aged_findings"):
                pdf.section_title("Top 10 Oldest Findings")
                _table_header(pdf, [("Title", 40, "L"), ("Sev", 16), ("Age", 12), ("Overdue", 16), ("Project", 30, "L"), ("Owner", 24, "L"), ("Location", 52, "L")])
                for f in d["top_aged_findings"][:10]:
                    overdue_txt = f"+{f.get('overdue_by', 0)}d" if f.get("overdue_by", 0) > 0 else "In SLA"
                    _table_row(pdf, [
                        (f.get("title", "")[:24], 40), (f.get("severity", "")[:6], 16),
                        (f"{f.get('age_days', 0)}d", 12), (overdue_txt, 16),
                        (f.get("repo_name", "")[:16], 30), ((f.get("assignee") or "-")[:14], 24),
                        (f.get("file", "")[:28], 52),
                    ], sev_hint=f.get("severity"))
                pdf.ln(3)

            # Overdue tables per severity
            for sev_key, sev_label in [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]:
                overdue_list = d.get(f"{sev_key}_overdue", [])
                if overdue_list:
                    overdue_count = d.get(f"{sev_key}_overdue_count", len(overdue_list))
                    pdf.section_title(f"{sev_label} Overdue ({overdue_count})")
                    _table_header(pdf, [("Title", 40, "L"), ("Age", 12), ("Overdue", 16), ("Project", 30, "L"), ("Owner", 28, "L"), ("Location", 64, "L")])
                    for f in overdue_list[:15]:
                        _table_row(pdf, [
                            (f.get("title", "")[:28], 40),
                            (f"{f.get('age_days', 0)}d", 12),
                            (f"+{f.get('overdue_by', 0)}d", 16),
                            (f.get("repo_name", ""), 30),
                            (f.get("assignee", "Unassigned"), 28),
                            (f.get("file", ""), 64),
                        ], sev_hint=sev_key)
                    pdf.ln(3)

        elif report_type == "trends":
            ps = d.get("period_summary", {})
            # KPI cards
            _ensure_space(pdf, 34)
            y0 = pdf.get_y()
            card_w = 44
            card_h = 26
            change = ps.get("change_pct", 0)
            trend = ps.get("trend", "stable")
            cards = [
                (str(ps.get("new_findings", 0)), "New This Period", "", BRAND_CYAN),
                (str(ps.get("previous_period", 0)), "Previous Period", "", (100, 116, 139)),
                (f"{'+' if change > 0 else ''}{change}%", "Change", "", (239, 68, 68) if change > 10 else (34, 197, 94) if change < -10 else (234, 179, 8)),
                (trend.upper(), "Trend", "", (239, 68, 68) if trend == "increasing" else (34, 197, 94) if trend == "decreasing" else BRAND_CYAN),
            ]
            for i, (val, label, sub, color) in enumerate(cards):
                pdf.kpi_card(10 + i * (card_w + 3), y0, card_w, card_h, label, val, sub, color)
            pdf.set_y(y0 + card_h + 5)

            # Trend mini chart
            if d.get("daily_counts"):
                _ensure_space(pdf, 45)
                pdf.section_title("Daily Finding Trend")
                counts = [day["count"] for day in d["daily_counts"][-30:]]
                cx, cy = pdf.get_x(), pdf.get_y()
                _mini_bar_chart(pdf, counts, cx, cy, W, 30, BRAND_CYAN)
                pdf.set_y(cy + 33)
                dates = d["daily_counts"][-30:]
                if dates:
                    pdf.set_font("Helvetica", "", 6)
                    pdf.set_text_color(*GRAY_600)
                    pdf.cell(95, 4, dates[0]["date"])
                    pdf.cell(95, 4, dates[-1]["date"], align="R", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(3)

            # Severity trend — stacked color bars
            if d.get("severity_trend"):
                pdf.section_title("Severity Trend")
                _table_header(pdf, [("Date", 40), ("Critical", 25), ("High", 25), ("Medium", 28), ("Low", 25), ("Info", 25)])
                for day in d["severity_trend"][-15:]:
                    _table_row(pdf, [
                        (day.get("date", ""), 40), (day.get("critical", 0), 25),
                        (day.get("high", 0), 25), (day.get("medium", 0), 28),
                        (day.get("low", 0), 25), (day.get("info", 0), 25),
                    ])
                pdf.ln(3)

        elif report_type == "repo_risk":
            pdf.section_title("Repository Risk Scorecard")
            _table_header(pdf, [("Repository", 45, "L"), ("Grade", 18), ("Score", 20), ("Total", 22), ("Critical", 22), ("High", 22), ("Last Scan", 38)])
            for r in d.get("repositories", []):
                _table_row(pdf, [
                    (r["name"], 45), (r.get("grade", ""), 18), (r.get("risk_score", 0), 20),
                    (r["total_findings"], 22), (r.get("criticals", 0), 22), (r.get("highs", 0), 22),
                    (str(r.get("last_scan", "Never"))[:10], 38),
                ])
            pdf.ln(3)

        elif report_type == "scanner":
            pdf.section_title("Scanner Comparison")
            for s in d.get("scanners", []):
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_text_color(*BRAND_DARK)
                pdf.cell(0, 7, s["scanner"], new_x="LMARGIN", new_y="NEXT")
                total = max(s["total_findings"], 1)
                tp_pct = s["true_positives"] / total * 100
                fp_pct = s["false_positives"] / total * 100
                # TP bar
                pdf.set_font("Helvetica", "", 7)
                pdf.set_text_color(*GRAY_600)
                pdf.cell(25, 5, "True Pos")
                bx = pdf.get_x()
                pdf.progress_bar(bx, pdf.get_y() + 0.5, 120, 4, tp_pct, (34, 197, 94))
                pdf.set_xy(bx + 122, pdf.get_y())
                pdf.set_text_color(*BRAND_DARK)
                pdf.cell(20, 5, str(s["true_positives"]), new_x="LMARGIN", new_y="NEXT")
                # FP bar
                pdf.set_text_color(*GRAY_600)
                pdf.cell(25, 5, "False Pos")
                bx = pdf.get_x()
                pdf.progress_bar(bx, pdf.get_y() + 0.5, 120, 4, fp_pct, (239, 68, 68))
                pdf.set_xy(bx + 122, pdf.get_y())
                pdf.set_text_color(*BRAND_DARK)
                pdf.cell(20, 5, str(s["false_positives"]), new_x="LMARGIN", new_y="NEXT")
                # FP Rate badge
                fp_rate = s["fp_rate"] * 100
                pdf.set_text_color(*GRAY_600)
                pdf.cell(25, 6, "FP Rate")
                badge_color = (34, 197, 94) if fp_rate < 30 else (234, 179, 8) if fp_rate < 60 else (239, 68, 68)
                pdf.badge(pdf.get_x(), pdf.get_y() + 0.5, f"{fp_rate:.1f}%", badge_color)
                pdf.ln(8)
            pdf.ln(3)

        elif report_type == "ai":
            # KPI cards — 6 compact
            _ensure_space(pdf, 30)
            y0 = pdf.get_y()
            card_w = 30
            card_h = 22
            accuracy = d.get("accuracy", 0)
            cards = [
                (str(d.get("ai_triaged_findings", 0)), "AI Triaged", "", BRAND_CYAN),
                (str(d.get("user_confirmed_decisions", 0)), "Confirmed", "", (59, 130, 246)),
                (d.get("accuracy_pct", "N/A"), "Accuracy", "", (34, 197, 94) if accuracy >= 0.8 else (234, 179, 8)),
                (str(d.get("disagreement_count", 0)), "Disagree", "", (239, 68, 68) if d.get("disagreement_count", 0) > 0 else (34, 197, 94)),
                (str(d.get("low_confidence_count", 0)), "Low Conf.", "needs review", (249, 115, 22) if d.get("low_confidence_count", 0) > 0 else (34, 197, 94)),
                (str(d.get("high_conf_fp_unreviewed", 0)), "Auto-Close", "high conf FP", (34, 197, 94) if d.get("high_conf_fp_unreviewed", 0) > 0 else GRAY_600),
            ]
            for i, (val, label, sub, color) in enumerate(cards):
                pdf.kpi_card(10 + i * (card_w + 3), y0, card_w, card_h, label, val, sub, color)
            pdf.set_y(y0 + card_h + 5)

            # Confidence distribution
            conf = d.get("confidence_distribution", {})
            if any(v > 0 for v in conf.values()):
                pdf.section_title("Confidence Distribution")
                conf_items = [
                    ("0-25% (Low)", conf.get("low", 0), (239, 68, 68)),
                    ("25-50% (Medium)", conf.get("medium", 0), (249, 115, 22)),
                    ("50-75% (High)", conf.get("high", 0), (59, 130, 246)),
                    ("75-100% (Very High)", conf.get("very_high", 0), (34, 197, 94)),
                ]
                _bar_chart(pdf, conf_items)
                pdf.ln(3)

            # Accuracy by severity
            by_sev = d.get("by_severity", {})
            if by_sev:
                pdf.section_title("Accuracy by Severity")
                _table_header(pdf, [("Severity", 40, "L"), ("Confirmed", 30), ("Correct", 30), ("Accuracy", 30)])
                for sev in ["critical", "high", "medium", "low"]:
                    if sev in by_sev:
                        s = by_sev[sev]
                        _table_row(pdf, [(sev.title(), 40), (s.get("confirmed", 0), 30), (s.get("correct", 0), 30), (f"{s.get('accuracy_pct', 0)}%", 30)], sev_hint=sev)
                pdf.ln(3)

            # Accuracy by category
            by_cat = d.get("by_category", [])
            if by_cat:
                pdf.section_title("Accuracy by Category")
                _table_header(pdf, [("Category", 70, "L"), ("Confirmed", 25), ("Correct", 25), ("Accuracy", 25)])
                for cat in by_cat:
                    _table_row(pdf, [(cat.get("category", "")[:40], 70), (cat.get("confirmed", 0), 25), (cat.get("correct", 0), 25), (f"{cat.get('accuracy_pct', 0)}%", 25)])
                pdf.ln(3)

            # Low confidence table
            low_conf = d.get("low_confidence", [])
            if low_conf:
                pdf.section_title(f"Low Confidence — Needs Review ({d.get('low_confidence_count', len(low_conf))})")
                _table_header(pdf, [("Finding", 45, "L"), ("Severity", 16), ("Confidence", 18), ("Classification", 30, "L"), ("Project", 25, "L"), ("Location", 56, "L")])
                for item in low_conf:
                    _table_row(pdf, [
                        (item.get("title", "")[:30], 45), (item.get("severity", "").title(), 16),
                        (str(item.get("ai_confidence", 0)), 18), (item.get("classification", "")[:18], 30),
                        (item.get("repo_name", "")[:14], 25), (item.get("file", "")[:35], 56),
                    ], sev_hint=item.get("severity"))
                pdf.ln(3)

            # Disagreements table
            disagree = d.get("disagreements", [])
            if disagree:
                pdf.section_title(f"AI Disagreements ({d.get('disagreement_count', len(disagree))})")
                _table_header(pdf, [("Finding", 45, "L"), ("Severity", 16), ("AI Said", 30, "L"), ("Confidence", 18), ("Project", 25, "L"), ("Location", 56, "L")])
                for item in disagree:
                    _table_row(pdf, [
                        (item.get("title", "")[:30], 45), (item.get("severity", "").title(), 16),
                        (item.get("ai_said", "")[:18], 30), (str(item.get("ai_confidence", 0)), 18),
                        (item.get("repo_name", "")[:14], 25), (item.get("file", "")[:35], 56),
                    ], sev_hint=item.get("severity"))
                pdf.ln(3)

        elif report_type == "remediation":
            # KPI cards — 6 compact cards
            _ensure_space(pdf, 30)
            y0 = pdf.get_y()
            card_w = 30
            card_h = 22
            patch_rate = d.get("patch_rate", 0)
            cards = [
                (str(d.get("total_findings", 0)), "Total", "", BRAND_CYAN),
                (str(d.get("patched", 0)), "Patched", "", (34, 197, 94)),
                (f"{patch_rate}%", "Fix Rate", "", (34, 197, 94) if patch_rate > 50 else (234, 179, 8)),
                (str(d.get("pending_review", 0)), "Pending", "", (249, 115, 22)),
                (str(d.get("stalled_count", 0)), "Stalled", f">7 days", (239, 68, 68) if d.get("stalled_count", 0) > 0 else (34, 197, 94)),
                (str(d.get("unassigned_count", 0)), "Unassigned", "", (239, 68, 68) if d.get("unassigned_count", 0) > 0 else (34, 197, 94)),
            ]
            for i, (val, label, sub, color) in enumerate(cards):
                pdf.kpi_card(10 + i * (card_w + 3), y0, card_w, card_h, label, val, sub, color)
            pdf.set_y(y0 + card_h + 5)

            # Status bar chart
            if d.get("by_remediation_status"):
                pdf.section_title("Pipeline by Status")
                rem_items = [(s.replace("_", " ").title(), c, BRAND_CYAN) for s, c in d["by_remediation_status"].items()]
                _bar_chart(pdf, rem_items)
                pdf.ln(3)

            if d.get("by_severity"):
                pdf.section_title("Pipeline by Severity")
                statuses = set()
                for sev, rem_map in d["by_severity"].items():
                    statuses.update(rem_map.keys())
                statuses = sorted(statuses)
                col_w = min(int(150 / max(len(statuses), 1)), 30)
                cols = [("Severity", 40, "L")] + [(s.replace("_", " ")[:12], col_w) for s in statuses]
                _table_header(pdf, cols)
                for sev in ["critical", "high", "medium", "low", "info"]:
                    if sev in d["by_severity"]:
                        cells = [(sev.title(), 40)] + [(d["by_severity"][sev].get(s, 0), col_w) for s in statuses]
                        _table_row(pdf, cells)
                pdf.ln(3)

            # Awaiting Approval table
            awaiting = d.get("awaiting_approval", [])
            if awaiting:
                pdf.section_title(f"Awaiting Approval ({d.get('awaiting_approval_count', len(awaiting))})")
                _table_header(pdf, [("Finding", 40, "L"), ("Severity", 16), ("Age", 12), ("Project", 30, "L"), ("Owner", 28, "L"), ("Location", 64, "L")])
                for item in awaiting:
                    sev_label = item.get("severity", "").title()
                    _table_row(pdf, [
                        (item.get("title", "")[:30], 40), (sev_label, 16),
                        (f"{item.get('age_days', 0)}d", 12), (item.get("repo_name", "")[:18], 30),
                        (item.get("assignee", "Unassigned")[:16], 28), (item.get("file", "")[:40], 64),
                    ], sev_hint=item.get("severity"))
                pdf.ln(3)

            # Stalled table
            stalled_items = d.get("stalled", [])
            if stalled_items:
                pdf.section_title(f"Stalled > 7 Days ({d.get('stalled_count', len(stalled_items))})")
                _table_header(pdf, [("Finding", 40, "L"), ("Severity", 16), ("Status", 18, "L"), ("Age", 12), ("Project", 30, "L"), ("Owner", 28, "L"), ("Location", 46, "L")])
                for item in stalled_items:
                    sev_label = item.get("severity", "").title()
                    _table_row(pdf, [
                        (item.get("title", "")[:30], 40), (sev_label, 16),
                        (item.get("status", "")[:12], 18), (f"{item.get('age_days', 0)}d", 12),
                        (item.get("repo_name", "")[:18], 30), (item.get("assignee", "Unassigned")[:16], 28),
                        (item.get("file", "")[:28], 46),
                    ], sev_hint=item.get("severity"))
                pdf.ln(3)

            # Unassigned table
            unassigned_items = d.get("unassigned", [])
            if unassigned_items:
                pdf.section_title(f"Unassigned ({d.get('unassigned_count', len(unassigned_items))})")
                _table_header(pdf, [("Finding", 50, "L"), ("Severity", 18), ("Status", 22, "L"), ("Age", 14), ("Project", 36, "L"), ("Location", 50, "L")])
                for item in unassigned_items:
                    sev_label = item.get("severity", "").title()
                    _table_row(pdf, [
                        (item.get("title", "")[:35], 50), (sev_label, 18),
                        (item.get("status", "")[:14], 22), (f"{item.get('age_days', 0)}d", 14),
                        (item.get("repo_name", "")[:20], 36), (item.get("file", "")[:32], 50),
                    ], sev_hint=item.get("severity"))
                pdf.ln(3)

        elif report_type == "developer":
            pdf.section_title(f"Developer Activity (Last {d.get('period_days', 30)} days)")
            _table_header(pdf, [("Developer", 50, "L"), ("Total", 25), ("Mark FP", 25), ("Mark TP", 25), ("Accept Risk", 30), ("Other", 25)])
            for u in d.get("users", []):
                acts = u.get("actions", {})
                mark_fp = acts.get("mark_fp", 0)
                mark_tp = acts.get("mark_tp", 0)
                accept = acts.get("accept_risk", 0)
                other = u.get("total", 0) - mark_fp - mark_tp - accept
                _table_row(pdf, [
                    (u.get("name", "Unknown")[:25], 50), (u.get("total", 0), 25),
                    (mark_fp, 25), (mark_tp, 25), (accept, 30), (max(other, 0), 25),
                ])
            pdf.ln(3)

        elif report_type == "release_readiness":
            # GO / NO-GO banner
            status = d.get("release_status", "NO-GO")
            _ensure_space(pdf, 30)
            bx, by = 10, pdf.get_y()
            if status == "GO":
                pdf.set_fill_color(34, 197, 94)
            else:
                pdf.set_fill_color(239, 68, 68)
            pdf.rect(10, by, W, 18, "F")
            pdf.set_xy(16, by + 3)
            pdf.set_font("Helvetica", "B", 16)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(0, 12, f"Release Status: {status}", align="C")
            pdf.set_y(by + 22)

            # KPI cards
            _ensure_space(pdf, 34)
            y0 = pdf.get_y()
            card_w = 44
            card_h = 26
            cards = [
                (str(d.get("security_score", 0)), "Security Score", "", (34, 197, 94) if d.get("security_score", 0) >= 60 else (239, 68, 68)),
                (str(d.get("open_findings", 0)), "Open Findings", "", BRAND_CYAN),
                (f"{d.get('review_coverage_pct', 0)}%", "Review Coverage", "", (34, 197, 94) if d.get("review_coverage_pct", 0) >= 80 else (234, 179, 8)),
                (str(d.get("new_critical_7d", 0)), "New Critical (7d)", "", (239, 68, 68) if d.get("new_critical_7d", 0) > 0 else (34, 197, 94)),
            ]
            for i, (val, label, sub, color) in enumerate(cards):
                pdf.kpi_card(10 + i * (card_w + 3), y0, card_w, card_h, label, val, sub, color)
            pdf.set_y(y0 + card_h + 5)

            # Severity counts
            sev_counts = d.get("severity_counts", {})
            if sev_counts:
                pdf.section_title("Severity Breakdown")
                sev_items = [(s.upper(), c, SEV_COLORS.get(s, (100, 100, 100))) for s, c in sev_counts.items() if c > 0]
                _bar_chart(pdf, sev_items, label_w=28)
                pdf.ln(3)

            # Violations
            violations = d.get("violations", [])
            if violations:
                pdf.section_title(f"Policy Violations ({len(violations)})")
                for v in violations:
                    _ensure_space(pdf, 8)
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(239, 68, 68)
                    pdf.cell(5, 6, "-")  # bullet
                    pdf.set_text_color(*BRAND_DARK)
                    pdf.cell(0, 6, v, new_x="LMARGIN", new_y="NEXT")
                pdf.ln(3)

            # Recommendation
            rec = d.get("recommendation", "")
            if rec:
                _ensure_space(pdf, 16)
                pdf.set_fill_color(240, 249, 255)
                rx, ry = 10, pdf.get_y()
                pdf.rect(10, ry, W, 12, "F")
                pdf.set_fill_color(*BRAND_CYAN)
                pdf.rect(10, ry, 3, 12, "F")
                pdf.set_xy(16, ry + 2)
                pdf.set_font("Helvetica", "I", 8)
                pdf.set_text_color(30, 64, 100)
                pdf.multi_cell(W - 10, 4, rec)
                pdf.ln(5)

        elif report_type == "security_debt":
            # KPI cards
            _ensure_space(pdf, 34)
            y0 = pdf.get_y()
            card_w = 44
            card_h = 26
            cards = [
                (f"{d.get('total_hours', 0)}h", "Total Debt", d.get("debt_rating", ""), (239, 68, 68) if d.get("debt_rating") == "Critical" else (234, 179, 8)),
                (f"${d.get('total_cost_usd', 0):,.0f}", "Est. Cost", f"@ ${d.get('hourly_rate_used', 75)}/hr", BRAND_CYAN),
                (f"{d.get('overdue_hours', 0)}h", "Overdue Debt", f"${d.get('overdue_cost_usd', 0):,.0f}", (239, 68, 68)),
                (f"{d.get('mttr', {}).get('fix_rate_pct', 0)}%", "Fix Rate", f"MTTR: {d.get('mttr', {}).get('mttr_overall_days', 0)}d", (34, 197, 94) if d.get("mttr", {}).get("fix_rate_pct", 0) >= 50 else (234, 179, 8)),
            ]
            for i, (val, label, sub, color) in enumerate(cards):
                pdf.kpi_card(10 + i * (card_w + 3), y0, card_w, card_h, label, val, sub, color)
            pdf.set_y(y0 + card_h + 5)

            # Debt by severity bar chart
            by_sev = d.get("by_severity", {})
            if by_sev:
                pdf.section_title("Debt by Severity (hours)")
                debt_items = [(s.upper(), h, SEV_COLORS.get(s, (100, 100, 100))) for s, h in by_sev.items() if h > 0]
                _bar_chart(pdf, debt_items, label_w=28)
                pdf.ln(3)

            # MTTR by severity
            mttr = d.get("mttr", {})
            mttr_by_sev = mttr.get("mttr_by_severity", {})
            if mttr_by_sev:
                pdf.section_title("Mean Time to Remediate (days)")
                _table_header(pdf, [("Severity", 50, "L"), ("MTTR (days)", 50), ("Open Mean Age", 50)])
                open_ages = mttr.get("open_mean_age_by_severity", {})
                for sev in ["critical", "high", "medium", "low"]:
                    if sev in mttr_by_sev or sev in open_ages:
                        _table_row(pdf, [(sev.title(), 50), (mttr_by_sev.get(sev, "N/A"), 50), (open_ages.get(sev, "N/A"), 50)])
                pdf.ln(3)

        elif report_type == "fix_priority":
            pdf.section_title(f"Top {len(d.get('top_fixes', []))} Fixes (of {d.get('total_analyzed', 0)} analyzed)")
            top_fixes = d.get("top_fixes", [])
            if top_fixes:
                _table_header(pdf, [("Rank", 12), ("Title", 55, "L"), ("Severity", 20), ("Score", 18), ("Age", 18), ("Est.", 15), ("Reason", 52, "L")])
                for fix in top_fixes:
                    _table_row(pdf, [
                        (fix.get("rank", ""), 12),
                        (fix.get("title", "")[:28], 55),
                        (fix.get("severity", ""), 20),
                        (f"{fix.get('priority_score', 0):.2f}", 18),
                        (f"{fix.get('age_days', 0)}d", 18),
                        (f"{fix.get('estimated_fix_hours', 0)}h", 15),
                        (fix.get("reason", "")[:28], 52),
                    ])
                pdf.ln(3)

        elif report_type == "developer_report":
            dev_findings = d.get("findings", [])
            for idx, df in enumerate(dev_findings[:15]):
                _ensure_space(pdf, 60)
                # Finding header
                sev = df.get("severity", "medium")
                sev_color = SEV_COLORS.get(sev, (100, 100, 100))
                pdf.set_fill_color(*sev_color)
                fy = pdf.get_y()
                pdf.rect(10, fy, W, 10, "F")
                pdf.set_xy(12, fy + 1.5)
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(255, 255, 255)
                pdf.cell(0, 7, f"#{idx+1}  {df.get('title', '')[:80]}  [{sev.upper()}]  {df.get('cwe', '')}")
                pdf.set_y(fy + 12)

                # Location
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(*GRAY_600)
                loc_parts = []
                if df.get("file_path"):
                    loc_parts.append(df["file_path"])
                if df.get("line_start"):
                    loc_parts.append(f"Line {df['line_start']}")
                if df.get("function_name"):
                    loc_parts.append(f"fn: {df['function_name']}")
                if loc_parts:
                    pdf.cell(0, 5, "  |  ".join(loc_parts), new_x="LMARGIN", new_y="NEXT")

                # CVSS score
                cvss = df.get("cvss", {})
                if cvss:
                    pdf.set_font("Helvetica", "B", 8)
                    pdf.set_text_color(*BRAND_DARK)
                    pdf.cell(0, 5, f"CVSS: {cvss.get('score', 'N/A')} ({cvss.get('rating', '')})  |  Exploitability: {cvss.get('exploitability', 'N/A')}", new_x="LMARGIN", new_y="NEXT")

                # Guidance
                guidance = df.get("guidance", {})
                if guidance.get("explanation"):
                    pdf.ln(1)
                    pdf.set_font("Helvetica", "B", 8)
                    pdf.set_text_color(*BRAND_DARK)
                    pdf.cell(0, 5, "What is this?", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_font("Helvetica", "", 7.5)
                    pdf.set_text_color(60, 60, 60)
                    pdf.multi_cell(W, 4, guidance["explanation"][:300])

                if guidance.get("exploitation_scenario"):
                    pdf.ln(1)
                    pdf.set_font("Helvetica", "B", 8)
                    pdf.set_text_color(239, 68, 68)
                    pdf.cell(0, 5, "Exploitation Scenario", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_font("Helvetica", "", 7.5)
                    pdf.set_text_color(60, 60, 60)
                    pdf.multi_cell(W, 4, guidance["exploitation_scenario"][:250])

                if guidance.get("fix_strategy"):
                    pdf.ln(1)
                    pdf.set_font("Helvetica", "B", 8)
                    pdf.set_text_color(34, 197, 94)
                    pdf.cell(0, 5, "Fix Strategy", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_font("Helvetica", "", 7.5)
                    pdf.set_text_color(60, 60, 60)
                    pdf.multi_cell(W, 4, guidance["fix_strategy"][:250])

                # Before / After code
                if guidance.get("before_code") and guidance.get("after_code"):
                    _ensure_space(pdf, 30)
                    pdf.ln(1)
                    # Before code
                    pdf.set_font("Helvetica", "B", 7)
                    pdf.set_text_color(239, 68, 68)
                    pdf.cell(0, 4, "VULNERABLE CODE:", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_fill_color(255, 245, 245)
                    code_y = pdf.get_y()
                    pdf.set_font("Courier", "", 6.5)
                    pdf.set_text_color(60, 60, 60)
                    pdf.multi_cell(W, 3.5, guidance["before_code"][:200], fill=True)
                    pdf.ln(1)
                    # After code
                    pdf.set_font("Helvetica", "B", 7)
                    pdf.set_text_color(34, 197, 94)
                    pdf.cell(0, 4, "SECURE CODE:", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_fill_color(245, 255, 245)
                    pdf.set_font("Courier", "", 6.5)
                    pdf.set_text_color(60, 60, 60)
                    pdf.multi_cell(W, 3.5, guidance["after_code"][:200], fill=True)

                # Fix metadata
                pdf.ln(1)
                pdf.set_font("Helvetica", "", 7)
                pdf.set_text_color(*GRAY_600)
                meta_parts = []
                if guidance.get("fix_difficulty"):
                    meta_parts.append(f"Difficulty: {guidance['fix_difficulty'].title()}")
                if guidance.get("estimated_fix_minutes"):
                    meta_parts.append(f"Est. Fix: {guidance['estimated_fix_minutes']} min")
                if meta_parts:
                    pdf.cell(0, 4, "  |  ".join(meta_parts), new_x="LMARGIN", new_y="NEXT")

                pdf.ln(4)

        # ═══════════════════════════════════════════════
        # FINDINGS DETAIL TABLE
        # ═══════════════════════════════════════════════
        if findings:
            pdf.section_title(f"Findings Detail ({min(len(findings), 50)} of {len(findings)})")
            _table_header(pdf, [("Title", 52, "L"), ("Severity", 20), ("Classification", 35), ("CWE", 18), ("File", 65, "L")])
            for f in findings[:50]:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                cls = f.classification.value if hasattr(f.classification, "value") else str(f.classification)
                _table_row(pdf, [
                    (f.title, 52), (sev, 20), (cls.replace("_", " "), 35),
                    (f.cwe or "", 18), (f.file_path or "", 65),
                ])

        output = io.BytesIO()
        pdf.output(output)
        output.seek(0)

        return StreamingResponse(
            output,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=vooda-{report_type}-report.pdf"},
        )

    except ImportError:
        return JSONResponse(content={
            "error": "PDF generation requires fpdf2. Install with: pip install fpdf2",
        })
