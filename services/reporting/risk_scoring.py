# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Enterprise risk scoring engine.

Provides: CVSS-like scoring, business impact rating, security debt calculation,
MTTR metrics, fix prioritisation, release readiness, and risk heat-map data.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone, timedelta
from typing import Optional


# ================================================================
#  CVSS v3.1-Compatible Scoring
# ================================================================

_EXPLOITABILITY_WEIGHTS = {
    "network": 0.85,
    "adjacent": 0.62,
    "local": 0.55,
    "physical": 0.20,
}

_SEVERITY_BASE: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}

_CWE_EXPLOITABILITY: dict[str, float] = {
    "CWE-89": 0.95,   # SQL injection -- trivially exploitable
    "CWE-78": 0.95,   # OS command injection
    "CWE-79": 0.85,   # XSS
    "CWE-22": 0.80,   # Path traversal
    "CWE-502": 0.80,  # Deserialization
    "CWE-798": 0.90,  # Hard-coded credentials
    "CWE-918": 0.75,  # SSRF
    "CWE-94": 0.90,   # Code injection
    "CWE-434": 0.75,  # Unrestricted upload
    "CWE-352": 0.60,  # CSRF
    "CWE-287": 0.80,  # Auth bypass
    "CWE-306": 0.85,  # Missing auth
    "CWE-862": 0.80,  # Missing authorization
    "CWE-269": 0.70,  # Privilege management
    "CWE-611": 0.70,  # XXE
    "CWE-77": 0.90,   # Command injection
    "CWE-326": 0.40,  # Weak crypto
    "CWE-327": 0.40,  # Broken crypto
}


def compute_cvss_score(
    severity: str,
    cwe: Optional[str] = None,
    exploitability_score: Optional[float] = None,
    has_data_flow: bool = False,
    is_internet_facing: bool = False,
) -> dict:
    """Compute a CVSS v3.1-compatible score with attack vector context."""
    base = _SEVERITY_BASE.get(severity.lower(), 5.0)

    exploit_factor = exploitability_score or _CWE_EXPLOITABILITY.get(
        (cwe or "").upper(), 0.5
    )

    # Adjust for reachability
    if has_data_flow:
        exploit_factor = min(exploit_factor + 0.1, 1.0)
    if is_internet_facing:
        exploit_factor = min(exploit_factor + 0.15, 1.0)

    score = round(min(base * (0.6 + 0.4 * exploit_factor), 10.0), 1)

    if score >= 9.0:
        rating = "Critical"
    elif score >= 7.0:
        rating = "High"
    elif score >= 4.0:
        rating = "Medium"
    elif score >= 0.1:
        rating = "Low"
    else:
        rating = "None"

    return {
        "score": score,
        "rating": rating,
        "exploitability": round(exploit_factor, 2),
        "impact_subscore": round(base, 1),
        "vector_string": f"CVSS:3.1/S:{severity[0].upper()}/E:{exploit_factor:.1f}",
    }


# ================================================================
#  Business Impact Rating
# ================================================================

def compute_business_impact(
    severity: str,
    is_internet_facing: bool = False,
    has_data_flow: bool = False,
    repo_business_criticality: str = "medium",
    data_classification: str = "internal",
) -> dict:
    """Rate business impact considering application context."""
    sev_weight = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.05}.get(severity.lower(), 0.5)
    biz_weight = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}.get(repo_business_criticality.lower(), 0.5)
    data_weight = {"restricted": 1.0, "confidential": 0.8, "internal": 0.5, "public": 0.2}.get(data_classification.lower(), 0.5)

    raw = sev_weight * 0.4 + biz_weight * 0.3 + data_weight * 0.2
    if is_internet_facing:
        raw += 0.08
    if has_data_flow:
        raw += 0.02
    raw = min(raw, 1.0)

    if raw >= 0.8:
        rating = "Critical"
    elif raw >= 0.6:
        rating = "High"
    elif raw >= 0.35:
        rating = "Medium"
    else:
        rating = "Low"

    return {
        "score": round(raw * 10, 1),
        "rating": rating,
        "factors": {
            "severity_weight": sev_weight,
            "business_criticality": repo_business_criticality,
            "data_classification": data_classification,
            "internet_facing": is_internet_facing,
            "data_flow_present": has_data_flow,
        },
    }


# ================================================================
#  Security Debt Calculation
# ================================================================

_FIX_EFFORT_HOURS: dict[str, float] = {
    "critical": 8.0,
    "high": 4.0,
    "medium": 2.0,
    "low": 1.0,
    "info": 0.25,
}

_HOURLY_COST_USD = 75.0  # blended developer cost


def calculate_security_debt(findings: list[dict]) -> dict:
    """
    Calculate security technical debt in hours and estimated cost.

    findings: list of dicts with 'severity', 'created_at' (ISO str or datetime), 'classification'.
    """
    total_hours = 0.0
    by_severity: dict[str, float] = {}
    overdue_hours = 0.0
    now = datetime.now(timezone.utc)

    sla_days = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}

    for f in findings:
        cls = f.get("classification", "").lower()
        if "false_positive" in cls or "accepted_risk" in cls:
            continue
        sev = f.get("severity", "medium").lower()
        hours = _FIX_EFFORT_HOURS.get(sev, 2.0)
        total_hours += hours
        by_severity[sev] = by_severity.get(sev, 0.0) + hours

        created = f.get("created_at")
        if created:
            if isinstance(created, str):
                try:
                    created = datetime.fromisoformat(created.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    created = None
            if created:
                age_days = (now - created).days
                if age_days > sla_days.get(sev, 180):
                    overdue_hours += hours

    total_cost = round(total_hours * _HOURLY_COST_USD, 2)

    if total_hours > 500:
        rating = "Critical"
    elif total_hours > 200:
        rating = "High"
    elif total_hours > 80:
        rating = "Medium"
    else:
        rating = "Low"

    return {
        "total_hours": round(total_hours, 1),
        "total_cost_usd": total_cost,
        "overdue_hours": round(overdue_hours, 1),
        "overdue_cost_usd": round(overdue_hours * _HOURLY_COST_USD, 2),
        "by_severity": {k: round(v, 1) for k, v in by_severity.items()},
        "debt_rating": rating,
        "hourly_rate_used": _HOURLY_COST_USD,
    }


# ================================================================
#  MTTR Metrics  (Mean Time To Remediate)
# ================================================================

def compute_mttr(findings: list[dict]) -> dict:
    """
    Compute Mean Time To Remediate and related velocity metrics.

    findings: list of dicts with 'severity', 'created_at', 'remediation_status', 'updated_at'.
    """
    resolved_ages: dict[str, list[float]] = {}
    open_ages: dict[str, list[float]] = {}
    now = datetime.now(timezone.utc)

    for f in findings:
        sev = f.get("severity", "medium").lower()
        created = f.get("created_at")
        if not created:
            continue
        if isinstance(created, str):
            try:
                created = datetime.fromisoformat(created.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue

        rem = f.get("remediation_status", "none").lower()
        if rem in ("applied", "approved"):
            updated = f.get("updated_at")
            if isinstance(updated, str):
                try:
                    updated = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    updated = now
            elif not updated:
                updated = now
            days = max((updated - created).days, 0)
            resolved_ages.setdefault(sev, []).append(days)
        else:
            age = (now - created).days
            open_ages.setdefault(sev, []).append(age)

    def _avg(lst: list) -> float:
        return round(sum(lst) / len(lst), 1) if lst else 0.0

    all_resolved = [d for ages in resolved_ages.values() for d in ages]
    all_open = [d for ages in open_ages.values() for d in ages]

    return {
        "mttr_overall_days": _avg(all_resolved),
        "mttr_by_severity": {sev: _avg(ages) for sev, ages in resolved_ages.items()},
        "open_mean_age_days": _avg(all_open),
        "open_mean_age_by_severity": {sev: _avg(ages) for sev, ages in open_ages.items()},
        "total_resolved": len(all_resolved),
        "total_open": len(all_open),
        "fix_rate_pct": round(len(all_resolved) / max(len(all_resolved) + len(all_open), 1) * 100, 1),
    }


# ================================================================
#  Fix Prioritisation  (Top-N)
# ================================================================

def prioritise_fixes(findings: list[dict], top_n: int = 20) -> list[dict]:
    """
    Return the top-N findings to fix first, ranked by composite priority score.

    Composite = severity_weight * 0.35 + exploitability * 0.25 + age_factor * 0.20 + business_risk * 0.20
    """
    now = datetime.now(timezone.utc)
    sev_w = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.05}

    scored = []
    for f in findings:
        cls = f.get("classification", "").lower()
        if "false_positive" in cls:
            continue

        sev = f.get("severity", "medium").lower()
        sw = sev_w.get(sev, 0.5)

        exploit = f.get("exploitability_score") or _CWE_EXPLOITABILITY.get((f.get("cwe") or "").upper(), 0.5)

        created = f.get("created_at")
        age_days = 0
        if created:
            if isinstance(created, str):
                try:
                    created = datetime.fromisoformat(created.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    created = None
            if created:
                age_days = (now - created).days
        age_factor = min(age_days / 90, 1.0)

        biz_risk = f.get("business_risk_score") or (sw * 0.7)

        priority = sw * 0.35 + exploit * 0.25 + age_factor * 0.20 + biz_risk * 0.20
        fix_hours = _FIX_EFFORT_HOURS.get(sev, 2.0)

        scored.append({
            "id": f.get("id"),
            "title": f.get("title", ""),
            "severity": sev,
            "cwe": f.get("cwe"),
            "file_path": f.get("file_path"),
            "line_start": f.get("line_start"),
            "priority_score": round(priority, 3),
            "exploitability": round(exploit, 2),
            "age_days": age_days,
            "estimated_fix_hours": fix_hours,
            "reason": _priority_reason(sev, exploit, age_days, biz_risk),
        })

    scored.sort(key=lambda x: x["priority_score"], reverse=True)
    for i, item in enumerate(scored[:top_n], 1):
        item["rank"] = i
    return scored[:top_n]


def _priority_reason(sev: str, exploit: float, age: int, biz: float) -> str:
    parts = []
    if sev in ("critical", "high"):
        parts.append(f"{sev}-severity")
    if exploit >= 0.8:
        parts.append("easily exploitable")
    if age > 90:
        parts.append(f"open {age}d")
    if biz >= 0.7:
        parts.append("high business impact")
    return "; ".join(parts) if parts else "standard priority"


# ================================================================
#  Release Readiness / Security Quality Gate
# ================================================================

def evaluate_release_readiness(
    findings: list[dict],
    gate_policy: Optional[dict] = None,
) -> dict:
    """
    Evaluate whether an application is ready for release based on security gate policy.
    """
    policy = gate_policy or {
        "max_critical": 0,
        "max_high": 5,
        "max_medium": 50,
        "block_on_new_critical": True,
        "required_review_pct": 80,
        "min_security_score": 60,
    }

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    open_count = 0
    reviewed = 0
    total_actionable = 0
    new_critical = 0
    now = datetime.now(timezone.utc)

    for f in findings:
        cls = f.get("classification", "").lower()
        if "false_positive" in cls:
            continue

        sev = f.get("severity", "medium").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        total_actionable += 1

        rem = f.get("remediation_status", "none").lower()
        if rem not in ("applied", "approved"):
            open_count += 1

        rev = f.get("review_status", "unreviewed").lower()
        if rev in ("reviewed", "in_review"):
            reviewed += 1

        created = f.get("created_at")
        if created and sev == "critical":
            if isinstance(created, str):
                try:
                    created = datetime.fromisoformat(created.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    created = None
            if created and (now - created).days <= 7:
                new_critical += 1

    review_pct = round(reviewed / max(total_actionable, 1) * 100, 1)

    violations = []
    if sev_counts["critical"] > policy.get("max_critical", 0):
        violations.append(f"Critical findings ({sev_counts['critical']}) exceed threshold ({policy['max_critical']})")
    if sev_counts["high"] > policy.get("max_high", 5):
        violations.append(f"High findings ({sev_counts['high']}) exceed threshold ({policy['max_high']})")
    if sev_counts["medium"] > policy.get("max_medium", 50):
        violations.append(f"Medium findings ({sev_counts['medium']}) exceed threshold ({policy['max_medium']})")
    if policy.get("block_on_new_critical") and new_critical > 0:
        violations.append(f"{new_critical} new critical finding(s) in last 7 days")
    if review_pct < policy.get("required_review_pct", 80):
        violations.append(f"Review coverage ({review_pct}%) below required ({policy['required_review_pct']}%)")

    status = "GO" if not violations else "NO-GO"

    # Compute security score
    total = max(total_actionable, 1)
    score = max(0, 100 - (sev_counts["critical"] * 15 + sev_counts["high"] * 8 + sev_counts["medium"] * 3 + sev_counts["low"] * 1))
    score = min(score, 100)

    if score < policy.get("min_security_score", 60):
        if f"Security score ({score}) below minimum ({policy['min_security_score']})" not in violations:
            violations.append(f"Security score ({score}) below minimum ({policy['min_security_score']})")
        status = "NO-GO"

    return {
        "release_status": status,
        "security_score": score,
        "severity_counts": sev_counts,
        "open_findings": open_count,
        "review_coverage_pct": review_pct,
        "new_critical_7d": new_critical,
        "violations": violations,
        "violation_count": len(violations),
        "policy_applied": policy,
        "recommendation": _release_recommendation(status, violations),
    }


def _release_recommendation(status: str, violations: list) -> str:
    if status == "GO":
        return "Application meets all security gate criteria. Cleared for release."
    elif len(violations) == 1:
        return f"Release blocked: {violations[0]}. Address this issue before proceeding."
    else:
        return f"Release blocked with {len(violations)} policy violations. Remediate critical/high findings and increase review coverage before release."


# ================================================================
#  Risk Heat-Map Data
# ================================================================

def generate_risk_heatmap(findings_by_repo: dict[str, list[dict]]) -> list[dict]:
    """
    Generate risk heat-map data: severity vs. exploitability per repository.

    findings_by_repo: {repo_name: [finding_dicts]}
    """
    heatmap = []
    for repo_name, findings in findings_by_repo.items():
        sev_w = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        total_risk = 0
        total_exploit = 0.0
        count = 0
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for f in findings:
            cls = f.get("classification", "").lower()
            if "false_positive" in cls:
                continue
            sev = f.get("severity", "medium").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            total_risk += sev_w.get(sev, 1)
            total_exploit += f.get("exploitability_score") or 0.5
            count += 1

        if count == 0:
            continue

        avg_risk = total_risk / count
        avg_exploit = total_exploit / count

        if avg_risk >= 3 and avg_exploit >= 0.7:
            zone = "red"
        elif avg_risk >= 2 or avg_exploit >= 0.5:
            zone = "amber"
        else:
            zone = "green"

        heatmap.append({
            "repository": repo_name,
            "finding_count": count,
            "severity_counts": sev_counts,
            "avg_risk_level": round(avg_risk, 2),
            "avg_exploitability": round(avg_exploit, 2),
            "risk_zone": zone,
        })

    heatmap.sort(key=lambda x: x["avg_risk_level"], reverse=True)
    return heatmap
