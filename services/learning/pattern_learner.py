# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Org-Wide Pattern Learning — auto-suppresses patterns consistently marked
as false positive across multiple repositories.

When the same (scanner_rule_id + code_pattern_hash) has been marked FP by users
N times across M or more repos, creates an auto-suppression rule.

All auto-suppressions are:
- Auditable (linked back to the evidence finding IDs)
- Reversible (admin can disable/delete learned rules)
- Visible in the UI (Settings → Learned Rules)
"""

import hashlib
import re
import structlog
from uuid import UUID
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

logger = structlog.get_logger()

# Thresholds for auto-suppression
MIN_FP_COUNT = 3      # Must be marked FP at least N times
MIN_REPO_COUNT = 2    # Across at least M different repositories


@dataclass
class LearnedPattern:
    """A pattern that was consistently marked as FP."""
    rule_id: str
    pattern_hash: str
    category: str
    fp_count: int
    repo_count: int
    evidence_finding_ids: list[str] = field(default_factory=list)
    sample_code: str = ""


def normalize_code_for_hashing(code: str) -> str:
    """
    Normalize code snippet for pattern matching.
    Strips variable names, whitespace, and string literals to create
    a structural fingerprint that matches semantically similar code.
    """
    if not code:
        return ""

    # Remove comments
    code = re.sub(r"#.*$", "", code, flags=re.MULTILINE)
    code = re.sub(r"//.*$", "", code, flags=re.MULTILINE)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)

    # Normalize string literals to placeholder
    code = re.sub(r'"[^"]*"', '"STR"', code)
    code = re.sub(r"'[^']*'", "'STR'", code)

    # Normalize numeric literals
    code = re.sub(r"\b\d+\b", "NUM", code)

    # Collapse whitespace
    code = re.sub(r"\s+", " ", code).strip()

    return code


def compute_pattern_hash(code: str) -> str:
    """Compute a normalized hash of a code pattern."""
    normalized = normalize_code_for_hashing(code)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


async def learn_patterns(
    db: AsyncSession,
    tenant_id: UUID,
) -> list[LearnedPattern]:
    """
    Analyze all FP decisions across the tenant to find patterns
    that should be auto-suppressed.

    Returns a list of LearnedPattern objects that meet the thresholds.
    """
    from apps.api.app.models.finding import NormalizedFinding, FindingDecision, Classification

    # Find all findings that were marked as FP by users
    result = await db.execute(
        select(
            NormalizedFinding.id,
            NormalizedFinding.scanner_rule_id,
            NormalizedFinding.vulnerability_category,
            NormalizedFinding.code_snippet,
            NormalizedFinding.repository_id,
        )
        .join(FindingDecision, FindingDecision.finding_id == NormalizedFinding.id)
        .where(
            NormalizedFinding.tenant_id == tenant_id,
            FindingDecision.action == "mark_fp",
        )
    )
    fp_findings = result.all()

    if not fp_findings:
        return []

    # Group by (rule_id, pattern_hash)
    pattern_groups: dict[str, dict] = {}  # key -> {count, repos, finding_ids, sample}

    for finding_id, rule_id, category, snippet, repo_id in fp_findings:
        if not rule_id:
            continue

        p_hash = compute_pattern_hash(snippet or "")
        key = f"{rule_id}|{p_hash}"

        if key not in pattern_groups:
            pattern_groups[key] = {
                "rule_id": rule_id,
                "pattern_hash": p_hash,
                "category": category or "",
                "count": 0,
                "repos": set(),
                "finding_ids": [],
                "sample": snippet or "",
            }

        group = pattern_groups[key]
        group["count"] += 1
        group["repos"].add(str(repo_id))
        group["finding_ids"].append(str(finding_id))

    # Filter to patterns meeting thresholds
    learned = []
    for key, group in pattern_groups.items():
        if group["count"] >= MIN_FP_COUNT and len(group["repos"]) >= MIN_REPO_COUNT:
            learned.append(LearnedPattern(
                rule_id=group["rule_id"],
                pattern_hash=group["pattern_hash"],
                category=group["category"],
                fp_count=group["count"],
                repo_count=len(group["repos"]),
                evidence_finding_ids=group["finding_ids"][:10],
                sample_code=group["sample"][:200],
            ))

    logger.info(
        "patterns_learned",
        total_fp_findings=len(fp_findings),
        pattern_groups=len(pattern_groups),
        learned_patterns=len(learned),
    )

    return learned


async def apply_learned_suppressions(
    db: AsyncSession,
    tenant_id: UUID,
    findings_to_check: list,
) -> int:
    """
    Check new findings against learned suppression patterns.
    Marks matching findings as suppressed.

    Returns count of findings suppressed.
    """
    from apps.api.app.models.finding import Classification

    learned = await learn_patterns(db, tenant_id)
    if not learned:
        return 0

    # Build lookup: (rule_id, pattern_hash) -> LearnedPattern
    pattern_lookup = {}
    for lp in learned:
        pattern_lookup[(lp.rule_id, lp.pattern_hash)] = lp

    suppressed = 0
    for finding in findings_to_check:
        if finding.is_suppressed:
            continue

        p_hash = compute_pattern_hash(finding.code_snippet or "")
        key = (finding.scanner_rule_id, p_hash)

        if key in pattern_lookup:
            lp = pattern_lookup[key]
            finding.is_suppressed = True
            finding.classification = Classification.CONFIRMED_FALSE_POSITIVE
            finding.ai_explanation = (
                f"Auto-suppressed by org-wide learning: this pattern ({lp.rule_id}) "
                f"has been marked as false positive {lp.fp_count} times across "
                f"{lp.repo_count} repositories."
            )
            finding.source_metadata = {
                **(finding.source_metadata or {}),
                "suppressed_by": "org_learning",
                "learned_pattern_hash": lp.pattern_hash,
                "evidence_count": lp.fp_count,
            }
            suppressed += 1

    if suppressed > 0:
        await db.flush()
        logger.info("org_learning_suppressed", count=suppressed)

    return suppressed
