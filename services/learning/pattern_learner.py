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

# Thresholds for auto-suppression from CONFIRMED human decisions.
MIN_FP_COUNT = 3      # Must be marked FP at least N times
MIN_REPO_COUNT = 2    # Across at least M different repositories

# Thresholds for PROPOSALS derived from AI triage. Higher, because each
# piece of evidence is weaker: a human FP mark is someone stating they
# looked, while `likely_false_positive` is the model's opinion about a
# finding nobody has examined. A proposal is also inert until approved,
# so the cost of the bar being too high is a slower queue, not a missed
# secret — which is the direction to err in.
MIN_AI_FP_COUNT = 5
MIN_AI_REPO_COUNT = 2

#: Evidence sources.
SOURCE_HUMAN = "human"   # FindingDecision(action="mark_fp")
SOURCE_AI = "ai"         # classification == likely_false_positive


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
    source: str = "human"   # SOURCE_HUMAN | SOURCE_AI


def repo_identity(repo_id, url: str | None) -> str:
    """Which codebase a finding came from, not which row.

    The repository table can hold the same codebase many times — one row
    per scan configuration, per model being evaluated, per branch policy.
    Counting rows makes "seen across 5 repositories" mean "seen in one
    repository configured 5 ways", which is the opposite of the
    independence the thresholds are trying to establish. A pattern that
    is noise in one codebase would clear a cross-repository bar on the
    strength of duplicate registrations alone.

    Falls back to the row id when there is no URL, so a repository we
    cannot identify counts only as itself rather than merging with every
    other URL-less row.
    """
    if not url:
        return f"id:{repo_id}"
    u = url.strip().lower().rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    return f"url:{u}"


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
    from apps.api.app.models.repository import Repository

    result = await db.execute(
        select(
            NormalizedFinding.id,
            NormalizedFinding.scanner_rule_id,
            NormalizedFinding.vulnerability_category,
            NormalizedFinding.code_snippet,
            NormalizedFinding.repository_id,
            Repository.url,
        )
        .join(FindingDecision, FindingDecision.finding_id == NormalizedFinding.id)
        .outerjoin(Repository, Repository.id == NormalizedFinding.repository_id)
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

    for finding_id, rule_id, category, snippet, repo_id, repo_url in fp_findings:
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
        group["repos"].add(repo_identity(repo_id, repo_url))
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
                source=SOURCE_HUMAN,
            ))

    logger.info(
        "patterns_learned",
        total_fp_findings=len(fp_findings),
        pattern_groups=len(pattern_groups),
        learned_patterns=len(learned),
    )

    return learned


async def _patterns_a_human_called_real(db: AsyncSession, tenant_id: UUID) -> set:
    """Fingerprints where somebody marked a finding a TRUE positive.

    A veto list for AI-derived proposals. If a person looked at this
    exact shape of code and said it was a real secret, the model's
    opinion that it is noise does not get to become a rule — not even a
    proposed one, because a proposal in the queue is an invitation to
    approve it, and the reviewer cannot see the earlier disagreement.
    """
    from apps.api.app.models.finding import FindingDecision, NormalizedFinding

    result = await db.execute(
        select(NormalizedFinding.scanner_rule_id, NormalizedFinding.code_snippet)
        .join(FindingDecision, FindingDecision.finding_id == NormalizedFinding.id)
        .where(
            NormalizedFinding.tenant_id == tenant_id,
            FindingDecision.action == "mark_tp",
        )
    )
    return {
        (rule_id, compute_pattern_hash(snippet or ""))
        for rule_id, snippet in result.all()
        if rule_id
    }


async def propose_patterns(db: AsyncSession, tenant_id: UUID) -> list[LearnedPattern]:
    """Patterns AI triage repeatedly called false positive.

    Same grouping as `learn_patterns`, different evidence and a higher
    bar. Everything this returns is a PROPOSAL: it must be stored
    inactive and approved by a person before it suppresses anything.

    The reason for that asymmetry is the feedback loop. If the model's
    own verdict could create a live rule, matching findings would be
    suppressed before any human saw them, and the evidence that would
    reveal a systematic blind spot is exactly what gets hidden. The
    fingerprint makes that sharper: string literals normalise to "STR",
    so a real credential and a documentation sample share a pattern.
    That is a fair generalisation from several people agreeing, and a
    reckless one from a guess about a finding nobody opened.
    """
    from apps.api.app.models.finding import Classification, NormalizedFinding
    from apps.api.app.models.repository import Repository

    result = await db.execute(
        select(
            NormalizedFinding.id,
            NormalizedFinding.scanner_rule_id,
            NormalizedFinding.vulnerability_category,
            NormalizedFinding.code_snippet,
            NormalizedFinding.repository_id,
            Repository.url,
        )
        .outerjoin(Repository, Repository.id == NormalizedFinding.repository_id)
        .where(
            NormalizedFinding.tenant_id == tenant_id,
            NormalizedFinding.classification == Classification.LIKELY_FALSE_POSITIVE,
            NormalizedFinding.is_suppressed == False,  # noqa: E712
        )
    )
    rows = result.all()
    if not rows:
        return []

    vetoed = await _patterns_a_human_called_real(db, tenant_id)

    groups: dict = {}
    for finding_id, rule_id, category, snippet, repo_id, repo_url in rows:
        if not rule_id:
            continue
        p_hash = compute_pattern_hash(snippet or "")
        if (rule_id, p_hash) in vetoed:
            continue
        key = f"{rule_id}|{p_hash}"
        g = groups.setdefault(key, {
            "rule_id": rule_id, "pattern_hash": p_hash,
            "category": category or "", "count": 0,
            "repos": set(), "finding_ids": [], "sample": snippet or "",
        })
        g["count"] += 1
        g["repos"].add(repo_identity(repo_id, repo_url))
        g["finding_ids"].append(str(finding_id))

    proposals = [
        LearnedPattern(
            rule_id=g["rule_id"], pattern_hash=g["pattern_hash"],
            category=g["category"], fp_count=g["count"],
            repo_count=len(g["repos"]),
            evidence_finding_ids=g["finding_ids"][:10],
            sample_code=g["sample"][:200],
            source=SOURCE_AI,
        )
        for g in groups.values()
        if g["count"] >= MIN_AI_FP_COUNT and len(g["repos"]) >= MIN_AI_REPO_COUNT
    ]

    logger.info(
        "patterns_proposed",
        candidates=len(groups), proposed=len(proposals), vetoed=len(vetoed),
    )
    return proposals


async def sync_learned_rules(db: AsyncSession, tenant_id: UUID) -> dict:
    """Turn learned patterns into suppression rules. Returns counts.

    This is the only writer of `learned` rules, and it replaces the old
    arrangement where the scan path suppressed findings directly. That
    left no rule row, so an auto-suppression was invisible in the
    suppressions list, absent from its audit trail, and reversible only
    by re-classifying each finding by hand. Going through rules means
    learned suppressions behave like every other one: visible, counted,
    and undone by deactivating the rule.

    Two tiers, by evidence:

      human FP decisions  → active rule, suppresses immediately
      AI triage           → 'pending' proposal, inert until approved

    Idempotent. A pattern that already has a rule is skipped whatever
    its review_status, so a rejected proposal is never raised again and
    an approved one is not duplicated.
    """
    from apps.api.app.models.suppression import SuppressionRule

    existing = await db.execute(
        select(SuppressionRule.scanner_rule_id, SuppressionRule.pattern_hash)
        .where(SuppressionRule.tenant_id == tenant_id)
    )
    seen = {(r, h) for r, h in existing.all()}

    created_active = 0
    created_pending = 0

    confirmed = await learn_patterns(db, tenant_id)
    proposed = await propose_patterns(db, tenant_id)

    # Confirmed first: if both tiers derive the same pattern, the human
    # evidence wins and it goes live rather than sitting in the queue.
    for p in confirmed + proposed:
        key = (p.rule_id, p.pattern_hash)
        if key in seen:
            continue
        seen.add(key)

        is_ai = p.source == SOURCE_AI
        db.add(SuppressionRule(
            tenant_id=tenant_id,
            name=f"Learned: {p.rule_id} ({p.category})" if not is_ai
                 else f"Proposed: {p.rule_id} ({p.category})",
            description=(
                f"Proposed from AI triage: {p.fp_count} findings across "
                f"{p.repo_count} repositories were classified likely false "
                f"positive. Not suppressing anything until approved."
                if is_ai else
                f"Auto-learned from {p.fp_count} false-positive decisions "
                f"across {p.repo_count} repositories."
            ),
            suppression_type="learned",
            scanner_rule_id=p.rule_id,
            pattern_hash=p.pattern_hash,
            vulnerability_category=p.category or None,
            evidence_count=p.fp_count,
            evidence_repo_count=p.repo_count,
            evidence_finding_ids=p.evidence_finding_ids,
            sample_code=p.sample_code,
            # Confidence is evidence strength, not model score. An AI
            # proposal is explicitly the weaker claim.
            confidence=0.60 if is_ai else 0.85,
            created_by="ai_triage" if is_ai else "system_learning",
            is_active=not is_ai,
            review_status="pending" if is_ai else None,
        ))
        if is_ai:
            created_pending += 1
        else:
            created_active += 1

    if created_active or created_pending:
        await db.flush()
        logger.info(
            "learned_rules_synced",
            tenant=str(tenant_id),
            active=created_active, pending=created_pending,
        )

    return {"created_active": created_active, "created_pending": created_pending}
