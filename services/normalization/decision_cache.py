# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Decision Cache Service — carries forward triage decisions across scans.

Three levels of cache matching:
1. EXACT MATCH (stability_id + same code_hash) — same code, same location → carry forward
2. CODE CHANGED (stability_id matches but code_hash differs) → invalidate, re-analyze
3. PATTERN MATCH (pattern_hash matches in same org) → suggest classification from similar finding

Priority: User decisions > AI decisions
"""

import structlog
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.decision_cache import FindingDecisionCache
from services.normalization.stability import compute_stability_id, compute_code_hash, compute_pattern_hash

logger = structlog.get_logger()


class CacheResult:
    """Result of a cache lookup."""

    def __init__(self):
        self.hit = False
        self.hit_type: Optional[str] = None  # "exact", "pattern", None
        self.classification: Optional[str] = None
        self.ai_confidence: Optional[float] = None
        self.ai_explanation: Optional[str] = None
        self.exploitability_score: Optional[float] = None
        self.true_positive_reasons: list = []
        self.false_positive_reasons: list = []
        self.compensating_controls: list = []
        self.ai_evidence_refs: list = []
        self.decided_by: Optional[str] = None
        # Who made the ORIGINAL decision. A replay of a human's
        # verdict has to carry their id forward, or the copy claims
        # a confirmation with nobody's name on it.
        self.decided_by_user_id = None
        self.invalidated: bool = False  # True if code changed
        self.invalidation_reason: Optional[str] = None


async def lookup_cache(
    db: AsyncSession,
    tenant_id: UUID,
    repository_id: UUID,
    stability_id: str,
    code_hash: str,
) -> CacheResult:
    """
    Look up a finding in the decision cache.

    Returns:
        CacheResult with hit=True if a cached decision exists and code hasn't changed.
    """
    result = CacheResult()

    # 1. Check exact match by stability_id
    cache_r = await db.execute(
        select(FindingDecisionCache).where(
            FindingDecisionCache.stability_id == stability_id,
            FindingDecisionCache.repository_id == repository_id,
            FindingDecisionCache.tenant_id == tenant_id,
        ).order_by(FindingDecisionCache.created_at.desc()).limit(1)
    )
    cached = cache_r.scalar_one_or_none()

    if cached:
        # Check if code has changed
        if cached.code_hash == code_hash:
            # EXACT MATCH — same code, same location
            result.hit = True
            result.hit_type = "exact"
            result.classification = cached.classification
            result.ai_confidence = cached.ai_confidence
            result.ai_explanation = cached.ai_explanation
            result.exploitability_score = cached.exploitability_score
            result.true_positive_reasons = cached.true_positive_reasons or []
            result.false_positive_reasons = cached.false_positive_reasons or []
            result.compensating_controls = cached.compensating_controls or []
            result.ai_evidence_refs = cached.ai_evidence_refs or []
            result.decided_by = cached.decided_by
            result.decided_by_user_id = cached.decided_by_user_id

            # Update hit count
            cached.hit_count = (cached.hit_count or 0) + 1
            cached.last_hit_at = datetime.now(timezone.utc)
            await db.flush()

            logger.info("cache_hit_exact",
                stability_id=stability_id,
                classification=cached.classification,
                hit_count=cached.hit_count,
                decided_by=cached.decided_by,
            )
            return result
        else:
            # CODE CHANGED — invalidate cache
            result.invalidated = True
            result.invalidation_reason = f"Code changed (hash {cached.code_hash[:8]} → {code_hash[:8]})"

            logger.info("cache_invalidated_code_changed",
                stability_id=stability_id,
                old_hash=cached.code_hash,
                new_hash=code_hash,
            )
            return result

    # No cache match — finding needs AI analysis
    return result


async def store_in_cache(
    db: AsyncSession,
    tenant_id: UUID,
    repository_id: Optional[UUID],
    stability_id: str,
    code_hash: str,
    pattern_hash: Optional[str],
    classification: str,
    ai_confidence: Optional[float],
    ai_explanation: Optional[str],
    exploitability_score: Optional[float],
    true_positive_reasons: list,
    false_positive_reasons: list,
    compensating_controls: list,
    ai_evidence_refs: list,
    decided_by: str,  # "ai" or "user"
    decided_by_user_id: Optional[UUID] = None,
    source_scan_job_id: Optional[UUID] = None,
    # Source-scan finding scope. Either `repository_id` or
    # `scan_source_id` should be set (not both, not neither). Added
    # 2026-05-04 alongside the migration that drops NOT NULL on
    # `repository_id` so source-scan AI decisions can cache correctly.
    scan_source_id: Optional[UUID] = None,
    rule_id: Optional[str] = None,
    file_path: Optional[str] = None,
    function_name: Optional[str] = None,
    cwe: Optional[str] = None,
    finding_title: Optional[str] = None,
):
    """Store a triage decision in the cache."""

    # Check if entry exists — update it. Branch the lookup on
    # parent type: repository_id for git findings, scan_source_id
    # for source findings. NULL == NULL doesn't match in SQL, so
    # we use IS NULL for the unset side.
    cache_filter = [
        FindingDecisionCache.stability_id == stability_id,
        FindingDecisionCache.tenant_id == tenant_id,
    ]
    if repository_id is not None:
        cache_filter.append(FindingDecisionCache.repository_id == repository_id)
    elif scan_source_id is not None:
        cache_filter.append(FindingDecisionCache.scan_source_id == scan_source_id)
    else:
        # Neither parent set — fall back to stability_id + tenant
        # alone (rare; mostly defensive).
        pass
    existing_r = await db.execute(
        select(FindingDecisionCache).where(*cache_filter).limit(1)
    )
    existing = existing_r.scalar_one_or_none()

    if existing:
        # Update existing entry
        # User decisions always overwrite AI decisions
        if decided_by == "user" or existing.decided_by != "user":
            existing.classification = classification
            existing.ai_confidence = ai_confidence
            existing.ai_explanation = ai_explanation
            existing.exploitability_score = exploitability_score
            existing.true_positive_reasons = true_positive_reasons
            existing.false_positive_reasons = false_positive_reasons
            existing.compensating_controls = compensating_controls
            existing.ai_evidence_refs = ai_evidence_refs
            existing.decided_by = decided_by
            existing.decided_by_user_id = decided_by_user_id
            existing.source_scan_job_id = source_scan_job_id
            existing.code_hash = code_hash
            existing.pattern_hash = pattern_hash
            existing.updated_at = datetime.now(timezone.utc)
            await db.flush()
            logger.info("cache_updated", stability_id=stability_id, decided_by=decided_by)
    else:
        # Create new entry
        entry = FindingDecisionCache(
            tenant_id=tenant_id,
            repository_id=repository_id,
            scan_source_id=scan_source_id,
            stability_id=stability_id,
            classification=classification,
            ai_confidence=ai_confidence,
            ai_explanation=ai_explanation,
            exploitability_score=exploitability_score,
            true_positive_reasons=true_positive_reasons,
            false_positive_reasons=false_positive_reasons,
            compensating_controls=compensating_controls,
            ai_evidence_refs=ai_evidence_refs,
            decided_by=decided_by,
            decided_by_user_id=decided_by_user_id,
            source_scan_job_id=source_scan_job_id,
            code_hash=code_hash,
            pattern_hash=pattern_hash,
            rule_id=rule_id,
            file_path=file_path,
            function_name=function_name,
            cwe=cwe,
            finding_title=finding_title,
        )
        db.add(entry)
        await db.flush()
        logger.info("cache_stored", stability_id=stability_id, classification=classification, decided_by=decided_by)


async def store_user_decision_in_cache(
    db: AsyncSession,
    finding,  # NormalizedFinding
    classification: str,
    user_id: UUID,
):
    """
    Store a USER's triage decision in the cache.
    Called when a user marks a finding as TP/FP/Accept Risk.
    User decisions take priority over AI decisions.
    """
    if not finding.stability_id:
        return

    await store_in_cache(
        db=db,
        tenant_id=finding.tenant_id,
        repository_id=finding.repository_id,
        # Source-scan findings carry their parent on scan_source_id
        # (repository_id is None). Pass it through so user-triage
        # decisions on Slack/Jira/etc. findings cache correctly.
        scan_source_id=getattr(finding, "scan_source_id", None),
        stability_id=finding.stability_id,
        code_hash=finding.code_hash or "",
        pattern_hash=compute_pattern_hash(
            finding.scanner_rule_id or "",
            finding.code_snippet or "",
            finding.cwe,
        ),
        classification=classification,
        ai_confidence=finding.ai_confidence,
        ai_explanation=finding.ai_explanation,
        exploitability_score=finding.exploitability_score,
        true_positive_reasons=finding.true_positive_reasons or [],
        false_positive_reasons=finding.false_positive_reasons or [],
        compensating_controls=finding.compensating_controls or [],
        ai_evidence_refs=finding.ai_evidence_refs or [],
        decided_by="user",
        decided_by_user_id=user_id,
        rule_id=finding.scanner_rule_id,
        file_path=finding.file_path,
        function_name=finding.function_name,
        cwe=finding.cwe,
        finding_title=finding.title,
    )
