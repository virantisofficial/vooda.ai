# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Suppression Rules API — CRUD for managing learned and manual suppression rules.
"""

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.suppression import SuppressionRule
# Audit logging — every suppression mutation lands an AuditEvent so
# compliance can answer "who muted what scanner rule, when, and
# why".  Without these calls (the state of the world before
# 2026-05-19), Settings → Suppressions was a silent compliance
# gap: rules could be created or disabled with no trace beyond the
# row's is_active flag — no actor, no timestamp narrative, no
# reason.  Flagged in the Track-A audit as a SOC 2 / ISO 27001
# violation source.
from apps.api.app.core.audit import log_audit

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────

class SuppressionRuleResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    suppression_type: str
    scanner_rule_id: Optional[str]
    pattern_hash: Optional[str]
    vulnerability_category: Optional[str]
    cwe: Optional[str]
    file_path_pattern: Optional[str]
    evidence_count: int
    evidence_repo_count: int
    confidence: float
    sample_code: Optional[str]
    is_active: bool
    created_by: str
    times_applied: int
    created_at: str

    model_config = {"from_attributes": True}


class SuppressionRuleCreate(BaseModel):
    # ``name`` is the human-readable label that appears in the audit
    # log + suppressions list view — NOT the secret value being matched.
    # Suppression criteria are the optional fields below; an empty
    # criteria set is rejected by the router.
    name: str = Field(
        ..., examples=["AWS demo keys in /examples"],
        description="Display label shown in the UI + audit log.",
    )
    description: Optional[str] = Field(
        None, examples=["Documentation samples; not real AWS credentials."],
    )
    suppression_type: str = Field(
        "manual", examples=["manual", "auto_learned"],
    )
    scanner_rule_id: Optional[str] = Field(
        None, examples=["aws-access-key-id"],
    )
    vulnerability_category: Optional[str] = Field(
        None, examples=["secret"],
    )
    cwe: Optional[str] = Field(None, examples=["CWE-798"])
    file_path_pattern: Optional[str] = Field(
        None, examples=["examples/**", "docs/**/*.md"],
        description="Glob pattern matched against the finding's file_path.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "name": "AWS demo keys in /examples",
                "description": "Documentation samples; not real credentials.",
                "suppression_type": "manual",
                "scanner_rule_id": "aws-access-key-id",
                "file_path_pattern": "examples/**",
            }],
        },
    }


class SuppressionRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    scanner_rule_id: Optional[str] = None
    vulnerability_category: Optional[str] = None
    cwe: Optional[str] = None
    file_path_pattern: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────

@router.get("", response_model=list[SuppressionRuleResponse])
async def list_suppression_rules(
    suppression_type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = select(SuppressionRule).where(SuppressionRule.tenant_id == user.tenant_id)

    if suppression_type:
        query = query.where(SuppressionRule.suppression_type == suppression_type)
    if is_active is not None:
        query = query.where(SuppressionRule.is_active == is_active)

    query = query.order_by(SuppressionRule.created_at.desc())
    result = await db.execute(query)
    rules = result.scalars().all()

    return [
        SuppressionRuleResponse(
            **{c.name: getattr(r, c.name) for c in r.__table__.columns if c.name != "created_at"},
            created_at=str(r.created_at),
        )
        for r in rules
    ]


@router.post("", response_model=SuppressionRuleResponse, status_code=201)
async def create_suppression_rule(
    body: SuppressionRuleCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rule = SuppressionRule(
        tenant_id=user.tenant_id,
        name=body.name,
        description=body.description,
        suppression_type=body.suppression_type,
        scanner_rule_id=body.scanner_rule_id,
        vulnerability_category=body.vulnerability_category,
        cwe=body.cwe,
        file_path_pattern=body.file_path_pattern,
        created_by=user.email,
        is_active=True,
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)

    # Audit row — captures every dimension a compliance reviewer
    # needs to reconstruct the decision: actor (user_id on the
    # event), target rule id, scope (rule + category + cwe + path
    # pattern), and free-text rationale.  Metadata is JSONB so we
    # can filter "all suppressions created without a description"
    # downstream.  See log_audit() docstring for the IP/UA capture.
    await log_audit(
        db, user, "suppression_created", "suppression_rule",
        resource_id=rule.id,
        detail=f"Created suppression '{body.name}' (type={body.suppression_type})",
        metadata={
            "name": body.name,
            "suppression_type": body.suppression_type,
            "scanner_rule_id": body.scanner_rule_id,
            "vulnerability_category": body.vulnerability_category,
            "cwe": body.cwe,
            "file_path_pattern": body.file_path_pattern,
            "description": body.description,
        },
    )

    return SuppressionRuleResponse(
        **{c.name: getattr(rule, c.name) for c in rule.__table__.columns if c.name != "created_at"},
        created_at=str(rule.created_at),
    )


@router.put("/{rule_id}", response_model=SuppressionRuleResponse)
async def update_suppression_rule(
    rule_id: UUID,
    body: SuppressionRuleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(SuppressionRule).where(
            SuppressionRule.id == rule_id,
            SuppressionRule.tenant_id == user.tenant_id,
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Suppression rule not found")

    # Snapshot the pre-update state so the audit metadata can express
    # diffs.  Reviewers especially care about is_active flips — those
    # are the "muted / unmuted" decisions compliance needs to track.
    # Captured here before the in-place setattr loop mutates the row.
    pre_state = {
        "name": rule.name,
        "description": rule.description,
        "is_active": rule.is_active,
        "scanner_rule_id": rule.scanner_rule_id,
        "vulnerability_category": rule.vulnerability_category,
        "cwe": rule.cwe,
        "file_path_pattern": rule.file_path_pattern,
    }

    changes = body.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(rule, field, value)

    await db.flush()
    await db.refresh(rule)

    # Pick the most specific action name when the update is purely
    # an is_active flip — auditors scan for "suppression_deactivated"
    # and "suppression_reactivated" to find muting decisions
    # specifically.  A mixed update (rename + flip) defaults to
    # "suppression_updated" with the flip recorded in metadata.
    action = "suppression_updated"
    if "is_active" in changes and len(changes) == 1:
        action = "suppression_deactivated" if changes["is_active"] is False else "suppression_reactivated"

    diff: dict = {}
    for k, v in changes.items():
        if pre_state.get(k) != v:
            diff[k] = {"from": pre_state.get(k), "to": v}

    await log_audit(
        db, user, action, "suppression_rule",
        resource_id=rule.id,
        detail=f"{action.replace('_', ' ').capitalize()}: '{rule.name}' (changes: {list(diff.keys())})"[:500],
        metadata={
            "name": rule.name,
            "suppression_type": rule.suppression_type,
            "scanner_rule_id": rule.scanner_rule_id,
            "diff": diff,
        },
    )

    return SuppressionRuleResponse(
        **{c.name: getattr(rule, c.name) for c in rule.__table__.columns if c.name != "created_at"},
        created_at=str(rule.created_at),
    )


@router.delete("/{rule_id}", status_code=204)
async def delete_suppression_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(SuppressionRule).where(
            SuppressionRule.id == rule_id,
            SuppressionRule.tenant_id == user.tenant_id,
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Suppression rule not found")

    # Capture the scope BEFORE delete so the audit row preserves what
    # was muted — the row itself is gone after this call so the
    # metadata is the only record left.
    metadata = {
        "name": rule.name,
        "suppression_type": rule.suppression_type,
        "scanner_rule_id": rule.scanner_rule_id,
        "vulnerability_category": rule.vulnerability_category,
        "cwe": rule.cwe,
        "file_path_pattern": rule.file_path_pattern,
        "times_applied": rule.times_applied,
    }
    rule_name = rule.name
    rule_uuid = rule.id

    await db.delete(rule)
    await log_audit(
        db, user, "suppression_deleted", "suppression_rule",
        resource_id=rule_uuid,
        detail=f"Deleted suppression '{rule_name}' (times_applied={metadata['times_applied']})",
        metadata=metadata,
    )


@router.get("/stats")
async def suppression_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get suppression statistics for the tenant."""
    total = await db.execute(
        select(func.count(SuppressionRule.id)).where(SuppressionRule.tenant_id == user.tenant_id)
    )
    active = await db.execute(
        select(func.count(SuppressionRule.id)).where(
            SuppressionRule.tenant_id == user.tenant_id,
            SuppressionRule.is_active == True,
        )
    )
    learned = await db.execute(
        select(func.count(SuppressionRule.id)).where(
            SuppressionRule.tenant_id == user.tenant_id,
            SuppressionRule.suppression_type == "learned",
        )
    )
    total_applied = await db.execute(
        select(func.sum(SuppressionRule.times_applied)).where(
            SuppressionRule.tenant_id == user.tenant_id,
        )
    )

    total_val = total.scalar() or 0
    active_val = active.scalar() or 0
    learned_val = learned.scalar() or 0
    applied_val = total_applied.scalar() or 0

    return {
        "total_rules": total_val,
        "active_rules": active_val,
        "learned_rules": learned_val,
        "manual_rules": total_val - learned_val,
        "total_suppressions_applied": applied_val,
    }


@router.post("/learn", status_code=200)
async def trigger_learning(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Manually trigger org-wide pattern learning."""
    from services.learning.pattern_learner import learn_patterns

    patterns = await learn_patterns(db, user.tenant_id)

    # Create suppression rules for newly learned patterns
    created = 0
    for p in patterns:
        # Check if rule already exists
        existing = await db.execute(
            select(SuppressionRule).where(
                SuppressionRule.tenant_id == user.tenant_id,
                SuppressionRule.scanner_rule_id == p.rule_id,
                SuppressionRule.pattern_hash == p.pattern_hash,
            )
        )
        if existing.scalar_one_or_none():
            continue

        rule = SuppressionRule(
            tenant_id=user.tenant_id,
            name=f"Learned: {p.rule_id} ({p.category})",
            description=f"Auto-learned from {p.fp_count} FP decisions across {p.repo_count} repos",
            suppression_type="learned",
            scanner_rule_id=p.rule_id,
            pattern_hash=p.pattern_hash,
            vulnerability_category=p.category,
            evidence_count=p.fp_count,
            evidence_repo_count=p.repo_count,
            evidence_finding_ids=p.evidence_finding_ids,
            sample_code=p.sample_code,
            confidence=0.85,
            created_by="system_learning",
            is_active=True,
        )
        db.add(rule)
        created += 1

    await db.flush()

    # Audit the learning run when it actually created rules.
    # Skipped for no-op runs so the audit log isn't spammed by
    # routine background passes that found nothing new.
    if created > 0:
        await log_audit(
            db, user, "suppressions_learned", "suppression_rule",
            resource_id=None,
            detail=f"Pattern-learning created {created} new suppression(s) (from {len(patterns)} candidate(s))",
            metadata={
                "patterns_found": len(patterns),
                "rules_created": created,
                "trigger": "manual" if user.email != "system_learning" else "system",
            },
        )

    return {"patterns_found": len(patterns), "rules_created": created}
