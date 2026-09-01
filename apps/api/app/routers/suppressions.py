# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Suppression Rules API — CRUD for managing learned and manual suppression rules.
"""

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User, UserRole, RoleType
import structlog

from apps.api.app.models.suppression import SuppressionRule, SuppressionType
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
logger = structlog.get_logger()


async def _require_admin(db: AsyncSession, user: User) -> None:
    """403 unless the user holds the admin role in this tenant.

    Every write here moves findings out of (or back into) the working
    queue for the whole tenant — a suppression rule is policy, not a
    per-finding triage call. Reads stay open to every member; writes
    are admin's.

    Same inlined shape as rule_overrides._require_admin, and for the
    same reason — core/security.require_role's async-factory shape does
    not compose with Depends(...). The two surfaces are the two halves
    of noise control and should refuse in the same voice.
    """
    row = await db.execute(
        select(UserRole).where(
            UserRole.user_id == user.id,
            UserRole.role == RoleType.ADMIN,
        )
    )
    if row.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=403,
            detail="Suppression rules can only be modified by tenant admins.",
        )


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
    # NULL for an ordinary rule; 'pending' while a proposal awaits
    # review. Declared here because the list endpoint expands every
    # table column into this model — an undeclared one is dropped, and
    # the review queue would have had nothing to filter on.
    review_status: Optional[str] = None
    created_by: str
    times_applied: int
    created_at: str

    model_config = {"from_attributes": True}


class SuppressionRuleCreate(BaseModel):
    # ``name`` is the human-readable label that appears in the audit
    # log + suppressions list view — NOT the secret value being matched.
    # Suppression criteria are the optional match fields below; a
    # rule that sets none of them is rejected, because the matcher
    # treats an empty criteria set as matching nothing rather than
    # everything.
    name: str = Field(
        ..., examples=["AWS demo keys in /examples"],
        description="Display label shown in the UI + audit log.",
    )
    description: Optional[str] = Field(
        None, examples=["Documentation samples; not real AWS credentials."],
    )
    suppression_type: str = Field(
        "manual", examples=["manual", "scanner_rule"],
        description=(
            "Provenance label only — it does not affect matching. "
            "`learned` is reserved for rules the learning engine writes."
        ),
    )

    @field_validator("suppression_type")
    @classmethod
    def _known_type(cls, v: str) -> str:
        allowed = {t.value for t in SuppressionType}
        if v not in allowed:
            raise ValueError(
                f"suppression_type must be one of {sorted(allowed)}"
            )
        return v

    @model_validator(mode="after")
    def _needs_at_least_one_criterion(self):
        """A rule with no criteria matches nothing.

        The matcher refuses to treat an empty criteria set as a wildcard,
        so such a rule saves as Active, reports zero matches forever, and
        looks like a feature that does not work. Reject it at the edge
        where we can say why.
        """
        if not any((
            self.scanner_rule_id,
            self.vulnerability_category,
            self.cwe,
            self.file_path_pattern,
        )):
            raise ValueError(
                "A suppression rule needs at least one match criterion: "
                "scanner_rule_id, vulnerability_category, cwe or "
                "file_path_pattern. Name and description alone would "
                "match nothing."
            )
        return self
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
    await _require_admin(db, user)
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

    # Apply immediately. An operator writes a rule to silence noise they
    # are looking at; leaving that noise on screen until the next scan is
    # not what they asked for.
    # Best-effort: the rule is saved either way and the next scan applies
    # it, so a backfill failure must not fail the create. Logged rather
    # than swallowed — an operator who sees the rule saved but the noise
    # still on screen needs something to point at.
    from services.suppressions.engine import apply_rule_to_existing
    try:
        applied = await apply_rule_to_existing(db, user.tenant_id, rule)
        if applied:
            logger.info("suppression_rule_backfilled", rule=str(rule.id), suppressed=applied)
        await db.flush()
    except Exception as _e:
        logger.warning(
            "suppression_rule_backfill_failed",
            rule=str(rule.id), error=str(_e)[:200],
            detail="rule saved; it will apply on the next scan",
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
    await _require_admin(db, user)
    result = await db.execute(
        select(SuppressionRule).where(
            SuppressionRule.id == rule_id,
            SuppressionRule.tenant_id == user.tenant_id,
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Suppression rule not found")

    _was_active = bool(rule.is_active)

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

    # Same rule as on create, enforced against the MERGED result rather
    # than the patch: a partial update that clears the last criterion
    # would leave an Active rule matching nothing. Checked before the
    # setattr loop so a rejected edit does not mutate the row.
    #
    # Only enforced when the edit actually touches a criterion. Rules
    # predating this validation can already be criteria-less, and
    # blocking their rename or deactivation would trap an operator with
    # a rule they can neither fix nor mute. Adding a criterion to one
    # still passes; only clearing the last is refused.
    # Switching a pending proposal to Active IS approving it. The
    # generic toggle used to set is_active alone, leaving review_status
    # 'pending' — and the matcher excludes pending rules, so the rule
    # read Active in the list and suppressed nothing. Routed through the
    # same decision the review action takes, so the audit trail records
    # an approval rather than a reactivation of something never reviewed.
    if rule.review_status == "pending" and changes.get("is_active") is True:
        return await review_proposal(
            rule_id=rule_id, decision="approve", db=db, user=user,
        )

    _CRITERIA = ("scanner_rule_id", "vulnerability_category",
                 "cwe", "file_path_pattern")
    _touches_criteria = any(f in changes for f in _CRITERIA)
    _merged = {f: changes.get(f, getattr(rule, f)) for f in _CRITERIA}
    if _touches_criteria and not any(_merged.values()):
        raise HTTPException(
            status_code=422,
            detail=(
                "A suppression rule needs at least one match criterion: "
                "scanner_rule_id, vulnerability_category, cwe or "
                "file_path_pattern. This edit would clear them all."
            ),
        )

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

    # An is_active toggle has to move findings, or the switch is
    # decorative: deactivating a rule while its findings stay hidden
    # would leave the operator with no way to get them back short of
    # deleting the rule. Criteria edits re-apply for the same reason —
    # the old match set is no longer what the rule describes.
    from services.suppressions.engine import apply_rule_to_existing, unapply_rule
    _criteria_changed = any(
        k in diff for k in
        ("scanner_rule_id", "pattern_hash", "vulnerability_category", "cwe", "file_path_pattern")
    )
    try:
        if _was_active and not rule.is_active:
            _n = await unapply_rule(db, user.tenant_id, rule.id)
            logger.info("suppression_rule_deactivated", rule=str(rule.id), restored=_n)
        elif rule.is_active and (not _was_active or _criteria_changed):
            if _criteria_changed:
                await unapply_rule(db, user.tenant_id, rule.id)
            _n = await apply_rule_to_existing(db, user.tenant_id, rule)
            logger.info("suppression_rule_reapplied", rule=str(rule.id), suppressed=_n)
        await db.flush()
    except Exception as _e:
        logger.warning(
            "suppression_rule_reapply_failed",
            rule=str(rule.id), error=str(_e)[:200],
            detail="rule updated; findings re-evaluate on the next scan",
        )

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
    await _require_admin(db, user)
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

    # Restore what this rule hid. Scoped by the rule:<uuid> reason, so a
    # manual or verified-inactive suppression is never reverted. Without
    # this the rows would stay hidden with a reason pointing at a rule
    # that no longer exists — unauditable and unreachable from the UI.
    from services.suppressions.engine import unapply_rule
    try:
        restored = await unapply_rule(db, user.tenant_id, rule.id)
        if restored:
            logger.info("suppression_rule_reverted", rule=str(rule.id), restored=restored)
    except Exception as _e:
        logger.warning(
            "suppression_rule_revert_failed", rule=str(rule.id), error=str(_e)[:200],
        )

    await db.delete(rule)
    await log_audit(
        db, user, "suppression_deleted", "suppression_rule",
        resource_id=rule_uuid,
        detail=f"Deleted suppression '{rule_name}' (times_applied={metadata['times_applied']})",
        metadata=metadata,
    )


class SuppressionPreviewRequest(BaseModel):
    """Criteria to dry-run — the create schema minus identity fields."""
    scanner_rule_id: Optional[str] = None
    vulnerability_category: Optional[str] = None
    cwe: Optional[str] = None
    file_path_pattern: Optional[str] = None

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def _needs_a_criterion(self):
        if not any((self.scanner_rule_id, self.vulnerability_category,
                    self.cwe, self.file_path_pattern)):
            raise ValueError("Preview needs at least one match criterion.")
        return self


@router.post("/preview")
async def preview_suppression_rule(
    body: SuppressionPreviewRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """How many current findings these criteria would suppress.

    A dry run for the create form: writing a rule blind and discovering
    its blast radius from the Applied column afterwards is the wrong
    order for an action that hides findings. Read-only, so any member
    may call it — it reveals nothing the findings list doesn't.

    Counts only unsuppressed findings: the number answers "what will
    change when I save this", and already-hidden findings won't.
    """
    from services.suppressions.engine import rule_matches

    probe = SuppressionRule(
        scanner_rule_id=body.scanner_rule_id,
        vulnerability_category=body.vulnerability_category,
        cwe=body.cwe,
        file_path_pattern=body.file_path_pattern,
    )
    from services.suppressions.engine import _exact_criteria_clauses
    from apps.api.app.models.finding import NormalizedFinding
    result = await db.execute(
        select(NormalizedFinding).where(
            NormalizedFinding.tenant_id == user.tenant_id,
            NormalizedFinding.is_suppressed == False,  # noqa: E712
            *_exact_criteria_clauses(probe),
        )
    )
    matches = sum(1 for f in result.scalars().all() if rule_matches(probe, f))
    return {"matches": matches}


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
    """Re-derive learned rules now, instead of waiting for the next scan.

    The scan pipeline calls the same function, so this is a convenience
    for an operator who has just finished triaging a batch and wants the
    result immediately. Idempotent: patterns that already have a rule —
    including ones previously rejected — are not raised again.
    """
    await _require_admin(db, user)
    from services.learning.pattern_learner import sync_learned_rules

    result = await sync_learned_rules(db, user.tenant_id)
    created = result["created_active"] + result["created_pending"]

    if created > 0:
        await log_audit(
            db, user, "suppressions_learned", "suppression_rule",
            resource_id=None,
            detail=(
                f"Learning created {result['created_active']} active rule(s) "
                f"and {result['created_pending']} proposal(s) awaiting review"
            ),
            metadata={
                "rules_created": result["created_active"],
                "proposals_created": result["created_pending"],
                "trigger": "manual",
            },
        )

    return {
        "rules_created": result["created_active"],
        "proposals_created": result["created_pending"],
    }


@router.post("/{rule_id}/review", status_code=200)
async def review_proposal(
    rule_id: UUID,
    decision: str = Query(..., pattern="^(approve|reject)$"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Approve or reject a proposed rule.

    Approving activates it and applies it to findings already stored, so
    the queue reflects the decision straight away rather than at the next
    scan. Rejecting leaves the rule inert and remembered, which is what
    stops learning re-proposing the same pattern every scan.
    """
    await _require_admin(db, user)
    result = await db.execute(
        select(SuppressionRule).where(
            SuppressionRule.id == rule_id,
            SuppressionRule.tenant_id == user.tenant_id,
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    if rule.review_status != "pending":
        raise HTTPException(
            status_code=409,
            detail="This rule is not awaiting review.",
        )

    approved = decision == "approve"
    rule.review_status = "approved" if approved else "rejected"
    rule.is_active = approved
    await db.flush()

    applied = 0
    if approved:
        # Best-effort: the decision itself is recorded either way. A
        # failure here means findings stay visible, which is the safe
        # direction — never the reverse.
        try:
            from services.suppressions.engine import apply_rule_to_existing
            applied = await apply_rule_to_existing(db, user.tenant_id, rule)
        except Exception as e:
            logger.warning("proposal_apply_failed", rule=str(rule_id), error=str(e)[:200])

    await log_audit(
        db, user,
        "suppression_proposal_approved" if approved else "suppression_proposal_rejected",
        "suppression_rule",
        resource_id=rule.id,
        detail=(
            f"{'Approved' if approved else 'Rejected'} proposed suppression "
            f"'{rule.name}' (evidence: {rule.evidence_count} findings across "
            f"{rule.evidence_repo_count} repos)"
        ),
        metadata={
            "decision": rule.review_status,
            "scanner_rule_id": rule.scanner_rule_id,
            "evidence_count": rule.evidence_count,
            "findings_suppressed": applied,
        },
    )
    await db.commit()

    return {
        "id": str(rule.id),
        "review_status": rule.review_status,
        "findings_suppressed": applied,
    }
