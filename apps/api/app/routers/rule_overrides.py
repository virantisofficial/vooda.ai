# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Rule Overrides API — proactive muting of specific scanner rules per
repository or org-wide.

This is the *proactive* counterpart to /api/v1/suppressions (reactive,
post-finding triage).  See models/rule_override.py for the audit /
lifecycle reasoning behind keeping the two surfaces separate, and the
migration x1y2z3a4b5c6_add_rule_overrides for the schema.

Endpoints
---------
  GET    /rule-overrides                — list (filters)
  GET    /rule-overrides/stats          — counters for the admin tab header
  GET    /rule-overrides/available-rules — catalogue for the typeahead picker
  POST   /rule-overrides                — create  (admin role required)
  PATCH  /rule-overrides/{id}           — update (admin role required)
  DELETE /rule-overrides/{id}           — hard delete (admin role required).
                                           Soft-disable via PATCH is_active=false
                                           is the preferred audit-friendly path —
                                           DELETE is for cleaning up mistakes.

Authorization
-------------
Mutating endpoints require the "admin" role because rule overrides
silently change scanner behaviour.  Read endpoints are open to any
authenticated user in the tenant so developers can see why a rule
isn't firing for their repo.
"""

from typing import Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.audit import log_audit
from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.repository import Repository
from apps.api.app.models.rule_override import RuleOverride
from apps.api.app.models.scan_source import ScanSource
from apps.api.app.models.user import User, UserRole, RoleType
from apps.api.app.schemas.rule_override import (
    AvailableRule,
    RuleOverrideCreate,
    RuleOverrideResponse,
    RuleOverrideStats,
    RuleOverrideUpdate,
)

logger = structlog.get_logger("vooda.api.rule_overrides")

router = APIRouter()


# ── Helpers ─────────────────────────────────────────────────────────

async def _require_admin(
    db: AsyncSession,
    user: User,
) -> None:
    """403 unless the user holds the admin role in this tenant.

    Inlined here rather than reusing core/security.require_role because
    that helper's async-factory shape isn't compatible with FastAPI's
    Depends(...) construction (see comments on the helper).  Kept small
    and self-contained so the gate is obvious to a reviewer.
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
            detail="Rule overrides can only be modified by tenant admins.",
        )


async def _to_response(
    db: AsyncSession,
    rule: RuleOverride,
) -> RuleOverrideResponse:
    """Hydrate a RuleOverride row into its wire response.

    Resolves convenience FK fields (repository_name, source_name,
    source_type, created_by_email) with bounded extra lookups so the
    API client doesn't have to fan out.  At most one of repository_name
    / source_name is populated per row (mirrors the XOR scope).
    """
    repo_name: Optional[str] = None
    if rule.repository_id is not None:
        repo_row = await db.execute(
            select(Repository.name).where(Repository.id == rule.repository_id)
        )
        repo_name = repo_row.scalar_one_or_none()

    source_name: Optional[str] = None
    source_type: Optional[str] = None
    if rule.scan_source_id is not None:
        # Pull both columns in one round-trip so the row renders with
        # "Slack: workspace-prod" style pills without a second query.
        src_row = await db.execute(
            select(ScanSource.name, ScanSource.source_type).where(
                ScanSource.id == rule.scan_source_id
            )
        )
        result = src_row.one_or_none()
        if result is not None:
            source_name, source_type = result

    actor_email: Optional[str] = None
    if rule.created_by is not None:
        actor_row = await db.execute(
            select(User.email).where(User.id == rule.created_by)
        )
        actor_email = actor_row.scalar_one_or_none()

    return RuleOverrideResponse(
        id=rule.id,
        scanner_rule_id=rule.scanner_rule_id,
        repository_id=rule.repository_id,
        scan_source_id=rule.scan_source_id,
        repository_name=repo_name,
        source_name=source_name,
        source_type=source_type,
        mode=rule.mode,
        reason=rule.reason,
        created_by=rule.created_by,
        created_by_email=actor_email,
        is_active=rule.is_active,
        expires_at=rule.expires_at,
        times_blocked=rule.times_blocked,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


async def _verify_repo_in_tenant(
    db: AsyncSession,
    tenant_id: UUID,
    repository_id: UUID,
) -> Repository:
    """Reject cross-tenant repository ids with a 404 (not 403).

    404 instead of 403 because we don't want the API to confirm or
    deny the existence of repos in other tenants.
    """
    row = await db.execute(
        select(Repository).where(
            Repository.id == repository_id,
            Repository.tenant_id == tenant_id,
        )
    )
    repo = row.scalar_one_or_none()
    if repo is None:
        raise HTTPException(status_code=404, detail="Repository not found")
    return repo


async def _verify_source_in_tenant(
    db: AsyncSession,
    tenant_id: UUID,
    scan_source_id: UUID,
) -> ScanSource:
    """Twin of _verify_repo_in_tenant for scan_sources.  Same 404-not-403
    policy to avoid leaking cross-tenant existence."""
    row = await db.execute(
        select(ScanSource).where(
            ScanSource.id == scan_source_id,
            ScanSource.tenant_id == tenant_id,
        )
    )
    src = row.scalar_one_or_none()
    if src is None:
        raise HTTPException(status_code=404, detail="Scan source not found")
    return src


# ── Read ────────────────────────────────────────────────────────────

@router.get("", response_model=list[RuleOverrideResponse])
async def list_rule_overrides(
    repository_id: Optional[UUID] = Query(
        None,
        description=(
            "Filter to overrides scoped to this repo.  By default the listing "
            "includes both repo-scoped AND org-wide overrides — pass "
            "include_org_wide=false to get only repo-scoped."
        ),
    ),
    scan_source_id: Optional[UUID] = Query(
        None,
        description=(
            "Filter to overrides scoped to this scan source.  Org-wide "
            "overrides are also included when include_org_wide=true."
        ),
    ),
    include_org_wide: bool = Query(
        True,
        description=(
            "When repository_id or scan_source_id is set, also include "
            "org-wide overrides (both target columns NULL) that effectively "
            "apply to that target.  The per-repo / per-source detail cards "
            "use this; the admin tab passes include_org_wide=false when "
            "filtering to a single target to avoid double-counting."
        ),
    ),
    scope: Optional[str] = Query(
        None,
        description=(
            "Filter by scope category: 'org' (both target columns NULL), "
            "'repo' (repository_id NOT NULL), 'source' (scan_source_id "
            "NOT NULL).  Mutually exclusive with repository_id / "
            "scan_source_id (those are exact-target filters)."
        ),
    ),
    scanner_rule_id: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = select(RuleOverride).where(RuleOverride.tenant_id == user.tenant_id)

    # Exact-target filters.  repository_id and scan_source_id are
    # mutually exclusive because a single row can't target both — but
    # the QUERY can legitimately AND them when an admin opens the "all
    # overrides touching repo X + source Y" view via include_org_wide.
    if repository_id is not None and scan_source_id is not None:
        # Both passed: return rules that target EITHER (plus org-wide
        # if requested).  Useful when a user has both a repo card and
        # source card open simultaneously, though we don't expose that
        # in the UI today.
        target_clauses = [
            RuleOverride.repository_id == repository_id,
            RuleOverride.scan_source_id == scan_source_id,
        ]
        if include_org_wide:
            target_clauses.append(
                and_(
                    RuleOverride.repository_id.is_(None),
                    RuleOverride.scan_source_id.is_(None),
                )
            )
        q = q.where(or_(*target_clauses))
    elif repository_id is not None:
        if include_org_wide:
            q = q.where(
                or_(
                    RuleOverride.repository_id == repository_id,
                    and_(
                        RuleOverride.repository_id.is_(None),
                        RuleOverride.scan_source_id.is_(None),
                    ),
                )
            )
        else:
            q = q.where(RuleOverride.repository_id == repository_id)
    elif scan_source_id is not None:
        if include_org_wide:
            q = q.where(
                or_(
                    RuleOverride.scan_source_id == scan_source_id,
                    and_(
                        RuleOverride.repository_id.is_(None),
                        RuleOverride.scan_source_id.is_(None),
                    ),
                )
            )
        else:
            q = q.where(RuleOverride.scan_source_id == scan_source_id)

    # Scope-category filter (org / repo / source).  Independent of the
    # exact-target filters above; an admin tab might pass scope=source
    # to see ALL source-scoped overrides across every source.
    if scope == "org":
        q = q.where(
            RuleOverride.repository_id.is_(None),
            RuleOverride.scan_source_id.is_(None),
        )
    elif scope == "repo":
        q = q.where(RuleOverride.repository_id.isnot(None))
    elif scope == "source":
        q = q.where(RuleOverride.scan_source_id.isnot(None))

    if scanner_rule_id:
        q = q.where(RuleOverride.scanner_rule_id == scanner_rule_id)
    if is_active is not None:
        q = q.where(RuleOverride.is_active == is_active)

    q = q.order_by(RuleOverride.created_at.desc())
    result = await db.execute(q)
    rules = result.scalars().all()

    return [await _to_response(db, r) for r in rules]


@router.get("/stats", response_model=RuleOverrideStats)
async def rule_override_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Counters for the admin tab header — total active vs muted-but-keep,
    scope split, and total findings blocked.  All scoped to the user's tenant.
    """
    base = select(RuleOverride).where(RuleOverride.tenant_id == user.tenant_id)

    total_active_row = await db.execute(
        select(func.count(RuleOverride.id)).where(
            RuleOverride.tenant_id == user.tenant_id,
            RuleOverride.is_active == True,
            # An expired mute is not enforcing anything: counting it as
            # Active would make the tile disagree with what scans do.
            or_(
                RuleOverride.expires_at.is_(None),
                RuleOverride.expires_at > func.now(),
            ),
        )
    )
    total_inactive_row = await db.execute(
        select(func.count(RuleOverride.id)).where(
            RuleOverride.tenant_id == user.tenant_id,
            RuleOverride.is_active == False,
        )
    )
    # "Org-wide" = neither target column set.  Important to AND both
    # IS NULL — a row with scan_source_id set should NOT count as
    # org-wide just because repository_id is null.
    org_wide_row = await db.execute(
        select(func.count(RuleOverride.id)).where(
            RuleOverride.tenant_id == user.tenant_id,
            RuleOverride.is_active == True,
            # An expired mute is not enforcing anything: counting it as
            # Active would make the tile disagree with what scans do.
            or_(
                RuleOverride.expires_at.is_(None),
                RuleOverride.expires_at > func.now(),
            ),
            RuleOverride.repository_id.is_(None),
            RuleOverride.scan_source_id.is_(None),
        )
    )
    repo_scoped_row = await db.execute(
        select(func.count(RuleOverride.id)).where(
            RuleOverride.tenant_id == user.tenant_id,
            RuleOverride.is_active == True,
            # An expired mute is not enforcing anything: counting it as
            # Active would make the tile disagree with what scans do.
            or_(
                RuleOverride.expires_at.is_(None),
                RuleOverride.expires_at > func.now(),
            ),
            RuleOverride.repository_id.isnot(None),
        )
    )
    source_scoped_row = await db.execute(
        select(func.count(RuleOverride.id)).where(
            RuleOverride.tenant_id == user.tenant_id,
            RuleOverride.is_active == True,
            # An expired mute is not enforcing anything: counting it as
            # Active would make the tile disagree with what scans do.
            or_(
                RuleOverride.expires_at.is_(None),
                RuleOverride.expires_at > func.now(),
            ),
            RuleOverride.scan_source_id.isnot(None),
        )
    )
    blocked_row = await db.execute(
        select(func.coalesce(func.sum(RuleOverride.times_blocked), 0)).where(
            RuleOverride.tenant_id == user.tenant_id,
            RuleOverride.is_active == True,
            # An expired mute is not enforcing anything: counting it as
            # Active would make the tile disagree with what scans do.
            or_(
                RuleOverride.expires_at.is_(None),
                RuleOverride.expires_at > func.now(),
            ),
        )
    )

    return RuleOverrideStats(
        total_active=total_active_row.scalar() or 0,
        total_inactive=total_inactive_row.scalar() or 0,
        org_wide_active=org_wide_row.scalar() or 0,
        repo_scoped_active=repo_scoped_row.scalar() or 0,
        source_scoped_active=source_scoped_row.scalar() or 0,
        total_findings_blocked=int(blocked_row.scalar() or 0),
    )


@router.get("/available-rules", response_model=list[AvailableRule])
async def list_available_rules(
    q: Optional[str] = Query(
        None,
        description="Free-text filter (case-insensitive) on rule_id or title.",
    ),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Catalogue of all scanner rules an admin could override.

    Sourced from the in-process detector registry (built-in rules) plus
    the tenant's enabled custom detectors.  The endpoint is intentionally
    a catalogue, not an admin-only resource — developers benefit from
    seeing the same picker when triaging "why isn't this rule firing for
    my repo".

    Rule-id branding
    ----------------
    Detectors define rule_id as ``VOODA-SEC-XXX-NNN`` but the worker
    persists findings with the prefix STRIPPED (via
    ``brand_rule_id``) — so the ``normalized_findings.scanner_rule_id``
    column actually contains values like ``AWS-001``, ``GEN-003-WEAK``.

    The rule-override lookup the worker performs at scan time compares
    against the SAME stripped form (``brand_rule_id(pf.rule_id)``).
    To make overrides actually fire, the picker must surface (and the
    create endpoint must store) the stripped form too — otherwise an
    admin picks ``VOODA-SEC-AWS-001`` and the worker compares
    ``AWS-001`` against ``{"VOODA-SEC-AWS-001"}`` and misses every time.

    De-duplicate by stripped form: if two detector modules define
    overlapping rules (``VOODA-SEC-AWS-001`` and ``AWS-001``) they
    collapse to the same picker entry.
    """
    from packages.common.scanner_branding import brand_rule_id
    from services.secret_scan.detectors.registry import get_all_rules_with_custom

    rules = await get_all_rules_with_custom(user.tenant_id, db)

    needle = (q or "").strip().lower()
    seen: set[str] = set()
    items: list[AvailableRule] = []
    for r in rules:
        # Normalize to the same key the worker compares against.
        display_id = brand_rule_id(r.rule_id) if r.rule_id else r.rule_id
        if not display_id or display_id in seen:
            continue
        seen.add(display_id)

        if needle:
            # Match against both the raw and branded id so admins searching
            # by either form still find the rule.
            hay = f"{display_id} {r.rule_id or ''} {r.title}".lower()
            if needle not in hay:
                continue
        items.append(
            AvailableRule(
                rule_id=display_id,
                name=r.title,
                category=r.secret_type or None,
                severity=r.severity or None,
                description=(r.description or None) if r.description else None,
            )
        )

    # Deterministic order so the typeahead doesn't reshuffle on each
    # keystroke.  Sort by rule_id since that's what admins remember.
    items.sort(key=lambda x: x.rule_id)
    return items


# ── Write ───────────────────────────────────────────────────────────

@router.post("", response_model=RuleOverrideResponse, status_code=201)
async def create_rule_override(
    body: RuleOverrideCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create a new rule override.  Admin role required.

    Storage normalization
    ---------------------
    The worker compares against the stripped ``brand_rule_id`` form at
    scan time (see /available-rules docstring for the full reasoning).
    We normalize the inbound scanner_rule_id the same way here so an
    admin pasting ``VOODA-SEC-AWS-001`` directly (instead of picking
    ``AWS-001`` from the typeahead) still gets an override that fires.
    """
    from packages.common.scanner_branding import brand_rule_id

    await _require_admin(db, user)

    # Verify the target lives in the caller's tenant before doing
    # anything else.  XOR enforcement on (repo, source) already happened
    # in the Pydantic model_validator, so at this point at most one is
    # set.
    if body.repository_id is not None:
        await _verify_repo_in_tenant(db, user.tenant_id, body.repository_id)
    elif body.scan_source_id is not None:
        await _verify_source_in_tenant(db, user.tenant_id, body.scan_source_id)

    normalized_rule_id = brand_rule_id(body.scanner_rule_id) if body.scanner_rule_id else body.scanner_rule_id

    # Reject duplicate active overrides up front with a friendlier 409
    # than the unique-index integrity error the DB would otherwise raise.
    # Three scope cases, each lines up with one of the partial unique
    # indexes added in migration y2z3a4b5c6d7.
    dup_q = select(RuleOverride).where(
        RuleOverride.tenant_id == user.tenant_id,
        RuleOverride.scanner_rule_id == normalized_rule_id,
        RuleOverride.is_active == True,
    )
    if body.repository_id is not None:
        dup_q = dup_q.where(RuleOverride.repository_id == body.repository_id)
    elif body.scan_source_id is not None:
        dup_q = dup_q.where(RuleOverride.scan_source_id == body.scan_source_id)
    else:
        # Org-wide: BOTH target columns must be NULL.  Important to AND
        # both — a row with scan_source_id set is NOT an org-wide dup.
        dup_q = dup_q.where(
            RuleOverride.repository_id.is_(None),
            RuleOverride.scan_source_id.is_(None),
        )
    dup = (await db.execute(dup_q)).scalar_one_or_none()
    if dup is not None:
        if body.repository_id is not None:
            scope = "this repo"
        elif body.scan_source_id is not None:
            scope = "this scan source"
        else:
            scope = "org-wide"
        raise HTTPException(
            status_code=409,
            detail=(
                f"An active override for {normalized_rule_id} already exists "
                f"for {scope}.  Edit or disable the existing rule instead."
            ),
        )

    rule = RuleOverride(
        tenant_id=user.tenant_id,
        scanner_rule_id=normalized_rule_id,
        repository_id=body.repository_id,
        scan_source_id=body.scan_source_id,
        mode=body.mode,
        reason=body.reason,
        expires_at=body.expires_at,
        created_by=user.id,
        is_active=True,
        times_blocked=0,
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)

    if rule.repository_id is not None:
        scope_label = f"repo {rule.repository_id}"
    elif rule.scan_source_id is not None:
        scope_label = f"source {rule.scan_source_id}"
    else:
        scope_label = "org-wide"
    await log_audit(
        db,
        user,
        "rule_override_created",
        "rule_override",
        rule.id,
        f"Muted {rule.scanner_rule_id} ({scope_label}) — {rule.reason[:200] if rule.reason else ''}",
        request=request,
        metadata={
            "scanner_rule_id": rule.scanner_rule_id,
            "repository_id": str(rule.repository_id) if rule.repository_id else None,
            "scan_source_id": str(rule.scan_source_id) if rule.scan_source_id else None,
            "mode": rule.mode,
            "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
        },
    )

    return await _to_response(db, rule)


@router.patch("/{rule_id}", response_model=RuleOverrideResponse)
async def update_rule_override(
    rule_id: UUID,
    body: RuleOverrideUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update an existing rule override.  Admin role required.

    Toggling is_active is the canonical way to "un-mute" a rule while
    preserving audit history.  Use DELETE only for true cleanup of a
    mistakenly-created override.
    """
    await _require_admin(db, user)

    row = await db.execute(
        select(RuleOverride).where(
            RuleOverride.id == rule_id,
            RuleOverride.tenant_id == user.tenant_id,
        )
    )
    rule = row.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule override not found")

    changes = body.model_dump(exclude_unset=True)
    if not changes:
        # No-op update — still return the row so the FE can refresh state.
        return await _to_response(db, rule)

    # Re-activating: re-check uniqueness against other active rows in
    # the SAME scope as this rule.  Mirrors the three-scope shape of
    # the create endpoint + the partial unique indexes in the DB.
    if changes.get("is_active") is True and not rule.is_active:
        dup_q = select(RuleOverride).where(
            RuleOverride.tenant_id == user.tenant_id,
            RuleOverride.scanner_rule_id == rule.scanner_rule_id,
            RuleOverride.is_active == True,
            RuleOverride.id != rule.id,
        )
        if rule.repository_id is not None:
            dup_q = dup_q.where(RuleOverride.repository_id == rule.repository_id)
        elif rule.scan_source_id is not None:
            dup_q = dup_q.where(RuleOverride.scan_source_id == rule.scan_source_id)
        else:
            # Org-wide: both target columns must be NULL on the conflict
            # candidate too.
            dup_q = dup_q.where(
                RuleOverride.repository_id.is_(None),
                RuleOverride.scan_source_id.is_(None),
            )
        if (await db.execute(dup_q)).scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Cannot re-activate: another active override already exists "
                    "for this rule + scope.  Disable that one first."
                ),
            )

    for field, value in changes.items():
        setattr(rule, field, value)

    await db.flush()
    await db.refresh(rule)

    await log_audit(
        db,
        user,
        "rule_override_updated",
        "rule_override",
        rule.id,
        f"Changed {sorted(changes.keys())} on {rule.scanner_rule_id}",
        request=request,
        metadata={
            "scanner_rule_id": rule.scanner_rule_id,
            "changes": {k: (str(v) if isinstance(v, UUID) else v) for k, v in changes.items()},
        },
    )

    return await _to_response(db, rule)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule_override(
    rule_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Hard-delete an override.  Admin role required.

    Prefer PATCH is_active=false for the routine "un-mute" path —
    DELETE is for cleaning up entries created in error.  Audit log
    is written BEFORE the delete so we keep a trail of who removed
    what.
    """
    await _require_admin(db, user)

    row = await db.execute(
        select(RuleOverride).where(
            RuleOverride.id == rule_id,
            RuleOverride.tenant_id == user.tenant_id,
        )
    )
    rule = row.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule override not found")

    await log_audit(
        db,
        user,
        "rule_override_deleted",
        "rule_override",
        rule.id,
        f"Deleted override for {rule.scanner_rule_id}",
        request=request,
        metadata={
            "scanner_rule_id": rule.scanner_rule_id,
            "repository_id": str(rule.repository_id) if rule.repository_id else None,
            "scan_source_id": str(rule.scan_source_id) if rule.scan_source_id else None,
            "times_blocked": rule.times_blocked,
        },
    )

    await db.delete(rule)
