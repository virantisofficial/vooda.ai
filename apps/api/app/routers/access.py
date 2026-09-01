# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Access Control API — Business Units and User Access Grants.
"""

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from apps.api.app.schemas.strict import StrictModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.access import BusinessUnit, UserAccessGrant, AccessLevel, AccessRole

router = APIRouter()


async def _require_org_admin(db: AsyncSession, user) -> None:
    """Require org-admin role. Raises 403 if not admin."""
    from apps.api.app.core.access_control import is_org_admin
    if not await is_org_admin(db, user):
        raise HTTPException(status_code=403, detail="Admin access required")


# ── Schemas ───────────────────────────────────────────

class BUCreate(StrictModel):
    name: str
    description: Optional[str] = None
    parent_id: Optional[UUID] = None


class BUResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    parent_id: Optional[UUID]
    is_active: bool
    project_count: int = 0
    member_count: int = 0

    model_config = {"from_attributes": True}


class AccessGrantCreate(StrictModel):
    user_id: UUID
    access_level: str  # "organization", "business_unit", "project"
    business_unit_id: Optional[UUID] = None
    repository_id: Optional[UUID] = None
    role: str = "member"  # "admin", "member", "viewer"


class AccessGrantResponse(BaseModel):
    id: UUID
    user_id: UUID
    access_level: str
    business_unit_id: Optional[UUID]
    repository_id: Optional[UUID]
    role: str
    user_name: Optional[str] = None
    scope_name: Optional[str] = None

    model_config = {"from_attributes": True}


# ── Business Units ────────────────────────────────────

@router.get("/business-units")
async def list_business_units(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _require_org_admin(db, user)
    from sqlalchemy import func
    from apps.api.app.models.repository import Repository

    result = await db.execute(
        select(BusinessUnit).where(
            BusinessUnit.tenant_id == user.tenant_id, BusinessUnit.is_active == True
        ).order_by(BusinessUnit.name)
    )
    bus = result.scalars().all()

    response = []
    for bu in bus:
        # Count projects
        proj_count = await db.execute(
            select(func.count(Repository.id)).where(Repository.business_unit_id == bu.id)
        )
        # Count members
        member_count = await db.execute(
            select(func.count(UserAccessGrant.id)).where(
                UserAccessGrant.business_unit_id == bu.id,
                UserAccessGrant.access_level == AccessLevel.BUSINESS_UNIT,
            )
        )
        response.append({
            "id": str(bu.id), "name": bu.name, "description": bu.description,
            "parent_id": str(bu.parent_id) if bu.parent_id else None,
            "is_active": bu.is_active,
            "project_count": proj_count.scalar() or 0,
            "member_count": member_count.scalar() or 0,
        })

    return response


@router.post("/business-units", status_code=201)
async def create_business_unit(
    body: BUCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _require_org_admin(db, user)
    bu = BusinessUnit(
        tenant_id=user.tenant_id,
        name=body.name,
        description=body.description,
        parent_id=body.parent_id,
    )
    db.add(bu)
    await db.flush()
    await db.refresh(bu)

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "bu_created", "business_unit", bu.id, f"Created BU: {bu.name}")

    return {"id": str(bu.id), "name": bu.name, "description": bu.description}


@router.put("/business-units/{bu_id}")
async def update_business_unit(
    bu_id: UUID,
    body: BUCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _require_org_admin(db, user)
    result = await db.execute(
        select(BusinessUnit).where(BusinessUnit.id == bu_id, BusinessUnit.tenant_id == user.tenant_id)
    )
    bu = result.scalar_one_or_none()
    if not bu:
        raise HTTPException(status_code=404, detail="Business unit not found")
    bu.name = body.name
    bu.description = body.description
    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "bu_updated", "business_unit", bu_id, f"Updated BU: {bu.name}")

    return {"id": str(bu.id), "name": bu.name}


@router.delete("/business-units/{bu_id}", status_code=204)
async def delete_business_unit(
    bu_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _require_org_admin(db, user)
    result = await db.execute(
        select(BusinessUnit).where(BusinessUnit.id == bu_id, BusinessUnit.tenant_id == user.tenant_id)
    )
    bu = result.scalar_one_or_none()
    if not bu:
        raise HTTPException(status_code=404, detail="Business unit not found")
    bu.is_active = False
    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "bu_deleted", "business_unit", bu_id, f"Deleted BU: {bu.name}")


# ── Access Grants ─────────────────────────────────────

@router.get("/grants")
async def list_access_grants(
    user_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _require_org_admin(db, user)
    query = select(UserAccessGrant).where(UserAccessGrant.tenant_id == user.tenant_id)
    if user_id:
        query = query.where(UserAccessGrant.user_id == user_id)

    result = await db.execute(query.order_by(UserAccessGrant.created_at.desc()))
    grants = result.scalars().all()

    # Resolve user names and scope names
    from apps.api.app.models.user import User as UserModel
    from apps.api.app.models.repository import Repository

    response = []
    for g in grants:
        # Get user name
        user_r = await db.execute(select(UserModel.full_name).where(UserModel.id == g.user_id))
        user_name = user_r.scalar_one_or_none() or "Unknown"

        # Get scope name
        scope_name = "Organization"
        if g.access_level == AccessLevel.BUSINESS_UNIT and g.business_unit_id:
            bu_r = await db.execute(select(BusinessUnit.name).where(BusinessUnit.id == g.business_unit_id))
            scope_name = f"BU: {bu_r.scalar_one_or_none() or 'Unknown'}"
        elif g.access_level == AccessLevel.PROJECT and g.repository_id:
            repo_r = await db.execute(select(Repository.name).where(Repository.id == g.repository_id))
            scope_name = f"Project: {repo_r.scalar_one_or_none() or 'Unknown'}"

        response.append({
            "id": str(g.id),
            "user_id": str(g.user_id),
            "user_name": user_name,
            "access_level": g.access_level.value,
            "business_unit_id": str(g.business_unit_id) if g.business_unit_id else None,
            "repository_id": str(g.repository_id) if g.repository_id else None,
            "role": g.role.value,
            "scope_name": scope_name,
        })

    return response


@router.post("/grants", status_code=201)
async def create_access_grant(
    body: AccessGrantCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _require_org_admin(db, user)
    # Validate
    if body.access_level == "business_unit" and not body.business_unit_id:
        raise HTTPException(status_code=400, detail="business_unit_id required for BU-level access")
    if body.access_level == "project" and not body.repository_id:
        raise HTTPException(status_code=400, detail="repository_id required for project-level access")

    grant = UserAccessGrant(
        tenant_id=user.tenant_id,
        user_id=body.user_id,
        access_level=AccessLevel(body.access_level),
        business_unit_id=body.business_unit_id,
        repository_id=body.repository_id,
        role=AccessRole(body.role),
    )
    db.add(grant)
    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "grant_created", "access_grant", grant.id, f"{body.access_level} {body.role} for user {body.user_id}")

    return {"id": str(grant.id), "status": "created"}


@router.delete("/grants/{grant_id}", status_code=204)
async def delete_access_grant(
    grant_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _require_org_admin(db, user)
    result = await db.execute(
        select(UserAccessGrant).where(
            UserAccessGrant.id == grant_id, UserAccessGrant.tenant_id == user.tenant_id
        )
    )
    grant = result.scalar_one_or_none()
    if not grant:
        raise HTTPException(status_code=404, detail="Grant not found")
    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "grant_revoked", "access_grant", grant_id, f"Revoked {grant.access_level.value} grant")

    await db.delete(grant)
    await db.flush()


# ── My Access ─────────────────────────────────────────

@router.get("/my-access")
async def get_my_access(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get current user's access grants."""
    from apps.api.app.core.access_control import is_org_admin, get_accessible_repo_ids

    admin = await is_org_admin(db, user)
    accessible = await get_accessible_repo_ids(db, user)

    return {
        "user_id": str(user.id),
        "is_org_admin": admin,
        "has_full_access": accessible is None,
        "accessible_repo_count": "all" if accessible is None else len(accessible),
    }
