# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
User Management API — CRUD, invite, role assignment, activate/deactivate.
"""

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user, hash_password
from apps.api.app.core.password_policy import password_policy_error, PASSWORD_HISTORY_DEPTH
from apps.api.app.models.user import User, UserRole, RoleType

router = APIRouter()


# ── Schemas ───────────────────────────────────────────

class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    role: str = "viewer"


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None


class UserListResponse(BaseModel):
    id: UUID
    full_name: str
    email: str
    is_active: bool
    roles: list[str]
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


# ── Helpers ───────────────────────────────────────────

async def _user_to_response(db: AsyncSession, user: User) -> dict:
    roles_result = await db.execute(
        select(UserRole).where(UserRole.user_id == user.id)
    )
    roles = [r.role.value for r in roles_result.scalars().all()]
    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "is_active": user.is_active,
        "roles": roles,
        "created_at": str(user.created_at),
        "updated_at": str(user.updated_at),
    }


def _check_admin(current_user: User, current_roles: list[str]):
    if "admin" not in current_roles:
        raise HTTPException(status_code=403, detail="Admin access required")


# ── Endpoints ─────────────────────────────────────────

@router.get("", response_model=list[UserListResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(User)
        .where(User.tenant_id == user.tenant_id)
        .order_by(User.created_at)
    )
    users = result.scalars().all()
    responses = []
    for u in users:
        responses.append(await _user_to_response(db, u))
    return responses


@router.post("", response_model=UserListResponse, status_code=201)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Check admin
    roles_result = await db.execute(select(UserRole).where(UserRole.user_id == current_user.id))
    current_roles = [r.role.value for r in roles_result.scalars().all()]
    _check_admin(current_user, current_roles)

    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Validate role
    try:
        role_enum = RoleType(body.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {body.role}. Valid: {[r.value for r in RoleType]}")

    # Enforce password strength on the initial password too.
    policy_error = password_policy_error(body.password)
    if policy_error:
        raise HTTPException(status_code=400, detail=policy_error)

    new_user = User(
        tenant_id=current_user.tenant_id,
        full_name=body.full_name,
        email=body.email,
        hashed_password=hash_password(body.password),
        is_active=True,
    )
    db.add(new_user)
    await db.flush()

    user_role = UserRole(user_id=new_user.id, role=role_enum)
    db.add(user_role)
    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(db, current_user, "user_created", "user", new_user.id, f"Created {body.email} with role {body.role}")

    return await _user_to_response(db, new_user)


@router.get("/{user_id}", response_model=UserListResponse)
async def get_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id)
    )
    u = result.scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return await _user_to_response(db, u)


@router.put("/{user_id}", response_model=UserListResponse)
async def update_user(
    user_id: UUID,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Admin check (or self-update for name only)
    roles_result = await db.execute(select(UserRole).where(UserRole.user_id == current_user.id))
    current_roles = [r.role.value for r in roles_result.scalars().all()]
    is_self = str(current_user.id) == str(user_id)

    if not is_self:
        _check_admin(current_user, current_roles)

    result = await db.execute(
        select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id)
    )
    u = result.scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    if body.full_name is not None:
        u.full_name = body.full_name
    if body.email is not None:
        # Check uniqueness
        dup = await db.execute(select(User).where(User.email == body.email, User.id != user_id))
        if dup.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Email already in use")
        u.email = body.email
    if body.is_active is not None and not is_self:
        u.is_active = body.is_active
    if body.password is not None:
        # Self-service password changes must prove knowledge of the current
        # password — route them to POST /auth/change-password. This PUT
        # path only sets a password as an administrative reset of *another*
        # user (admin already enforced above via the not-is_self check).
        if is_self:
            raise HTTPException(
                status_code=400,
                detail="Use POST /api/v1/auth/change-password to change your own password — it requires your current password.",
            )
        policy_error = password_policy_error(body.password)
        if policy_error:
            raise HTTPException(status_code=400, detail=policy_error)
        # Record the outgoing hash so a later self-service change can't
        # reuse an administratively-set password either.
        history = list(u.password_history or [])
        history.append(u.hashed_password)
        u.password_history = history[-PASSWORD_HISTORY_DEPTH:]
        u.hashed_password = hash_password(body.password)

    # Role change (admin only, not self)
    if body.role is not None and not is_self:
        _check_admin(current_user, current_roles)
        try:
            role_enum = RoleType(body.role)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid role: {body.role}")

        # Delete existing roles and set new one
        await db.execute(delete(UserRole).where(UserRole.user_id == user_id))
        await db.flush()
        new_role = UserRole(user_id=user_id, role=role_enum)
        db.add(new_role)

    await db.flush()
    await db.refresh(u)

    from apps.api.app.core.audit import log_audit
    changes = []
    if body.full_name is not None: changes.append("name")
    if body.email is not None: changes.append("email")
    if body.password is not None: changes.append("password")
    if body.role is not None: changes.append(f"role→{body.role}")
    await log_audit(db, current_user, "user_updated", "user", user_id, f"Updated {u.email}: {', '.join(changes)}")

    return await _user_to_response(db, u)


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    roles_result = await db.execute(select(UserRole).where(UserRole.user_id == current_user.id))
    current_roles = [r.role.value for r in roles_result.scalars().all()]
    _check_admin(current_user, current_roles)

    if str(current_user.id) == str(user_id):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    result = await db.execute(
        select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id)
    )
    u = result.scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    # Soft delete — deactivate
    u.is_active = False
    await db.flush()

    from apps.api.app.core.audit import log_audit
    await log_audit(db, current_user, "user_deactivated", "user", user_id, f"Deactivated {u.email}")


@router.post("/{user_id}/activate", response_model=UserListResponse)
async def activate_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    roles_result = await db.execute(select(UserRole).where(UserRole.user_id == current_user.id))
    current_roles = [r.role.value for r in roles_result.scalars().all()]
    _check_admin(current_user, current_roles)

    result = await db.execute(
        select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id)
    )
    u = result.scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    u.is_active = True
    await db.flush()
    await db.refresh(u)

    from apps.api.app.core.audit import log_audit
    await log_audit(db, current_user, "user_activated", "user", user_id, f"Reactivated {u.email}")

    return await _user_to_response(db, u)
