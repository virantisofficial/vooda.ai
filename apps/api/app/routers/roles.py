# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Roles & Permissions API — CRUD for role definitions with permission management.
Seeds built-in roles on first access per tenant.
"""

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User, UserRole
from apps.api.app.models.role_definition import RoleDefinition

router = APIRouter()


# ── All available permissions in the system ────────────

ALL_PERMISSIONS = [
    {"key": "manage_users", "label": "Manage Users", "group": "Administration", "description": "Create, edit, deactivate users and assign roles"},
    {"key": "manage_settings", "label": "Manage Settings", "group": "Administration", "description": "Configure platform settings, AI models, SSO"},
    {"key": "manage_integrations", "label": "Manage Integrations", "group": "Administration", "description": "Connect and configure external scanner integrations"},
    {"key": "manage_policies", "label": "Manage Policies", "group": "Security", "description": "Create and edit security policies and automation rules"},
    {"key": "view_findings", "label": "View Findings", "group": "Security", "description": "View scan results, findings, and evidence"},
    {"key": "triage_findings", "label": "Triage Findings", "group": "Security", "description": "Mark findings as true/false positive, accept risk"},
    {"key": "approve_remediation", "label": "Approve Remediation", "group": "Security", "description": "Approve or reject AI-generated code patches"},
    {"key": "run_scans", "label": "Run Scans", "group": "Operations", "description": "Trigger scans and import scanner findings"},
    {"key": "manage_repositories", "label": "Manage Repositories", "group": "Operations", "description": "Add, edit, and delete repositories"},
    {"key": "view_audit", "label": "View Audit Logs", "group": "Compliance", "description": "View audit trail and compliance reports"},
    {"key": "export_reports", "label": "Export Reports", "group": "Reporting", "description": "Export findings, metrics, and compliance reports"},
    {"key": "manage_api_keys", "label": "Manage API Keys", "group": "Administration", "description": "Generate and revoke platform API keys"},
]

# ── Built-in role templates ────────────────────────────

BUILTIN_ROLES = [
    {
        "name": "Admin", "slug": "admin", "color": "red",
        "description": "Full platform access. Manage users, settings, integrations, and all security operations.",
        "permissions": [p["key"] for p in ALL_PERMISSIONS],
    },
    {
        "name": "Security Engineer", "slug": "security_engineer", "color": "purple",
        "description": "Full access to security operations. Can triage, remediate, and manage scan configurations.",
        "permissions": ["view_findings", "triage_findings", "approve_remediation", "run_scans", "manage_integrations", "manage_policies", "manage_repositories", "export_reports"],
    },
    {
        "name": "Developer", "slug": "developer", "color": "cyan",
        "description": "Can view findings for assigned repositories, request remediations, and mark false positives.",
        "permissions": ["view_findings", "triage_findings", "run_scans", "manage_repositories", "export_reports"],
    },
    {
        "name": "Viewer", "slug": "viewer", "color": "slate",
        "description": "Read-only access. Can view findings, reports, and dashboards but cannot take actions.",
        "permissions": ["view_findings", "export_reports"],
    },
]


# ── Schemas ───────────────────────────────────────────

class RoleCreate(BaseModel):
    name: str = Field(..., examples=["Security Reviewer"])
    # slug is the stable machine-readable identifier — name can be
    # renamed without breaking grants/integrations that reference the
    # role.  Must be unique within the tenant.
    slug: str = Field(
        ..., examples=["security_reviewer"],
        description="Stable machine-readable identifier (a-z, 0-9, _).",
    )
    description: Optional[str] = Field(
        None, examples=["Reads + triages findings, can't change settings."],
    )
    color: str = Field("slate", examples=["red", "emerald", "slate"])
    permissions: list[str] = Field(
        default_factory=list,
        examples=[["findings:read", "findings:triage"]],
        description="See GET /roles/permissions for the catalog.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "name": "Security Reviewer",
                "slug": "security_reviewer",
                "description": "Reads + triages findings; no settings access.",
                "color": "emerald",
                "permissions": ["findings:read", "findings:triage"],
            }],
        },
    }


class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    color: Optional[str] = None
    permissions: Optional[list[str]] = None


class RoleResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    description: Optional[str]
    color: str
    permissions: list[str]
    is_builtin: bool
    is_active: bool
    user_count: int = 0
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


# ── Helpers ───────────────────────────────────────────

async def _seed_builtins(db: AsyncSession, tenant_id) -> None:
    """Seed built-in roles if they don't exist for this tenant."""
    existing = await db.execute(
        select(RoleDefinition).where(RoleDefinition.tenant_id == tenant_id)
    )
    if existing.scalars().first():
        return  # Already seeded

    for role in BUILTIN_ROLES:
        r = RoleDefinition(
            tenant_id=tenant_id,
            name=role["name"],
            slug=role["slug"],
            description=role["description"],
            color=role["color"],
            permissions=role["permissions"],
            is_builtin=True,
        )
        db.add(r)
    await db.flush()


async def _count_users_per_role(db: AsyncSession, tenant_id) -> dict[str, int]:
    """Count users per role slug."""
    from sqlalchemy import func
    result = await db.execute(
        select(UserRole.role, func.count(UserRole.id))
        .join(User, User.id == UserRole.user_id)
        .where(User.tenant_id == tenant_id, User.is_active == True)
        .group_by(UserRole.role)
    )
    return {str(role): count for role, count in result.all()}


async def _to_response(role: RoleDefinition, user_counts: dict) -> dict:
    return {
        "id": role.id,
        "name": role.name,
        "slug": role.slug,
        "description": role.description,
        "color": role.color,
        "permissions": role.permissions or [],
        "is_builtin": role.is_builtin,
        "is_active": role.is_active,
        "user_count": user_counts.get(role.slug, 0),
        "created_at": str(role.created_at),
        "updated_at": str(role.updated_at),
    }


# ── Endpoints ─────────────────────────────────────────

@router.get("/permissions")
async def list_permissions():
    """Return all available permissions grouped by category."""
    groups: dict[str, list] = {}
    for p in ALL_PERMISSIONS:
        groups.setdefault(p["group"], []).append(p)
    return {"permissions": ALL_PERMISSIONS, "groups": groups}


@router.get("", response_model=list[RoleResponse])
async def list_roles(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _seed_builtins(db, user.tenant_id)
    result = await db.execute(
        select(RoleDefinition)
        .where(RoleDefinition.tenant_id == user.tenant_id, RoleDefinition.is_active == True)
        .order_by(RoleDefinition.is_builtin.desc(), RoleDefinition.created_at)
    )
    roles = result.scalars().all()
    user_counts = await _count_users_per_role(db, user.tenant_id)
    return [await _to_response(r, user_counts) for r in roles]


@router.post("", response_model=RoleResponse, status_code=201)
async def create_role(
    body: RoleCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Validate permissions
    valid_keys = {p["key"] for p in ALL_PERMISSIONS}
    invalid = [p for p in body.permissions if p not in valid_keys]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid permissions: {invalid}")

    # Check slug uniqueness
    existing = await db.execute(
        select(RoleDefinition).where(
            RoleDefinition.tenant_id == user.tenant_id,
            RoleDefinition.slug == body.slug,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"Role slug '{body.slug}' already exists")

    role = RoleDefinition(
        tenant_id=user.tenant_id,
        name=body.name,
        slug=body.slug,
        description=body.description,
        color=body.color,
        permissions=body.permissions,
        is_builtin=False,
    )
    db.add(role)
    await db.flush()
    await db.refresh(role)

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "role_created", "role", role.id, f"Created role: {body.name} ({body.slug})")

    user_counts = await _count_users_per_role(db, user.tenant_id)
    return await _to_response(role, user_counts)


@router.put("/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: UUID,
    body: RoleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(RoleDefinition).where(
            RoleDefinition.id == role_id,
            RoleDefinition.tenant_id == user.tenant_id,
        )
    )
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if body.permissions is not None:
        valid_keys = {p["key"] for p in ALL_PERMISSIONS}
        invalid = [p for p in body.permissions if p not in valid_keys]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Invalid permissions: {invalid}")
        role.permissions = body.permissions

    if body.name is not None:
        role.name = body.name
    if body.description is not None:
        role.description = body.description
    if body.color is not None:
        role.color = body.color

    await db.flush()
    await db.refresh(role)

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "role_updated", "role", role_id, f"Updated role: {role.name}")

    user_counts = await _count_users_per_role(db, user.tenant_id)
    return await _to_response(role, user_counts)


@router.delete("/{role_id}", status_code=204)
async def delete_role(
    role_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(RoleDefinition).where(
            RoleDefinition.id == role_id,
            RoleDefinition.tenant_id == user.tenant_id,
        )
    )
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.is_builtin:
        raise HTTPException(status_code=400, detail="Cannot delete built-in roles")

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "role_deleted", "role", role_id, f"Deleted role: {role.name}")

    role.is_active = False
    await db.flush()


@router.post("/{role_id}/reset", response_model=RoleResponse)
async def reset_builtin_role(
    role_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Reset a built-in role to its default permissions."""
    result = await db.execute(
        select(RoleDefinition).where(
            RoleDefinition.id == role_id,
            RoleDefinition.tenant_id == user.tenant_id,
        )
    )
    role = result.scalar_one_or_none()
    if not role or not role.is_builtin:
        raise HTTPException(status_code=400, detail="Can only reset built-in roles")

    default = next((r for r in BUILTIN_ROLES if r["slug"] == role.slug), None)
    if default:
        role.permissions = default["permissions"]
        role.description = default["description"]

    await db.flush()
    await db.refresh(role)

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "role_reset", "role", role_id, f"Reset role: {role.name} to defaults")

    user_counts = await _count_users_per_role(db, user.tenant_id)
    return await _to_response(role, user_counts)
