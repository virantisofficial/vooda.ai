# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Access Control Helper — resolves what repositories a user can see
based on their access grants (org, BU, or project level).

Usage in routers:
    repos = await get_accessible_repositories(db, user)
    findings = await get_accessible_findings(db, user)
"""

from uuid import UUID
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.user import User, UserRole, RoleType
from apps.api.app.models.repository import Repository
from apps.api.app.models.access import UserAccessGrant, AccessLevel, AccessRole


async def is_org_admin(db: AsyncSession, user: User) -> bool:
    """Check if user has admin role (org-level access to everything)."""
    result = await db.execute(
        select(UserRole).where(UserRole.user_id == user.id, UserRole.role == RoleType.ADMIN)
    )
    if result.scalar_one_or_none():
        return True

    # Also check for organization-level access grant with ADMIN role specifically
    org_grant = await db.execute(
        select(UserAccessGrant).where(
            UserAccessGrant.user_id == user.id,
            UserAccessGrant.tenant_id == user.tenant_id,
            UserAccessGrant.access_level == AccessLevel.ORGANIZATION,
            UserAccessGrant.role == AccessRole.ADMIN,
        ).limit(1)
    )
    return org_grant.scalar_one_or_none() is not None


async def has_org_level_access(db: AsyncSession, user: User) -> bool:
    """Check if user has ANY org-level grant (admin, member, or viewer)."""
    org_grant = await db.execute(
        select(UserAccessGrant).where(
            UserAccessGrant.user_id == user.id,
            UserAccessGrant.tenant_id == user.tenant_id,
            UserAccessGrant.access_level == AccessLevel.ORGANIZATION,
        ).limit(1)
    )
    return org_grant.scalar_one_or_none() is not None


async def get_accessible_repo_ids(db: AsyncSession, user: User) -> list[UUID] | None:
    """
    Get list of repository IDs the user can access.
    Returns None if user has org-level access (meaning ALL repos).
    Returns list of IDs if user has BU or project-level access.
    """
    # Admin or any org-level user sees everything
    if await has_org_level_access(db, user):
        return None  # None = no filter needed, see everything

    # Also check legacy admin role
    if await is_org_admin(db, user):
        return None

    # Get all access grants for this user
    grants_r = await db.execute(
        select(UserAccessGrant).where(
            UserAccessGrant.user_id == user.id,
            UserAccessGrant.tenant_id == user.tenant_id,
        )
    )
    grants = grants_r.scalars().all()

    if not grants:
        # No grants at all — for backward compatibility, return None (see everything)
        # This handles existing users who don't have grants yet
        return None

    repo_ids = set()
    bu_ids = set()

    for grant in grants:
        if grant.access_level == AccessLevel.ORGANIZATION:
            return None  # Org level = see everything
        elif grant.access_level == AccessLevel.BUSINESS_UNIT and grant.business_unit_id:
            bu_ids.add(grant.business_unit_id)
        elif grant.access_level == AccessLevel.PROJECT and grant.repository_id:
            repo_ids.add(grant.repository_id)

    # Get repos from BU grants
    if bu_ids:
        bu_repos_r = await db.execute(
            select(Repository.id).where(
                Repository.tenant_id == user.tenant_id,
                Repository.business_unit_id.in_(list(bu_ids)),
                Repository.is_active == True,
            )
        )
        for row in bu_repos_r.all():
            repo_ids.add(row[0])

    return list(repo_ids) if repo_ids else []


async def filter_repositories_query(db: AsyncSession, user: User, base_query):
    """
    Add access control filter to a repository query.
    Returns the modified query.
    """
    accessible = await get_accessible_repo_ids(db, user)
    if accessible is None:
        # Org-level or no grants (backward compat) — no additional filter
        return base_query
    else:
        return base_query.where(Repository.id.in_(accessible))


async def can_access_repository(db: AsyncSession, user: User, repo_id: UUID) -> bool:
    """Check if user can access a specific repository."""
    accessible = await get_accessible_repo_ids(db, user)
    if accessible is None:
        return True  # Org-level access
    return repo_id in accessible


async def can_access_finding(db: AsyncSession, user: User, finding) -> bool:
    """Check if user can access a finding (through its repository)."""
    return await can_access_repository(db, user, finding.repository_id)
