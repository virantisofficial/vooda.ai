# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.saved_view import SavedView

router = APIRouter()


class SavedViewCreate(BaseModel):
    name: str
    filters: dict
    view_type: str = "findings"


class SavedViewResponse(BaseModel):
    id: UUID
    name: str
    filters: dict
    view_type: str
    is_default: str
    created_at: str

    model_config = {"from_attributes": True}


@router.get("")
async def list_saved_views(
    view_type: str = "findings",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(SavedView).where(
            SavedView.user_id == user.id,
            SavedView.view_type == view_type,
        ).order_by(SavedView.created_at.desc())
    )
    views = result.scalars().all()
    return [{"id": str(v.id), "name": v.name, "filters": v.filters, "view_type": v.view_type, "is_default": v.is_default, "created_at": str(v.created_at)} for v in views]


@router.post("", status_code=201)
async def create_saved_view(
    body: SavedViewCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    view = SavedView(
        tenant_id=user.tenant_id,
        user_id=user.id,
        name=body.name,
        filters=body.filters,
        view_type=body.view_type,
    )
    db.add(view)
    await db.flush()
    await db.refresh(view)
    return {"id": str(view.id), "name": view.name, "filters": view.filters}


@router.delete("/{view_id}")
async def delete_saved_view(
    view_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(SavedView).where(SavedView.id == view_id, SavedView.user_id == user.id)
    )
    view = result.scalar_one_or_none()
    if not view:
        raise HTTPException(status_code=404, detail="View not found")
    await db.delete(view)
    await db.flush()
    return {"status": "deleted"}
