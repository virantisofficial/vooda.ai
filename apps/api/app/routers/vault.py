# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Vault API — coverage, migration guidance and rotation write-back.

The vault connection itself is an ordinary `IntegrationConfig` row with
`category == "vault"`, created through `/api/v1/integrations`. That is
deliberate: it means vault credentials get the same Fernet encryption
at rest, the same tenant scoping and the same CRUD surface as every
other integration, instead of a parallel path that would have to
re-earn all three.

What lives here is what is specific to vaults — the three questions a
user actually has once one is connected:

  * Which of my leaked credentials are already under vault management?
  * How do I move one that is not?
  * I have rotated a credential; write the new value back.
"""

from typing import Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.finding import SecretIncident
from apps.api.app.models.integration import IntegrationConfig
from apps.api.app.models.user import User
from services.vault_integration.coverage import check_coverage
from services.vault_integration.factory import VAULT_PROVIDERS, create_vault_provider
from services.vault_integration.migration import generate_migration

logger = structlog.get_logger()
router = APIRouter()


class VaultConnectionOut(BaseModel):
    id: UUID
    name: str
    provider: str
    is_active: bool


class CoverageItem(BaseModel):
    incident_id: str
    title: str
    secret_type: Optional[str] = None
    status: str
    vault_path: Optional[str] = None
    confidence: float
    detail: str
    candidates: list[str] = Field(default_factory=list)


class CoverageSummary(BaseModel):
    provider: str
    covered: int
    uncovered: int
    unknown: int
    items: list[CoverageItem]


class MigrationRequest(BaseModel):
    incident_id: UUID
    vault_path: str = Field(..., min_length=1, max_length=512)
    variable_name: Optional[str] = None


class MigrationOut(BaseModel):
    vault_provider: str
    vault_path: str
    before_code: str
    after_code: str
    cli_commands: list[str]
    instructions: list[str]


class RotateRequest(BaseModel):
    vault_path: str = Field(..., min_length=1, max_length=512)
    new_value: str = Field(..., min_length=1)


async def _load_vault(db: AsyncSession, tenant_id, integration_id: UUID):
    """Fetch a vault integration and build its provider client.

    Config is decrypted here and never leaves this function — callers
    receive the constructed provider, not the credentials.
    """
    row = (
        await db.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.id == integration_id,
                IntegrationConfig.tenant_id == tenant_id,
            )
        )
    ).scalar_one_or_none()

    if row is None:
        raise HTTPException(status_code=404, detail="Vault connection not found")
    if row.provider not in VAULT_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Integration {integration_id} is not a vault ({row.provider})",
        )
    if not row.is_active:
        raise HTTPException(status_code=400, detail="Vault connection is disabled")

    from packages.common.encryption import decrypt_config_dict

    return row, create_vault_provider(row.provider, decrypt_config_dict(dict(row.config or {})))


@router.get("/connections", response_model=list[VaultConnectionOut])
async def list_vault_connections(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List configured vaults. Credentials are never returned."""
    rows = (
        await db.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == user.tenant_id,
                IntegrationConfig.provider.in_(VAULT_PROVIDERS),
            )
        )
    ).scalars().all()
    return [
        VaultConnectionOut(id=r.id, name=r.name, provider=r.provider, is_active=r.is_active)
        for r in rows
    ]


@router.get("/{integration_id}/coverage", response_model=CoverageSummary)
async def get_coverage(
    integration_id: UUID,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Report which leaked credentials already exist in this vault.

    Coverage is matched on name, not value — Vooda stores only a hash of
    a secret, never the secret itself, so a value comparison is not
    possible. Each result carries a confidence score, and a vault that
    cannot be listed yields `unknown` rather than a misleading
    `uncovered`.
    """
    row, vault = await _load_vault(db, user.tenant_id, integration_id)

    incidents = (
        await db.execute(
            select(SecretIncident)
            .where(SecretIncident.tenant_id == user.tenant_id)
            .limit(min(limit, 1000))
        )
    ).scalars().all()

    results = await check_coverage(
        [
            {"id": i.id, "title": i.title, "secret_type": i.secret_type}
            for i in incidents
        ],
        vault,
    )

    items = [CoverageItem(**r.__dict__ | {"status": r.status.value}) for r in results]
    return CoverageSummary(
        provider=row.provider,
        covered=sum(1 for i in items if i.status == "covered"),
        uncovered=sum(1 for i in items if i.status == "uncovered"),
        unknown=sum(1 for i in items if i.status == "unknown"),
        items=items,
    )


@router.post("/{integration_id}/migration", response_model=MigrationOut)
async def get_migration_guidance(
    integration_id: UUID,
    body: MigrationRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate the steps to move a hardcoded credential into the vault.

    Returns a before/after code diff and the provider's CLI commands.
    Nothing is executed and no secret value is transmitted — the user
    supplies the value themselves when they run the commands.
    """
    row, _ = await _load_vault(db, user.tenant_id, integration_id)

    incident = (
        await db.execute(
            select(SecretIncident).where(
                SecretIncident.id == body.incident_id,
                SecretIncident.tenant_id == user.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    script = generate_migration(
        secret_type=incident.secret_type or "generic",
        file_path=(incident.title or "").split(":")[0] or "unknown",
        variable_name=body.variable_name or "SECRET_VALUE",
        vault_provider=row.provider,
        vault_path=body.vault_path,
    )
    return MigrationOut(
        vault_provider=row.provider,
        vault_path=body.vault_path,
        before_code=script.before_code,
        after_code=script.after_code,
        cli_commands=script.cli_commands,
        instructions=script.instructions,
    )


@router.post("/{integration_id}/rotate", status_code=200)
async def rotate_secret(
    integration_id: UUID,
    body: RotateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Write a rotated credential value into the vault.

    This writes only — it does not rotate the credential at the provider
    and does not record the value. Rotating the upstream credential
    remains the user's action; this closes the loop by getting the new
    value into the vault the application reads from.
    """
    _, vault = await _load_vault(db, user.tenant_id, integration_id)

    ok = await vault.rotate_secret(body.vault_path, body.new_value)
    if not ok:
        raise HTTPException(
            status_code=502,
            detail="Vault rejected the write — check the path and the token's write permission",
        )
    # Log the path, never the value.
    logger.info(
        "vault_secret_written",
        tenant_id=str(user.tenant_id),
        integration_id=str(integration_id),
        vault_path=body.vault_path,
    )
    return {"status": "written", "vault_path": body.vault_path}
