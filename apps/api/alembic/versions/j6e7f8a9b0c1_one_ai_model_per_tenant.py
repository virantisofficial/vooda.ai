# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""one AI model per tenant; drop is_primary

Revision ID: j6e7f8a9b0c1
Revises: i5d6e7f8a9b0
Create Date: 2026-09-15 18:00:00.000000

Vooda runs triage on a single AI model per tenant, so the primary flag
and the list of models go away:

- Tenants with several models keep the one triage was actually using —
  the same pick get_provider_for_task made: active first, then assigned
  to triage, then primary, then most recently updated. The others are
  deleted (nothing references ai_model_configs by foreign key).
- The kept model is assigned to triage if it was not.
- ``is_primary`` is dropped and ``tenant_id`` becomes unique.

Fresh installs already get this shape from the model (create_all), so
each step checks the current schema first. Downgrade restores the
column (every remaining model becomes its tenant's primary) and drops
the constraint; deleted models are not recoverable.
"""
from alembic import op
import sqlalchemy as sa


revision = "j6e7f8a9b0c1"
down_revision = "i5d6e7f8a9b0"
branch_labels = None
depends_on = None

_UQ = "uq_ai_model_configs_tenant_id"


def _columns(bind):
    return {c["name"] for c in sa.inspect(bind).get_columns("ai_model_configs")}


def _has_unique(bind):
    return any(u["name"] == _UQ for u in sa.inspect(bind).get_unique_constraints("ai_model_configs"))


def upgrade() -> None:
    bind = op.get_bind()
    primary_order = "is_primary DESC NULLS LAST, " if "is_primary" in _columns(bind) else ""
    bind.execute(sa.text(f"""
        DELETE FROM ai_model_configs a
         USING (
            SELECT id, row_number() OVER (
                PARTITION BY tenant_id
                ORDER BY COALESCE(is_active, true) DESC,
                         COALESCE(tasks, '[]'::jsonb) @> '["triage"]'::jsonb DESC,
                         {primary_order}updated_at DESC, created_at DESC
            ) AS rn
            FROM ai_model_configs
         ) ranked
         WHERE a.id = ranked.id AND ranked.rn > 1
    """))
    bind.execute(sa.text("""
        UPDATE ai_model_configs SET tasks = '["triage"]'::jsonb
        WHERE NOT COALESCE(tasks, '[]'::jsonb) @> '["triage"]'::jsonb
    """))
    if "is_primary" in _columns(bind):
        op.drop_column("ai_model_configs", "is_primary")
    if not _has_unique(bind):
        op.create_unique_constraint(_UQ, "ai_model_configs", ["tenant_id"])


def downgrade() -> None:
    bind = op.get_bind()
    if _has_unique(bind):
        op.drop_constraint(_UQ, "ai_model_configs", type_="unique")
    if "is_primary" not in _columns(bind):
        op.add_column(
            "ai_model_configs",
            sa.Column("is_primary", sa.Boolean(), nullable=True, server_default=sa.false()),
        )
        op.execute("UPDATE ai_model_configs SET is_primary = true")
