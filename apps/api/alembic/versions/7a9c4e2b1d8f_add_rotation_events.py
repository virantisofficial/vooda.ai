# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add_rotation_events

Captures credential rotation telemetry — one row per ``active -> inactive``
transition detected by the verifier, feeding MTTR metrics and compliance
audit trails.

Revision ID: 7a9c4e2b1d8f
Revises: 25907caaf14c
Create Date: 2026-04-18 17:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "7a9c4e2b1d8f"
down_revision = "25907caaf14c"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    has_table = "credential_rotation_events" in inspector.get_table_names()
    if has_table:
        # Initial-schema migration already created this table from
        # the SQLAlchemy model. Fall through to the (idempotent)
        # index creates below — composite indexes may not be on the
        # model and need to be ensured separately.
        _ensure_rotation_event_indexes()
        return
    op.create_table(
        "credential_rotation_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("normalized_findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("repository_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("secret_hash", sa.String(128), nullable=False),
        sa.Column("first_seen_active_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("time_to_rotation_s", sa.Integer(), nullable=False),
        sa.Column("detected_via", sa.String(16), nullable=False, server_default="live"),
        sa.Column(
            "extra_data",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    _ensure_rotation_event_indexes()


def _ensure_rotation_event_indexes() -> None:
    """Create indexes idempotently (CREATE INDEX IF NOT EXISTS).

    Model-derived indexes from `index=True` columns may already exist
    after the initial-schema migration. Composite indexes (multi-
    column) are usually NOT on the model and need to be explicit
    here. Using raw SQL with IF NOT EXISTS keeps both paths safe.
    """
    op.execute("CREATE INDEX IF NOT EXISTS ix_credential_rotation_events_tenant_id ON credential_rotation_events (tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_credential_rotation_events_finding_id ON credential_rotation_events (finding_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_credential_rotation_events_repository_id ON credential_rotation_events (repository_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_credential_rotation_events_provider ON credential_rotation_events (provider)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_credential_rotation_events_secret_hash ON credential_rotation_events (secret_hash)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_rotation_events_tenant_rotated_at ON credential_rotation_events (tenant_id, rotated_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_rotation_events_tenant_provider ON credential_rotation_events (tenant_id, provider)")


def downgrade():
    op.drop_index("ix_rotation_events_tenant_provider", table_name="credential_rotation_events")
    op.drop_index("ix_rotation_events_tenant_rotated_at", table_name="credential_rotation_events")
    op.drop_index("ix_credential_rotation_events_secret_hash", table_name="credential_rotation_events")
    op.drop_index("ix_credential_rotation_events_provider", table_name="credential_rotation_events")
    op.drop_index("ix_credential_rotation_events_repository_id", table_name="credential_rotation_events")
    op.drop_index("ix_credential_rotation_events_finding_id", table_name="credential_rotation_events")
    op.drop_index("ix_credential_rotation_events_tenant_id", table_name="credential_rotation_events")
    op.drop_table("credential_rotation_events")
