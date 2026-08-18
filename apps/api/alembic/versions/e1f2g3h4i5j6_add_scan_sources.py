# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Add scan_sources table and scan_source_id to findings/scan_jobs

Revision ID: e1f2g3h4i5j6
Revises: d8e9f0a1b2c3
Create Date: 2026-04-11 14:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "e1f2g3h4i5j6"
down_revision = "d8e9f0a1b2c3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    has_scan_sources = "scan_sources" in inspector.get_table_names()

    # If the initial-schema migration already created the table +
    # the related FK columns from the model, only ensure that the
    # scan_jobs and normalized_findings columns + nullable changes
    # are in place. Use ADD COLUMN IF NOT EXISTS for safety.
    if has_scan_sources:
        op.execute("ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS scan_source_id UUID")
        op.execute("ALTER TABLE normalized_findings ADD COLUMN IF NOT EXISTS scan_source_id UUID")
        op.execute("""
            DO $$ BEGIN
                ALTER TABLE scan_jobs
                    ADD CONSTRAINT fk_scan_jobs_scan_source
                    FOREIGN KEY (scan_source_id) REFERENCES scan_sources (id);
            EXCEPTION
                WHEN duplicate_object THEN NULL;
                WHEN duplicate_table THEN NULL;
            END $$;
        """)
        op.execute("""
            DO $$ BEGIN
                ALTER TABLE normalized_findings
                    ADD CONSTRAINT fk_findings_scan_source
                    FOREIGN KEY (scan_source_id) REFERENCES scan_sources (id);
            EXCEPTION
                WHEN duplicate_object THEN NULL;
                WHEN duplicate_table THEN NULL;
            END $$;
        """)
        # `ALTER COLUMN ... DROP NOT NULL` is idempotent — applying it
        # to an already-nullable column is a metadata-only no-op in
        # Postgres but doesn't error.
        op.execute("ALTER TABLE scan_jobs ALTER COLUMN repository_id DROP NOT NULL")
        op.execute("ALTER TABLE normalized_findings ALTER COLUMN repository_id DROP NOT NULL")
        return
    op.create_table(
        "scan_sources",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("source_type", sa.String(20), nullable=False, index=True),
        sa.Column("integration_config_id", UUID(as_uuid=True), sa.ForeignKey("integration_configs.id"), nullable=False, index=True),
        sa.Column("is_active", sa.Boolean, default=True, nullable=False),
        sa.Column("scan_schedule", sa.String(20), default="on_demand", nullable=False),
        sa.Column("config", JSONB, server_default="{}"),
        sa.Column("sync_state", JSONB, server_default="{}"),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stats", JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    # Add scan_source_id to scan_jobs
    op.add_column("scan_jobs", sa.Column("scan_source_id", UUID(as_uuid=True), nullable=True, index=True))
    op.create_foreign_key("fk_scan_jobs_scan_source", "scan_jobs", "scan_sources", ["scan_source_id"], ["id"])

    # Make scan_jobs.repository_id nullable
    op.alter_column("scan_jobs", "repository_id", nullable=True)

    # Add scan_source_id to normalized_findings
    op.add_column("normalized_findings", sa.Column("scan_source_id", UUID(as_uuid=True), nullable=True, index=True))
    op.create_foreign_key("fk_findings_scan_source", "normalized_findings", "scan_sources", ["scan_source_id"], ["id"])

    # Make normalized_findings.repository_id nullable
    op.alter_column("normalized_findings", "repository_id", nullable=True)


def downgrade() -> None:
    # Restore NOT NULL on repository_id columns
    op.alter_column("normalized_findings", "repository_id", nullable=False)
    op.alter_column("scan_jobs", "repository_id", nullable=False)

    # Drop FKs and columns
    op.drop_constraint("fk_findings_scan_source", "normalized_findings", type_="foreignkey")
    op.drop_column("normalized_findings", "scan_source_id")
    op.drop_constraint("fk_scan_jobs_scan_source", "scan_jobs", type_="foreignkey")
    op.drop_column("scan_jobs", "scan_source_id")

    # Drop scan_sources table
    op.drop_table("scan_sources")
