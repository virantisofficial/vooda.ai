# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Add enterprise scale indexes for JSONB and search performance

Revision ID: d8e9f0a1b2c3
Revises: b7d9e1f2a3c4
Create Date: 2026-04-11 12:00:00.000000
"""
from alembic import op

revision = "d8e9f0a1b2c3"
down_revision = "b7d9e1f2a3c4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # All indexes use IF NOT EXISTS — already idempotent. Each
    # `op.execute` runs in its own implicit transaction with
    # alembic's online mode; that's fine for plain CREATE INDEX
    # (the CONCURRENT variants live in the dedicated perf-indexes
    # migration which uses autocommit_block).
    op.execute("CREATE INDEX IF NOT EXISTS idx_nf_source_metadata_provider ON normalized_findings ((source_metadata->>'provider'))")
    op.execute("CREATE INDEX IF NOT EXISTS idx_nf_source_metadata_detection ON normalized_findings ((source_metadata->>'detection_method'))")
    op.execute("CREATE INDEX IF NOT EXISTS idx_nf_source_metadata_validation ON normalized_findings ((source_metadata->>'validation_status'))")

    # Repository search index
    op.execute("CREATE INDEX IF NOT EXISTS idx_repositories_name_lower ON repositories (lower(name))")

    # GIN indexes for languages/frameworks array filtering. These
    # only work if the column type is array/jsonb; if a previous
    # schema version had them as plain text the CREATE will fail.
    # Wrap in EXCEPTION blocks so a partially-migrated DB doesn't
    # bail on the entire migration.
    op.execute("""
        DO $$ BEGIN
            CREATE INDEX IF NOT EXISTS idx_repositories_languages ON repositories USING gin (languages);
        EXCEPTION
            WHEN undefined_column THEN NULL;
            WHEN datatype_mismatch THEN NULL;
        END $$;
    """)
    op.execute("""
        DO $$ BEGIN
            CREATE INDEX IF NOT EXISTS idx_repositories_frameworks ON repositories USING gin (frameworks);
        EXCEPTION
            WHEN undefined_column THEN NULL;
            WHEN datatype_mismatch THEN NULL;
        END $$;
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_nf_source_metadata_provider")
    op.execute("DROP INDEX IF EXISTS idx_nf_source_metadata_detection")
    op.execute("DROP INDEX IF EXISTS idx_nf_source_metadata_validation")
    op.execute("DROP INDEX IF EXISTS idx_repositories_name_lower")
    op.execute("DROP INDEX IF EXISTS idx_repositories_languages")
    op.execute("DROP INDEX IF EXISTS idx_repositories_frameworks")
