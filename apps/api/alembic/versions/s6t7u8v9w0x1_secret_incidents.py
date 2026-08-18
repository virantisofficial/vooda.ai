# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""secret_incidents: first-class entity for unique credentials (Case-B aggregation)

Revision ID: s6t7u8v9w0x1
Revises: r5s6t7u8v9w0
Create Date: 2026-05-11 09:00:00.000000

Why
---
NormalizedFinding is per-occurrence: same credential leaked in 5
files = 5 rows.  The "incident" model that GitGuardian, TruffleHog,
Wiz, Orca all ship treats the CREDENTIAL itself as a first-class
entity — distinct from its locations — so that:

* Triage decisions (TP / FP / accepted risk) attach to the credential,
  not each location.  Marking 1 of 5 occurrences as FP and re-deciding
  for the other 4 is busywork; the credential is one decision.
* Rotation status tracks the credential ("rotated", "verified inactive
  after rotation") independently of cleanup status ("git history
  scrubbed", "removed from .env.example"), which is per-occurrence.
* Aggregate stats (occurrence_count, severity_max, last_seen_at across
  all locations) live on the incident, ready for the UI's incident
  view without ad-hoc GROUP BYs at read time.
* Cross-source / cross-repo merging is automatic — same secret_hash =
  same incident, regardless of where the occurrences sit.

What this migration does
------------------------
1. Create ``secret_incidents`` table.  One row per (tenant_id,
   secret_hash) pair.  Carries the credential-level triage and
   aggregate fields.
2. Add ``incident_id`` FK on ``normalized_findings``.  Nullable —
   non-secret findings (no secret_hash) carry NULL and continue to
   work as before.  ON DELETE SET NULL so deleting an incident
   doesn't cascade to the per-occurrence records.
3. Backfill: for every existing finding that has a
   ``source_metadata->>'secret_hash'`` value, find-or-create the
   corresponding incident and set the FK.  Aggregates carried over
   from the most-recent finding in each group.

Enum-typed fields (severity, classification, review_status) are stored
as VARCHAR with application-level validation rather than Postgres
native enums.  Reasons:
* Avoids the migration-cascade problem when the application's enum
  vocabulary expands — the recent Classification additions
  (RESOLVED_FILE_DELETED, RESOLVED_ITEM_DELETED, etc.) would
  otherwise require an ALTER TYPE for the new incident column.
* Keeps the backfill INSERT path simple (no triple-cast
  ``foo::text::enumtype`` boilerplate).
* The values are still validated by the SecretIncident model's
  SAEnum at the SQLAlchemy layer.

Backfill is idempotent — re-running the migration on a partially-
backfilled table is safe because we INSERT ... ON CONFLICT DO
NOTHING and only update findings whose incident_id is still NULL.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = "s6t7u8v9w0x1"
down_revision = "r5s6t7u8v9w0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # ── 1. Create the secret_incidents table ───────────────────────
    if "secret_incidents" not in existing_tables:
        op.create_table(
            "secret_incidents",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
            sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            # Natural key — uniquely identifies the credential per tenant.
            # SHA-256 hex is 64 chars; allow 128 to accommodate future hash
            # algorithm changes or hash+algo prefix conventions.
            sa.Column("secret_hash", sa.String(128), nullable=False),
            # Display fields denormalized from the latest occurrence so the
            # incident card / row can render without joining findings.
            sa.Column("title", sa.Text, nullable=False),
            sa.Column("secret_type", sa.String(255), nullable=True),
            sa.Column("masked_value", sa.String(255), nullable=True),
            # Severity / classification / review_status: VARCHAR-backed
            # for migration-ease — see module docstring.  Values are the
            # lowercase enum member values (severity = "critical"|"high"|
            # "medium"|"low"|"info"; classification = "needs_review"|...;
            # review_status = "unreviewed"|...).
            sa.Column("severity_max", sa.String(20), nullable=False),
            sa.Column("occurrence_count", sa.Integer, nullable=False, server_default="1"),
            sa.Column("classification", sa.String(40), nullable=False, server_default="needs_review"),
            sa.Column("review_status", sa.String(40), nullable=False, server_default="unreviewed"),
            # Live-validation status of the credential at the provider.
            # Free string here because the verifier vocabulary is still
            # evolving (active / inactive / unknown / unsupported /
            # rate_limited / errored).
            sa.Column("validation_status", sa.String(50), nullable=True),
            sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
            # Rotation lifecycle — the credential-level remediation state.
            # Distinct from NormalizedFinding.remediation_status which
            # tracks per-location code cleanup (git history scrub etc.).
            # Values: "open" / "rotated" / "verified_inactive" / "n/a".
            sa.Column("rotation_status", sa.String(50), nullable=True),
            sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
            # Assignment + tags
            sa.Column("assigned_to", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("tags", postgresql.JSONB, nullable=False, server_default="[]"),
            # Cross-scan tracking
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
            # AI metadata (denormalized from the most-recent occurrence's
            # AI explanation — saves a join when rendering an incident
            # detail view).
            sa.Column("ai_explanation", sa.Text, nullable=True),
            sa.Column("ai_confidence", sa.Float, nullable=True),
            # Timestamps
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            # One incident per (tenant, credential).  This is the natural
            # key — the find-or-create upsert in the worker keys on it.
            sa.UniqueConstraint("tenant_id", "secret_hash", name="uq_secret_incidents_tenant_hash"),
        )
        op.execute("CREATE INDEX IF NOT EXISTS ix_secret_incidents_tenant_id ON secret_incidents (tenant_id)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_secret_incidents_classification ON secret_incidents (classification)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_secret_incidents_severity_max ON secret_incidents (severity_max)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_secret_incidents_assigned_to ON secret_incidents (assigned_to)")

    # ── 2. Add incident_id FK on normalized_findings ───────────────
    # ADD COLUMN IF NOT EXISTS: safe when initial schema already created this.
    op.execute("""
        ALTER TABLE normalized_findings
            ADD COLUMN IF NOT EXISTS incident_id UUID
            REFERENCES secret_incidents (id) ON DELETE SET NULL
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_normalized_findings_incident_id ON normalized_findings (incident_id)")

    # ── 2b. Guarantee the natural-key UNIQUE constraint ────────────
    # Runs after step 2 because the dedup pass below repoints
    # normalized_findings.incident_id, which step 2 is what guarantees
    # exists.
    # The create_table above only runs when the table is absent, but the
    # initial-schema migration (a0b1c2d3e4f5) builds every table with
    # ``Base.metadata.create_all()`` — so on a FRESH database
    # secret_incidents already exists here and that whole block is
    # skipped, taking its UniqueConstraint with it. The backfill in
    # step 3 then aborts with "there is no unique or exclusion
    # constraint matching the ON CONFLICT specification", which broke
    # bootstrapping a new install outright.
    #
    # The model now declares the constraint (finding.py __table_args__)
    # so create_all supplies it on fresh installs; this block covers
    # databases created before that declaration existed. Idempotent, so
    # both paths converge on the same schema.
    #
    # The dedup pass is required for the legacy path only: without the
    # constraint, older databases could accumulate duplicate
    # (tenant_id, secret_hash) rows that would make ADD CONSTRAINT fail.
    # Keep the earliest row per key and repoint its findings, so no
    # occurrence is orphaned. No-ops on a fresh (empty) table.
    op.execute(
        """
        WITH ranked AS (
            SELECT id, tenant_id, secret_hash,
                   FIRST_VALUE(id) OVER (
                       PARTITION BY tenant_id, secret_hash
                       ORDER BY created_at, id
                   ) AS keep_id
            FROM secret_incidents
        )
        UPDATE normalized_findings nf
           SET incident_id = r.keep_id
          FROM ranked r
         WHERE nf.incident_id = r.id
           AND r.id <> r.keep_id;
        """
    )
    op.execute(
        """
        DELETE FROM secret_incidents si
         USING (
            SELECT id,
                   FIRST_VALUE(id) OVER (
                       PARTITION BY tenant_id, secret_hash
                       ORDER BY created_at, id
                   ) AS keep_id
              FROM secret_incidents
         ) r
         WHERE si.id = r.id
           AND r.id <> r.keep_id;
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                 WHERE conname = 'uq_secret_incidents_tenant_hash'
            ) THEN
                ALTER TABLE secret_incidents
                    ADD CONSTRAINT uq_secret_incidents_tenant_hash
                    UNIQUE (tenant_id, secret_hash);
            END IF;
        END $$;
        """
    )

    # ── 3. Backfill: collapse existing findings into incidents ─────
    # One SQL statement creates incidents from the existing data,
    # aggregating per (tenant_id, secret_hash):
    #   - display fields (title / secret_type / masked / ai_*):
    #     take from the most-recent occurrence.
    #   - severity_max: max across occurrences.
    #   - classification / review_status: prefer the latest non-default
    #     value across the group so prior triage isn't lost.
    #   - validation_status: take from the most-recent occurrence
    #     (verifier output evolves over time, latest wins).
    #   - first/last_seen_at: min / max across the group.
    op.execute(
        """
        WITH
        -- One row per unique (tenant, secret_hash) carrying
        -- aggregates and references to the "winning" occurrence rows.
        groups AS (
            SELECT
                tenant_id,
                source_metadata->>'secret_hash' AS secret_hash,
                COUNT(*) AS occurrence_count,
                MIN(first_seen_at) AS first_seen_at,
                MAX(last_seen_at) AS last_seen_at,
                MAX(
                    -- Postgres native_enum stores values uppercase
                    -- ('CRITICAL', 'HIGH', …) so we match in uppercase
                    -- here.  The SecretIncident.severity_max output is
                    -- still lowercase ("critical") to match how the
                    -- application reads it.
                    CASE severity::text
                        WHEN 'CRITICAL' THEN 5
                        WHEN 'HIGH' THEN 4
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 2
                        ELSE 1
                    END
                ) AS severity_rank
            FROM normalized_findings
            WHERE source_metadata->>'secret_hash' IS NOT NULL
              AND source_metadata->>'secret_hash' != ''
            GROUP BY tenant_id, source_metadata->>'secret_hash'
        ),
        -- "Display winner" — the most-recent occurrence per group.
        -- DISTINCT ON keeps just one row per (tenant, hash) pair.
        latest AS (
            SELECT DISTINCT ON (tenant_id, source_metadata->>'secret_hash')
                tenant_id,
                source_metadata->>'secret_hash' AS secret_hash,
                title,
                source_metadata->>'secret_type' AS secret_type,
                source_metadata->>'masked_value' AS masked_value,
                source_metadata->>'validation_status' AS validation_status,
                ai_explanation,
                ai_confidence
            FROM normalized_findings
            WHERE source_metadata->>'secret_hash' IS NOT NULL
              AND source_metadata->>'secret_hash' != ''
            ORDER BY tenant_id, source_metadata->>'secret_hash', created_at DESC
        ),
        -- "Triage winner" — the most-recent non-default
        -- classification/review_status per group.  Falls back to the
        -- default if no triage decisions exist.
        triage AS (
            -- Postgres native_enum stores uppercase form ('NEEDS_REVIEW',
            -- 'LIKELY_TRUE_POSITIVE'); the SecretIncident model stores
            -- the lowercase enum-value form to match how the rest of
            -- the application serializes these values.  LOWER() the
            -- output to bridge.
            SELECT DISTINCT ON (tenant_id, source_metadata->>'secret_hash')
                tenant_id,
                source_metadata->>'secret_hash' AS secret_hash,
                LOWER(classification::text) AS classification,
                LOWER(review_status::text) AS review_status
            FROM normalized_findings
            WHERE source_metadata->>'secret_hash' IS NOT NULL
              AND source_metadata->>'secret_hash' != ''
              AND classification::text != 'NEEDS_REVIEW'
            ORDER BY tenant_id, source_metadata->>'secret_hash', created_at DESC
        )
        INSERT INTO secret_incidents (
            tenant_id, secret_hash, title, secret_type, masked_value,
            severity_max, occurrence_count,
            classification, review_status,
            validation_status,
            first_seen_at, last_seen_at,
            ai_explanation, ai_confidence
        )
        SELECT
            g.tenant_id,
            g.secret_hash,
            l.title,
            l.secret_type,
            l.masked_value,
            CASE g.severity_rank
                WHEN 5 THEN 'critical'
                WHEN 4 THEN 'high'
                WHEN 3 THEN 'medium'
                WHEN 2 THEN 'low'
                ELSE 'info'
            END AS severity_max,
            g.occurrence_count,
            COALESCE(t.classification, 'needs_review'),
            COALESCE(t.review_status, 'unreviewed'),
            l.validation_status,
            g.first_seen_at,
            g.last_seen_at,
            l.ai_explanation,
            l.ai_confidence
        FROM groups g
        JOIN latest l ON l.tenant_id = g.tenant_id AND l.secret_hash = g.secret_hash
        LEFT JOIN triage t ON t.tenant_id = g.tenant_id AND t.secret_hash = g.secret_hash
        ON CONFLICT (tenant_id, secret_hash) DO NOTHING;
        """
    )

    # ── 4. Link existing findings to their incidents ───────────────
    op.execute(
        """
        UPDATE normalized_findings nf
        SET incident_id = si.id
        FROM secret_incidents si
        WHERE nf.incident_id IS NULL
          AND nf.tenant_id = si.tenant_id
          AND nf.source_metadata->>'secret_hash' = si.secret_hash;
        """
    )


def downgrade() -> None:
    # Drop FK + column on findings first, then the incidents table.
    op.drop_index("ix_normalized_findings_incident_id", table_name="normalized_findings")
    op.drop_column("normalized_findings", "incident_id")
    op.drop_index("ix_secret_incidents_assigned_to", table_name="secret_incidents")
    op.drop_index("ix_secret_incidents_severity_max", table_name="secret_incidents")
    op.drop_index("ix_secret_incidents_classification", table_name="secret_incidents")
    op.drop_index("ix_secret_incidents_tenant_id", table_name="secret_incidents")
    op.drop_table("secret_incidents")
