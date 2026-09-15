# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""drop AI code-fix (auto-remediation) schema

Revision ID: i5d6e7f8a9b0
Revises: h4d5e6f7a8b9
Create Date: 2026-09-15 12:00:00.000000

Vooda supports AI triage only; AI-generated patches and fix PRs are
gone. This drops the code-fix tables and the ``patchstatus`` enum, and
cleans code-fix values out of rows that outlive it:

- ``normalized_findings.remediation_status``: the code-fix states
  (PENDING, IN_PROGRESS, PATCH_GENERATED, APPROVED, REJECTED) return to
  NONE (compared as text: a fresh install's enum type only has NONE and
  APPLIED). The column stays: NONE / APPLIED still mean open / resolved
  (stale-finding auto-resolve, MTTR, ticket filters). APPROVED goes to
  NONE, not APPLIED — approval only queued a fix PR, it never fixed
  anything. The unused labels stay in the Postgres enum type because
  Postgres cannot drop enum values in place.
- ``ai_model_configs.tasks``: the "remediation" task keyword.
- ``role_definitions.permissions``: the "approve_remediation" permission.
- ``notification_rules``: the never-emitted "remediation_ready" and
  "patch_approved" events.

Downgrade recreates the tables empty so earlier downgrades still work;
dropped patches, plans and feedback are not recoverable.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "i5d6e7f8a9b0"
down_revision = "h4d5e6f7a8b9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("""
        UPDATE normalized_findings SET remediation_status='NONE'
        WHERE remediation_status::text IN
              ('PENDING','IN_PROGRESS','PATCH_GENERATED','APPROVED','REJECTED')
    """))

    op.execute("DROP TABLE IF EXISTS review_feedback")
    op.execute("DROP TABLE IF EXISTS remediation_patches")
    op.execute("DROP TABLE IF EXISTS remediation_plans")
    op.execute("DROP TYPE IF EXISTS patchstatus")

    bind.execute(sa.text("""
        UPDATE ai_model_configs
           SET tasks = COALESCE((SELECT jsonb_agg(t) FROM jsonb_array_elements(tasks) t
                                 WHERE t <> '"remediation"'::jsonb), '[]'::jsonb)
         WHERE tasks @> '["remediation"]'::jsonb
    """))
    bind.execute(sa.text("""
        UPDATE role_definitions
           SET permissions = COALESCE((SELECT jsonb_agg(p) FROM jsonb_array_elements(permissions) p
                                       WHERE p <> '"approve_remediation"'::jsonb), '[]'::jsonb)
         WHERE permissions @> '["approve_remediation"]'::jsonb
    """))
    bind.execute(sa.text("""
        DELETE FROM notification_rules
        WHERE event_type IN ('remediation_ready', 'patch_approved')
    """))


def _id():
    return sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                     server_default=sa.text("gen_random_uuid()"))


def _timestamps():
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    ]


def downgrade() -> None:
    op.create_table(
        "remediation_plans",
        _id(),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("normalized_findings.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("generated_by", sa.String(50), nullable=False),
        sa.Column("vulnerability_summary", sa.Text(), nullable=False),
        sa.Column("root_cause", sa.Text(), nullable=False),
        sa.Column("fix_rationale", sa.Text(), nullable=False),
        sa.Column("developer_notes", postgresql.JSONB()),
        sa.Column("validation_steps", postgresql.JSONB()),
        sa.Column("risk_of_breakage", sa.String(20)),
        sa.Column("confidence_score", sa.Float()),
        sa.Column("status", sa.String(20), nullable=False, server_default="generating"),
        sa.Column("error", sa.Text()),
        sa.Column("metadata", postgresql.JSONB()),
        *_timestamps(),
    )
    op.create_table(
        "remediation_patches",
        _id(),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("patch_diff", sa.Text(), nullable=False),
        sa.Column("files_changed", postgresql.JSONB()),
        sa.Column("status",
                  sa.Enum("DRAFT", "PROPOSED", "APPROVED", "REJECTED", "APPLIED",
                          name="patchstatus"),
                  nullable=False),
        sa.Column("confidence_score", sa.Float()),
        sa.Column("safety_score", sa.Float()),
        sa.Column("pr_url", sa.String(1024)),
        sa.Column("metadata", postgresql.JSONB()),
        *_timestamps(),
    )
    op.create_table(
        "review_feedback",
        _id(),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("normalized_findings.id"), index=True),
        sa.Column("patch_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("remediation_patches.id"), index=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("feedback_type", sa.String(50), nullable=False),
        sa.Column("comment", sa.Text()),
        sa.Column("rating", sa.String(20)),
        sa.Column("metadata", postgresql.JSONB()),
        *_timestamps(),
    )
