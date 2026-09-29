"""Cache what happened when Vooda asked a model to triage.

Revision ID: p1j2k3l4m5n6
Revises: n0i1j2k3l4m5
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "p1j2k3l4m5n6"
down_revision = "n0i1j2k3l4m5"
branch_labels = None
depends_on = None

#: The probe's four states. A CHECK rather than a comment because the
#: filter hides rows on this value, and a typo'd state would silently
#: drop a working model out of the customer's list.
_STATES = ("ready", "needs_setup", "unverified", "unusable")


def upgrade() -> None:
    op.create_table(
        "ai_model_probe_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("model_id", sa.String(255), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("headline", sa.String(500), nullable=False, server_default=""),
        sa.Column("remedy", sa.String(500), nullable=False, server_default=""),
        sa.Column("suggested_config", postgresql.JSONB, server_default=sa.text("'{}'::jsonb")),
        sa.Column("detail", postgresql.JSONB, server_default=sa.text("'{}'::jsonb")),
        sa.Column("latency_ms", sa.Float, server_default="0"),
        sa.Column("probed_at", sa.String(50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.UniqueConstraint("tenant_id", "provider", "model_id",
                            name="uq_ai_model_probe_tenant_provider_model"),
        # NOT NULL is already declared, but state IN (...) evaluates to
        # NULL for a NULL value and PostgreSQL treats a NULL CHECK as
        # satisfied — the same three-valued-logic hole that let bad
        # reasons through on the findings table earlier.
        sa.CheckConstraint(
            "state IS NOT NULL AND state IN " + str(_STATES),
            name="ck_ai_model_probe_state",
        ),
    )
    op.create_index("ix_ai_model_probe_lookup", "ai_model_probe_results",
                    ["tenant_id", "provider"])


def downgrade() -> None:
    op.drop_index("ix_ai_model_probe_lookup", table_name="ai_model_probe_results")
    op.drop_table("ai_model_probe_results")
