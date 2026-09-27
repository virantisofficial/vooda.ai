"""Keep what the provider's metadata said, not just what we did with it.

Revision ID: r3l4m5n6o7p8
Revises: q2k3l4m5n6o7
"""
from alembic import op
import sqlalchemy as sa

revision = "r3l4m5n6o7p8"
down_revision = "q2k3l4m5n6o7"
branch_labels = None
depends_on = None

#: The classifier's vocabulary — see model_suitability.py, which owns
#: it. Nullable because a row written before this existed, or by a path
#: that had no discovery response to hand, genuinely has no verdict;
#: NOT NULL with a default would invent one.
_TIERS = ("candidate", "other_modality", "cannot_serve")


def upgrade() -> None:
    op.add_column("ai_model_probe_results",
                  sa.Column("suitability", sa.String(20), nullable=True))
    op.add_column("ai_model_probe_results",
                  sa.Column("suitability_reason", sa.String(200), nullable=True))
    op.add_column("ai_model_probe_results",
                  sa.Column("suitability_may_exclude", sa.Boolean(), nullable=True))
    # `IN (...)` yields NULL for a NULL value and PostgreSQL treats a
    # NULL CHECK as satisfied, so the IS NULL arm is written out rather
    # than relied upon.
    op.create_check_constraint(
        "ck_ai_model_probe_suitability",
        "ai_model_probe_results",
        "suitability IS NULL OR suitability IN " + str(_TIERS),
    )


def downgrade() -> None:
    op.drop_constraint("ck_ai_model_probe_suitability", "ai_model_probe_results")
    for c in ("suitability_may_exclude", "suitability_reason", "suitability"):
        op.drop_column("ai_model_probe_results", c)
