"""Record how often a model is right, beside whether it answers.

Revision ID: q2k3l4m5n6o7
Revises: p1j2k3l4m5n6
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "q2k3l4m5n6o7"
down_revision = "p1j2k3l4m5n6"
branch_labels = None
depends_on = None

#: All nullable on purpose. A model nobody has scored must be
#: distinguishable from one that scored zero — defaulting these to 0
#: would render an unmeasured model as perfectly wrong.
_COLUMNS = (
    ("accuracy_total", sa.Integer()),
    ("accuracy_correct", sa.Integer()),
    ("accuracy_missed_secrets", sa.Integer()),
    ("accuracy_unanswered", sa.Integer()),
    ("accuracy_headline", sa.String(300)),
    ("accuracy_detail", postgresql.JSONB),
    ("accuracy_checked_at", sa.String(50)),
)


def upgrade() -> None:
    for name, type_ in _COLUMNS:
        op.add_column("ai_model_probe_results", sa.Column(name, type_, nullable=True))
    # A count cannot exceed the number of cases run, and a negative one
    # is a bug rather than a value — the same three-valued-logic guard
    # the state column uses, so a NULL is not read as satisfied.
    op.create_check_constraint(
        "ck_ai_model_probe_accuracy_bounds",
        "ai_model_probe_results",
        "accuracy_total IS NULL OR ("
        " accuracy_total >= 0"
        " AND accuracy_correct BETWEEN 0 AND accuracy_total"
        " AND accuracy_missed_secrets BETWEEN 0 AND accuracy_total"
        " AND accuracy_unanswered BETWEEN 0 AND accuracy_total)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_ai_model_probe_accuracy_bounds", "ai_model_probe_results")
    for name, _ in reversed(_COLUMNS):
        op.drop_column("ai_model_probe_results", name)
