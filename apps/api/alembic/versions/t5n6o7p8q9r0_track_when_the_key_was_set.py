"""Record when a provider key was set, so stale evidence stops counting.

A probe that is refused tells you different things depending on whether
anything else answered on the same key: if others worked, this model is
unavailable to the account; if nothing did, the credential is the
problem. That inference read every stored probe result, with no regard
for which key produced it — so after a key changed, results from the
previous credential still argued that "the key works for other models".
Measured against a deliberately invalid key that authenticated nothing,
every model was reported as a billing or availability problem.

Backfilled from ``updated_at``: any key change goes through the update
route, which touches it, so it is never earlier than the real moment
the key was set. Erring late discards some evidence that was in fact
valid, which costs a re-check. Erring early would keep evidence from a
retired credential, which is the bug.

Revision ID: t5n6o7p8q9r0
Revises: s4m5n6o7p8q9
"""
from alembic import op
import sqlalchemy as sa

revision = "t5n6o7p8q9r0"
down_revision = "s4m5n6o7p8q9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_model_configs",
        sa.Column("api_key_set_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "UPDATE ai_model_configs SET api_key_set_at = updated_at "
        "WHERE api_key_encrypted IS NOT NULL AND api_key_encrypted <> ''"
    )


def downgrade() -> None:
    op.drop_column("ai_model_configs", "api_key_set_at")
