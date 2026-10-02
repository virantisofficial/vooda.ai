"""Give an accepted risk a name and an end date.

Dismissing a finding as an acceptable risk recorded who clicked and
nothing else. Two things were missing, and both are what an auditor
asks for first: who is accountable for the exposure, and until when.

Without an end date an acceptance is permanent by default, which is
the one thing a risk acceptance is never meant to be. The credential
stays live, the finding stays closed, and nothing ever asks again.

Enforcement is read-side, like the rule-override snooze it mirrors:
nothing flips the row when the date passes. The scan pipeline stops
replaying a lapsed acceptance onto new occurrences, so the finding
comes back on its own at the next scan, and the row survives its own
expiry for the audit trail. Re-dating it re-arms the acceptance.

Both columns are nullable, and both are cleared whenever a finding
leaves a closing status, so a re-opened finding never carries the
previous acceptance's owner.

Revision ID: u6o7p8q9r0s1
Revises: t5n6o7p8q9r0
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


revision = "u6o7p8q9r0s1"
down_revision = "t5n6o7p8q9r0"
branch_labels = None
depends_on = None


_TABLES = ("normalized_findings", "secret_incidents")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(
            table,
            # Who is accountable, which is not always who clicked.
            # `resolved_by` already records the latter. SET NULL on
            # user delete so the acceptance outlives the account, the
            # same way the rule-override `created_by` does.
            sa.Column("risk_owner", UUID(as_uuid=True), nullable=True),
        )
        op.create_foreign_key(
            f"fk_{table}_risk_owner_users",
            table,
            "users",
            ["risk_owner"],
            ["id"],
            ondelete="SET NULL",
        )
        op.add_column(
            table,
            sa.Column(
                "risk_accepted_until",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
        )

    # The findings list filters on it, so the date is worth an index
    # on the occurrence table.
    op.create_index(
        "ix_normalized_findings_risk_accepted_until",
        "normalized_findings",
        ["risk_accepted_until"],
    )

    # The decision cache replays a stored verdict onto new occurrences
    # without consulting the finding it came from. Carrying the date
    # here is what makes the expiry mean anything: a lapsed acceptance
    # stops being replayed, and the finding resurfaces at the next
    # scan. Without it the cache would keep re-closing the finding
    # forever and the end date would be decoration.
    op.add_column(
        "finding_decision_cache",
        sa.Column("risk_accepted_until", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("finding_decision_cache", "risk_accepted_until")
    op.drop_index(
        "ix_normalized_findings_risk_accepted_until",
        table_name="normalized_findings",
    )
    for table in _TABLES:
        op.drop_constraint(f"fk_{table}_risk_owner_users", table, type_="foreignkey")
        op.drop_column(table, "risk_accepted_until")
        op.drop_column(table, "risk_owner")
