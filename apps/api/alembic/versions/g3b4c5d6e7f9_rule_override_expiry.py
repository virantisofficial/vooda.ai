# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""expires_at on rule_overrides — mutes that resurface on their own

Revision ID: g3b4c5d6e7f9
Revises: f2a3b4c5d6e8
Create Date: 2026-09-01 12:00:00.000000

Why
---
A rule override is easy to create and easy to forget. "Mute this while
we clean up the demo repo" quietly becomes "muted forever" because
nothing ever asks again — the standard failure mode of noise controls,
and the reason mature scanners offer snooze-until semantics rather
than only a permanent off switch.

Fix
---
Nullable ``expires_at``. NULL means what every existing row already
means: no expiry, mute until someone turns it off. A dated override
stops being enforced the moment a scan starts after that instant —
the worker's loader filters on it, so there is no cron to run and no
state to flip: the next scan simply sees the rule again and findings
resurface on their own. The row itself is kept (audit trail, and the
admin can extend or clear the date to re-arm it).
"""
from alembic import op
import sqlalchemy as sa


revision = "g3b4c5d6e7f9"
down_revision = "f2a3b4c5d6e8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "rule_overrides",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("rule_overrides", "expires_at")
