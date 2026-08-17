# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""optimistic-lock version column on secret_incidents + normalized_findings

Revision ID: z3a4b5c6d7e8
Revises: y2z3a4b5c6d7
Create Date: 2026-05-19 09:00:00.000000

Why
---
Two reviewers (or two API calls from the same script) editing the same
incident or finding at the same time silently overwrote each other.
No 409, no audit trail of the conflict — the loser's classification,
tags, comment all disappeared.  Documented in the Track-A product
audit as the highest-impact correctness bug across the workflow
surface.

Fix
---
Add a small integer ``version`` column to both tables, defaulting to
1 server-side so already-persisted rows backfill non-NULL without a
separate UPDATE pass.  The model classes wire the column into
SQLAlchemy's ``__mapper_args__["version_id_col"]`` plumbing, which
auto-increments on every flush and folds the value into every UPDATE's
WHERE clause.  When a concurrent write tries to commit with a stale
version, zero rows match → SQLAlchemy raises ``StaleDataError`` →
the triage routers catch it and return ``HTTP 409 Conflict`` so the
UI can reload.

Backwards-compatibility
-----------------------
The migration only adds a column with a server default.  Existing
INSERT statements that don't mention ``version`` continue to work
(the DB fills in 1).  Existing PATCH requests that don't send
``expected_version`` skip the conflict check entirely — the column
still bumps, but no 409 fires.  This keeps CI scripts / integrations
that drive the API non-interactively working without immediate
client-side changes; only the UI surfaces 409s today.

Downgrade
---------
Drops both columns.  Safe because nothing else FK's them.
"""
from alembic import op
import sqlalchemy as sa


revision = "z3a4b5c6d7e8"
down_revision = "y2z3a4b5c6d7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── normalized_findings.version ───────────────────────────────
    # server_default="1" guarantees existing rows backfill non-NULL
    # at column-add time; we then NULL-set nullable=False since every
    # row already has a value.
    op.add_column(
        "normalized_findings",
        sa.Column(
            "version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )

    # ── secret_incidents.version ──────────────────────────────────
    op.add_column(
        "secret_incidents",
        sa.Column(
            "version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )


def downgrade() -> None:
    op.drop_column("secret_incidents", "version")
    op.drop_column("normalized_findings", "version")
