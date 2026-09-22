# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Split the 13-value Classification into status + reason + ai_verdict.

``classification`` was four fields in a trench coat: the verdict, who
reached it, why the finding closed, and how. Every new reason
multiplied the enum instead of adding a row — which is how four
``RESOLVED_*`` values appeared that differ only in what kind of thing
disappeared.

Additive. ``classification`` is untouched and still authoritative;
this lands the new columns and backfills them so reads can migrate
before writes do.

A note on ``resolved_at``: it is left NULL for backfilled rows. The
closing timestamp was never recorded, and ``updated_at`` is not it —
any row touched by a later rescan would carry a fabricated resolution
time. An empty audit field is honest; an invented one fails an audit.

Revision ID: n0i1j2k3l4m5
Revises: m9h0i1j2k3l4
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "n0i1j2k3l4m5"
down_revision = "m9h0i1j2k3l4"
branch_labels = None
depends_on = None

_STATUS = "('open','triaging','resolved','dismissed')"
_RESOLVED_R = "('rotated','revoked','provider_disabled')"
_DISMISSED_R = ("('false_positive','test_credential','acceptable_risk',"
                "'mitigating_control','no_longer_present')")

# Mirrors apps/api/app/core/finding_status.py::FROM_CLASSIFICATION.
# A guard test asserts the two stay in step.
_STATUS_CASE = """
    CASE lower(classification::text)
        WHEN 'confirmed_true_positive'  THEN 'triaging'
        WHEN 'confirmed_false_positive' THEN 'dismissed'
        WHEN 'test_credential'          THEN 'dismissed'
        WHEN 'accepted_risk'            THEN 'dismissed'
        WHEN 'rotated'                  THEN 'resolved'
        WHEN 'resolved_file_deleted'    THEN 'dismissed'
        WHEN 'resolved_item_deleted'    THEN 'dismissed'
        WHEN 'resolved_repo_removed'    THEN 'dismissed'
        WHEN 'resolved_source_removed'  THEN 'dismissed'
        ELSE 'open'
    END
"""

_REASON_CASE = """
    CASE lower(classification::text)
        WHEN 'confirmed_false_positive' THEN 'false_positive'
        WHEN 'test_credential'          THEN 'test_credential'
        WHEN 'accepted_risk'            THEN 'acceptable_risk'
        WHEN 'rotated'                  THEN 'rotated'
        WHEN 'resolved_file_deleted'    THEN 'no_longer_present'
        WHEN 'resolved_item_deleted'    THEN 'no_longer_present'
        WHEN 'resolved_repo_removed'    THEN 'no_longer_present'
        WHEN 'resolved_source_removed'  THEN 'no_longer_present'
        ELSE NULL
    END
"""

_VERDICT_CASE = """
    CASE lower(classification::text)
        WHEN 'likely_true_positive'  THEN 'likely_tp'
        WHEN 'likely_false_positive' THEN 'likely_fp'
        WHEN 'not_enough_evidence'   THEN 'unsure'
        ELSE NULL
    END
"""

# The four legacy RESOLVED_* values collapse to one reason; the detail
# they carried moves into the note, where it belonged.
_NOTE_CASE = """
    CASE lower(classification::text)
        WHEN 'resolved_file_deleted'   THEN 'Migrated: the file carrying this finding was deleted.'
        WHEN 'resolved_item_deleted'   THEN 'Migrated: the source item carrying this finding was deleted.'
        WHEN 'resolved_repo_removed'   THEN 'Migrated: the repository was removed from Vooda.'
        WHEN 'resolved_source_removed' THEN 'Migrated: the scan source was removed from Vooda.'
        ELSE NULL
    END
"""

_TABLES = ("normalized_findings", "secret_incidents")


def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)

    for table in _TABLES:
        cols = {c["name"] for c in insp.get_columns(table)}

        def add(name, col):
            if name not in cols:
                op.add_column(table, col)

        add("status", sa.Column("status", sa.String(20), nullable=True))
        add("resolution_reason",
            sa.Column("resolution_reason", sa.String(30), nullable=True))
        add("resolution_note",
            sa.Column("resolution_note", sa.Text(), nullable=True))
        add("resolved_at",
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
        add("resolved_by",
            sa.Column("resolved_by", postgresql.UUID(as_uuid=True),
                      nullable=True))
        add("ai_verdict", sa.Column("ai_verdict", sa.String(20), nullable=True))

        conn.execute(sa.text(f"""
            UPDATE {table}
               SET status            = {_STATUS_CASE},
                   resolution_reason = {_REASON_CASE},
                   ai_verdict        = {_VERDICT_CASE},
                   resolution_note   = COALESCE(resolution_note, {_NOTE_CASE})
        """))

        op.alter_column(table, "status", existing_type=sa.String(20),
                        nullable=False, server_default="open")

        existing = {c["name"] for c in insp.get_check_constraints(table)}
        if f"ck_{table}_status" not in existing:
            op.create_check_constraint(
                f"ck_{table}_status", table, f"status IN {_STATUS}")
        # The contract: closing requires a reason, and the reason must
        # belong to the status. Enforced here so no code path can close
        # a finding without recording why.
        if f"ck_{table}_status_reason" not in existing:
            op.create_check_constraint(
                f"ck_{table}_status_reason", table,
                # The IS NOT NULL guards are load-bearing. Without them
                # `resolution_reason IN (...)` yields NULL when the column
                # is NULL, the whole OR collapses to NULL, and PostgreSQL
                # treats a NULL CHECK as SATISFIED — so `dismissed` with
                # no reason would sail straight through the constraint
                # that exists to forbid exactly that.
                f"(status = 'resolved'  AND resolution_reason IS NOT NULL "
                f"                      AND resolution_reason IN {_RESOLVED_R}) OR "
                f"(status = 'dismissed' AND resolution_reason IS NOT NULL "
                f"                      AND resolution_reason IN {_DISMISSED_R}) OR "
                f"(status IN ('open','triaging') AND resolution_reason IS NULL)",
            )
        if f"ck_{table}_ai_verdict" not in existing:
            op.create_check_constraint(
                f"ck_{table}_ai_verdict", table,
                "ai_verdict IS NULL OR ai_verdict IN "
                "('likely_tp','likely_fp','unsure')",
            )

        op.create_index(f"ix_{table}_status", table, ["status"],
                        if_not_exists=True)

    op.create_index(
        "ix_normalized_findings_resolution_reason",
        "normalized_findings", ["resolution_reason"], if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("ix_normalized_findings_resolution_reason",
                  table_name="normalized_findings", if_exists=True)
    for table in _TABLES:
        op.drop_index(f"ix_{table}_status", table_name=table, if_exists=True)
        for ck in ("status", "status_reason", "ai_verdict"):
            op.drop_constraint(f"ck_{table}_{ck}", table, type_="check")
        for col in ("ai_verdict", "resolved_by", "resolved_at",
                    "resolution_note", "resolution_reason", "status"):
            op.drop_column(table, col)
