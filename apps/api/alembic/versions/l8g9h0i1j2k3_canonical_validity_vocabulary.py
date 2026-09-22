# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""One canonical vocabulary for credential validity, enforced by the database.

"Is this credential still live?" had no enum and no constraint. Eight
spellings were in flight for five states, produced by two independent
engines, and the findings copy lived inside a JSONB blob where nothing
could constrain it at all.

This migration:
  1. promotes ``normalized_findings.validation_status`` out of
     ``source_metadata`` into a real column,
  2. rewrites every legacy spelling in both tables onto the five
     canonical values,
  3. makes the column NOT NULL DEFAULT 'unknown' and adds a CHECK, so
     an unconstrained string can never be written again.

Additive and idempotent: safe to re-run, and the JSONB key is left in
place so a rollback loses nothing.

Revision ID: l8g9h0i1j2k3
Revises: k7f8a9b0c1d2
"""
from alembic import op
import sqlalchemy as sa

revision = "l8g9h0i1j2k3"
down_revision = "k7f8a9b0c1d2"
branch_labels = None
depends_on = None

# Mirrors apps/api/app/core/validity.py::_LEGACY. Kept as one SQL
# expression so the backfill and the runtime normaliser agree by
# construction; the guard test asserts they stay in step.
_NORMALIZE = """
    CASE lower(trim({src}))
        WHEN 'active'           THEN 'active'
        WHEN 'valid'            THEN 'active'
        WHEN 'inactive'         THEN 'inactive'
        WHEN 'invalid'          THEN 'inactive'
        WHEN 'revoked'          THEN 'inactive'
        WHEN 'expired'          THEN 'inactive'
        WHEN 'unsupported'      THEN 'unsupported'
        WHEN 'no_checker'       THEN 'unsupported'
        WHEN 'error'            THEN 'check_failed'
        WHEN 'validation_error' THEN 'check_failed'
        WHEN 'failed_to_check'  THEN 'check_failed'
        WHEN 'rate_limited'     THEN 'check_failed'
        ELSE 'unknown'
    END
"""

_ALLOWED = "('active','inactive','unknown','unsupported','check_failed')"


def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)

    # ── normalized_findings: promote out of JSONB ────────────────────
    cols = {c["name"] for c in insp.get_columns("normalized_findings")}
    if "validation_status" not in cols:
        op.add_column(
            "normalized_findings",
            sa.Column("validation_status", sa.String(20), nullable=True),
        )
        conn.execute(sa.text(f"""
            UPDATE normalized_findings
               SET validation_status = {_NORMALIZE.format(
                       src="source_metadata->>'validation_status'")}
        """))

    conn.execute(sa.text(
        "UPDATE normalized_findings SET validation_status = 'unknown' "
        "WHERE validation_status IS NULL"
    ))
    op.alter_column(
        "normalized_findings", "validation_status",
        existing_type=sa.String(20), nullable=False,
        server_default="unknown",
    )

    # ── secret_incidents: rewrite the existing column in place ───────
    conn.execute(sa.text(f"""
        UPDATE secret_incidents
           SET validation_status = {_NORMALIZE.format(src="validation_status")}
    """))
    conn.execute(sa.text(
        "UPDATE secret_incidents SET validation_status = 'unknown' "
        "WHERE validation_status IS NULL"
    ))
    op.alter_column(
        "secret_incidents", "validation_status",
        existing_type=sa.String(50), type_=sa.String(20), nullable=False,
        server_default="unknown",
    )

    # ── the constraints that stop this recurring ─────────────────────
    for table in ("normalized_findings", "secret_incidents"):
        name = f"ck_{table}_validation_status"
        existing = {c["name"] for c in insp.get_check_constraints(table)}
        if name not in existing:
            op.create_check_constraint(
                name, table, f"validation_status IN {_ALLOWED}"
            )

    op.create_index(
        "ix_normalized_findings_validation_status",
        "normalized_findings", ["validation_status"],
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_normalized_findings_validation_status",
        table_name="normalized_findings", if_exists=True,
    )
    for table in ("normalized_findings", "secret_incidents"):
        op.drop_constraint(f"ck_{table}_validation_status", table, type_="check")
    op.alter_column(
        "secret_incidents", "validation_status",
        existing_type=sa.String(20), type_=sa.String(50),
        nullable=True, server_default=None,
    )
    # The JSONB key was never removed, so dropping the column is lossless.
    op.drop_column("normalized_findings", "validation_status")
