# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Constrain the last two unguarded state axes: severity and scan status.

Both followed the same pattern as validity: a typed enum existed, and a
parallel unconstrained ``String`` column let anything through beside it.

  * ``secret_incidents.severity_max`` — varchar, no constraint.
  * ``imported_findings.severity`` — varchar, the ingestion surface for
    third-party scanners, i.e. exactly where unvetted values arrive.
  * ``custom_detectors.severity`` / ``notification_deliveries.severity``
    — varchar, customer-authored.
  * ``scan_phase_events.status`` — varchar re-declaring ScanStatus in a
    trailing comment.

Values are normalised to lowercase first, so the CHECK cannot fail on
existing rows.

Revision ID: m9h0i1j2k3l4
Revises: l8g9h0i1j2k3
"""
from alembic import op
import sqlalchemy as sa

revision = "m9h0i1j2k3l4"
down_revision = "l8g9h0i1j2k3"
branch_labels = None
depends_on = None

_SEV = "('critical','high','medium','low','info')"
# scan_phase_events records a phase transition, so it never carries the
# queue-only PENDING state.
_PHASE = "('running','analyzing','completed','failed','cancelled')"

_SEV_COLS = [
    ("secret_incidents", "severity_max", False),
    ("imported_findings", "severity", True),
    ("custom_detectors", "severity", False),
    ("notification_deliveries", "severity", True),
]


def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    tables = set(insp.get_table_names())

    for table, col, nullable in _SEV_COLS:
        if table not in tables:
            continue
        # Fold casing and unrecognised spellings before constraining.
        conn.execute(sa.text(f"""
            UPDATE {table} SET {col} = CASE lower(trim({col}))
                WHEN 'critical' THEN 'critical'
                WHEN 'crit'     THEN 'critical'
                WHEN 'blocker'  THEN 'critical'
                WHEN 'high'     THEN 'high'
                WHEN 'major'    THEN 'high'
                WHEN 'medium'   THEN 'medium'
                WHEN 'moderate' THEN 'medium'
                WHEN 'warning'  THEN 'medium'
                WHEN 'low'      THEN 'low'
                WHEN 'minor'    THEN 'low'
                ELSE 'info'
            END
            WHERE {col} IS NOT NULL
        """))
        name = f"ck_{table}_{col}"
        if name not in {c["name"] for c in insp.get_check_constraints(table)}:
            cond = f"{col} IN {_SEV}"
            if nullable:
                cond = f"{col} IS NULL OR {cond}"
            op.create_check_constraint(name, table, cond)

    if "scan_phase_events" in tables:
        conn.execute(sa.text(
            "UPDATE scan_phase_events SET status = lower(trim(status))"
        ))
        name = "ck_scan_phase_events_status"
        if name not in {
            c["name"] for c in insp.get_check_constraints("scan_phase_events")
        }:
            op.create_check_constraint(
                name, "scan_phase_events", f"status IN {_PHASE}"
            )


def downgrade() -> None:
    conn = op.get_bind()
    tables = set(sa.inspect(conn).get_table_names())
    for table, col, _ in _SEV_COLS:
        if table in tables:
            op.drop_constraint(f"ck_{table}_{col}", table, type_="check")
    if "scan_phase_events" in tables:
        op.drop_constraint(
            "ck_scan_phase_events_status", "scan_phase_events", type_="check"
        )
