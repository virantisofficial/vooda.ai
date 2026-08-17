# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add ROTATED + TEST_CREDENTIAL classification values

Revision ID: k8l9m0n1o2p3
Revises: j7k8l9m0n1o2
Create Date: 2026-05-04 09:00:00.000000

Background
----------
The findings UI (`apps/web/src/components/findings/FindingPanel.tsx`)
has a status dropdown that exposes six triage actions:

  - Needs Review        (reopen)
  - True Positive       (mark_tp)
  - Rotated / Revoked   (mark_rotated)   ← was silently broken
  - False Positive      (mark_fp)
  - Test Credential     (mark_test)      ← was silently broken
  - Accepted Risk       (accept_risk)

The backend ``action_map`` in ``apps/api/app/routers/findings.py``
only mapped 5 of those actions to a ``Classification`` value. Clicking
"Rotated / Revoked" or "Test Credential" returned a 200 from the API
but did NOT actually change the finding's classification — the action
key fell through ``action_map.get(body.action)`` to ``None``, the
``if new_class:`` guard skipped the assignment, and the column kept
its previous value. Discovered 2026-05-04 during the lifecycle audit
vs industry tooling (GitGuardian / GitHub Secret Scanning / etc. —
all expose Rotated and Test states as first-class).

This migration adds the two missing enum values so the existing UI
buttons can finally do what they advertise. Companion changes ship
in the same commit:

  - ``Classification`` enum gains ``ROTATED`` + ``TEST_CREDENTIAL``
    (apps/api/app/models/finding.py)
  - ``action_map`` gains ``mark_rotated`` and ``mark_test`` entries
    (apps/api/app/routers/findings.py)

Why ALTER TYPE rather than a new migration scheme
-------------------------------------------------
Postgres enum values are added in-place with ``ALTER TYPE ... ADD
VALUE``. This is a metadata-only change — no table rewrite, no row
scan, safe on a live database. ``IF NOT EXISTS`` makes the migration
idempotent (re-running on a partially-migrated DB is a no-op).

Important Postgres quirk
------------------------
``ALTER TYPE ... ADD VALUE`` cannot run inside a transaction block
on Postgres < 12. We're on 16-alpine which lifts that restriction,
but we use ``op.get_context().autocommit_block()`` defensively — the
extra safety net costs nothing and keeps the migration portable to
older Postgres versions a customer might be running.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "k8l9m0n1o2p3"
down_revision: Union[str, None] = "j7k8l9m0n1o2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLAlchemy's ``SAEnum(Classification)`` stores the enum's
    # **name** (uppercase, e.g. ``NEEDS_REVIEW``) not its ``.value``
    # (lowercase, e.g. ``needs_review``). Verified against existing
    # production rows on 2026-05-04. So we add the UPPERCASE variants
    # here — that's what the ORM will actually write.
    #
    # We also add the lowercase variants for defensive purposes:
    # any code path that bypasses the ORM and writes the .value
    # directly (raw SQL, ad-hoc psql session, future SQLAlchemy
    # config change to ``values_callable=lambda x: [e.value for e in x]``)
    # won't break. Postgres enum values are cheap (4 bytes of
    # metadata each); the cost of having "rotated" + "ROTATED"
    # both registered is functionally zero.
    #
    # ALTER TYPE ADD VALUE outside a txn for Postgres-version
    # safety. On PG 16 the txn restriction is lifted, but the
    # autocommit block is harmless and makes this migration work
    # back to PG 11.
    with op.get_context().autocommit_block():
        # Uppercase — what SQLAlchemy actually persists today
        op.execute(
            "ALTER TYPE classification ADD VALUE IF NOT EXISTS 'ROTATED'"
        )
        op.execute(
            "ALTER TYPE classification ADD VALUE IF NOT EXISTS 'TEST_CREDENTIAL'"
        )
        # Lowercase — defensive belt + braces (cheap, future-proof)
        op.execute(
            "ALTER TYPE classification ADD VALUE IF NOT EXISTS 'rotated'"
        )
        op.execute(
            "ALTER TYPE classification ADD VALUE IF NOT EXISTS 'test_credential'"
        )


def downgrade() -> None:
    """No-op.

    Postgres has no native ``DROP VALUE`` for enums — the only path
    is to recreate the type and re-bind every column that uses it,
    which would be a destructive table-rewrite operation. Since these
    two values are purely additive (no existing row depends on their
    absence), the practical downgrade is to leave them in place. If
    you genuinely need to remove them, do so manually:

      1. UPDATE every row using the value to a different one
      2. CREATE the new enum type without the values
      3. ALTER COLUMN ... USING new_type
      4. DROP the old type

    But realistically, there's no reason to ever do that.
    """
    pass
