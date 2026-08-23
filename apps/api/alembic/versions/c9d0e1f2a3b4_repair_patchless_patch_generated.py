# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""downgrade PATCH_GENERATED findings that have no patch

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-08-23 12:00:00.000000

Why
---
``remediation_status`` can read PATCH_GENERATED on findings that only
have an advisory plan and no persisted patch. The status is a claim
that a draft fix exists; a finding in that state never re-enters the
generation queue because it looks done, and any coverage number built
on the status counts a patch that is not there.

Fix
---
Data-only repair: any PATCH_GENERATED finding with no non-trivial patch
behind it (via remediation_plans -> remediation_patches) goes back to
PENDING, which is what those findings are — planned, awaiting a patch.
The code paths that stamp the status now do so only after persisting a
real patch, so the state cannot recur.

Idempotent by construction (the WHERE clause matches nothing on a
healthy database). No downgrade: restoring a false status would only
re-create the lie, so ``downgrade`` is a no-op.
"""
from alembic import op

revision = "c9d0e1f2a3b4"
down_revision = "b8c9d0e1f2a3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE normalized_findings f
           SET remediation_status = 'PENDING'
         WHERE f.remediation_status = 'PATCH_GENERATED'
           AND NOT EXISTS (
                SELECT 1
                  FROM remediation_plans p
                  JOIN remediation_patches rp ON rp.plan_id = p.id
                 WHERE p.finding_id = f.id
                   AND length(coalesce(rp.patch_diff, '')) > 20
           )
        """
    )


def downgrade() -> None:
    # Deliberately a no-op: the upgraded state is the truthful one.
    pass
