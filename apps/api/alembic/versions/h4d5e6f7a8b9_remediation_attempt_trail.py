# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""status + error trail on remediation_plans

Revision ID: h4d5e6f7a8b9
Revises: g3b4c5d6e7f9
Create Date: 2026-09-12 10:00:00.000000

Why
---
A remediation attempt that failed left nothing behind: no status, no
error, no retry — the plan row (when one existed at all) was
indistinguishable from success, and the finding sat looking
in-progress forever. 47 findings were in that state, silently, with
no way for the UI or an operator to tell.

Fix
---
``status`` on the plan ('generating' → 'patched' | 'no_patch' |
'failed') plus a nullable ``error``. A plan row now records the
ATTEMPT, created before the model is called, so even a crash mid-call
leaves a row that says so.

Backfill is honest about what it cannot know: existing plans with a
real patch become 'patched'; plans without one become 'no_patch' with
an error noting that crash-vs-plan-only is indistinguishable for rows
that predate the trail. Findings stuck at PENDING with no plan at all
(queued attempts that bailed before recording anything) return to
NONE so they read as "no fix exists" and become re-queueable.
"""
from alembic import op
import sqlalchemy as sa


revision = "h4d5e6f7a8b9"
down_revision = "g3b4c5d6e7f9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "remediation_plans",
        sa.Column("status", sa.String(length=20), nullable=False,
                  server_default="generating"),
    )
    op.add_column(
        "remediation_plans",
        sa.Column("error", sa.Text(), nullable=True),
    )

    bind = op.get_bind()
    bind.execute(sa.text("""
        UPDATE remediation_plans p SET status='patched'
        WHERE EXISTS (SELECT 1 FROM remediation_patches rp
                      WHERE rp.plan_id = p.id
                        AND length(coalesce(rp.patch_diff,'')) > 20)
    """))
    bind.execute(sa.text("""
        UPDATE remediation_plans p
           SET status='no_patch',
               error='no patch artifact recorded (predates the attempt '
                     'trail; a crash and a plan-only model response are '
                     'indistinguishable for this row)'
        WHERE NOT EXISTS (SELECT 1 FROM remediation_patches rp
                          WHERE rp.plan_id = p.id
                            AND length(coalesce(rp.patch_diff,'')) > 20)
    """))
    # Queued attempts that bailed before creating any plan: the finding
    # claimed PENDING forever. NONE is the truthful state and makes the
    # finding eligible for re-queue. The no-plan guard keeps any
    # genuinely in-flight row untouched only if its worker has already
    # written the plan; the deploy window makes in-flight rows unlikely.
    bind.execute(sa.text("""
        UPDATE normalized_findings SET remediation_status='NONE'
        WHERE remediation_status='PENDING'
          AND id NOT IN (SELECT finding_id FROM remediation_plans)
    """))


def downgrade() -> None:
    op.drop_column("remediation_plans", "error")
    op.drop_column("remediation_plans", "status")
