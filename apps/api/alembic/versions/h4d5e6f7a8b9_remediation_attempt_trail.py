# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""status + error trail on remediation_plans

Revision ID: h4d5e6f7a8b9
Revises: g3b4c5d6e7f9
Create Date: 2026-09-12 10:00:00.000000

Adds ``status`` ('generating' -> 'patched' | 'no_patch' | 'failed')
and a nullable ``error`` so a plan row records the attempt, not only a
success. Backfill: plans with a real patch become 'patched', the rest
'no_patch'; findings left PENDING with no plan return to NONE so they
read as "no fix exists" and can be re-queued.
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
