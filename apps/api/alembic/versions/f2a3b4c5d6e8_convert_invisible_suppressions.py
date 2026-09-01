# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""convert org-learning suppressions into visible rules

Revision ID: f2a3b4c5d6e8
Revises: e1f2a3b4c5d7
Create Date: 2026-09-01 09:30:00.000000

Why
---
Org-wide learning used to suppress findings inline. It set
``is_suppressed``, wrote ``CONFIRMED_FALSE_POSITIVE``, and stamped
``source_metadata.suppressed_by = 'org_learning'`` — but created no
suppression rule. The result was a finding hidden from the queue with
no rule to point at, nothing in the suppressions audit trail, a
confirmed verdict no human made, and no way to undo it except by
re-classifying each finding by hand.

Fix
---
Convert, rather than revert. Each distinct
``(tenant, scanner_rule_id, learned_pattern_hash)`` becomes a real
``learned`` suppression rule, and the findings it hid are re-stamped
with ``rule:<uuid>`` so the existing unapply path can restore them.
The machine-written ``CONFIRMED_FALSE_POSITIVE`` is downgraded to
``LIKELY_FALSE_POSITIVE``: the finding was never confirmed by anyone,
and leaving that word in place is the misstatement this release exists
to correct.

Findings stay suppressed. Un-suppressing them would be the more
literal repair, but it would empty a rule's worth of noise back into
the queue of every install that upgrades, punishing the people who
used the feature. The effective state is unchanged; what changes is
that it is now visible, attributable and reversible.

Idempotent: keyed on ``suppression_reason IS NULL``, which the
conversion fills in.
"""
from alembic import op
import sqlalchemy as sa
import uuid


revision = "f2a3b4c5d6e8"
down_revision = "e1f2a3b4c5d7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    groups = bind.execute(sa.text("""
        SELECT tenant_id,
               scanner_rule_id,
               source_metadata->>'learned_pattern_hash'  AS pattern_hash,
               max(vulnerability_category)               AS category,
               count(*)                                  AS n_findings,
               count(DISTINCT repository_id)             AS n_repos,
               max(code_snippet)                         AS sample
          FROM normalized_findings
         WHERE is_suppressed = true
           AND suppression_reason IS NULL
           AND source_metadata->>'suppressed_by' = 'org_learning'
           AND scanner_rule_id IS NOT NULL
      GROUP BY tenant_id, scanner_rule_id, source_metadata->>'learned_pattern_hash'
    """)).fetchall()

    for tenant_id, rule_id, p_hash, category, n_findings, n_repos, sample in groups:
        new_id = uuid.uuid4()
        bind.execute(sa.text("""
            INSERT INTO suppression_rules (
                id, tenant_id, name, description, suppression_type,
                scanner_rule_id, pattern_hash, vulnerability_category,
                evidence_count, evidence_repo_count, confidence,
                sample_code, is_active, created_by, times_applied,
                review_status, created_at, updated_at
            ) VALUES (
                :id, :tenant_id, :name, :description, 'learned',
                :rule_id, :p_hash, :category,
                :n_findings, :n_repos, 0.85,
                :sample, true, 'system_learning', :n_findings,
                NULL, now(), now()
            )
        """), {
            "id": new_id, "tenant_id": tenant_id,
            "name": f"Learned: {rule_id}" + (f" ({category})" if category else ""),
            "description": (
                "Recovered from an org-learning suppression that predated "
                "suppression rules. It hid "
                f"{n_findings} finding(s) across {n_repos} repositor(y/ies) "
                "with no rule to point at; deactivate this rule to restore them."
            ),
            "rule_id": rule_id, "p_hash": p_hash, "category": category,
            "n_findings": n_findings, "n_repos": n_repos,
            "sample": (sample or "")[:200],
        })

        # Point the findings at their new rule. The reason is what the
        # unapply path matches on, so this is what makes them restorable.
        bind.execute(sa.text("""
            UPDATE normalized_findings
               SET suppression_reason = :reason,
                   classification = CASE
                       WHEN classification = 'CONFIRMED_FALSE_POSITIVE'
                       THEN 'LIKELY_FALSE_POSITIVE'
                       ELSE classification
                   END
             WHERE is_suppressed = true
               AND suppression_reason IS NULL
               AND source_metadata->>'suppressed_by' = 'org_learning'
               AND tenant_id = :tenant_id
               AND scanner_rule_id = :rule_id
               AND source_metadata->>'learned_pattern_hash' IS NOT DISTINCT FROM :p_hash
        """), {
            "reason": f"rule:{new_id}", "tenant_id": tenant_id,
            "rule_id": rule_id, "p_hash": p_hash,
        })


def downgrade() -> None:
    # Return the findings to their unattributed state and drop the
    # recovered rules. The CONFIRMED_* value is NOT restored: it was
    # never true, and re-asserting it on the way down would reintroduce
    # the misstatement.
    bind = op.get_bind()
    bind.execute(sa.text("""
        UPDATE normalized_findings f
           SET suppression_reason = NULL
          FROM suppression_rules r
         WHERE f.suppression_reason = 'rule:' || r.id::text
           AND r.created_by = 'system_learning'
           AND r.description LIKE 'Recovered from an org-learning%'
    """))
    bind.execute(sa.text("""
        DELETE FROM suppression_rules
         WHERE created_by = 'system_learning'
           AND description LIKE 'Recovered from an org-learning%'
    """))
