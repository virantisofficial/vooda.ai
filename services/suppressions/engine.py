# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Applies suppression rules to findings.

A suppression rule is the *reactive* half of noise control: the finding
is detected, stored and auditable, and then hidden from the working
queue. That is the difference from a rule override, which is a
*pre-persist* gate — the finding is never created at all. Both exist
because "I never want to see this rule again" and "this particular
pattern is a known false positive" are different statements, and only
the second one should leave evidence behind.

Matching
--------
A rule carries up to five criteria. Every criterion that is SET must
match — an empty criterion is not a wildcard vote, it is simply not part
of the test. A rule with no criteria at all matches nothing; the router
rejects those on create, and this module refuses them again rather than
trusting that.

That AND-semantics matters: a rule naming both a scanner_rule_id and a
file_path_pattern means "this rule, in these files", not "this rule
anywhere, or anything in these files". The looser reading would let a
narrow-looking rule silence a whole codebase.

Reversibility
-------------
Every suppression this module applies stamps ``suppression_reason`` with
``rule:<uuid>``, so deleting or deactivating a rule can find exactly the
findings it hid and restore them. Without that back-reference a
suppression would be a one-way door: unsuppressing would either miss
findings or un-hide ones a human had suppressed by hand.
"""
from __future__ import annotations

import fnmatch
from typing import Iterable, Optional
from uuid import UUID

import structlog
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.finding import NormalizedFinding
from apps.api.app.models.suppression import SuppressionRule
from services.learning.pattern_learner import (
    compute_pattern_hash as _learner_hash,
)

logger = structlog.get_logger()

#: Prefix for machine-written suppression reasons. Distinguishes a rule
#: suppression from `verified_inactive` (written by credential
#: verification) and from anything a human typed, so unsuppressing can
#: never revert someone else's decision.
REASON_PREFIX = "rule:"


def reason_for(rule_id) -> str:
    return f"{REASON_PREFIX}{rule_id}"


def compute_pattern_hash(code: str) -> str:
    """Normalised hash of a code snippet.

    Delegates to the learning engine's hash rather than defining a second
    one. These have to be the same function: a ``learned`` rule stores
    the hash the learner computed, and this module is what later compares
    it against a finding. Two implementations meant a learned rule could
    never match — different normalisation and different digest length —
    so every auto-learned rule was inert while looking healthy in the UI.
    """
    return _learner_hash(code or "")


def rule_has_criteria(rule: SuppressionRule) -> bool:
    return any((
        rule.scanner_rule_id,
        rule.pattern_hash,
        rule.vulnerability_category,
        rule.cwe,
        rule.file_path_pattern,
    ))


def rule_matches(rule: SuppressionRule, finding: NormalizedFinding) -> bool:
    """True when every criterion the rule sets matches the finding."""
    if not rule_has_criteria(rule):
        # No criteria means "match everything". Refuse rather than
        # silently suppressing an entire tenant's findings.
        return False

    if rule.scanner_rule_id and rule.scanner_rule_id != finding.scanner_rule_id:
        return False
    if rule.vulnerability_category and rule.vulnerability_category != finding.vulnerability_category:
        return False
    if rule.cwe and rule.cwe != finding.cwe:
        return False
    if rule.file_path_pattern:
        path = finding.file_path or ""
        # fnmatch, not a regex: operators write globs, and `*` in a glob
        # crosses directory separators here on purpose — `tests/*` should
        # cover `tests/unit/x.py`, which is what someone writing that
        # pattern means.
        if not fnmatch.fnmatch(path, rule.file_path_pattern):
            return False
    if rule.pattern_hash:
        if rule.pattern_hash != compute_pattern_hash(finding.code_snippet or ""):
            return False
    return True


async def _active_rules(db: AsyncSession, tenant_id: UUID) -> list[SuppressionRule]:
    result = await db.execute(
        select(SuppressionRule).where(
            SuppressionRule.tenant_id == tenant_id,
            SuppressionRule.is_active == True,  # noqa: E712
            # A proposal awaiting review must never suppress, and this
            # does not rely on it also being inactive. The two are set
            # together at creation, but approving is a two-field write,
            # and a rule that went live while still reading 'pending'
            # would be suppressing findings the reviewer has not seen.
            SuppressionRule.review_status.is_distinct_from("pending"),
        )
    )
    return [r for r in result.scalars().all() if rule_has_criteria(r)]


async def apply_suppression_rules(
    db: AsyncSession,
    tenant_id: UUID,
    findings: Iterable[NormalizedFinding],
    *,
    only_rule: Optional[SuppressionRule] = None,
) -> int:
    """Suppress findings matching this tenant's active rules.

    Returns the number newly suppressed. Findings already suppressed are
    left alone — including ones suppressed by a human or by credential
    verification, whose reason must not be overwritten.

    Does not commit: the caller owns the transaction, so a suppression
    lands in the same commit as the scan that produced the findings.
    """
    rules = [only_rule] if only_rule is not None else await _active_rules(db, tenant_id)
    if not rules:
        return 0

    applied_per_rule: dict = {}
    suppressed = 0

    for finding in findings:
        if finding.is_suppressed:
            continue
        for rule in rules:
            if not rule_matches(rule, finding):
                continue
            finding.is_suppressed = True
            finding.suppression_reason = reason_for(rule.id)
            applied_per_rule[rule.id] = applied_per_rule.get(rule.id, 0) + 1
            suppressed += 1
            break  # first matching rule owns it — the reason must be one rule

    # `times_applied` is what the UI's "Matches" column reads. Counted
    # here rather than by re-querying, so it reflects exactly what this
    # pass did.
    for rule in rules:
        n = applied_per_rule.get(rule.id, 0)
        if n:
            rule.times_applied = (rule.times_applied or 0) + n

    if suppressed:
        logger.info(
            "suppression_rules_applied",
            tenant=str(tenant_id),
            suppressed=suppressed,
            rules_matched=len(applied_per_rule),
        )
    return suppressed


def _exact_criteria_clauses(rule: SuppressionRule) -> list:
    """WHERE clauses for the criteria the database can check exactly.

    scanner_rule_id, category and cwe are equality tests, so the
    database can discard non-candidates before they cross the wire.
    file_path_pattern (fnmatch) and pattern_hash (recomputed from the
    snippet) stay in Python — pushing a glob into SQL LIKE would change
    its semantics, and the hash needs normalisation SQL doesn't do.
    Every returned row still goes through rule_matches(); this is a
    prefilter, never the decision.
    """
    clauses = []
    if rule.scanner_rule_id:
        clauses.append(NormalizedFinding.scanner_rule_id == rule.scanner_rule_id)
    if rule.vulnerability_category:
        clauses.append(
            NormalizedFinding.vulnerability_category == rule.vulnerability_category
        )
    if rule.cwe:
        clauses.append(NormalizedFinding.cwe == rule.cwe)
    return clauses


async def apply_rule_to_existing(
    db: AsyncSession, tenant_id: UUID, rule: SuppressionRule
) -> int:
    """Apply a newly created rule to findings already in the database.

    Creating a rule to silence noise you can currently see, and having
    that noise stay on screen until the next scan, is not what the
    operator asked for. Applied immediately instead.
    """
    if not rule_has_criteria(rule):
        return 0
    result = await db.execute(
        select(NormalizedFinding).where(
            NormalizedFinding.tenant_id == tenant_id,
            NormalizedFinding.is_suppressed == False,  # noqa: E712
            *_exact_criteria_clauses(rule),
        )
    )
    return await apply_suppression_rules(
        db, tenant_id, result.scalars().all(), only_rule=rule
    )


async def unapply_rule(db: AsyncSession, tenant_id: UUID, rule_id) -> int:
    """Restore findings this rule suppressed. Returns the count.

    Scoped by the `rule:<uuid>` reason, so it can only revert what this
    rule did — never a manual suppression or a verified-inactive one.
    """
    result = await db.execute(
        update(NormalizedFinding)
        .where(
            NormalizedFinding.tenant_id == tenant_id,
            NormalizedFinding.is_suppressed == True,  # noqa: E712
            NormalizedFinding.suppression_reason == reason_for(rule_id),
        )
        .values(is_suppressed=False, suppression_reason=None)
    )
    restored = result.rowcount or 0
    if restored:
        logger.info("suppression_rule_unapplied", rule=str(rule_id), restored=restored)
    return restored


async def count_matching(db: AsyncSession, tenant_id: UUID, rule: SuppressionRule) -> int:
    """How many current findings a rule would suppress — for previewing
    a rule before saving it."""
    if not rule_has_criteria(rule):
        return 0
    result = await db.execute(
        select(NormalizedFinding).where(
            NormalizedFinding.tenant_id == tenant_id,
            *_exact_criteria_clauses(rule),
        )
    )
    return sum(1 for f in result.scalars().all() if rule_matches(rule, f))
