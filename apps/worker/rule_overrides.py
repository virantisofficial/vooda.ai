# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Worker-side helpers for consulting the rule_overrides table during a
scan.

A rule override is the proactive counterpart to a suppression: instead
of muting a finding after it lands, the admin tells the scanner "don't
even produce findings for rule X (in this repo / org-wide)".  See
apps/api/app/models/rule_override.py for the model and the migration
x1y2z3a4b5c6_add_rule_overrides for the schema.

The persist loop in apps/worker/tasks.py runs a *lot* of iterations
(potentially tens of thousands per scan).  Hitting the DB once per
finding to check for an override would be both slow and pointless —
the active override set is small and changes infrequently.

So this module exposes one entry point, ``load_active_rule_ids``,
which fetches every active override for the (tenant, repo) tuple in
a single query and returns a plain ``set[str]`` of scanner_rule_ids
to skip.  The persist loop checks the set in O(1) and only writes
back to the DB once at the end (via ``record_blocks``) to bump the
``times_blocked`` counter on the actual override rows.

Why a set + a separate write-back step:
  - The hot path stays O(1) per finding and DB-free.
  - We aggregate blocks per rule_id, so the times_blocked counter is
    incremented with N += k rather than N += 1 once per blocked
    finding (one UPDATE per rule instead of one per finding).
  - The set is computed once at the START of the scan, so adding a
    new override mid-scan won't change behaviour for the in-flight
    scan — which is what an admin would actually expect.

The single query joins on (tenant_id, is_active=True, repository_id
== repo_id OR IS NULL) so it picks up both repo-scoped and org-wide
overrides in one shot.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING
from uuid import UUID

import structlog
from sqlalchemy import and_, func, or_, select, update

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger("vooda.worker.rule_overrides")


async def load_active_rule_ids(
    db: "AsyncSession",
    tenant_id: UUID,
    repository_id: UUID | None = None,
    scan_source_id: UUID | None = None,
    scan_job=None,
) -> set[str]:
    """Return the set of scanner_rule_ids the scanner should drop for
    this scan target — both target-scoped AND org-wide overrides.

    Exactly one of ``repository_id`` / ``scan_source_id`` should be set:
        - repo scan: pass repository_id
        - source scan: pass scan_source_id
        - both None: only org-wide overrides are returned (rare; the
          callers always know one or the other)

    Errors are swallowed (return empty set) so a transient DB hiccup
    can't kill a scan.  The fail-open behaviour is intentional and
    documented: a missed override produces a noisy finding the admin
    can clean up; a missed *scan* loses signal that's harder to
    recover.
    """
    # Imported lazily so worker tasks that don't scan secrets (e.g. the
    # learning job) don't pay the import cost.
    from apps.api.app.models.rule_override import RuleOverride

    try:
        # Build the scope predicate based on which target id was passed.
        # Org-wide rows have BOTH target columns NULL — important to
        # match both, otherwise a row with scan_source_id set would
        # leak into a repo-scan lookup.
        scope_clauses = [
            and_(
                RuleOverride.repository_id.is_(None),
                RuleOverride.scan_source_id.is_(None),
            )
        ]
        if repository_id is not None:
            scope_clauses.append(RuleOverride.repository_id == repository_id)
        if scan_source_id is not None:
            scope_clauses.append(RuleOverride.scan_source_id == scan_source_id)

        result = await db.execute(
            select(RuleOverride.scanner_rule_id).where(
                RuleOverride.tenant_id == tenant_id,
                RuleOverride.is_active == True,
                # A dated mute stops enforcing the moment its expiry
                # passes — no cron, no state flip: the next scan simply
                # sees the rule again and the findings resurface. NULL
                # (no expiry) keeps meaning "until someone turns it off".
                or_(
                    RuleOverride.expires_at.is_(None),
                    RuleOverride.expires_at > func.now(),
                ),
                or_(*scope_clauses),
            )
        )
        rule_ids = {row[0] for row in result.all() if row[0]}
        if rule_ids:
            logger.info(
                "rule_overrides.loaded",
                tenant_id=str(tenant_id),
                repository_id=str(repository_id) if repository_id else None,
                scan_source_id=str(scan_source_id) if scan_source_id else None,
                count=len(rule_ids),
            )
        return rule_ids
    except Exception as exc:  # noqa: BLE001
        # Fail-open stays the right call — a missed override is a noisy
        # finding an admin can clean up, a killed scan loses signal —
        # but silently-open is not: this scan just ran WITHOUT the mutes
        # the admin configured, and nothing in the product said so. So
        # the failure is stamped onto the scan job's stats where the
        # scan card can show it, and logged at error so ops can alert
        # on the event name.
        logger.error(
            "rule_overrides.load_failed",
            tenant_id=str(tenant_id),
            repository_id=str(repository_id) if repository_id else None,
            scan_source_id=str(scan_source_id) if scan_source_id else None,
            error=str(exc),
        )
        if scan_job is not None:
            try:
                scan_job.stats = {
                    **(scan_job.stats or {}),
                    "rule_overrides_load_failed": True,
                }
            except Exception:  # noqa: BLE001
                pass  # observability must never out-fail the fail-open
        return set()


async def record_blocks(
    db: "AsyncSession",
    tenant_id: UUID,
    blocked_counts: dict[str, int],
    repository_id: UUID | None = None,
    scan_source_id: UUID | None = None,
) -> None:
    """Bump ``times_blocked`` on every active override that fired during
    the scan.

    Pass whichever target id matches the scan path that called
    ``load_active_rule_ids``: repo scans pass repository_id, source
    scans pass scan_source_id.  We only bump rows whose scope matches
    the scan target (or the org-wide rows) so a Slack-source scan
    doesn't accidentally increment counters on a repo-scoped override.

    Notes
    -----
    * When a target-scoped and an org-wide override both cover the
      same rule, the SCOPED one owns the count — precedence, resolved
      here with one extra SELECT rather than by threading per-finding
      attribution through the hot loop. Both incrementing (the old
      behaviour) made the Findings Blocked tile over-count.
    * No-op when blocked_counts is empty so the common case (no
      overrides hit) doesn't issue a single UPDATE.
    """
    if not blocked_counts:
        return

    from apps.api.app.models.rule_override import RuleOverride

    # Build the same scope predicate shape as load_active_rule_ids so
    # the two stay in sync.
    scope_clauses = [
        and_(
            RuleOverride.repository_id.is_(None),
            RuleOverride.scan_source_id.is_(None),
        )
    ]
    if repository_id is not None:
        scope_clauses.append(RuleOverride.repository_id == repository_id)
    if scan_source_id is not None:
        scope_clauses.append(RuleOverride.scan_source_id == scan_source_id)

    try:
        # One SELECT for all fired rules, then attribute each rule's
        # count to the MOST SPECIFIC live override: target-scoped over
        # org-wide. When both exist, precedence says the scoped one is
        # the rule doing the muting, so it alone owns the number —
        # incrementing both made "Findings Blocked" over-count, and a
        # tile that over-counts trains people to distrust every number
        # next to it. Expired rows can no longer have caused a skip, so
        # they are excluded the same way the loader excludes them.
        rows = (await db.execute(
            select(
                RuleOverride.id,
                RuleOverride.scanner_rule_id,
                RuleOverride.repository_id,
                RuleOverride.scan_source_id,
            ).where(
                RuleOverride.tenant_id == tenant_id,
                RuleOverride.scanner_rule_id.in_(
                    [r for r, c in blocked_counts.items() if c > 0]
                ),
                RuleOverride.is_active == True,
                or_(
                    RuleOverride.expires_at.is_(None),
                    RuleOverride.expires_at > func.now(),
                ),
                or_(*scope_clauses),
            )
        )).all()

        owner_for: dict[str, "UUID"] = {}
        for oid, rule_id, repo_id, src_id in rows:
            is_scoped = repo_id is not None or src_id is not None
            if rule_id not in owner_for or is_scoped:
                owner_for[rule_id] = oid

        for rule_id, count in blocked_counts.items():
            if count <= 0 or rule_id not in owner_for:
                continue
            await db.execute(
                update(RuleOverride)
                .where(RuleOverride.id == owner_for[rule_id])
                .values(times_blocked=RuleOverride.times_blocked + count)
            )
        logger.info(
            "rule_overrides.blocks_recorded",
            tenant_id=str(tenant_id),
            repository_id=str(repository_id) if repository_id else None,
            scan_source_id=str(scan_source_id) if scan_source_id else None,
            total_blocks=sum(blocked_counts.values()),
            rules_hit=len(blocked_counts),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "rule_overrides.record_failed",
            tenant_id=str(tenant_id),
            repository_id=str(repository_id) if repository_id else None,
            scan_source_id=str(scan_source_id) if scan_source_id else None,
            error=str(exc),
        )


def new_block_counter() -> dict[str, int]:
    """Factory for the dict the persist loop accumulates into.

    Wraps ``defaultdict(int)`` so the call site can do
    ``counter[rule_id] += 1`` without a key-existence check.
    """
    return defaultdict(int)
