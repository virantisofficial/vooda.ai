# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Applying an incident-level verdict to the findings underneath it.

A secret leaks once and shows up in N places. The incident is the
credential; the findings are where it was seen. So a decision about the
credential — rotated, false positive, accepted risk — belongs to every
occurrence of it.

Every propagation site used to write this by hand, and they disagreed in
three ways that each produced a bug:

  * some sites did not propagate at all, so rotating a credential left
    its findings open forever and the dashboard never moved;
  * the sites that did propagate overwrote occurrences that a person had
    already judged, silently replacing one human's verdict with
    another's;
  * they wrote `CONFIRMED_*` through a Core UPDATE, which the ORM-level
    provenance guard cannot see — the one write the guard exists to
    refuse.

One helper, three rules: only undecided occurrences are touched, a
confirmation always carries its provenance, and the count comes back so
callers can report what actually happened.
"""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.classification_provenance import build, requires_provenance
from apps.api.app.models.finding import Classification, NormalizedFinding, ReviewStatus

#: Occurrences nobody has ruled on yet. A verdict propagates into these
#: and stops at anything a person decided — accepted risk, a confirmed
#: verdict, a test credential, or a closure that already happened.
UNDECIDED = (
    Classification.NEEDS_REVIEW,
    Classification.LIKELY_TRUE_POSITIVE,
    Classification.LIKELY_FALSE_POSITIVE,
)


async def propagate_to_occurrences(
    db: AsyncSession,
    *,
    incident_id: Any,
    tenant_id: Any,
    classification: Classification,
    mechanism: str,
    actor: Any = None,
    now: Any = None,
    exclude_finding_id: Any = None,
    note: Optional[str] = None,
) -> int:
    """Apply `classification` to the incident's undecided occurrences.

    Returns how many rows changed, so a caller can tell the user that
    something happened even when the incident itself was already in the
    target state.
    """
    if incident_id is None:
        return 0

    values: dict = {
        "classification": classification,
        "review_status": ReviewStatus.REVIEWED,
    }
    if now is not None:
        values["updated_at"] = now
    # A Core UPDATE bypasses the ORM guard, so the provenance has to be
    # written here explicitly or the row lands unattributable.
    if requires_provenance(classification):
        values["classification_provenance"] = build(
            mechanism=mechanism, actor=actor, note=note,
        )

    stmt = (
        update(NormalizedFinding)
        .where(
            NormalizedFinding.incident_id == incident_id,
            NormalizedFinding.tenant_id == tenant_id,
            NormalizedFinding.classification.in_(UNDECIDED),
        )
        .values(**values)
    )
    if exclude_finding_id is not None:
        stmt = stmt.where(NormalizedFinding.id != exclude_finding_id)

    result = await db.execute(stmt)
    return result.rowcount or 0
