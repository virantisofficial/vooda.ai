# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Secret-incident API — Case-B aggregation surface.

An "incident" represents one unique credential exposure regardless of
how many locations it appears in.  This router exposes the
SecretIncident table in two shapes:

* ``GET /incidents`` — paginated list.  Powers an "incidents" view
  alongside the existing per-occurrence findings list.
* ``GET /incidents/{id}`` — incident detail with its occurrences.
  Powers the drill-down: "show me every location where this
  credential was found."

Triage actions (mark TP / FP / accepted risk / rotated) belong on
this router too, since they're decisions about the CREDENTIAL not
the location.  Those are wired up below as PATCH endpoints.

Why a separate router (rather than nesting under /findings):
The existing /findings router is large and per-occurrence.  Mixing
incident endpoints in would muddy responsibility.  Keeping them
separate also lets the UI evolve toward an incident-primary
experience (à la GitGuardian) without entangling the routes.
"""

from typing import Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.database import get_db
from apps.api.app.core.access_control import get_accessible_repo_ids
from apps.api.app.models.finding import NormalizedFinding, SecretIncident
from apps.api.app.models.user import User
from apps.api.app.routers.auth import get_current_user

router = APIRouter()


class IncidentSignals(BaseModel):
    """Deterministic scanner-signal flags aggregated across an incident's
    occurrences.  Powers the SuggestionChips UI on the drawer + standalone
    page (gap #6 from the commercial-grade audit — Option B).

    Aggregation rule is "ALL occurrences agree" — an incident-level chip
    only fires when EVERY underlying occurrence carries the flag.  If
    even one occurrence is in prod code (not a test file), the incident
    isn't safely a test-credential.

    Computed once during GET /incidents/{id} from the occurrence
    source_metadata.  None when no occurrences exist or none of them
    carry the flag.
    """
    is_placeholder: bool = False        # every occurrence's value matched a placeholder pattern
    is_test_file_only: bool = False     # every occurrence lives in a test/spec/fixture file
    is_git_history_only: bool = False   # every occurrence comes from git-history scan (not current code)


class IncidentOut(BaseModel):
    """Public shape for a SecretIncident row.

    Fields mirror the model 1:1 except `tags` which has the same
    nullable-list-to-empty coercion the findings router uses.
    """
    id: UUID
    tenant_id: UUID
    title: str
    secret_type: Optional[str] = None
    masked_value: Optional[str] = None
    severity_max: str
    occurrence_count: int
    classification: str
    review_status: str
    validation_status: Optional[str] = None
    last_validated_at: Optional[datetime] = None
    rotation_status: Optional[str] = None
    rotated_at: Optional[datetime] = None
    assigned_to: Optional[UUID] = None
    tags: Optional[list[str]] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    ai_explanation: Optional[str] = None
    ai_confidence: Optional[float] = None
    created_at: datetime
    updated_at: datetime
    # Optimistic-lock counter — the UI sends this back as
    # ``expected_version`` on PATCH so concurrent edits surface as 409
    # rather than silently overwriting each other.  See model docstring.
    version: int = 1
    # Derived signals — only populated on the detail GET, not on the
    # list endpoint (where it'd be N round trips per row).
    signals: Optional[IncidentSignals] = None

    model_config = {"from_attributes": True}

    @field_validator("tags", mode="before")
    @classmethod
    def _none_tags_to_empty(cls, v):
        return v if v is not None else []


class IncidentOccurrence(BaseModel):
    """Minimal occurrence shape returned inline on incident detail."""
    id: UUID
    title: str
    severity: str
    file_path: str
    line_start: Optional[int] = None
    scan_source_id: Optional[UUID] = None
    repository_id: Optional[UUID] = None
    classification: str
    remediation_status: str
    created_at: datetime
    last_seen_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class IncidentDetail(IncidentOut):
    """Incident + the list of occurrences (per-location records).

    Each occurrence is a NormalizedFinding row pointing at this
    incident_id.  The UI typically renders this as the expanded
    "View all N locations" panel under the incident header.
    """
    occurrences: list[IncidentOccurrence] = []


@router.get("")
async def list_incidents(
    severity_max: Optional[str] = Query(None, description="critical | high | medium | low | info"),
    classification: Optional[str] = Query(None),
    review_status: Optional[str] = Query(None),
    validation_status: Optional[str] = Query(None),
    rotation_status: Optional[str] = Query(None),
    assigned_to: Optional[UUID] = Query(None),
    search: Optional[str] = Query(None, description="Substring match on title / masked_value / secret_type"),
    sort_by: str = Query("last_seen_at", description="last_seen_at | first_seen_at | severity_max | occurrence_count | title"),
    sort_dir: str = Query("desc"),
    # An incident is hidden when ALL its occurrences are in archived
    # repos (cross-scope survival rule, same logic as orphan-close on
    # delete).  Override with ?include_archived_sources=true.
    include_archived_sources: bool = Query(False),
    # Hide incidents whose credential was verified DEAD (incident
    # validation_status == "inactive"). Default-hidden from the active-risk
    # view; the `hidden_inactive` count is returned so the UI can offer a
    # "show dead credentials" toggle. Override with ?include_inactive=true.
    include_inactive: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Paginated list of secret incidents for the current tenant.

    Access control: the caller sees incidents whose occurrences fall
    within their accessible repository scope.  Cross-tenant isolation
    is enforced via the tenant_id filter (TenantMixin's standard).
    """
    base = [SecretIncident.tenant_id == user.tenant_id]

    # Repo access scope — limit incidents whose occurrences sit in
    # repos this user can see.  When the user has full tenant scope,
    # `get_accessible_repo_ids` returns None and we skip the join.
    accessible = await get_accessible_repo_ids(db, user)
    if accessible is not None:
        # An incident is visible if it has at least one occurrence in
        # an accessible repo OR at least one source-scan occurrence
        # (which isn't repo-scoped).  We accept both via EXISTS.
        from sqlalchemy import exists
        visibility = exists(
            select(NormalizedFinding.id).where(
                NormalizedFinding.incident_id == SecretIncident.id,
                (NormalizedFinding.repository_id.in_(accessible)) | (NormalizedFinding.scan_source_id.isnot(None)),
            )
        )
        base.append(visibility)

    if severity_max:
        base.append(SecretIncident.severity_max == severity_max)
    if classification:
        base.append(SecretIncident.classification == classification)
    if review_status:
        base.append(SecretIncident.review_status == review_status)
    if validation_status:
        base.append(SecretIncident.validation_status == validation_status)
    if rotation_status:
        base.append(SecretIncident.rotation_status == rotation_status)
    if assigned_to:
        base.append(SecretIncident.assigned_to == assigned_to)
    if search:
        like = f"%{search}%"
        from sqlalchemy import or_
        base.append(or_(
            SecretIncident.title.ilike(like),
            SecretIncident.masked_value.ilike(like),
            SecretIncident.secret_type.ilike(like),
        ))

    # ── Archive filter ─────────────────────────────────────────────
    # Hide incidents whose EVERY occurrence is in an archived parent.
    # "Archived parent" covers both:
    #   - Repository with metadata.archived == true
    #   - ScanSource with is_active == false
    # Survival rule: an incident stays visible if it has at least one
    # occurrence whose parent is NOT archived.  Mirrors the orphan-
    # survival logic from delete_repository / delete_scan_source.
    if not include_archived_sources:
        from sqlalchemy import exists, literal_column, or_, and_
        from apps.api.app.models.repository import Repository
        from apps.api.app.models.scan_source import ScanSource
        archived_repo_ids = select(Repository.id).where(
            Repository.tenant_id == user.tenant_id,
            literal_column("repositories.metadata->>'archived'") == "true",
        ).scalar_subquery()
        archived_source_ids = select(ScanSource.id).where(
            ScanSource.tenant_id == user.tenant_id,
            ScanSource.is_active == False,  # noqa: E712
        ).scalar_subquery()
        # An occurrence is "non-archived" when:
        #   - it's a source-only finding AND its source is NOT in archived_source_ids, OR
        #   - it's a repo finding AND its repo is NOT in archived_repo_ids
        non_archived_occurrence = exists(
            select(NormalizedFinding.id).where(
                NormalizedFinding.incident_id == SecretIncident.id,
                or_(
                    # source occurrence with a non-archived source
                    and_(
                        NormalizedFinding.scan_source_id.isnot(None),
                        ~NormalizedFinding.scan_source_id.in_(archived_source_ids),
                    ),
                    # repo occurrence with a non-archived repo
                    and_(
                        NormalizedFinding.repository_id.isnot(None),
                        ~NormalizedFinding.repository_id.in_(archived_repo_ids),
                    ),
                ),
            )
        )
        base.append(non_archived_occurrence)

    # ── Verified-dead filter (default) ──────────────────────────────
    # Hide incidents whose credential was verified DEAD (incident
    # validation_status == "inactive", set by the scan/re-verify pipeline —
    # S3). PRECISE: keys off the incident's own validation_status, NOT the
    # generic is_suppressed flag — so correlation's duplicate_same_scanner
    # suppressions (which leave validation_status null) are NOT affected. The
    # `hidden_inactive` count lets the UI offer a "show N dead credentials"
    # toggle. Reverses automatically when a credential is live again (the
    # pipeline flips validation_status back). Override with ?include_inactive=true.
    hidden_inactive = 0
    if not include_inactive:
        from sqlalchemy import or_ as _or
        hidden_inactive = (await db.execute(
            select(sa_func.count(SecretIncident.id)).where(
                *base, SecretIncident.validation_status == "inactive")
        )).scalar() or 0
        base.append(_or(
            SecretIncident.validation_status.is_(None),
            SecretIncident.validation_status != "inactive",
        ))

    total_q = select(sa_func.count(SecretIncident.id)).where(*base)
    total = (await db.execute(total_q)).scalar() or 0

    sort_map = {
        "last_seen_at": SecretIncident.last_seen_at,
        "first_seen_at": SecretIncident.first_seen_at,
        "severity_max": SecretIncident.severity_max,
        "occurrence_count": SecretIncident.occurrence_count,
        "title": SecretIncident.title,
        "created_at": SecretIncident.created_at,
    }
    sort_col = sort_map.get(sort_by, SecretIncident.last_seen_at)
    order = sort_col.asc() if sort_dir == "asc" else sort_col.desc()

    q = (
        select(SecretIncident)
        .where(*base)
        .order_by(order)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await db.execute(q)).scalars().all()

    return {
        "items": rows,
        "total": total,
        # Count of incidents hidden by the verified-dead filter (0 when
        # include_inactive=true). Lets the UI offer a "show N dead credentials"
        # toggle without a second round-trip.
        "hidden_inactive": hidden_inactive,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
    }


@router.get("/{incident_id}")
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Incident detail with every occurrence inline.

    Returns the SecretIncident row plus every NormalizedFinding
    linked to it (occurrences) for in-place drill-down.
    """
    inc_q = await db.execute(
        select(SecretIncident).where(
            SecretIncident.id == incident_id,
            SecretIncident.tenant_id == user.tenant_id,
        )
    )
    incident = inc_q.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    occ_q = await db.execute(
        select(NormalizedFinding)
        .where(NormalizedFinding.incident_id == incident.id)
        .order_by(NormalizedFinding.created_at.desc())
    )
    occurrences = occ_q.scalars().all()

    # Build the detail explicitly from the parent fields + the
    # already-loaded occurrences list.  Going through
    # ``IncidentDetail.model_validate(incident, from_attributes=True)``
    # would trigger Pydantic to walk every field including
    # ``occurrences``, which is a lazy SQLAlchemy relationship — the
    # lazy load issues a sync `await_only` call from inside Pydantic's
    # extraction context, which crashes with MissingGreenlet.  By
    # constructing IncidentOut first (no relationship fields) and
    # then merging the explicitly-loaded occurrences into the
    # IncidentDetail kwargs, we avoid any deferred IO during
    # validation.
    base = IncidentOut.model_validate(incident, from_attributes=True).model_dump()

    # Aggregate per-occurrence scanner signals into incident-level
    # booleans.  Rule: ALL occurrences must agree before the chip
    # fires (e.g. one prod-code occurrence vetoes the test_file chip).
    # Done here rather than in the SQL query because source_metadata is
    # JSONB and the conditional logic (default-False on missing keys,
    # all-vs-any semantics) is cleaner in Python.
    sm_list: list[dict] = [
        (o.source_metadata or o.raw_data or {}) for o in occurrences
    ]
    base["signals"] = {
        "is_placeholder": (
            bool(sm_list) and all(sm.get("is_placeholder") is True for sm in sm_list)
        ),
        "is_test_file_only": (
            bool(sm_list) and all(sm.get("file_context") == "test_file" for sm in sm_list)
        ),
        "is_git_history_only": (
            bool(sm_list) and all(sm.get("detection_engine") == "secret_scan_history" for sm in sm_list)
        ),
    }

    return IncidentDetail(
        **base,
        occurrences=[
            IncidentOccurrence.model_validate(o, from_attributes=True) for o in occurrences
        ],
    )


# ── History / audit timeline ─────────────────────────────────────────
#
# Surfaces the audit trail for a single incident so the
# IncidentDetailDrawer's History tab can render a timeline that
# mirrors FindingPanel's `decisions` list.  All entries already get
# written by patch_incident + bulk_mark_rotated via log_audit; this
# endpoint just exposes them filtered by resource_id and normalized
# into a shape the UI can render without further mapping.
#
# Added 2026-05-17 to close the compliance gap flagged in the
# commercial-grade audit (SOC 2 / ISO 27001 traceability).

class IncidentHistoryEntry(BaseModel):
    id: str
    action: str
    # Synthetic short "kind" the UI uses to pick a coloured dot:
    #   mark_tp / mark_fp / mark_rotated / mark_test / accept_risk /
    #   reopen / assigned / unassigned / tagged / other
    kind: str
    # Pretty label rendered as the row title (e.g. "Marked True Positive").
    label: str
    previous_classification: Optional[str] = None
    new_classification: Optional[str] = None
    previous_review_status: Optional[str] = None
    new_review_status: Optional[str] = None
    previous_rotation_status: Optional[str] = None
    new_rotation_status: Optional[str] = None
    previous_assigned_to: Optional[str] = None
    new_assigned_to: Optional[str] = None
    comment: Optional[str] = None
    user_id: Optional[str] = None
    user_name: str
    created_at: str
    detail: Optional[str] = None
    via: Optional[str] = None  # e.g. "bulk_mark_rotated"


def _classify_incident_audit(
    action: str,
    changes: dict,
    previous: dict,
) -> tuple[str, str]:
    """Derive (kind, label) from a raw audit row for the timeline.

    Centralised here so the UI doesn't need to know how to interpret
    `changes` — backend ships a ready-to-render label + a short kind
    string that maps cleanly to a coloured dot.
    """
    if action == "incident_rotated" or (changes.get("rotation_status") == "rotated"):
        return ("mark_rotated", "Marked Rotated / Revoked")

    # Manual re-verify actions — distinct kind so the timeline
    # renders them with a teal dot ("validation" kind).  Two paths:
    # one ran the verifier successfully (status was updated), the
    # other found no verifier for the provider.
    if action == "incident_verified":
        new_val = (changes.get("validation_status") or "").lower()
        if new_val == "active":
            return ("validation", "Re-verified — credential is LIVE")
        if new_val in ("inactive", "revoked"):
            return ("validation", f"Re-verified — credential is {new_val}")
        if new_val:
            return ("validation", f"Re-verified — {new_val}")
        return ("validation", "Re-verified")
    if action == "incident_verify_attempted":
        return ("validation", "Re-verify attempted (provider unsupported)")

    cls = (changes.get("classification") or "").lower()
    if cls:
        if "true_positive" in cls:
            return ("mark_tp", "Marked True Positive")
        if "false_positive" in cls:
            return ("mark_fp", "Marked False Positive")
        if cls == "rotated":
            return ("mark_rotated", "Marked Rotated / Revoked")
        if cls == "test_credential":
            return ("mark_test", "Marked Test Credential")
        if cls == "accepted_risk":
            return ("accept_risk", "Marked Accepted Risk")
        if cls == "needs_review":
            return ("reopen", "Reopened for review")

    # No classification change — must be assign / tags / status-only.
    if "assigned_to" in changes:
        if changes.get("assigned_to"):
            return ("assigned", "Assigned")
        return ("unassigned", "Unassigned")
    if "tags" in changes:
        return ("tagged", "Updated tags")
    if "review_status" in changes:
        return ("review_status", f"Review status → {changes['review_status']}")
    if "validation_status" in changes:
        return ("validation", f"Validation → {changes['validation_status']}")
    return ("other", action.replace("_", " "))


@router.get("/{incident_id}/history", response_model=list[IncidentHistoryEntry])
async def get_incident_history(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Timeline of audit events for a single incident.

    Returns events newest-first (matches FindingPanel's History tab
    ordering).  Joins user_id → full_name in one query to avoid N+1.
    Cross-tenant requests get 404 (consistent with the rest of the
    router) — we verify ownership of the incident before fetching its
    history.
    """
    # Tenant ownership check — same 404-not-403 policy as the rest of
    # the router to avoid leaking cross-tenant existence.
    own_q = await db.execute(
        select(SecretIncident.id).where(
            SecretIncident.id == incident_id,
            SecretIncident.tenant_id == user.tenant_id,
        )
    )
    if own_q.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    from apps.api.app.models.audit import AuditEvent
    from apps.api.app.models.user import User as UserModel

    events_q = await db.execute(
        select(AuditEvent)
        .where(
            AuditEvent.tenant_id == user.tenant_id,
            AuditEvent.resource_type == "secret_incident",
            AuditEvent.resource_id == str(incident_id),
        )
        .order_by(AuditEvent.created_at.desc())
        .limit(200)
    )
    events = list(events_q.scalars().all())

    # Resolve user names in one round trip.
    user_ids = list({e.user_id for e in events if e.user_id})
    user_map: dict = {}
    if user_ids:
        users_r = await db.execute(select(UserModel).where(UserModel.id.in_(user_ids)))
        user_map = {u.id: u.full_name for u in users_r.scalars().all()}

    # Assigned-to user resolution: if `changes.assigned_to` is a UUID
    # string, render the user's full name on the row (matches the
    # meta-bar pattern).  Cache to avoid repeated lookups.
    assignee_ids: set[str] = set()
    for e in events:
        m = e.metadata_ or {}
        for src in (m.get("changes", {}), m.get("previous", {})):
            v = src.get("assigned_to") if isinstance(src, dict) else None
            if isinstance(v, str) and len(v) == 36:
                assignee_ids.add(v)
    assignee_name_map: dict = {}
    if assignee_ids:
        from uuid import UUID as _UUID
        try:
            uuid_objs = [_UUID(a) for a in assignee_ids]
            ar = await db.execute(select(UserModel).where(UserModel.id.in_(uuid_objs)))
            assignee_name_map = {str(u.id): u.full_name for u in ar.scalars().all()}
        except Exception:  # noqa: BLE001
            assignee_name_map = {}

    def _name_for(uid_str: Optional[str]) -> Optional[str]:
        if not uid_str:
            return None
        return assignee_name_map.get(uid_str, uid_str)

    out: list[IncidentHistoryEntry] = []
    for e in events:
        meta = e.metadata_ or {}
        changes = meta.get("changes") or {}
        previous = meta.get("previous") or {}
        kind, label = _classify_incident_audit(e.action, changes, previous)

        out.append(IncidentHistoryEntry(
            id=str(e.id),
            action=e.action,
            kind=kind,
            label=label,
            previous_classification=previous.get("classification"),
            new_classification=changes.get("classification"),
            previous_review_status=previous.get("review_status"),
            new_review_status=changes.get("review_status"),
            previous_rotation_status=previous.get("rotation_status"),
            new_rotation_status=changes.get("rotation_status"),
            previous_assigned_to=_name_for(previous.get("assigned_to")),
            new_assigned_to=_name_for(changes.get("assigned_to")),
            comment=meta.get("comment"),
            user_id=str(e.user_id) if e.user_id else None,
            user_name=user_map.get(e.user_id, "System"),
            created_at=str(e.created_at),
            detail=e.detail,
            via=meta.get("via"),
        ))
    return out


# ── Manual re-verification ───────────────────────────────────────────
#
# An incident is the credential itself, and the credential value is
# identical across all of its occurrences (same secret_hash).  So
# verifying any one occurrence's source_metadata gives us the
# definitive verification status for the incident — we then propagate
# the result to incident.validation_status + every occurrence's
# source_metadata so the per-finding views stay in lockstep with the
# incident-level view.
#
# Mirrors POST /findings/{id}/verify but at the credential level,
# which is where re-verify conceptually belongs (rotating once kills
# every occurrence at once).
#
# Added 2026-05-17 — the commercial-grade audit flagged this as a
# parity gap: re-verify on Findings forces the user to navigate into
# one specific occurrence rather than acting on the credential itself.


@router.post("/{incident_id}/verify")
async def verify_incident_credential(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Re-run live verification against the provider API for an incident.

    Strategy:
      1. Tenant-scope check on the incident
      2. Pick the most-recently-seen occurrence — its
         ``source_metadata`` carries the credential payload the
         verifier needs (same credential as every other occurrence;
         just a question of which row's metadata we hand in)
      3. Call ``services.secret_verification.verifier.verify_finding``
      4. Update incident.validation_status + incident.last_validated_at
      5. Patch every occurrence's source_metadata so the Findings
         drawer's Validation card reflects the same status
      6. Auto-run Blast Radius analysis when the result is "active"
         (matches the Findings verify path)
      7. Audit-log the action — shows up in the History tab with
         kind="validation"
    """
    own_q = await db.execute(
        select(SecretIncident).where(
            SecretIncident.id == incident_id,
            SecretIncident.tenant_id == user.tenant_id,
        )
    )
    incident = own_q.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Pick the most-recently-seen occurrence as the canonical source.
    # `last_seen_at` may be NULL on older rows — fall back to created_at
    # for the ordering so we always get *some* result.
    occ_q = await db.execute(
        select(NormalizedFinding)
        .where(NormalizedFinding.incident_id == incident.id)
        .order_by(
            NormalizedFinding.last_seen_at.desc().nullslast(),
            NormalizedFinding.created_at.desc(),
        )
        .limit(1)
    )
    occurrence = occ_q.scalar_one_or_none()
    if occurrence is None:
        # An incident with zero occurrences is a data-integrity bug,
        # not a user error — but we still respond gracefully.
        return {"status": "error", "message": "Incident has no occurrences to verify against."}

    sm = occurrence.source_metadata or occurrence.raw_data or {}

    from services.secret_verification.verifier import verify_finding as _verify, SUPPORTED_PROVIDERS
    from apps.api.app.core.audit import log_audit

    provider = (sm.get("provider") or "").lower()
    if provider not in SUPPORTED_PROVIDERS:
        # No verifier ships for this provider yet — incident-level
        # validation_status is left untouched.  Audit log records the
        # attempt so the History tab shows the user tried.
        await log_audit(
            db, user, "incident_verify_attempted", "secret_incident",
            resource_id=incident.id,
            detail=f"unsupported_provider={provider}",
            metadata={
                "incident_id": str(incident.id),
                "changes": {"validation_status": "unsupported"},
                "previous": {"validation_status": incident.validation_status},
                "via": "manual_reverify",
            },
        )
        await db.commit()
        return {"status": "unsupported", "message": f"No verifier for provider: {provider}"}

    verification = await _verify(sm)
    if not verification:
        return {"status": "error", "message": "Verification failed"}

    # Propagate to all occurrences so the Findings drawer shows the
    # same fresh result.  Done in Python (not a single UPDATE ... SET
    # source_metadata=jsonb_set(...)) because the verifier returns
    # multiple fields and we want them all merged atomically per row.
    all_occ_q = await db.execute(
        select(NormalizedFinding).where(NormalizedFinding.incident_id == incident.id)
    )
    blast_radius_dict = None
    if verification.status == "active":
        try:
            from services.secret_verification.blast_radius import analyze_blast_radius
            br_result = await analyze_blast_radius({
                **sm,
                "validation_status": verification.status,
                "verification_details": verification.details,
                "verification_permissions": verification.permissions,
            })
            if br_result:
                blast_radius_dict = br_result.to_dict()
        except Exception:  # noqa: BLE001
            # Blast radius is best-effort enrichment — never block the
            # verify response on its failure.
            blast_radius_dict = None

    prev_validation_status = incident.validation_status

    for occ in all_occ_q.scalars().all():
        merged = dict(occ.source_metadata or occ.raw_data or {})
        merged["validation_status"] = verification.status
        merged["verification_details"] = verification.details
        merged["verification_permissions"] = verification.permissions
        if blast_radius_dict is not None:
            merged["blast_radius"] = blast_radius_dict
        occ.source_metadata = merged

    incident.validation_status = verification.status
    incident.last_validated_at = datetime.utcnow()

    await log_audit(
        db, user, "incident_verified", "secret_incident",
        resource_id=incident.id,
        detail=f"validation_status={verification.status}; provider={verification.provider}",
        metadata={
            "incident_id": str(incident.id),
            "changes": {"validation_status": verification.status},
            "previous": {"validation_status": prev_validation_status},
            "comment": verification.details,
            "via": "manual_reverify",
        },
    )

    await db.commit()
    return {
        "status": verification.status,
        "details": verification.details,
        "permissions": verification.permissions,
        "provider": verification.provider,
        "blast_radius": blast_radius_dict,
    }


class IncidentTriagePatch(BaseModel):
    """Incident-level triage update.

    Frontend sends this to mark an incident as TP / FP / Accepted Risk
    / Rotated etc.  Setting classification on the incident is the
    canonical place — per-occurrence classification on
    NormalizedFinding is a denormalized cache (kept in sync for
    backwards-compatible UI behaviour).

    Optional ``comment`` rides along to the audit log so triage
    decisions carry a "why" trail (matches the Findings drawer's
    save-with-comment pattern).  Never persisted on the incident row
    itself — it lives only in the audit record.

    Field validation (Track-A P0 #4, 2026-05-20)
    --------------------------------------------
    ``classification`` and ``review_status`` are validated against
    the canonical Classification / ReviewStatus enum vocabularies
    PLUS the incident-only `"confirmed"` review-status synonym that
    the cascade code maps to REVIEWED.  Stops a direct API caller
    (CI script, malicious user, sloppy integration) from writing
    arbitrary garbage into the column.

    The underlying ``SecretIncident.classification`` column is
    intentionally kept as ``String(40)`` rather than a strict
    Postgres enum: rows backfilled from older versions or
    other-vocabulary imports can still be loaded, and changing the
    DB type would require coordinating an enum migration across
    multiple writers.  Validating at the API boundary catches every
    write path without that risk.
    """
    classification: Optional[str] = None
    review_status: Optional[str] = None
    rotation_status: Optional[str] = None
    validation_status: Optional[str] = None
    assigned_to: Optional[UUID] = None

    # ── Vocabulary guards ────────────────────────────────────────
    # Imported locally inside the validators so the class definition
    # has no model-layer import (keeps Pydantic schemas decoupled).
    # The synonyms mirror what patch_incident's cascade already
    # translates (see the rs_map in patch_incident()).

    @field_validator("classification")
    @classmethod
    def _validate_classification(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        from apps.api.app.models.finding import Classification
        valid = {c.value for c in Classification}
        if v not in valid:
            raise ValueError(
                f"classification must be one of {sorted(valid)} (got {v!r})"
            )
        return v

    @field_validator("review_status")
    @classmethod
    def _validate_review_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        from apps.api.app.models.finding import ReviewStatus
        # The incident vocabulary historically also accepted "confirmed"
        # as a synonym for "reviewed" (see the rs_map cascade in
        # patch_incident).  Keep accepting it so frontend rev-N clients
        # don't regress, but reject anything outside this union.
        valid = {s.value for s in ReviewStatus} | {"confirmed"}
        if v not in valid:
            raise ValueError(
                f"review_status must be one of {sorted(valid)} (got {v!r})"
            )
        return v

    @field_validator("rotation_status")
    @classmethod
    def _validate_rotation_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        # Free strings used historically: rotated / pending / in_progress
        # / failed / overdue.  Lock the vocabulary to those + None.
        valid = {"rotated", "pending", "in_progress", "failed", "overdue"}
        if v not in valid:
            raise ValueError(
                f"rotation_status must be one of {sorted(valid)} (got {v!r})"
            )
        return v
    # Tag list replacement (Findings drawer parity — IncidentDetailDrawer
    # rev 3 mounts a tag editor in the meta bar the same way FindingPanel
    # does, so we accept the full replacement list on save).  Empty list
    # clears all tags; ``None`` leaves them untouched.
    tags: Optional[list[str]] = None
    comment: Optional[str] = None
    # Provenance marker — when the action came from a SuggestionChip
    # click (gap #6) the frontend sets this to "suggestion_placeholder",
    # "suggestion_test_file", "suggestion_git_history".  Surfaced in the
    # audit metadata `via` field so the History tab can render
    # signal-confirmed actions distinctly from manual triage and so
    # compliance can answer "what % of TPs were AI-suggested?".
    source: Optional[str] = None
    # Optimistic-lock token from the row the client loaded.  When set,
    # a mismatch with the current row triggers HTTP 409 so the user
    # can reload instead of overwriting another reviewer's save.
    # When ``None``, the check is skipped — preserves backwards-compat
    # for non-UI callers (CI scripts / integrations) that haven't
    # adopted the protocol yet.
    expected_version: Optional[int] = None


@router.patch("/{incident_id}")
async def patch_incident(
    incident_id: UUID,
    patch: IncidentTriagePatch,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update incident-level triage state.

    Cascades classification/review_status changes to all occurrences
    of this incident so the existing /findings list UI stays
    consistent until that UI fully migrates to the incident model.
    """
    inc_q = await db.execute(
        select(SecretIncident).where(
            SecretIncident.id == incident_id,
            SecretIncident.tenant_id == user.tenant_id,
        )
    )
    incident = inc_q.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    # ── Optimistic-lock check ────────────────────────────────────
    # When the client passes ``expected_version``, reject the write
    # if the row has moved on under us — typically another reviewer
    # saved a different decision in the same window.  Return 409
    # with the current version so the UI can refetch and re-prompt.
    # When ``expected_version`` is omitted (older clients / scripts),
    # we keep the legacy last-write-wins behaviour — SQLAlchemy still
    # bumps ``version`` automatically on flush via
    # ``__mapper_args__["version_id_col"]`` so the next caller will
    # see the new value.
    if patch.expected_version is not None and patch.expected_version != incident.version:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "stale_version",
                "message": "Incident was modified by another reviewer; reload and retry.",
                "current_version": incident.version,
                "expected_version": patch.expected_version,
            },
        )

    # Capture pre-patch values so the audit metadata can record the
    # "previous → new" arrow that the IncidentDetailDrawer's History
    # timeline renders.  Mirrors what NormalizedFinding.decisions
    # carries on the Findings side.  Read BEFORE mutating below.
    prev_classification = incident.classification
    prev_review_status = incident.review_status
    prev_rotation_status = incident.rotation_status
    prev_assigned_to = incident.assigned_to

    if patch.classification is not None:
        incident.classification = patch.classification
    if patch.review_status is not None:
        incident.review_status = patch.review_status
    if patch.rotation_status is not None:
        incident.rotation_status = patch.rotation_status
        if patch.rotation_status == "rotated":
            incident.rotated_at = datetime.utcnow()
    if patch.validation_status is not None:
        incident.validation_status = patch.validation_status
    if patch.assigned_to is not None:
        incident.assigned_to = patch.assigned_to
    if patch.tags is not None:
        # Lowercase + dedupe — matches the convention FindingPanel
        # already enforces client-side on updateFindingTags.  Keeping
        # the canonical form server-side too so tag filters stay
        # case-insensitive without client coordination.
        seen: set[str] = set()
        cleaned: list[str] = []
        for t in patch.tags:
            tn = (t or "").strip().lower()
            if tn and tn not in seen:
                seen.add(tn)
                cleaned.append(tn)
        incident.tags = cleaned

    # Cascade classification / review_status to occurrences so the
    # legacy per-finding views remain in sync.  Future cleanup once
    # the UI migrates fully to incident-level: drop this cascade and
    # have the finding read its classification from the incident.
    if patch.classification is not None or patch.review_status is not None:
        from sqlalchemy import update as sa_update
        updates = {}
        if patch.classification is not None:
            # Re-translate to the uppercase native_enum form used by
            # NormalizedFinding.classification.
            updates["classification"] = patch.classification.upper()
        if patch.review_status is not None:
            # SecretIncident.review_status is a free String(40) and the
            # IncidentDetailDrawer writes domain values like
            # "confirmed" / "unreviewed".  NormalizedFinding.review_status
            # is a strict PostgreSQL enum (ReviewStatus) with only
            # UNREVIEWED / IN_REVIEW / REVIEWED / DISPUTED.  Bug found
            # E2E on 2026-05-17: the cascade did .upper() blindly and
            # tried to push "CONFIRMED" into the enum, which 500's.
            # Map the incident vocabulary onto the finding enum:
            #   unreviewed → UNREVIEWED  (re-opened for triage)
            #   confirmed  → REVIEWED    (a triage decision has been made)
            #   anything else → pass through uppercase as a best-effort
            #   (covers "in_review" → IN_REVIEW, "disputed" → DISPUTED).
            rs_in = (patch.review_status or "").strip().lower()
            rs_map = {
                "unreviewed": "UNREVIEWED",
                "confirmed": "REVIEWED",
                "in_review": "IN_REVIEW",
                "reviewed": "REVIEWED",
                "disputed": "DISPUTED",
            }
            updates["review_status"] = rs_map.get(rs_in, rs_in.upper())
        await db.execute(
            sa_update(NormalizedFinding)
            .where(NormalizedFinding.incident_id == incident.id)
            .values(**updates)
        )

    # Audit log entry — captures which field(s) changed + the optional
    # comment so the audit trail answers "who marked this and why".
    # Matches the Findings drawer's save-with-comment contract.
    from apps.api.app.core.audit import log_audit
    changed = patch.model_dump(exclude_unset=True, exclude={"comment"})
    if changed or patch.comment:
        detail_parts: list[str] = []
        for k, v in changed.items():
            detail_parts.append(f"{k}={v}")
        if patch.comment:
            detail_parts.append(f"comment={patch.comment[:200]!r}")
        await log_audit(
            db, user, "incident_triaged", "secret_incident",
            resource_id=incident.id,
            detail="; ".join(detail_parts)[:500],
            metadata={
                "incident_id": str(incident.id),
                "changes": {k: (str(v) if isinstance(v, UUID) else v) for k, v in changed.items()},
                # Snapshot of values BEFORE this patch so the History
                # timeline can render "needs_review → confirmed_true_positive"
                # arrows.  Only the relevant deltas are included.
                "previous": {
                    "classification": prev_classification,
                    "review_status": prev_review_status,
                    "rotation_status": prev_rotation_status,
                    "assigned_to": str(prev_assigned_to) if prev_assigned_to else None,
                },
                "comment": patch.comment,
                # `via` is rendered as a small chip on each History
                # timeline row — defaults to "manual" but the
                # SuggestionChips UI flips it to e.g.
                # "suggestion_placeholder" so compliance can audit
                # signal-driven actions distinctly.
                "via": patch.source or "manual",
            },
        )

    # ── Belt + braces: catch the StaleDataError that fires when a
    # concurrent transaction beat us between SELECT and UPDATE.  The
    # pre-flight check above handles the common case (client knew
    # the version), but the race window between SELECT and flush can
    # still bite under heavy concurrent triage.  SQLAlchemy's
    # version_id_col plumbing folds the version into the UPDATE's
    # WHERE clause and raises StaleDataError on a zero-row result.
    from sqlalchemy.orm.exc import StaleDataError
    try:
        await db.commit()
    except StaleDataError:
        await db.rollback()
        # Re-read current state so the client sees the live version
        # in the response and can prompt the user to reload.
        await db.refresh(incident)
        raise HTTPException(
            status_code=409,
            detail={
                "error": "stale_version",
                "message": "Incident was modified by another reviewer mid-flight; reload and retry.",
                "current_version": incident.version,
                "expected_version": patch.expected_version,
            },
        )
    await db.refresh(incident)

    # ── Auto re-verify after rotation (Track-A P0 #3) ────────────
    # Symmetric with bulk_mark_rotated: when the single-incident PATCH
    # flips rotation_status to "rotated", queue an async verifier run
    # so we don't ship a "rotated" badge while the credential is
    # still live on the provider.  We only enqueue when the change
    # was actually applied in THIS call (not when the row was already
    # rotated) — `patch.rotation_status == "rotated"` is the signal
    # we acted on the flip just above.
    if patch.rotation_status == "rotated" and prev_rotation_status != "rotated":
        try:
            from apps.worker.tasks import reverify_incident_after_rotation
            reverify_incident_after_rotation.delay(
                str(incident.id), str(user.tenant_id), str(user.id),
            )
        except Exception as exc:  # noqa: BLE001
            import structlog
            structlog.get_logger("vooda.api.incidents").warning(
                "reverify_dispatch_failed_single",
                incident_id=str(incident.id),
                error=str(exc)[:200],
            )

    return IncidentOut.model_validate(incident, from_attributes=True)


# ── Bulk actions ─────────────────────────────────────────────────────

class BulkMarkRotatedRequest(BaseModel):
    """Body for POST /incidents/bulk-mark-rotated.

    A secret leaks once but appears in N locations — the rotate-once-
    kill-many UX that's uniquely secret-scanner-specific.  Bulk-marking
    incidents as rotated also records CredentialRotationEvent rows so
    the existing MTTR analytics on /rotation-events stay accurate.
    """
    incident_ids: list[UUID]
    note: Optional[str] = None  # optional free-text remark, surfaced in audit log

    @field_validator("incident_ids")
    @classmethod
    def _non_empty(cls, v: list[UUID]) -> list[UUID]:
        if not v:
            raise ValueError("incident_ids cannot be empty")
        if len(v) > 200:
            # Cap at 200 to keep the request size bounded.  Frontend
            # bulk-actions UI typically operates on a single page of
            # results (50–100 rows) — 200 is comfortable headroom.
            raise ValueError("Up to 200 incidents per bulk request")
        return v


class BulkMarkRotatedResponse(BaseModel):
    rotated: int     # incidents whose rotation_status transitioned to "rotated"
    already_rotated: int  # incidents that were already in rotated state
    not_found: int   # incident_ids that didn't resolve to a tenant row
    events_recorded: int  # CredentialRotationEvent rows created


@router.post("/bulk-mark-rotated", response_model=BulkMarkRotatedResponse)
async def bulk_mark_rotated(
    body: BulkMarkRotatedRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Mark N incidents as rotated in one call.

    Mirrors the single-incident PATCH path's behaviour (sets
    rotation_status + rotated_at) but in a single transaction across
    many incidents, AND also records a CredentialRotationEvent for
    each so MTTR analytics pick it up.

    Idempotent: incidents already in rotated state are counted
    separately rather than triggering a second event.  Cross-tenant
    incident_ids are silently dropped (counted as not_found) — same
    404-not-403 policy as the rest of the router to avoid leaking
    cross-tenant existence.
    """
    from apps.api.app.models.rotation_event import CredentialRotationEvent
    from apps.api.app.core.audit import log_audit

    now = datetime.utcnow()
    rotated = 0
    already = 0
    events_recorded = 0

    # Single query for all in-tenant incidents — avoid N+1 round trips.
    rows = await db.execute(
        select(SecretIncident).where(
            SecretIncident.id.in_(body.incident_ids),
            SecretIncident.tenant_id == user.tenant_id,
        )
    )
    incidents = list(rows.scalars().all())
    found_ids = {inc.id for inc in incidents}
    not_found = len(body.incident_ids) - len(found_ids)

    for incident in incidents:
        if (incident.rotation_status or "").lower() == "rotated":
            already += 1
            continue
        prev_rotation_status = incident.rotation_status
        incident.rotation_status = "rotated"
        incident.rotated_at = now
        rotated += 1

        # Per-incident audit entry — so the IncidentDetailDrawer's
        # History tab shows the rotation event.  The bulk summary
        # audit entry written at the end of this handler has
        # resource_id=None and is invisible to per-incident history
        # queries — bug fix 2026-05-17.  We also want one entry per
        # incident for forensic clarity ("when was THIS credential
        # rotated, by whom?").
        await log_audit(
            db, user, "incident_rotated", "secret_incident",
            resource_id=incident.id,
            detail=f"rotation_status=rotated (bulk{', note=' + repr(body.note[:200]) if body.note else ''})",
            metadata={
                "incident_id": str(incident.id),
                "changes": {"rotation_status": "rotated"},
                "previous": {"rotation_status": prev_rotation_status},
                "comment": body.note,
                "via": "bulk_mark_rotated",
            },
        )

        # Record a CredentialRotationEvent for MTTR analytics.
        #
        # The model requires non-NULL first_seen_active_at and
        # time_to_rotation_s.  When the incident never went through
        # live-validation (first_seen_at unset), we fall back to the
        # rotation moment itself, which yields time_to_rotation_s=0.
        # That's the honest answer: we didn't OBSERVE active-time for
        # this credential, so MTTR can't be longer than now-now=0.
        # The "manual_bulk" detected_via tag lets dashboards filter
        # these out of organic MTTR if desired.
        try:
            seen = incident.first_seen_at
            if seen is not None and seen.tzinfo is not None:
                # Strip tz so the arithmetic with naive `now` (utcnow)
                # works.  PG stores the value as timestamptz either way.
                seen = seen.replace(tzinfo=None)
            first_seen_active = seen if seen is not None else now
            time_to_rotation_s = max(0, int((now - first_seen_active).total_seconds()))

            event = CredentialRotationEvent(
                tenant_id=user.tenant_id,
                finding_id=None,
                repository_id=None,
                provider=(incident.secret_type or "unknown")[:64],
                secret_hash=incident.secret_hash,
                first_seen_active_at=first_seen_active,
                rotated_at=now,
                time_to_rotation_s=time_to_rotation_s,
                detected_via="manual_bulk",
                # NOTE: the SQLAlchemy attribute is `extra` even though
                # the underlying column is named `extra_data` — see
                # apps/api/app/models/rotation_event.py:63.  Passing
                # the wrong kwarg name silently no-ops the field on
                # construction (caught the hard way in QA).
                extra={
                    "incident_id": str(incident.id),
                    "actor_user_id": str(user.id),
                    "note": body.note,
                },
            )
            db.add(event)
            events_recorded += 1
        except Exception as exc:  # noqa: BLE001
            # MTTR-event recording is best-effort; never fail the
            # rotation update because the analytics row failed.  Log
            # so we can see real schema drift in QA rather than have
            # it silently disappear (the prior bug).
            import structlog
            structlog.get_logger("vooda.api.incidents").warning(
                "rotation_event_record_failed",
                incident_id=str(incident.id),
                error=str(exc)[:200],
            )

    await log_audit(
        db, user, "incidents_bulk_mark_rotated", "secret_incident",
        resource_id=None,
        detail=(
            f"Marked {rotated} incident(s) as rotated "
            f"({already} already rotated, {not_found} not found)"
        ),
        metadata={
            "rotated": rotated,
            "already_rotated": already,
            "not_found": not_found,
            "note": body.note,
        },
    )

    await db.commit()

    # ── Auto re-verify after rotation (Track-A P0 #3) ────────────
    # Dispatch async verification for each newly-rotated incident so
    # we close the loop: incident says "rotated", verifier confirms
    # the provider sees it as revoked (or surfaces the contradiction
    # in the audit row + UI as a stale rotation marker).  Best-effort
    # — failures to enqueue are logged but never roll back the
    # rotation itself (rotation is the user-affecting state; the
    # verify is the compliance-grade follow-up).
    if rotated > 0:
        try:
            from apps.worker.tasks import reverify_incident_after_rotation
            # Only enqueue for the incidents we actually flipped to
            # "rotated" in this call — skip the already-rotated ones
            # (their last validation is still relevant).
            for incident in incidents:
                if (incident.rotation_status or "").lower() != "rotated":
                    continue
                if incident.id not in {i.id for i in incidents if i.rotated_at == now}:
                    continue
                reverify_incident_after_rotation.delay(
                    str(incident.id), str(user.tenant_id), str(user.id),
                )
        except Exception as exc:  # noqa: BLE001
            # Dispatch failure is a soft signal — log it but don't
            # break the API response.  The rotation itself succeeded.
            import structlog
            structlog.get_logger("vooda.api.incidents").warning(
                "reverify_dispatch_failed",
                error=str(exc)[:200],
                rotated_count=rotated,
            )

    return BulkMarkRotatedResponse(
        rotated=rotated,
        already_rotated=already,
        not_found=not_found,
        events_recorded=events_recorded,
    )


# ── Bulk triage ──────────────────────────────────────────────────────
#
# Mirrors the IncidentDetailDrawer's status dropdown actions but
# applies them to N incidents in a single transaction.  Replaces the
# fan-out pattern the Findings list used to do (N parallel PATCHes)
# — at 5k+ incidents the difference is "4 hours vs 4 days" worth of
# triage work per analyst (the commercial-grade gap the user flagged).
#
# Same 6 actions as the drawer + a forwarded comment so the audit
# trail answers "who marked these 200 things and why".  Per-incident
# audit entries get `via="bulk_triage"` so the History tab can render
# that distinction.

# Action keyword → (classification, review_status, rotation_status?)
# tuple.  Mirrors the frontend ACTION_TO_PATCH map in the drawer
# (apps/web/src/components/incidents/IncidentDetailDrawer.tsx) so the
# two surfaces commit IDENTICAL state for the same action.
_BULK_TRIAGE_MAP: dict = {
    "mark_tp":      {"classification": "confirmed_true_positive", "review_status": "confirmed"},
    "mark_fp":      {"classification": "confirmed_false_positive", "review_status": "confirmed"},
    "mark_rotated": {"classification": "rotated",                  "review_status": "confirmed", "rotation_status": "rotated"},
    "mark_test":    {"classification": "test_credential",          "review_status": "confirmed"},
    "accept_risk":  {"classification": "accepted_risk",            "review_status": "confirmed"},
    "reopen":       {"classification": "needs_review",             "review_status": "unreviewed"},
}


class BulkTriageRequest(BaseModel):
    """Body for POST /incidents/bulk-triage.

    `action` must be one of the keys in _BULK_TRIAGE_MAP — pydantic
    validates membership server-side so a typo in the frontend can't
    push the database into an undefined state.

    `comment` rides along into each per-incident audit entry, matching
    the save-with-comment contract the single-incident PATCH already
    has.  Optional — bulk actions are sometimes obvious enough that
    no comment is needed (e.g. mass-cleanup of test-credential
    findings after an auto-detection rule lands).
    """
    incident_ids: list[UUID]
    action: str
    comment: Optional[str] = None

    @field_validator("incident_ids")
    @classmethod
    def _non_empty(cls, v: list[UUID]) -> list[UUID]:
        if not v:
            raise ValueError("incident_ids cannot be empty")
        if len(v) > 500:
            # Cap higher than bulk-mark-rotated (200) because triage
            # doesn't write a CredentialRotationEvent per incident, so
            # the per-row cost is lower.  500 is a comfortable upper
            # bound for a single page-of-results × select-all action
            # at the largest page size we support (200).
            raise ValueError("Up to 500 incidents per bulk-triage request")
        return v

    @field_validator("action")
    @classmethod
    def _known_action(cls, v: str) -> str:
        if v not in _BULK_TRIAGE_MAP:
            raise ValueError(
                f"Unknown action '{v}'. Must be one of: "
                + ", ".join(sorted(_BULK_TRIAGE_MAP.keys()))
            )
        return v


class BulkTriageResponse(BaseModel):
    updated: int      # incidents whose triage state was actually changed
    unchanged: int    # incidents already in the requested state (idempotent skip)
    not_found: int    # incident_ids that didn't resolve to a tenant row
    cascaded_findings: int  # NormalizedFinding rows updated as part of the cascade


@router.post("/bulk-triage", response_model=BulkTriageResponse)
async def bulk_triage_incidents(
    body: BulkTriageRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Apply the same triage action to N incidents in one transaction.

    Behaviour per incident:
      1. Skip if not in tenant (counted as not_found)
      2. Skip if already in the requested triage state (unchanged)
      3. Apply classification/review_status (+ rotation_status when
         action=mark_rotated)
      4. Cascade to occurrences via a single bulk UPDATE per incident
         (re-uses the patch_incident review_status map fix — confirmed
         → REVIEWED so the strict reviewstatus enum is happy)
      5. Write a per-incident audit entry with via="bulk_triage"

    NOTE: mark_rotated via this endpoint does NOT write a
    CredentialRotationEvent — that's owned by bulk_mark_rotated which
    has its own dedicated MTTR-tracking semantics.  Bulk-triage's
    mark_rotated is the "just change the state" pathway for users who
    rotated the credential outside Vooda and want to record that fact
    without spawning rotation events.  Callers wanting MTTR analytics
    should hit /bulk-mark-rotated instead.
    """
    from apps.api.app.core.audit import log_audit
    from sqlalchemy import update as sa_update

    patch_fields = _BULK_TRIAGE_MAP[body.action]
    new_classification = patch_fields["classification"]
    new_review_status = patch_fields["review_status"]
    new_rotation_status = patch_fields.get("rotation_status")

    # Same review_status enum-mapping the single-incident PATCH uses —
    # SecretIncident.review_status accepts free strings but the cascade
    # to NormalizedFinding.review_status goes into a strict
    # PostgreSQL enum.  See patch_incident comments for the full
    # backstory (review_status enum mismatch was a 500 bug).
    rs_for_findings = {
        "confirmed": "REVIEWED",
        "unreviewed": "UNREVIEWED",
        "in_review": "IN_REVIEW",
        "reviewed": "REVIEWED",
        "disputed": "DISPUTED",
    }.get(new_review_status, new_review_status.upper())

    # Single-query incident fetch — avoid N+1.
    rows = await db.execute(
        select(SecretIncident).where(
            SecretIncident.id.in_(body.incident_ids),
            SecretIncident.tenant_id == user.tenant_id,
        )
    )
    incidents = list(rows.scalars().all())
    found_ids = {inc.id for inc in incidents}
    not_found = len(body.incident_ids) - len(found_ids)

    updated = 0
    unchanged = 0
    cascaded = 0
    now = datetime.utcnow()

    for incident in incidents:
        # Idempotent skip: already in the requested state.
        already_in_state = (
            (incident.classification or "") == new_classification
            and (incident.review_status or "") == new_review_status
            and (new_rotation_status is None or (incident.rotation_status or "") == new_rotation_status)
        )
        if already_in_state:
            unchanged += 1
            continue

        prev_classification = incident.classification
        prev_review_status = incident.review_status
        prev_rotation_status = incident.rotation_status

        incident.classification = new_classification
        incident.review_status = new_review_status
        if new_rotation_status is not None:
            incident.rotation_status = new_rotation_status
            if new_rotation_status == "rotated":
                incident.rotated_at = now
        updated += 1

        # Cascade to occurrences.  One UPDATE per incident keeps the
        # SQL simple and the row-count exact for the audit summary.
        result = await db.execute(
            sa_update(NormalizedFinding)
            .where(NormalizedFinding.incident_id == incident.id)
            .values(
                classification=new_classification.upper(),
                review_status=rs_for_findings,
            )
        )
        cascaded += result.rowcount or 0

        changes_dump: dict = {
            "classification": new_classification,
            "review_status": new_review_status,
        }
        if new_rotation_status is not None:
            changes_dump["rotation_status"] = new_rotation_status

        await log_audit(
            db, user, "incident_triaged", "secret_incident",
            resource_id=incident.id,
            detail=f"action={body.action}; via=bulk_triage"
                   + (f"; comment={body.comment[:200]!r}" if body.comment else ""),
            metadata={
                "incident_id": str(incident.id),
                "changes": changes_dump,
                "previous": {
                    "classification": prev_classification,
                    "review_status": prev_review_status,
                    "rotation_status": prev_rotation_status,
                },
                "comment": body.comment,
                "via": "bulk_triage",
            },
        )

    await db.commit()

    return BulkTriageResponse(
        updated=updated,
        unchanged=unchanged,
        not_found=not_found,
        cascaded_findings=cascaded,
    )


# ── CSV export ──────────────────────────────────────────────────────


@router.get("/export/csv")
async def export_incidents_csv(
    severity_max: Optional[str] = Query(None),
    classification: Optional[str] = Query(None),
    review_status: Optional[str] = Query(None),
    validation_status: Optional[str] = Query(None),
    rotation_status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export incidents as CSV — same filter axes as the list endpoint.

    Returns one row per SecretIncident (NOT per-finding), so the file
    is the credential-centric view a security lead would hand to a
    compliance reviewer.  Filtered identically to whatever the user
    sees in the Incidents view at click time.
    """
    from fastapi.responses import StreamingResponse
    from datetime import datetime, timezone
    import csv
    import io

    base = [SecretIncident.tenant_id == user.tenant_id]

    # Scope to accessible repos (same predicate as list endpoint).
    accessible = await get_accessible_repo_ids(db, user)
    if accessible is not None:
        from sqlalchemy import exists
        visibility = exists(
            select(NormalizedFinding.id).where(
                NormalizedFinding.incident_id == SecretIncident.id,
                (NormalizedFinding.repository_id.in_(accessible))
                | (NormalizedFinding.scan_source_id.isnot(None)),
            )
        )
        base.append(visibility)

    if severity_max:
        base.append(SecretIncident.severity_max == severity_max)
    if classification:
        base.append(SecretIncident.classification == classification)
    if review_status:
        base.append(SecretIncident.review_status == review_status)
    if validation_status:
        base.append(SecretIncident.validation_status == validation_status)
    if rotation_status:
        base.append(SecretIncident.rotation_status == rotation_status)
    if search:
        from sqlalchemy import or_ as sa_or
        like = f"%{search}%"
        base.append(sa_or(
            SecretIncident.title.ilike(like),
            SecretIncident.masked_value.ilike(like),
            SecretIncident.secret_type.ilike(like),
        ))

    result = await db.execute(
        select(SecretIncident).where(*base).order_by(SecretIncident.last_seen_at.desc())
    )
    incidents = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["VOODA AI - Incidents Export"])
    writer.writerow([f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"])
    writer.writerow([f"Total incidents: {len(incidents)}"])
    writer.writerow([])
    writer.writerow([
        "ID", "Title", "Secret Type", "Masked Value", "Severity",
        "Occurrence Count", "Classification", "Review Status",
        "Validation Status", "Rotation Status", "Rotated At",
        "First Seen", "Last Seen",
    ])
    for inc in incidents:
        writer.writerow([
            str(inc.id)[:8],
            (inc.title or "")[:200],
            inc.secret_type or "",
            inc.masked_value or "",
            inc.severity_max or "",
            inc.occurrence_count or 0,
            inc.classification or "",
            inc.review_status or "",
            inc.validation_status or "",
            inc.rotation_status or "",
            inc.rotated_at.isoformat() if inc.rotated_at else "",
            inc.first_seen_at.isoformat() if inc.first_seen_at else "",
            inc.last_seen_at.isoformat() if inc.last_seen_at else "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vooda-incidents.csv"},
    )
