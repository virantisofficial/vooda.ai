# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
API Key management endpoints — create, list, revoke, rotate, usage
analytics, IP allowlist.
"""

import hashlib
import ipaddress
from uuid import UUID
from typing import Optional
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from apps.api.app.schemas.strict import StrictModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.api_key import APIKey, generate_api_key
from apps.api.app.models.audit import AuditEvent


# Max CIDRs per key.  Enterprise CI fleets rarely need more than a
# dozen egress IPs; capping at 50 prevents a runaway config from
# bloating the auth-path memory footprint.  Customers who need more
# should use a wider CIDR block (e.g. /24 instead of 256 /32s).
_MAX_ALLOWED_CIDRS = 50


def _validate_cidr_list(raw: Optional[list[str]]) -> Optional[list[str]]:
    """Normalize + validate an allowed_ip_cidrs payload.

    Returns:
      * ``None`` when the input is None or [] — both mean "no
        restriction" semantically and we collapse them to NULL on
        the DB side for a consistent query predicate.
      * A list of canonicalized CIDR strings otherwise (e.g.
        "192.168.1.5/24" → "192.168.1.0/24"; IPv6 lower-cased and
        compressed).  Canonicalization avoids storing two semantically
        identical strings and ensures the auth-path check is a simple
        ``ipaddress.ip_address in ipaddress.ip_network`` containment.

    Raises HTTPException(422) on bad input — surfaces the offending
    entry so the operator sees exactly which line to fix.
    """
    if not raw:
        return None
    if len(raw) > _MAX_ALLOWED_CIDRS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Too many CIDR entries ({len(raw)}); max is "
                f"{_MAX_ALLOWED_CIDRS}.  Use a wider CIDR block instead "
                "of enumerating individual IPs."
            ),
        )
    normalized: list[str] = []
    seen: set[str] = set()
    for entry in raw:
        entry = (entry or "").strip()
        if not entry:
            continue  # silently drop blank lines from the UI textarea
        try:
            # strict=False so a host bit like "192.168.1.5/24" is
            # accepted and re-rendered as the network "192.168.1.0/24".
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Invalid CIDR entry {entry!r}: {exc}.  "
                    "Use forms like '203.0.113.0/24' or '2001:db8::/32', "
                    "or a single host like '203.0.113.5' (treated as /32)."
                ),
            )
        canonical = str(net)
        if canonical not in seen:
            seen.add(canonical)
            normalized.append(canonical)
    return normalized or None

router = APIRouter()


# Rotation invariants.  These bounds prevent the obvious foot-guns:
#   * MIN=0 lets operators do an immediate hard-cutover when they know
#     their CI redeploys atomically.
#   * MAX=30 prevents a forgotten "rotate me later" from leaving both
#     keys alive indefinitely — a leaked-key window with two valid keys
#     is the worst of both worlds.
_ROTATION_GRACE_MIN_DAYS = 0
_ROTATION_GRACE_MAX_DAYS = 30
_ROTATION_GRACE_DEFAULT_DAYS = 7

# Usage analytics window bounds.  The audit_events table is retention-
# bounded; we don't promise data beyond what retention guarantees.
_USAGE_WINDOW_MIN_DAYS = 1
_USAGE_WINDOW_MAX_DAYS = 90
_USAGE_WINDOW_DEFAULT_DAYS = 7


# DB column ``api_keys.name`` is ``String(255)``.  Pydantic mirrors the
# constraint so a too-long name 422s at the schema layer instead of
# leaking the DB error as an unactionable 500.  Empty names are also
# blocked here — the UI gates with a disabled button but a CLI caller
# would otherwise bypass that.  Found in the 2026-05-24 QA suite
# (Module 1.3 / 9.5).
_KEY_NAME_MIN = 1
_KEY_NAME_MAX = 255


class APIKeyCreate(StrictModel):
    name: str = Field(min_length=_KEY_NAME_MIN, max_length=_KEY_NAME_MAX)
    scopes: list[str] = ["scan", "findings", "gate"]
    expires_in_days: Optional[int] = 365
    # CIDR allowlist (Sprint 3 / GAP-10).  None or [] = unrestricted
    # (matches pre-Sprint-3 behaviour for backwards compatibility).
    # Each entry must parse via ``ipaddress.ip_network`` — see
    # _validate_cidr_list for canonicalization rules.
    allowed_ip_cidrs: Optional[list[str]] = None


class APIKeyUpdate(StrictModel):
    """PATCH body for editing a key in-place.  Scope changes are
    deliberately NOT supported here — changing a key's scope changes
    its blast radius and is better expressed by issuing a new key.
    Name + allowlist are operational metadata the team needs to
    update without re-deploying CI."""
    name: Optional[str] = Field(
        default=None, min_length=_KEY_NAME_MIN, max_length=_KEY_NAME_MAX,
    )
    # Pass ``[]`` (empty list) to CLEAR the allowlist; pass ``None`` (or
    # omit the field) to leave it untouched.  This is the standard
    # PATCH triple-state convention.
    allowed_ip_cidrs: Optional[list[str]] = Field(default=None)


class APIKeyRotate(BaseModel):
    """Rotation payload — operator controls the grace period that the
    OLD key remains valid for after the new key is issued."""
    grace_period_days: int = Field(
        default=_ROTATION_GRACE_DEFAULT_DAYS,
        ge=_ROTATION_GRACE_MIN_DAYS,
        le=_ROTATION_GRACE_MAX_DAYS,
        description=(
            "How long the old key stays usable after rotation "
            f"({_ROTATION_GRACE_MIN_DAYS}–{_ROTATION_GRACE_MAX_DAYS} days). "
            "0 = immediate revoke; 7 = default; 30 = max."
        ),
    )


class APIKeyResponse(BaseModel):
    id: UUID
    name: str
    key_prefix: str
    scopes: list[str]
    is_active: bool
    last_used_at: Optional[str]
    expires_at: Optional[str]
    created_at: str
    # Computed lifecycle state — derived from is_active + expires_at on
    # every response so the UI can render an Active/Expired/Revoked chip
    # without re-deriving the rule client-side.  Values:
    #   "active"   — is_active=true AND (expires_at is null OR > now)
    #   "expired"  — is_active=true AND expires_at <= now
    #   "revoked"  — is_active=false (regardless of expires_at)
    #   "rotating" — rotation_grace_until is set AND in the future
    #                (overrides "active" so the UI surfaces the grace
    #                window prominently — operators need to know that
    #                this key is on its way out).
    # Added 2026-05-24 (Sprint 1 Stage C of API-key audit follow-up).
    status: str = "active"
    # Rotation linkage (Sprint 2 / GAP-7).  Both are NULL for keys that
    # haven't been rotated.  rotated_to_id lets the UI render
    # "→ [successor key name]" on the soon-to-expire row.
    rotated_at: Optional[str] = None
    rotated_to_id: Optional[UUID] = None
    rotation_grace_until: Optional[str] = None
    # IP allowlist (Sprint 3 / GAP-10).  None = unrestricted.  Surfaced
    # so the UI can render "Restricted to N IPs" hint on the row and
    # pre-fill the edit modal.
    allowed_ip_cidrs: Optional[list[str]] = None

    model_config = {"from_attributes": True}


class APIKeyCreatedResponse(APIKeyResponse):
    """Response when creating a new key — includes the full key (shown only once)."""
    api_key: str  # Full key — only shown at creation time


class UsagePoint(BaseModel):
    date: str  # ISO-8601 YYYY-MM-DD bucket
    count: int


class EndpointCount(BaseModel):
    endpoint: str
    count: int


class IPCount(BaseModel):
    ip: str
    count: int


class APIKeyUsageResponse(BaseModel):
    """Per-key usage analytics — SIEM-friendly shape designed so
    customers can pull this into Splunk / Datadog directly.

    Built entirely from ``audit_events`` rows written by
    ``_authenticate_api_key`` (one per ≤60s window per key — see the
    throttle constant in core/security.py).  No new tables, no
    materialized views; the audit log IS the analytics store.

    Heuristics for "leaked key" detection that customers can implement
    against this payload:
      * unique_ips suddenly > baseline   → key spread beyond CI runner
      * top_endpoints rotation         → caller is enumerating
      * calls_by_day spike             → automated abuse
    """
    key_id: UUID
    key_name: str
    window_days: int
    total_calls: int
    unique_ips: int
    unique_endpoints: int
    first_call_at: Optional[str]
    last_call_at: Optional[str]
    calls_by_day: list[UsagePoint]
    top_endpoints: list[EndpointCount]
    top_ips: list[IPCount]


def _derive_status(api_key: APIKey) -> str:
    """Resolve the lifecycle state used by the UI badge.

    Priority order (most-salient operator action first):
        revoked  > rotating > expired > active

    "rotating" beats "active" so the UI surfaces the grace window
    prominently — operators need a visible reminder that this key is
    on its way out.  "revoked" beats everything because a manual
    revoke is always the most urgent state to communicate.
    """
    if not api_key.is_active:
        return "revoked"
    now = datetime.now(timezone.utc)
    if api_key.rotation_grace_until and api_key.rotation_grace_until > now:
        return "rotating"
    if api_key.expires_at and api_key.expires_at < now:
        return "expired"
    return "active"


def _to_response(k: APIKey) -> APIKeyResponse:
    """Single source of truth for APIKey → response shape — keeps the
    list endpoint, create endpoint, and rotate endpoint in lockstep
    when new fields are added."""
    return APIKeyResponse(
        id=k.id, name=k.name, key_prefix=k.key_prefix,
        scopes=k.scopes or [], is_active=k.is_active,
        last_used_at=str(k.last_used_at) if k.last_used_at else None,
        expires_at=str(k.expires_at) if k.expires_at else None,
        created_at=str(k.created_at),
        status=_derive_status(k),
        rotated_at=str(k.rotated_at) if k.rotated_at else None,
        rotated_to_id=k.rotated_to_id,
        rotation_grace_until=(
            str(k.rotation_grace_until) if k.rotation_grace_until else None
        ),
        allowed_ip_cidrs=k.allowed_ip_cidrs or None,
    )


AVAILABLE_SCOPES = [
    {"scope": "scan", "description": "Trigger scans and view scan status"},
    {"scope": "findings", "description": "Read findings and triage results"},
    {"scope": "gate", "description": "Check CI/CD gate pass/fail status"},
    {"scope": "reports", "description": "Generate and export reports"},
    # P0 two-way CLI/CI sync — least-privilege MACHINE scopes for pipeline keys.
    # A CI key should hold ONLY these two, never `scan`/`findings`/`admin`, so a
    # leaked CI key can push results but cannot read the finding corpus (the map
    # of where the org's secrets live) or other repos.
    {"scope": "findings:import", "description": "Import scan results from CI/CD (write-only — cannot read findings or other repos)"},
    {"scope": "policy:read", "description": "Read effective org policy / suppressions for local CI gating (read-only)"},
    {"scope": "admin", "description": "Full administrative access"},
]


@router.get("/scopes")
async def list_scopes():
    """List available API key scopes."""
    return AVAILABLE_SCOPES


@router.get("", response_model=list[APIKeyResponse])
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List every API key in the tenant — active, expired, AND revoked.
    Before Sprint 1 the API filtered out is_active=false rows, which
    made forensic queries ("when did we revoke the leaked CI key?")
    impossible from the UI.  The UI now renders a status chip so
    revoked rows are visually distinct."""
    result = await db.execute(
        select(APIKey)
        .where(APIKey.tenant_id == user.tenant_id)
        .order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()
    return [_to_response(k) for k in keys]


@router.post("", response_model=APIKeyCreatedResponse, status_code=201)
async def create_api_key(
    body: APIKeyCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create a new API key. The full key is only returned once."""
    raw_key = generate_api_key()
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    # Validate the CIDR allowlist BEFORE any DB write so a bad entry
    # fails fast with a 422 referencing the offending value, rather
    # than half-creating the key and rolling back.
    allowed_cidrs = _validate_cidr_list(body.allowed_ip_cidrs)

    api_key = APIKey(
        tenant_id=user.tenant_id,
        name=body.name,
        key_hash=key_hash,
        key_prefix=raw_key[:12],
        scopes=body.scopes,
        created_by=user.id,
        is_active=True,
        expires_at=expires_at,
        allowed_ip_cidrs=allowed_cidrs,
    )
    db.add(api_key)
    await db.flush()
    await db.refresh(api_key)

    from apps.api.app.core.audit import log_audit
    cidr_note = (
        f", ip_allowlist={allowed_cidrs}" if allowed_cidrs else ""
    )
    await log_audit(
        db, user, "api_key_created", "api_key", api_key.id,
        f"Key: {body.name}, scopes: {body.scopes}{cidr_note}",
    )

    base = _to_response(api_key)
    return APIKeyCreatedResponse(
        **base.model_dump(),
        api_key=raw_key,  # ONLY returned at creation time
    )


@router.delete("/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.tenant_id == user.tenant_id)
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "api_key_revoked", "api_key", key_id, f"Revoked key: {key.name}")

    key.is_active = False
    await db.flush()


# ── In-place update (Sprint 3 / GAP-10) ─────────────────────


@router.patch("/{key_id}", response_model=APIKeyResponse)
async def update_api_key(
    key_id: UUID,
    body: APIKeyUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update operational metadata on an existing key.

    Editable fields (intentionally narrow):
      * name              — labelling only, no auth impact
      * allowed_ip_cidrs  — source-network restriction; pass [] to
                            clear, pass a list to set, omit to leave
                            untouched (PATCH triple-state)

    Deliberately NOT editable:
      * scopes      — changing scope = changing blast radius; issue
                      a new key instead
      * expires_at  — expiry edits would let a "never expires" key
                      sneak past compliance audits; rotation is the
                      sanctioned path to extend
      * is_active   — use DELETE for revoke, /rotate for graceful
                      cut-over
    """
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id, APIKey.tenant_id == user.tenant_id
        )
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")

    changes: list[str] = []
    if body.name is not None and body.name != key.name:
        old_name = key.name
        key.name = body.name
        changes.append(f"name: '{old_name}' → '{body.name}'")

    # PATCH triple-state for allowlist: presence in body == intent to
    # mutate.  Pydantic doesn't distinguish "field omitted" from
    # "field = None" by default, so callers wishing to clear should
    # pass ``[]`` rather than ``null``.  Both collapse to NULL in DB
    # but the API contract is more honest this way.
    if body.allowed_ip_cidrs is not None:
        new_cidrs = _validate_cidr_list(body.allowed_ip_cidrs)
        if new_cidrs != (key.allowed_ip_cidrs or None):
            old = key.allowed_ip_cidrs or []
            key.allowed_ip_cidrs = new_cidrs
            changes.append(
                f"ip_allowlist: {old} → {new_cidrs or '(unrestricted)'}"
            )

    if changes:
        from apps.api.app.core.audit import log_audit
        await log_audit(
            db, user, "api_key_updated", "api_key", key.id,
            f"Updated '{key.name}': " + "; ".join(changes),
        )

    await db.flush()
    await db.refresh(key)
    return _to_response(key)


# ── Rotation (GAP-7) ────────────────────────────────────────


@router.post(
    "/{key_id}/rotate",
    response_model=APIKeyCreatedResponse,
    status_code=201,
)
async def rotate_api_key(
    key_id: UUID,
    body: APIKeyRotate = APIKeyRotate(),  # body is optional — defaults apply
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Issue a successor key with the same name/scopes/owner, then move
    the original's expires_at forward by ``grace_period_days`` so CI
    pipelines have a zero-downtime cutover window.

    Invariants enforced:
      * cannot rotate a revoked key — there's nothing to "carry over"
      * cannot rotate an already-rotated key — would chain grace windows
        and create confusing "key A → B → C" trails
      * cannot rotate an already-expired key — same reason as revoked
      * grace_period_days is clamped to [0, 30] by the Pydantic field

    On success returns the brand-new key (shown once, same pattern as
    create) plus all metadata.  The original key is mutated in-place
    and visible via ``GET /api-keys`` with ``status="rotating"`` until
    its grace window passes.
    """
    from apps.api.app.core.audit import log_audit

    # Fetch under tenant scope so cross-tenant rotation is impossible.
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id, APIKey.tenant_id == user.tenant_id
        )
    )
    old = result.scalar_one_or_none()
    if not old:
        raise HTTPException(status_code=404, detail="API key not found")

    # State-machine guards — explicit messages so the UI can render the
    # operator's exact reason without re-deriving from status enum.
    if not old.is_active:
        raise HTTPException(
            status_code=409,
            detail="Cannot rotate a revoked key — create a new key instead.",
        )
    if old.rotated_at is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                "Key has already been rotated.  Rotate its successor "
                f"({old.rotated_to_id}) instead, or wait for its grace "
                "window to expire before re-rotating."
            ),
        )
    now = datetime.now(timezone.utc)
    if old.expires_at and old.expires_at < now:
        raise HTTPException(
            status_code=409,
            detail="Cannot rotate an expired key — create a new key instead.",
        )

    # Mint the successor.  Carry over name+scopes; expires_at is set to
    # whatever the old key had, OR the current default 365 days when
    # the old key was a "never expires" key — enterprise compliance
    # prefers bounded keys, so rotation is a natural moment to bound.
    raw_key = generate_api_key()
    successor = APIKey(
        tenant_id=user.tenant_id,
        name=old.name,
        key_hash=hashlib.sha256(raw_key.encode()).hexdigest(),
        key_prefix=raw_key[:12],
        scopes=old.scopes,
        created_by=user.id,  # rotation operator, not original creator
        is_active=True,
        expires_at=old.expires_at or (now + timedelta(days=365)),
    )
    db.add(successor)
    await db.flush()
    await db.refresh(successor)

    # Mutate the old key — keep it alive for the grace window, link it
    # to the successor, stamp the rotation moment for audit.
    grace_until = now + timedelta(days=body.grace_period_days)
    old.rotated_at = now
    old.rotated_to_id = successor.id
    old.rotation_grace_until = grace_until
    # Move expires_at forward so the existing _authenticate_api_key
    # expiry check enforces the cutover automatically — no new code
    # path needed in the auth dispatcher.
    old.expires_at = grace_until

    await log_audit(
        db, user, "api_key_rotated", "api_key", old.id,
        f"Rotated '{old.name}': old key '{old.key_prefix}…' valid for "
        f"{body.grace_period_days}d, successor '{successor.key_prefix}…' "
        f"({successor.id}) issued.",
    )

    base = _to_response(successor)
    return APIKeyCreatedResponse(
        **base.model_dump(),
        api_key=raw_key,  # ONLY returned here, never again
    )


# ── Usage analytics (GAP-13) ────────────────────────────────


@router.get("/{key_id}/usage", response_model=APIKeyUsageResponse)
async def api_key_usage(
    key_id: UUID,
    days: int = Query(
        _USAGE_WINDOW_DEFAULT_DAYS,
        ge=_USAGE_WINDOW_MIN_DAYS,
        le=_USAGE_WINDOW_MAX_DAYS,
        description=(
            "Look-back window in days "
            f"({_USAGE_WINDOW_MIN_DAYS}–{_USAGE_WINDOW_MAX_DAYS}). "
            "Limited by audit-event retention."
        ),
    ),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Per-key usage analytics derived from audit_events.

    Returns SIEM-friendly aggregates so customers can detect leaked
    keys (sudden IP-set spread, endpoint enumeration, request bursts)
    either by eye in the UI or programmatically via this endpoint
    forwarded into Splunk / Datadog / Sumo.

    Note: rows are throttled to one per ≤60s per key on the write
    path (see core/security.py:_API_KEY_USE_AUDIT_THROTTLE_S), so the
    ``count`` columns approximate "distinct minutes the key was used"
    rather than literal HTTP-call counts.  That's the right trade-off
    for abuse detection — a key seeing traffic in 1 440 minutes/day is
    indistinguishable from one seeing traffic every second.
    """
    # Tenant-scope check.
    key_result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id, APIKey.tenant_id == user.tenant_id
        )
    )
    key = key_result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")

    since = datetime.now(timezone.utc) - timedelta(days=days)

    base = and_(
        AuditEvent.action == "api_key_used",
        AuditEvent.resource_id == str(key_id),
        AuditEvent.created_at >= since,
    )

    # Headline aggregates.  Use COUNT(DISTINCT ...) for IPs/endpoints
    # so a hot key against one IP doesn't inflate the unique counts.
    headline = await db.execute(
        select(
            func.count(AuditEvent.id),
            func.count(func.distinct(AuditEvent.ip_address)),
            # ``detail`` contains "Key 'X' used: METHOD /path" — the
            # ``METHOD /path`` substring is the endpoint identifier
            # we use for grouping.  See ``top_endpoints_q`` below for
            # the extraction sub-query.
            func.min(AuditEvent.created_at),
            func.max(AuditEvent.created_at),
        ).where(base)
    )
    total, unique_ips, first_at, last_at = headline.one()

    # Time series — bucket by day for sparkline rendering.
    by_day_result = await db.execute(
        select(
            func.date(AuditEvent.created_at).label("day"),
            func.count(AuditEvent.id).label("n"),
        )
        .where(base)
        .group_by("day")
        .order_by("day")
    )
    calls_by_day = [
        UsagePoint(date=str(row.day), count=row.n) for row in by_day_result
    ]

    # Top-10 endpoints — parse "Key 'name' used: METHOD /path" out of
    # detail.  The exact prefix is stable (see core/security.py) so a
    # SQL substr is safe and avoids Python-side parsing of every row.
    top_endpoints_q = await db.execute(
        select(
            func.split_part(AuditEvent.detail, "used: ", 2).label("ep"),
            func.count(AuditEvent.id).label("n"),
        )
        .where(base)
        .group_by("ep")
        .order_by(func.count(AuditEvent.id).desc())
        .limit(10)
    )
    top_endpoints = [
        EndpointCount(endpoint=row.ep or "unknown", count=row.n)
        for row in top_endpoints_q
    ]

    # Top-10 IPs — null IPs (audit rows written before Sprint 0 wired
    # request capture) are folded into a single "unknown" bucket.
    top_ips_q = await db.execute(
        select(
            AuditEvent.ip_address,
            func.count(AuditEvent.id).label("n"),
        )
        .where(base)
        .group_by(AuditEvent.ip_address)
        .order_by(func.count(AuditEvent.id).desc())
        .limit(10)
    )
    top_ips = [
        IPCount(ip=row.ip_address or "unknown", count=row.n) for row in top_ips_q
    ]
    unique_endpoint_count = len(top_endpoints)  # already-deduped result set

    return APIKeyUsageResponse(
        key_id=key.id,
        key_name=key.name,
        window_days=days,
        total_calls=total or 0,
        unique_ips=unique_ips or 0,
        unique_endpoints=unique_endpoint_count,
        first_call_at=str(first_at) if first_at else None,
        last_call_at=str(last_at) if last_at else None,
        calls_by_day=calls_by_day,
        top_endpoints=top_endpoints,
        top_ips=top_ips,
    )
