# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""
Verification Result Cache — Redis-backed dedup for the verification step.

Without this, a single scan hammers the provider once per finding even
when the same credential appears in 50 files. With a 2 000-finding repo
and 20 % dupes, that's 400 avoidable API calls per scan per tenant.

Design
------
* Key:    ``vooda:verify:{tenant_id}:{secret_hash}``
* Value:  JSON ``{status, details, provider, permissions, transient,
          verified_at_iso}``
* TTL:    6 hours (``CACHE_TTL_SECONDS``). Short enough that customer
          rotations propagate within a scan cycle; long enough that
          multiple scans a day dedup heavily.
* Scope:  Strictly ``(tenant_id, secret_hash)`` — cross-tenant leakage
          is prevented by construction.

What we cache
-------------
Only ``status in ("active", "inactive")`` results get cached. ``error``
(including transient errors) is intentionally **not cached** — the next
pass should retry. ``unsupported`` is also skipped because the answer is
derivable from provider coverage, not a credential fact.

Failure mode
------------
Every Redis call is wrapped in try/except and logged at debug level. A
cache miss due to Redis being down is indistinguishable from a real miss
and proceeds straight to the verifier — never blocks the verification
pipeline.
"""

import json
from datetime import datetime, timezone
from typing import Optional

import structlog

logger = structlog.get_logger()


CACHE_TTL_SECONDS = 6 * 60 * 60  # 6 hours

_KEY_PREFIX = "vooda:verify"


def _make_key(tenant_id: str, secret_hash: str) -> str:
    # Both inputs are trusted internal identifiers, but we lower-case the
    # tenant UUID for case-insensitive consistency and refuse empty strings.
    if not tenant_id or not secret_hash:
        return ""
    return f"{_KEY_PREFIX}:{str(tenant_id).lower()}:{secret_hash}"


async def _get_client():
    """Return an async Redis client using the worker's REDIS_URL."""
    import redis.asyncio as aioredis
    from apps.api.app.core.config import settings
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


async def get_cached_verification(
    tenant_id: str,
    secret_hash: str,
) -> Optional[dict]:
    """Return cached verification dict or None on miss / Redis failure.

    The returned dict is safe to merge into ``source_metadata`` directly
    (keys: ``status``, ``details``, ``provider``, ``permissions``,
    ``transient``, ``verified_at``).
    """
    key = _make_key(tenant_id, secret_hash)
    if not key:
        return None
    try:
        r = await _get_client()
        try:
            raw = await r.get(key)
        finally:
            await r.aclose()
        if not raw:
            return None
        return json.loads(raw)
    except Exception as e:
        logger.debug("verify_cache_get_failed", error=str(e)[:150])
        return None


async def set_cached_verification(
    tenant_id: str,
    secret_hash: str,
    *,
    status: str,
    details: str,
    provider: str,
    permissions: Optional[str] = None,
    transient: bool = False,
    permissions_detail: Optional[dict] = None,
    risk_level: Optional[str] = None,
    blast_radius_summary: Optional[str] = None,
) -> bool:
    """Write a verification result to cache. Returns True on success.

    Only ``active`` / ``inactive`` results should be cached by callers —
    ``error`` is transient and ``unsupported`` is derivable.
    """
    if status not in ("active", "inactive"):
        return False
    key = _make_key(tenant_id, secret_hash)
    if not key:
        return False
    payload = json.dumps({
        "status": status,
        "details": details,
        "provider": provider,
        "permissions": permissions,
        "transient": transient,
        "permissions_detail": permissions_detail,
        "risk_level": risk_level,
        "blast_radius_summary": blast_radius_summary,
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    try:
        r = await _get_client()
        try:
            await r.setex(key, CACHE_TTL_SECONDS, payload)
        finally:
            await r.aclose()
        return True
    except Exception as e:
        logger.debug("verify_cache_set_failed", error=str(e)[:150])
        return False


def is_fresh(verified_at_iso: str, max_age_seconds: int = CACHE_TTL_SECONDS) -> bool:
    """True when a stamped ``verified_at`` is still within the TTL window.

    Used by the worker to decide whether a finding whose source_metadata
    already has ``validation_status`` should be re-verified (stale) or
    skipped (fresh). Robust to missing/garbage input.
    """
    if not verified_at_iso:
        return False
    try:
        dt = datetime.fromisoformat(verified_at_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - dt).total_seconds()
        return age < max_age_seconds
    except Exception:
        return False
