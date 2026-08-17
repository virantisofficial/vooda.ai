# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Source-level concurrency control for scan_source runs.

The worker's `_run_source_scan` reads `source.sync_state` at start,
runs the adapter (which mutates internal state), then writes the
updated watermark back. Two concurrent scans on the same source
race on that round-trip — the first scan's commit can land while
the second is mid-iteration, so the second's writeback overwrites
the first's progress and items appear "skipped" on the next run.

This module provides a Redis-backed advisory lock that's acquired
once at scan start and released on completion (or via TTL if the
worker crashes mid-scan). One in-flight scan per source at a time;
duplicate dispatches see a `LockNotAcquired` and exit cleanly.

Picked Redis over PG row locks because:
  - Scans take seconds-to-minutes and span multiple DB commits, so
    `SELECT ... FOR UPDATE` would either span a long transaction
    (bad for the connection pool) or release the lock between
    commits (defeats the purpose).
  - Redis is already in the stack (Celery broker + verification
    cache + rate limiter); zero new infra.
  - TTL gives crash safety for free.
"""
from __future__ import annotations

import contextlib
import logging
import secrets
from typing import AsyncIterator, Awaitable, Callable

import redis.asyncio as aioredis

from apps.api.app.core.config import settings

logger = logging.getLogger(__name__)


# How long a single scan lock is allowed to hold. Sized to comfortably
# outlive Celery's HARD task time limit (task_time_limit=8100s / 2h15m
# in apps/worker/celery_app.py) so the lock can never expire while its
# task is still running — that would let a duplicate dispatch sneak in
# mid-scan, which is exactly what the lock exists to prevent. The
# previous 7200s (== the *soft* limit) was a latent bug: a worker that
# ran to the hard limit, or hung in the soft-limit handler, kept
# running for up to 900s after its lock had already expired. 8400s =
# hard limit + 5 min buffer. The cleanup beat task is the real safety
# net for stranded locks; the TTL is just the floor.
DEFAULT_LOCK_TTL_SECONDS = 8400  # 2h20m — exceeds Celery hard limit (8100s)

# Key prefix and pattern used by the cleanup task to enumerate locks.
LOCK_KEY_PREFIX = "vooda:source_scan:lock:"
LOCK_KEY_PATTERN = f"{LOCK_KEY_PREFIX}*"


class LockNotAcquired(RuntimeError):
    """Raised when another scan is already in progress for this source."""


def _key(source_id: str) -> str:
    # Single namespace prefix so all Vooda Redis keys are easy to
    # spot in a redis-cli scan. Source-id is sufficient — tenants
    # are scoped to their own source_ids.
    return f"{LOCK_KEY_PREFIX}{source_id}"


# Lua script for compare-and-delete on release. Defined once at module
# scope and reused by both the context manager and the cleanup helper
# so we never accidentally release someone else's lock if our snapshot
# of the value is stale.
_RELEASE_IF_MATCH_LUA = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""


@contextlib.asynccontextmanager
async def source_scan_lock(
    source_id: str,
    holder: str,
    ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS,
) -> AsyncIterator[str]:
    """Acquire an exclusive lock for `source_id` or raise.

    Usage:
        async with source_scan_lock(source_id, holder=str(job.id)):
            ... # do the scan; lock auto-released on context exit

    Args:
        source_id: ScanSource UUID to lock.
        holder: identifier of the holder for logging / diagnostics
                (typically the scan_job_id).
        ttl_seconds: defensive auto-expire if the holder crashes.

    Raises:
        LockNotAcquired: another holder owns the lock right now.
    """
    # Token uniquely identifies THIS holder so release is safe — we
    # only delete the key if its value still matches our token.
    # Prevents the classic "release someone else's lock after our
    # TTL fired" footgun.
    token = secrets.token_hex(8)
    payload = f"{holder}|{token}"
    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        # SET key value NX EX ttl → atomic acquire-or-fail. Returns
        # True on success, None when the key already exists.
        ok = await client.set(_key(source_id), payload, nx=True, ex=ttl_seconds)
        if not ok:
            existing = await client.get(_key(source_id)) or "<unknown>"
            existing_holder = existing.split("|", 1)[0]
            # Re-entrant guard (mirrors repo_scan_lock): a task that was
            # redelivered/retried, or that crashed without releasing,
            # must not coalesce into its own stale lock.  Re-take it and
            # proceed when the existing holder is this same holder.
            if existing_holder and existing_holder == holder:
                await client.set(_key(source_id), payload, ex=ttl_seconds)
                logger.info("source_scan_lock_reentrant source=%s holder=%s", source_id, holder)
            else:
                raise LockNotAcquired(
                    f"Source {source_id} is already being scanned by {existing_holder}"
                )
        try:
            yield token
        finally:
            # Compare-and-delete via Lua so we never accidentally
            # release someone else's lock if our TTL expired and
            # another holder picked up the key in the meantime.
            try:
                await client.eval(_RELEASE_IF_MATCH_LUA, 1, _key(source_id), payload)
            except Exception:
                # Best-effort release; the TTL is the safety net.
                pass
    finally:
        await client.aclose()


def parse_holder(value: str | None) -> str | None:
    """Extract the holder identifier (typically the scan_job_id) from a
    lock value. Lock values are written as ``"{holder}|{token}"`` by
    `source_scan_lock`. Returns None for empty / malformed values so
    the cleanup pass can skip them safely instead of misinterpreting a
    foreign key.
    """
    if not value:
        return None
    holder, sep, _ = value.partition("|")
    if not sep or not holder:
        return None
    return holder


async def cleanup_stale_locks(
    is_holder_terminal: Callable[[str], Awaitable[bool]],
    *,
    redis_client: aioredis.Redis | None = None,
    scan_count: int = 100,
) -> dict:
    """Sweep `vooda:source_scan:lock:*` keys and release ones whose
    holder is in a terminal state.

    Used by the periodic Celery beat task as a belt-and-braces against
    stranded locks: the in-process release in `_run_source_scan`
    handles the common case, but a SIGKILL'd worker (or a Celery
    revoke with terminate=True) can still leave the key behind. The
    TTL would eventually clear it; this just shortens the window.

    Args:
        is_holder_terminal: async callback invoked once per lock with
            the parsed holder id. Returns True iff that holder's job
            row is in {COMPLETED, FAILED, CANCELLED}. Treat lookup
            errors as "not terminal" — keeping the lock until the TTL
            fires is always safer than mistakenly releasing a live one.
        redis_client: optional injected client for tests. Caller-owned
            when supplied; otherwise we open and close our own.
        scan_count: SCAN cursor batch size. 100 is a fine default —
            the lock keyspace is bounded by the count of sources, so
            the whole sweep is a few KB at most.

    Returns:
        ``{"scanned": N, "released": M}`` for log/telemetry.
    """
    own_client = redis_client is None
    client = redis_client or aioredis.from_url(
        settings.REDIS_URL, decode_responses=True,
    )
    scanned = 0
    released = 0
    try:
        async for key in client.scan_iter(match=LOCK_KEY_PATTERN, count=scan_count):
            scanned += 1
            value = await client.get(key)
            holder = parse_holder(value)
            if holder is None:
                # Malformed value (e.g. set by something other than
                # source_scan_lock). Don't touch — TTL will clear it.
                continue
            try:
                terminal = await is_holder_terminal(holder)
            except Exception as e:
                logger.warning(
                    "source_scan_lock_cleanup_holder_check_failed "
                    "key=%s holder=%s error=%s",
                    key, holder, str(e)[:160],
                )
                continue
            if not terminal:
                continue
            # CAS delete: only release if the value still matches the
            # snapshot we read. Guards against the (very unlikely) race
            # where the legitimate holder released and a new scan
            # acquired the lock between our GET and our DEL.
            try:
                deleted = await client.eval(_RELEASE_IF_MATCH_LUA, 1, key, value)
            except Exception as e:
                logger.warning(
                    "source_scan_lock_cleanup_release_failed "
                    "key=%s error=%s", key, str(e)[:160],
                )
                continue
            if deleted:
                released += 1
                logger.info(
                    "source_scan_lock_cleanup_released "
                    "key=%s holder=%s", key, holder,
                )
    finally:
        if own_client:
            await client.aclose()
    return {"scanned": scanned, "released": released}


async def is_locked(source_id: str) -> bool:
    """Non-blocking probe: is there currently a holder?

    Used by the API trigger endpoint to surface a 409 to the user
    *before* dispatching a Celery task that would fail to acquire.
    Best-effort — there's still a TOCTOU window between this check
    and the worker's acquire, but the worker's lock is the real
    correctness boundary; this just makes the UX nicer when a
    scan is obviously already running.
    """
    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        return bool(await client.exists(_key(source_id)))
    finally:
        await client.aclose()
