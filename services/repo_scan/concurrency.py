# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Per-(repo, branch) concurrency control for code-scan runs.

Why we need it
--------------
Push storms from CI/CD or impatient users clicking "Run Scan" twice
in quick succession produce duplicate scan_jobs that all walk the
same files, hit the same verifier APIs, and write the same findings.
The dedup logic in ``_run_scan_job`` catches the duplicate INSERTs
(via stability_id), but only AFTER the duplicate work was done — the
filesystem walk, the regex pass on every file, the ~20 verifier API
calls per finding, etc.

This module provides a Redis-backed advisory lock that's acquired at
scan start. A second scan dispatched against the same (repo, branch)
sees ``LockNotAcquired`` and gracefully short-circuits the worker:
the duplicate ``scan_job`` row is marked ``CANCELLED`` with a
``status_message`` linking it to the running scan, and the worker
returns immediately. Net effect: a 100-event push storm produces 1
scan + 99 instant ``CANCELLED`` rows instead of 100 redundant scans.

Why per-(repo, branch) and not per-repo
---------------------------------------
A monorepo with active feature branches gets multiple concurrent
scans by design. Locking the whole repository would serialize them,
which would be incorrect for the user (both pushes deserve a scan)
and slow (one branch holds up another's CI feedback).

Key shape: ``vooda:repo_scan:lock:{repository_id}:{branch}``

Picked Redis over PG row locks for the same reasons as
source_scanners.concurrency:
  - Scans take seconds-to-minutes and span multiple DB commits, so
    ``SELECT ... FOR UPDATE`` would either span a long transaction
    or release the lock between commits.
  - Redis is already in the stack (Celery broker + verification cache
    + rate limiter); zero new infra.
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


# Sized to comfortably outlive Celery's HARD task time limit
# (task_time_limit=8100s / 2h15m in apps/worker/celery_app.py) so the
# lock can never expire while its task is still running. The previous
# 7200s (== the *soft* limit) was a latent bug: a worker that ran to
# the hard limit — or hung in the soft-limit handler — kept running for
# up to 900s after its lock had already expired, letting a duplicate
# scan dispatch sneak in mid-termination. 8400s = hard limit + 5 min
# buffer. The cleanup beat task is the real safety net for stranded
# locks; the TTL is the floor.
DEFAULT_LOCK_TTL_SECONDS = 8400  # 2h20m — exceeds Celery hard limit (8100s)

LOCK_KEY_PREFIX = "vooda:repo_scan:lock:"
LOCK_KEY_PATTERN = f"{LOCK_KEY_PREFIX}*"


class LockNotAcquired(RuntimeError):
    """Raised when another scan is already in progress for this (repo, branch)."""

    def __init__(self, message: str, holder: str | None = None):
        super().__init__(message)
        self.holder = holder  # scan_job_id of the running scan, if known


def _key(repository_id: str, branch: str | None) -> str:
    """Build the Redis lock key for a (repo, branch) pair.

    Branch is passed through verbatim. Redis is fine with ``/`` and
    most other ref characters in keys; SCAN patterns escape on the
    caller side (we use ``LOCK_KEY_PATTERN`` which is just the
    prefix wildcard). Empty / None branch maps to ``_default``.
    """
    safe_branch = branch if branch else "_default"
    return f"{LOCK_KEY_PREFIX}{repository_id}:{safe_branch}"


_RELEASE_IF_MATCH_LUA = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""


@contextlib.asynccontextmanager
async def repo_scan_lock(
    repository_id: str,
    branch: str | None,
    holder: str,
    ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS,
) -> AsyncIterator[str]:
    """Acquire an exclusive lock for ``(repository_id, branch)`` or raise.

    Usage:
        async with repo_scan_lock(repo_id, branch, holder=scan_job_id):
            ...  # do the scan; lock auto-released on context exit

    Raises:
        LockNotAcquired: another holder owns the lock right now. The
        ``holder`` attribute on the exception names the running scan's
        ``scan_job_id`` so the caller can stamp the cancelled row with
        a "coalesced into <id>" message.
    """
    token = secrets.token_hex(8)
    payload = f"{holder}|{token}|{branch or ''}"
    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        ok = await client.set(_key(repository_id, branch), payload, nx=True, ex=ttl_seconds)
        if not ok:
            existing = await client.get(_key(repository_id, branch)) or "<unknown>"
            running_holder = parse_holder(existing)
            # Re-entrant guard: if the lock is ALREADY held by this same
            # holder (== scan_job_id), this is a Celery redelivery / retry
            # of the very same task, or a previous run of THIS scan that
            # crashed without releasing.  A scan must never coalesce into
            # itself (live: a scan cancelled itself when holder==its own
            # id).  Re-take our own lock — overwrite with a fresh
            # token+TTL (plain SET, no NX, since it's ours) — and proceed
            # rather than raising.  A genuinely concurrent re-run of the
            # same scan_job_id is harmless: identical findings dedup on
            # stability_id.
            if running_holder is not None and running_holder == holder:
                await client.set(_key(repository_id, branch), payload, ex=ttl_seconds)
                logger.info(
                    "repo_scan_lock_reentrant repo=%s branch=%s holder=%s",
                    repository_id, branch or "_default", holder,
                )
            else:
                raise LockNotAcquired(
                    f"Another scan is already running for repo {repository_id} "
                    f"branch {branch or '_default'} (holder={running_holder})",
                    holder=running_holder,
                )
        try:
            yield token
        finally:
            try:
                await client.eval(
                    _RELEASE_IF_MATCH_LUA, 1, _key(repository_id, branch), payload
                )
            except Exception:
                # TTL is the safety net; a failed release just leaves
                # the key for the next cleanup pass.
                pass
    finally:
        await client.aclose()


def parse_holder(value: str | None) -> str | None:
    """Extract holder (scan_job_id) from a lock value.

    Lock values are written as ``"{holder}|{token}|{branch}"``. Returns
    None for empty/malformed so the cleanup pass can skip them safely.
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
    """Sweep ``vooda:repo_scan:lock:*`` keys and release ones whose
    holder is in a terminal state.

    Same shape as the source-scanner cleanup helper. Run on a beat
    schedule alongside it.
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
                continue
            try:
                terminal = await is_holder_terminal(holder)
            except Exception as e:
                logger.warning(
                    "repo_scan_lock_cleanup_holder_check_failed "
                    "key=%s holder=%s error=%s",
                    key, holder, str(e)[:160],
                )
                continue
            if not terminal:
                continue
            try:
                deleted = await client.eval(_RELEASE_IF_MATCH_LUA, 1, key, value)
            except Exception as e:
                logger.warning(
                    "repo_scan_lock_cleanup_release_failed "
                    "key=%s error=%s", key, str(e)[:160],
                )
                continue
            if deleted:
                released += 1
                logger.info(
                    "repo_scan_lock_cleanup_released "
                    "key=%s holder=%s", key, holder,
                )
    finally:
        if own_client:
            await client.aclose()
    return {"scanned": scanned, "released": released}


# ── #146: adaptive intra-scan CPU-slot budget ──────────────────────────────
# A box with N cores running K concurrent scans, each spawning a ProcessPool of
# min(8, N) workers, oversubscribes the CPU by K*min(8,N)/N. At 8 cores / 8
# concurrent scans / 8 workers that is 8x — every scan's heartbeat-emitting main
# loop is starved and the stall watchdog false-reaps a HEALTHY scan (the root of
# the #165 false-reap family). `scan_cpu_slots` bounds total intra-scan
# parallelism to ~cores: one scan alone gets the full budget (fast); K scans
# share it (≈1 each under heavy load), so the sum of all ProcessPool workers
# never exceeds the core count. A history scan is sequential (1 process) and
# also counts as one active scan, so its share is its own core.
SCAN_ACTIVE_KEY = "vooda:scan:active_count"
SCAN_ACTIVE_TTL = DEFAULT_LOCK_TTL_SECONDS  # outlive the Celery hard limit

# DECR but never below 0 — a double-release or a reconcile-then-release must not
# drive the gauge negative (negative → next scan computes share=budget →
# oversubscribe). The reconcile pass is the real source of truth; this is the floor.
_DECR_FLOOR_LUA = """
local v = tonumber(redis.call('get', KEYS[1]) or '0')
if v > 0 then return redis.call('decr', KEYS[1]) end
return 0
"""


def _scan_cpu_budget() -> int:
    """Total intra-scan CPU slots to share across concurrent scans.
    Default = cpu_count; override via VOODA_SCAN_CPU_BUDGET."""
    import os
    env = os.environ.get("VOODA_SCAN_CPU_BUDGET")
    if env:
        try:
            return max(1, int(env))
        except (ValueError, TypeError):
            pass
    return max(1, os.cpu_count() or 4)


@contextlib.asynccontextmanager
async def scan_cpu_slots(holder: str) -> AsyncIterator[int]:
    """Yield this scan's adaptive ProcessPool size (= budget // active_scans),
    incrementing the global active-scan gauge for the duration.

    Crash-safe: the gauge has a TTL, and a leaked count (SIGKILL'd worker that
    never decremented) only makes later scans MORE conservative — never an
    oversubscribe — and is healed by `reconcile_scan_active` on the beat. On any
    Redis error the share is 1 (fail closed: never oversubscribe)."""
    budget = _scan_cpu_budget()
    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        active = budget  # fail-safe default → share 1 if Redis is unreachable
        try:
            active = int(await client.incr(SCAN_ACTIVE_KEY))
            await client.expire(SCAN_ACTIVE_KEY, SCAN_ACTIVE_TTL)
        except Exception:
            logger.warning("scan_cpu_slots_incr_failed holder=%s", holder)
        share = max(1, budget // max(1, active))
        try:
            yield share
        finally:
            try:
                await client.eval(_DECR_FLOOR_LUA, 1, SCAN_ACTIVE_KEY)
            except Exception:
                pass
    finally:
        await client.aclose()


async def reconcile_scan_active(running_count: int) -> int:
    """Reset the active-scan gauge to the true count of RUNNING scans, healing
    drift left by workers that were SIGKILL'd before releasing. Called from the
    lock-cleanup beat with the DB's RUNNING/ANALYZING scan count. Returns the
    value written."""
    val = max(0, int(running_count))
    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        await client.set(SCAN_ACTIVE_KEY, val, ex=SCAN_ACTIVE_TTL)
    except Exception:
        pass
    finally:
        await client.aclose()
    return val


async def is_locked(repository_id: str, branch: str | None) -> bool:
    """Non-blocking probe: is there currently a holder for (repo, branch)?

    Used by the API trigger endpoint to surface a 409 / coalesce
    response before dispatching a Celery task that would fail to
    acquire. Best-effort — TOCTOU between probe and acquire is fine
    because the worker's acquire is the real correctness boundary.
    """
    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        return bool(await client.exists(_key(repository_id, branch)))
    finally:
        await client.aclose()
