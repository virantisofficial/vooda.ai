# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""
Cross-process rate limiter for verifier calls.

Celery runs a pool of forked worker processes, each with its own Python
memory and asyncio event loop. An in-process ``asyncio.Semaphore`` would
only guard one fork — two or three workers verifying a tenant's findings
in parallel would each hit GitHub (or any provider) at full speed, easily
tripping per-account rate limits that then masquerade as inactive-key
errors (see A3 for the symptom).

This module implements a **token bucket** in Redis, keyed by provider.
All workers share the bucket regardless of fork / pod / host, so the
sustained request rate to any one provider is bounded across the whole
Vooda deployment.

Algorithm
---------
Standard token bucket:
    tokens_t = min(capacity, tokens_{t-1} + elapsed * refill_rate)
    if tokens_t >= 1: consume one and proceed
    else: sleep for (1 - tokens_t) / refill_rate and retry once

The refill + consume is a Lua script executed server-side so the
check-update-decide is atomic — no TOCTOU gap between forks.

Failure mode
------------
If Redis is unreachable or the script errors, ``acquire()`` returns
``True`` (fail-open). Rate limits are a quota concern, not a correctness
one — dropping verifications on Redis outages would corrupt the signal
the whole verification layer exists to produce.

Defaults
--------
Conservative per-provider caps. Slack and similar strict APIs get a
tighter bucket. Defaults err toward never-DoS-a-provider rather than
maximum throughput. Callers can override per-call.
"""

import asyncio
import time
import structlog
from typing import Optional

logger = structlog.get_logger()


# ── Atomic Lua token bucket ──────────────────────────────────
#
# KEYS[1] — bucket hash key
# ARGV[1] — capacity (float)
# ARGV[2] — refill rate (tokens per second, float)
# ARGV[3] — now timestamp (float seconds since epoch)
#
# Returns:
#   1                 — token acquired
#   -<wait_ms:int>    — bucket empty; negative suggested wait in ms

_LUA_ACQUIRE = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket[1])
local last_refill = tonumber(bucket[2])
if tokens == nil then tokens = capacity end
if last_refill == nil then last_refill = now end

-- Refill based on wall-clock elapsed time
local elapsed = now - last_refill
if elapsed < 0 then elapsed = 0 end
tokens = math.min(capacity, tokens + elapsed * refill_rate)

if tokens >= 1 then
  tokens = tokens - 1
  redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
  redis.call('EXPIRE', key, 3600)
  return 1
else
  redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
  redis.call('EXPIRE', key, 3600)
  -- Suggested wait time to regenerate one token, in milliseconds
  local wait_ms = math.ceil((1 - tokens) / refill_rate * 1000)
  return -wait_ms
end
"""

_KEY_PREFIX = "vooda:ratelimit"


# ── Per-provider configuration ───────────────────────────────

# (capacity, refill_rate tokens/sec). Capacity controls burst size,
# refill rate controls sustained throughput.
DEFAULT_BUCKET = (20.0, 10.0)  # 20 burst, 10/sec sustained — permissive default

PROVIDER_BUCKETS: dict[str, tuple[float, float]] = {
    # Known-strict APIs — tighter to avoid tripping real provider limits
    "slack":      (5.0, 2.0),    # Slack docs cite 1 req/sec per-method
    "twilio":     (10.0, 5.0),
    "jira":       (10.0, 5.0),
    "stripe":     (15.0, 8.0),
    # Known-permissive APIs — full defaults
    "github":     (30.0, 15.0),  # GitHub authenticated is 5000/h per token
    "aws":        (30.0, 20.0),  # STS is rarely the bottleneck
    "gitlab":     (20.0, 10.0),
    # Default applies to everything else via DEFAULT_BUCKET
}


def _bucket_for(provider: str) -> tuple[float, float]:
    """Resolve (capacity, refill_rate) for a provider."""
    return PROVIDER_BUCKETS.get((provider or "").lower(), DEFAULT_BUCKET)


async def _get_client():
    import redis.asyncio as aioredis
    from apps.api.app.core.config import settings
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


async def acquire(
    provider: str,
    *,
    capacity: Optional[float] = None,
    refill_rate: Optional[float] = None,
    max_wait_s: float = 2.0,
) -> bool:
    """Acquire one token from ``provider``'s bucket.

    Blocks up to ``max_wait_s`` total — does one sleep-and-retry when
    the bucket is empty. Returns ``True`` on success (token taken OR
    fail-open fallback) and ``False`` only when we exhausted the wait
    budget. Callers that see ``False`` can choose to skip the call or
    proceed anyway; the current worker integration proceeds so recall
    is preserved at the cost of occasional over-rate bursts.
    """
    if capacity is None or refill_rate is None:
        cap, rate = _bucket_for(provider)
        capacity = capacity if capacity is not None else cap
        refill_rate = refill_rate if refill_rate is not None else rate

    key = f"{_KEY_PREFIX}:{(provider or 'unknown').lower()}"
    start = time.monotonic()

    try:
        r = await _get_client()
        try:
            for _attempt in range(2):  # one initial try + one retry after sleep
                now = time.time()
                result = await r.eval(_LUA_ACQUIRE, 1, key, capacity, refill_rate, now)
                if result == 1:
                    return True

                # Bucket empty — Lua returned the negative suggested wait
                wait_ms = -int(result) if result < 0 else 1000
                wait_s = wait_ms / 1000.0
                remaining = max_wait_s - (time.monotonic() - start)
                if wait_s > remaining:
                    # Not enough budget to wait; give up rather than
                    # exceed max_wait_s
                    logger.info(
                        "rate_limit_exhausted",
                        provider=provider,
                        wait_ms=wait_ms,
                        remaining_ms=int(remaining * 1000),
                    )
                    return False
                await asyncio.sleep(wait_s)
            # Second attempt also failed after the sleep
            return False
        finally:
            await r.aclose()
    except Exception as e:
        # Fail-open: Redis down or script error. Log and proceed.
        logger.debug("rate_limiter_unavailable", provider=provider, error=str(e)[:150])
        return True
