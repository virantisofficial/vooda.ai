# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Redis query cache — caches frequent dashboard queries.

Usage:
    from apps.api.app.core.cache import cache_get, cache_set

    result = await cache_get("dashboard:overview:tenant123")
    if not result:
        result = await compute_heavy_query()
        await cache_set("dashboard:overview:tenant123", result, ttl=300)
"""

import json
import structlog
from typing import Optional, Any

logger = structlog.get_logger()

DEFAULT_TTL = 300  # 5 minutes


async def cache_get(key: str) -> Optional[Any]:
    """Get a cached value from Redis."""
    try:
        import redis.asyncio as aioredis
        from apps.api.app.core.config import settings

        r = aioredis.from_url(settings.REDIS_URL)
        data = await r.get(f"vooda:cache:{key}")
        await r.aclose()

        if data:
            return json.loads(data)
    except Exception:
        pass
    return None


async def cache_set(key: str, value: Any, ttl: int = DEFAULT_TTL) -> None:
    """Set a cached value in Redis with TTL."""
    try:
        import redis.asyncio as aioredis
        from apps.api.app.core.config import settings

        r = aioredis.from_url(settings.REDIS_URL)
        await r.set(f"vooda:cache:{key}", json.dumps(value, default=str), ex=ttl)
        await r.aclose()
    except Exception:
        pass


async def cache_invalidate(pattern: str) -> None:
    """Invalidate cached keys matching a pattern."""
    try:
        import redis.asyncio as aioredis
        from apps.api.app.core.config import settings

        r = aioredis.from_url(settings.REDIS_URL)
        keys = []
        async for key in r.scan_iter(f"vooda:cache:{pattern}*"):
            keys.append(key)
        if keys:
            await r.delete(*keys)
        await r.aclose()
    except Exception:
        pass
