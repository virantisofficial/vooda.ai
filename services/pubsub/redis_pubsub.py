# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Redis Pub/Sub — broadcasts scan progress from worker to API WebSocket connections.

Worker publishes progress updates to Redis channel.
API WebSocket handler subscribes and forwards to connected clients.
"""

import json
import structlog
from typing import Optional

logger = structlog.get_logger()

SCAN_PROGRESS_CHANNEL = "vooda:scan_progress:{scan_job_id}"


async def publish_scan_progress(
    scan_job_id: str,
    status: str,
    progress_pct: int,
    message: str = "",
    stats: Optional[dict] = None,
) -> None:
    """Publish scan progress update to Redis channel."""
    try:
        import redis.asyncio as aioredis
        from apps.api.app.core.config import settings

        r = aioredis.from_url(settings.REDIS_URL)
        channel = SCAN_PROGRESS_CHANNEL.format(scan_job_id=scan_job_id)

        payload = json.dumps({
            "scan_job_id": scan_job_id,
            "status": status,
            "progress_pct": progress_pct,
            "message": message,
            "stats": stats or {},
        })

        await r.publish(channel, payload)
        await r.aclose()
    except Exception as e:
        logger.debug("pubsub_publish_failed", error=str(e)[:100])


async def subscribe_scan_progress(scan_job_id: str, poll_timeout: float = 1.0):
    """
    Subscribe to scan progress updates.

    Yields each update dict as it arrives, AND yields ``None`` every
    ``poll_timeout`` seconds as a liveness tick. The tick is what makes
    this interruptible: the old blocking ``pubsub.listen()`` parked this
    task on Redis forever for a quiet scan, so an open WebSocket hung
    uvicorn's graceful shutdown ("Waiting for background tasks to
    complete") until SIGKILL. With ``get_message(timeout=...)`` the
    WebSocket handler regains control regularly and can bail out when the
    socket/server is going away.
    """
    import redis.asyncio as aioredis
    from apps.api.app.core.config import settings

    r = aioredis.from_url(settings.REDIS_URL)
    pubsub = r.pubsub()
    channel = SCAN_PROGRESS_CHANNEL.format(scan_job_id=scan_job_id)

    await pubsub.subscribe(channel)

    try:
        while True:
            message = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=poll_timeout
            )
            if message is None:
                yield None  # liveness tick — lets the consumer check state
                continue
            if message.get("type") == "message":
                try:
                    data = json.loads(message["data"])
                except Exception:
                    continue
                yield data
                if data.get("status") in ("completed", "failed"):
                    break
    finally:
        try:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()
            await r.aclose()
        except Exception:
            pass
