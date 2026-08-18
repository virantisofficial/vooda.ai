# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
WebSocket endpoints for real-time scan progress streaming.

Usage:
    ws://localhost:8000/api/v1/ws/scan/{scan_job_id}?token=<jwt>

Client receives JSON messages:
    {"scan_job_id": "...", "status": "running", "progress_pct": 45, "message": "Scanning files..."}
"""

import json
import asyncio
import structlog

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from sqlalchemy import select

logger = structlog.get_logger()
router = APIRouter()


@router.websocket("/scan/{scan_job_id}")
async def scan_progress_ws(
    websocket: WebSocket,
    scan_job_id: str,
    token: str = Query(None),
):
    """
    WebSocket endpoint for real-time scan progress.
    Authenticates via query parameter token, then streams progress updates.
    """
    await websocket.accept()

    # Validate token
    if not token:
        await websocket.send_json({"error": "Authentication required. Pass ?token=<jwt>"})
        await websocket.close(code=4001)
        return

    try:
        from apps.api.app.core.security import decode_token
        payload = decode_token(token)
        tenant_id = payload.get("tenant")
    except Exception:
        await websocket.send_json({"error": "Invalid token"})
        await websocket.close(code=4001)
        return

    logger.info("ws_connected", scan_job_id=scan_job_id)

    # Send initial state from DB
    try:
        from apps.api.app.core.database import async_session_factory
        from apps.api.app.models.scan import ScanJob

        async with async_session_factory() as db:
            result = await db.execute(
                select(ScanJob).where(ScanJob.id == scan_job_id)
            )
            job = result.scalar_one_or_none()
            if job:
                await websocket.send_json({
                    "scan_job_id": scan_job_id,
                    "status": job.status.value if hasattr(job.status, "value") else str(job.status),
                    "progress_pct": job.progress_pct or 0,
                    "message": job.status_message or "",
                    "stats": job.stats or {},
                })

                # If already complete, close
                if job.status.value in ("completed", "failed", "cancelled"):
                    await websocket.close()
                    return
    except Exception as e:
        logger.warning("ws_initial_state_failed", error=str(e)[:100])

    # Subscribe to Redis pub/sub for live updates
    try:
        from services.pubsub.redis_pubsub import subscribe_scan_progress

        async for update in subscribe_scan_progress(scan_job_id):
            # Liveness tick (update is None): this socket only ever SENDS,
            # so without this it would never notice the client/server going
            # away and would block uvicorn's graceful shutdown forever
            # ("Waiting for background tasks"). Drain any queued disconnect
            # (uvicorn pushes one on shutdown) with a tiny non-blocking
            # receive, and bail out if the socket is gone.
            if update is None:
                try:
                    msg = await asyncio.wait_for(websocket.receive(), timeout=0.01)
                    if msg.get("type") == "websocket.disconnect":
                        break
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    break
                continue
            try:
                await websocket.send_json(update)
                if update.get("status") in ("completed", "failed"):
                    break
            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        logger.info("ws_disconnected", scan_job_id=scan_job_id)
    except Exception as e:
        logger.error("ws_error", scan_job_id=scan_job_id, error=str(e)[:200])
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
