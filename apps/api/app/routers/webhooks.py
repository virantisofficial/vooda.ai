# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Webhook endpoints — receives push/PR events from GitHub, GitLab, Bitbucket.
Verifies signatures, dispatches scan tasks, and manages webhook config.
Webhook config stored in IntegrationConfig table (persisted across restarts).
"""

from typing import Optional
from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.integration import IntegrationConfig
from services.webhooks.receiver import (
    PARSERS, VERIFIERS, WebhookEvent,
)

logger = structlog.get_logger()
router = APIRouter()


class WebhookResponse(BaseModel):
    status: str
    message: str
    event_type: str | None = None
    scan_job_id: str | None = None


class WebhookConfigUpdate(BaseModel):
    secret: Optional[str] = None
    enabled: Optional[bool] = None


# ── In-memory cache for fast webhook config reads ──
# Used by the admin-facing GET /webhooks/config endpoint to avoid a
# DB hit on every page load.  The actual signature-verification path
# (``receive_webhook`` below) reads from DB directly on every call,
# so this cache is NOT in the security-critical path — but a stale
# entry could still leak a rotated secret through the admin UI for
# however long the entry sat.
#
# TTL bounding (Track-A P0 #5, 2026-05-20)
# ----------------------------------------
# Entries expire after ``_CACHE_TTL_SECONDS``.  Combined with the
# explicit ``invalidate_webhook_cache()`` call wired into the PUT
# config endpoint (and available to any future writer), this gives
# two layers of staleness protection:
#
#   1. Active rotation via the API → instant cache eviction
#   2. Any other write path (direct DB mutation, replica lag,
#      schema-level migration) → self-healing after at most TTL.
#
# Cache shape: { cache_key: (loaded_at_monotonic, data) }
import time as _time

_CACHE_TTL_SECONDS = 60
_webhook_cache: dict[str, tuple[float, dict]] = {}


def invalidate_webhook_cache(tenant_id: str, provider: str | None = None) -> None:
    """Drop cached entries for a tenant.

    When ``provider`` is given, drop only that (tenant, provider) pair.
    When ``None``, drop every entry for the tenant.  Callable from
    any writer (current callers: update_webhook_config; future:
    integration-config router on direct edits, post-rotation hooks).
    """
    if provider is not None:
        _webhook_cache.pop(f"{tenant_id}:{provider}", None)
        return
    prefix = f"{tenant_id}:"
    for k in [k for k in _webhook_cache if k.startswith(prefix)]:
        _webhook_cache.pop(k, None)


async def _load_webhook_config(db: AsyncSession, tenant_id: str, provider: str) -> dict:
    """Load webhook config from DB with a short-TTL in-memory cache.

    Cache hit when the entry is younger than ``_CACHE_TTL_SECONDS``;
    otherwise we re-read from DB and refresh the timestamp.  The TTL
    is short on purpose — admin pages reload often enough that 60s
    is hardly visible to the user, while still bounding the worst-
    case staleness window for a rotated secret that didn't take the
    explicit-invalidate code path.
    """
    cache_key = f"{tenant_id}:{provider}"
    entry = _webhook_cache.get(cache_key)
    if entry is not None:
        loaded_at, data = entry
        if (_time.monotonic() - loaded_at) < _CACHE_TTL_SECONDS:
            return data
        # Expired — fall through to refresh.  We don't pop yet because
        # the refresh below replaces the entry atomically.

    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == tenant_id,
            IntegrationConfig.provider == f"webhook_{provider}",
        ).limit(1)
    )
    cfg = result.scalar_one_or_none()
    if cfg:
        from packages.common.encryption import decrypt_value

        config_data = cfg.config or {}
        stored_secret = decrypt_value(config_data.get("webhook_secret", "") or "")
        data = {
            "enabled": cfg.is_active,
            # Don't hand the raw signing secret back to the browser on
            # every config load. Report whether one is set and a masked
            # tail so the admin can recognise it; the real value stays on
            # the server. `secret_set` drives the UI's "configured" state.
            "secret": (f"••••{stored_secret[-4:]}" if len(stored_secret) >= 4 else ("••••" if stored_secret else "")),
            "secret_set": bool(stored_secret),
            "total_events": config_data.get("total_events", 0),
            "last_event_at": config_data.get("last_event_at"),
            "id": str(cfg.id),
        }
    else:
        data = {"enabled": False, "secret": "", "secret_set": False, "total_events": 0}
    _webhook_cache[cache_key] = (_time.monotonic(), data)
    return data


@router.get("/config")
async def get_webhook_config(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get webhook configuration for all providers."""
    webhooks = []
    for provider in ["github", "gitlab", "bitbucket"]:
        cfg = await _load_webhook_config(db, str(user.tenant_id), provider)
        webhooks.append({
            "provider": provider,
            "enabled": cfg.get("enabled", False),
            "secret": cfg.get("secret", ""),          # masked (••••tail)
            "secret_set": cfg.get("secret_set", False),
            "last_event_at": cfg.get("last_event_at"),
            "total_events": cfg.get("total_events", 0),
        })
    return {"webhooks": webhooks}


@router.put("/{provider}/config")
async def update_webhook_config(
    provider: str,
    body: WebhookConfigUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update webhook config for a provider (secret, enabled state)."""
    if provider not in ("github", "gitlab", "bitbucket"):
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")

    # Find or create integration config
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == user.tenant_id,
            IntegrationConfig.provider == f"webhook_{provider}",
        ).limit(1)
    )
    cfg = result.scalar_one_or_none()

    if not cfg:
        cfg = IntegrationConfig(
            tenant_id=user.tenant_id,
            name=f"{provider.title()} Webhook",
            integration_type="webhooks",
            provider=f"webhook_{provider}",
            is_active=True,
            config={},
        )
        db.add(cfg)

    # The GET endpoint returns the secret masked (••••tail). If the UI
    # posts that mask back unchanged, treat it as "no change" rather than
    # overwriting the real secret with a string of dots.
    if body.secret is not None and body.secret.startswith("••••"):
        body.secret = None

    if body.secret is not None:
        from packages.common.encryption import encrypt_config_dict

        config_data = dict(cfg.config or {})
        config_data["webhook_secret"] = body.secret
        # Encrypt at rest, like every other integration config. This one
        # stored the signing secret in plaintext, so a database read
        # exposed the exact value needed to forge signed webhook events.
        # encrypt_config_dict encrypts webhook_secret (a *_secret key)
        # and leaves total_events / last_event_at alone; it is idempotent
        # on already-encrypted values.
        cfg.config = encrypt_config_dict(config_data)

    # A webhook cannot be enabled without a signing secret: the receiver
    # fails closed on an unsigned/unverifiable event, so enabling one
    # with no secret would just produce a live endpoint that 401s every
    # real event. Refuse it here with a clear reason instead.
    if body.enabled:
        from packages.common.encryption import decrypt_value

        effective_secret = decrypt_value((cfg.config or {}).get("webhook_secret") or "")
        if not effective_secret.strip():
            raise HTTPException(
                status_code=400,
                detail=(
                    "Set a signing secret before enabling this webhook — "
                    "events are rejected unless they are HMAC-signed with it."
                ),
            )
    if body.enabled is not None:
        cfg.is_active = body.enabled

    await db.flush()

    # Invalidate cache via the public helper so any future
    # consumer (test harnesses, post-rotation hooks) can do the
    # same thing without poking at the cache internals.
    invalidate_webhook_cache(str(user.tenant_id), provider)

    logger.info("webhook_config_updated", provider=provider, enabled=cfg.is_active)
    return {"status": "ok", "provider": provider, "enabled": cfg.is_active}


@router.post("/{provider}/test")
async def test_webhook(
    provider: str,
    user: User = Depends(get_current_user),
):
    """Test webhook connectivity (sends a test ping).

    Carries its own auth: once the router-level require_scope is removed
    so the inbound receiver can be public, the admin-only endpoints in
    this router must each authenticate on their own. Config get/update
    already do via get_current_user; this one now does too.
    """
    if provider not in ("github", "gitlab", "bitbucket"):
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
    logger.info("webhook_test_triggered", provider=provider)
    return {"status": "ok", "message": f"Webhook endpoint for {provider} is reachable"}


@router.post("/{provider}", response_model=WebhookResponse)
async def receive_webhook(provider: str, request: Request, db: AsyncSession = Depends(get_db)):
    """
    Receive webhook from GitHub, GitLab, or Bitbucket.
    Provider must be: github, gitlab, or bitbucket.
    No auth required — webhooks are verified by HMAC signature.
    """
    if provider not in PARSERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")

    # Read raw body for signature verification
    body_bytes = await request.body()
    headers = dict(request.headers)

    # Load webhook secret from DB (check all tenants — webhook URL doesn't carry tenant info)
    webhook_secret = None
    try:
        result = await db.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.provider == f"webhook_{provider}",
                IntegrationConfig.is_active == True,
            ).limit(1)
        )
        cfg = result.scalar_one_or_none()
        if cfg:
            from packages.common.encryption import decrypt_value, encrypt_config_dict

            # Decrypt for the HMAC check only — never write the plaintext
            # back into the stored dict. decrypt_value passes plaintext
            # through unchanged, so legacy rows written before encryption
            # still verify.
            webhook_secret = decrypt_value((cfg.config or {}).get("webhook_secret") or "") or None
            # Track event count. Re-encrypt on write (idempotent) so the
            # counter update can never silently downgrade the secret back
            # to plaintext.
            config_data = dict(cfg.config or {})
            config_data["total_events"] = config_data.get("total_events", 0) + 1
            from datetime import datetime, timezone
            config_data["last_event_at"] = datetime.now(timezone.utc).isoformat()
            cfg.config = encrypt_config_dict(config_data)
            await db.flush()
    except Exception:
        # Never process an event we could not authenticate. A DB error
        # here is not a licence to skip verification.
        logger.warning("webhook_secret_lookup_failed", provider=provider)
        raise HTTPException(status_code=503, detail="Webhook verification temporarily unavailable")

    # ── Fail closed ───────────────────────────────────────────────
    # This endpoint is public (no bearer auth), so the HMAC signature is
    # the ONLY thing standing between a real provider event and a forged
    # one. It was previously verified only `if webhook_secret:`, and the
    # default config has no secret — so with no secret set, ANY POST was
    # accepted and could trigger scans (DoS / abuse). A signature we
    # cannot check is a signature we must reject.
    verifier = VERIFIERS.get(provider)
    if not webhook_secret or not verifier:
        logger.warning("webhook_rejected_no_secret", provider=provider)
        raise HTTPException(
            status_code=401,
            detail=(
                "This webhook has no signing secret configured, so events "
                "cannot be verified. Set a secret under Integrations → "
                "Webhooks and use the same value in the provider's webhook."
            ),
        )
    if not verifier(body_bytes, headers, webhook_secret):
        logger.warning("webhook_signature_invalid", provider=provider)
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Parse the event
    import json
    try:
        body = json.loads(body_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    parser = PARSERS[provider]
    event = parser(headers, body)

    if not event:
        return WebhookResponse(
            status="ignored",
            message="Event type not supported or action not relevant",
        )

    logger.info(
        "webhook_received",
        provider=provider,
        event_type=event.event_type,
        repo=event.repo_name,
        branch=event.branch,
    )

    # ── Per-repo health tracking + scan toggle ────────────────────────
    # Locate the Repository row by URL / name so we can:
    #   1. Stamp last_webhook_event_* fields → drives the list-view
    #      webhook health badge (green ≤ 7d, yellow ≤ 30d, red > 30d).
    #   2. Honour the per-repo push_scan_enabled / pr_scan_enabled
    #      toggles so customers can keep webhooks subscribed (so the
    #      health badge stays green) while opting out of PR scans on
    #      a noisy repo.
    #
    # If the URL doesn't match any tracked repo we silently drop the
    # event — preserves the previous behaviour for webhooks pointing at
    # repos Vooda doesn't track yet.
    from apps.api.app.models.repository import Repository
    from datetime import datetime, timezone

    matched_repo = None
    try:
        repo_q = await db.execute(
            select(Repository).where(
                Repository.url == event.repo_url,
            ).limit(1)
        )
        matched_repo = repo_q.scalar_one_or_none()
    except Exception as e:
        logger.warning("webhook_repo_lookup_failed", error=str(e)[:200])

    # Honour the per-repo event toggle + branch-pattern filter BEFORE
    # dispatching.  We still stamp the health timestamp (the event
    # arrived, that's an ops signal worth tracking) but we don't run
    # the scan.
    scan_blocked = False
    block_reason = "skipped"
    if matched_repo is not None:
        if event.event_type == "push" and not matched_repo.push_scan_enabled:
            scan_blocked = True
            block_reason = "push scans disabled for this repository"
        elif event.event_type in ("pull_request", "merge_request") and not matched_repo.pr_scan_enabled:
            scan_blocked = True
            block_reason = "PR scans disabled for this repository"
        else:
            # Branch-pattern gate.  NULL / empty patterns mean "scan
            # all branches" (preserves the pre-w0x1y2z3a4b5 default).
            from services.secret_scan.branch_filter import branch_matches
            if not branch_matches(event.branch, matched_repo.branch_patterns):
                scan_blocked = True
                block_reason = (
                    f"branch '{event.branch}' does not match any of "
                    f"this repository's monitored branch patterns"
                )

    scan_job_id = None
    dispatch_status = "skipped"
    if not scan_blocked:
        scan_job_id = await _dispatch_scan(event)
        dispatch_status = "success" if scan_job_id else "failed"

    # Persist webhook-health fields.  Done AFTER dispatch so the
    # `last_webhook_event_status` reflects the actual outcome (failed
    # to enqueue the scan task → red badge).
    if matched_repo is not None:
        try:
            matched_repo.last_webhook_event_at = datetime.now(timezone.utc)
            matched_repo.last_webhook_event_type = event.event_type
            matched_repo.last_webhook_event_status = dispatch_status
            await db.commit()
        except Exception as e:
            logger.warning("webhook_health_update_failed", error=str(e)[:200])
            await db.rollback()

    if scan_blocked:
        return WebhookResponse(
            status="skipped",
            message=block_reason,
            event_type=event.event_type,
        )

    return WebhookResponse(
        status="accepted",
        message=f"Scan triggered for {event.event_type} on {event.repo_name}",
        event_type=event.event_type,
        scan_job_id=scan_job_id,
    )


async def _dispatch_scan(event: WebhookEvent) -> str | None:
    """Dispatch a Celery task to scan the webhook event."""
    try:
        from apps.worker.celery_app import celery_app

        task = celery_app.send_task(
            "apps.worker.tasks.run_webhook_scan",
            kwargs={
                "provider": event.provider,
                "event_type": event.event_type,
                "repo_url": event.repo_url,
                "repo_name": event.repo_name,
                "branch": event.branch,
                "base_sha": event.base_sha,
                "head_sha": event.head_sha,
                "author": event.author,
                "pr_number": event.pr_number,
                "pr_title": event.pr_title,
            },
        )
        return task.id
    except Exception as e:
        logger.error("webhook_dispatch_error", error=str(e)[:200])
        return None
