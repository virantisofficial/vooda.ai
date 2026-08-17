# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Audit logging helper — call from any endpoint to record an audit event.

Usage:
    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "user_created", "user", new_user.id, f"Created {email}")

To capture client IP + user-agent for forensics (recommended for any
destructive / state-changing action — repo delete, archive, role grant,
etc.), pass the FastAPI Request:
    await log_audit(db, user, "repo_deleted", "repository", rid, detail, request=request)

For auth events (no user object):
    await log_audit_auth(db, "login_success", "auth", tenant_id=tid, user_id=uid, detail="...", ip="1.2.3.4")
"""

from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession


def _client_ip_from_request(request) -> Optional[str]:
    """Best-effort source-IP extraction.

    Honours the standard proxy chain headers in priority order:
      1. X-Forwarded-For — first IP (the original client) when set
      2. X-Real-IP — single-IP set by some load balancers / nginx
      3. request.client.host — direct connection fallback

    Returns None when no IP can be resolved (e.g. test client without
    a transport).  Truncated to the column width (45 = IPv6 max).
    """
    if request is None:
        return None
    try:
        # X-Forwarded-For: "client, proxy1, proxy2" — first hop is the
        # original client.  Many CDNs append; we always take the head.
        xff = request.headers.get("x-forwarded-for")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first[:45]
        xri = request.headers.get("x-real-ip")
        if xri:
            return xri.strip()[:45]
        # Direct connection — works for local / non-proxied deploys.
        if request.client and request.client.host:
            return str(request.client.host)[:45]
    except Exception:
        return None
    return None


def _user_agent_from_request(request) -> Optional[str]:
    """Pull the User-Agent header, truncated to the column width (500)."""
    if request is None:
        return None
    try:
        ua = request.headers.get("user-agent")
        return ua[:500] if ua else None
    except Exception:
        return None


async def log_audit(
    db: AsyncSession,
    user,
    action: str,
    resource_type: str,
    resource_id=None,
    detail: str | None = None,
    request=None,
    metadata: dict | None = None,
) -> None:
    """Record an audit event. Non-blocking — won't raise on failure.

    Backward-compatible: callers that don't pass `request` still work,
    leaving `ip_address` / `user_agent` as NULL (matches historical
    behaviour).  New callers should pass `request=request` so the
    forensic trail is complete.

    `metadata` (optional) — structured JSONB payload for filterable
    queries.  Use for "show me all deletes where active_creds > 10"
    style audit queries that would otherwise require text-regex over
    `detail`.
    """
    try:
        from apps.api.app.models.audit import AuditEvent
        event = AuditEvent(
            tenant_id=user.tenant_id,
            user_id=user.id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            detail=detail,
            metadata_=metadata,  # column is named `metadata` in SQL; ORM attr is `metadata_`
            ip_address=_client_ip_from_request(request),
            user_agent=_user_agent_from_request(request),
        )
        db.add(event)
    except Exception:
        pass  # Never fail the parent operation due to audit logging


async def log_audit_auth(
    db: AsyncSession,
    action: str,
    resource_type: str = "auth",
    tenant_id=None,
    user_id=None,
    resource_id=None,
    detail: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    commit: bool = False,
) -> None:
    """Record an auth audit event (login/logout/failed). Works without a user object.
    Set commit=True for events logged before an HTTPException (would otherwise rollback).
    """
    try:
        from apps.api.app.models.audit import AuditEvent
        event = AuditEvent(
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            detail=detail,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        db.add(event)
        if commit:
            await db.commit()
    except Exception:
        pass
