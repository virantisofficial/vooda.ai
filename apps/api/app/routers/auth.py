# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from apps.api.app.core.database import get_db
from apps.api.app.core.security import (
    verify_password_constant_time,
    verify_password,
    hash_password,
    create_access_token,
    get_current_user,
)
from apps.api.app.core.config import settings
from apps.api.app.core.password_policy import password_policy_error, PASSWORD_HISTORY_DEPTH
from apps.api.app.core.rate_limit import limiter
from apps.api.app.models.user import User, UserRole
from apps.api.app.schemas.auth import LoginRequest, TokenResponse, UserResponse
from pydantic import BaseModel

router = APIRouter()


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# Brute-force defence — much tighter than the global 600/min cap.
# 10/min per remote IP is enough for legitimate "I mistyped my password
# twice then succeeded" flows while blunting credential-stuffing.  Once
# we ship per-account lockout we can relax to 30/min.  slowapi's
# decorator injects the X-RateLimit-* headers via the `response`
# parameter — without it slowapi raises at request time.
#
# Read from settings through a callable rather than baked in at import:
# the budget is per client IP, so an office behind one NAT gateway
# shares it across every user and needs to raise the ceiling. A literal
# also made the integration suite unrunnable more than once a minute,
# which is how 31 tests came to be permanently erroring.
@router.post("/login", response_model=TokenResponse)
@limiter.limit(lambda: settings.AUTH_LOGIN_RATE_LIMIT)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    from apps.api.app.core.audit import log_audit_auth

    # Get client info for audit
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent", "")[:500]

    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    # Always run the hash, even when the account does not exist, so the
    # response time does not reveal which emails are registered. See
    # verify_password_constant_time for why this matters here.
    password_ok = verify_password_constant_time(
        body.password, user.hashed_password if user else None
    )

    if not password_ok:
        # Log failed login — known email goes through the standard
        # log_audit_auth (tenant_id resolves to the user's tenant).
        # Unknown email falls back to the first tenant for tenancy
        # (audit_events.tenant_id is NOT NULL).  Both paths call
        # log_audit_auth(commit=True) so the row commits BEFORE the
        # HTTPException tears down the session — fix for the 2026-05-24
        # QA finding that "Failed login for unknown email" rows weren't
        # appearing in audit_events.  The previous raw-SQL fallback
        # opened a new statement on the same session that then got
        # rolled back along with the failed login flow.
        if user:
            await log_audit_auth(db, "login_failed", "auth",
                tenant_id=user.tenant_id, user_id=user.id,
                detail=f"Failed login for {body.email} (wrong password)",
                ip_address=ip, user_agent=ua, commit=True)
        else:
            # Resolve a fallback tenant (first one — works for single-
            # tenant prod; multi-tenant SaaS would index by sub-domain
            # but we're not there yet).  Failure to resolve = silently
            # skip rather than break the login flow.
            try:
                from apps.api.app.models.user import Tenant
                fallback = (await db.execute(
                    select(Tenant).limit(1)
                )).scalar_one_or_none()
                if fallback is not None:
                    await log_audit_auth(
                        db, "login_failed", "auth",
                        tenant_id=fallback.id, user_id=None,
                        detail=f"Failed login for unknown email: {body.email}",
                        ip_address=ip, user_agent=ua, commit=True,
                    )
            except Exception:
                # Audit best-effort; never fail the login flow on it.
                pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        await log_audit_auth(db, "login_blocked", "auth",
            tenant_id=user.tenant_id, user_id=user.id,
            detail=f"Login blocked for {body.email} (account disabled)",
            ip_address=ip, user_agent=ua, commit=True)
        raise HTTPException(status_code=403, detail="Account disabled")

    # Log successful login
    await log_audit_auth(db, "login_success", "auth",
        tenant_id=user.tenant_id, user_id=user.id,
        detail=f"Logged in: {user.email}",
        ip_address=ip, user_agent=ua)

    token = create_access_token({"sub": str(user.id), "tenant": str(user.tenant_id)})
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserRole).where(UserRole.user_id == current_user.id)
    )
    roles = [r.role.value for r in result.scalars().all()]
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        is_active=current_user.is_active,
        roles=roles,
    )


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Change the signed-in user's own password.

    Requires the current password: a live session on its own is not enough
    to set a new one, so a walk-up on an unlocked screen or a stolen token
    cannot silently lock the owner out of their own account (CWE-620,
    Unverified Password Change). This is self-service only — an
    administrative reset of *another* user goes through PUT /users/{id}
    (admin-scoped) and does not require the old password.
    """
    # Re-load in this request's session so the update is tracked here.
    result = await db.execute(select(User).where(User.id == current_user.id))
    u = result.scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(body.current_password, u.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    new_pw = body.new_password or ""
    policy_error = password_policy_error(new_pw)
    if policy_error:
        raise HTTPException(status_code=400, detail=policy_error)
    if verify_password(new_pw, u.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="New password must be different from the current password",
        )

    # Block reuse of a recent password.
    history = list(u.password_history or [])
    for old_hash in history[-PASSWORD_HISTORY_DEPTH:]:
        if verify_password(new_pw, old_hash):
            raise HTTPException(
                status_code=400,
                detail=f"New password must not reuse any of your last {PASSWORD_HISTORY_DEPTH} passwords",
            )

    # Rotate: the outgoing hash joins history (capped), then set the new one.
    history.append(u.hashed_password)
    u.password_history = history[-PASSWORD_HISTORY_DEPTH:]
    u.hashed_password = hash_password(new_pw)
    await db.flush()

    try:
        from apps.api.app.core.audit import log_audit
        await log_audit(db, current_user, "password_changed", "user", u.id,
                        f"{u.email} changed their own password")
    except Exception:
        # Audit is best-effort; never fail the password change on a log write.
        pass

    return {"status": "password_changed"}
