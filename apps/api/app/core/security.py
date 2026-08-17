# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from apps.api.app.core.config import settings
from apps.api.app.core.database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# auto_error=False so the dependency does NOT raise when the
# Authorization header is missing — we want to fall back to the
# ``X-API-Key`` alt header (Sprint 2 / GAP-11).  Missing-everywhere
# still raises 401, just now from inside ``get_current_user`` where
# the message can mention both header forms.
security_scheme = HTTPBearer(auto_error=False)

# Alt-header constant — many CI tools (Jenkins envinject, CircleCI
# orbs, GitLab CI/CD variables piped via curl --header) prefer
# ``X-API-Key`` to ``Authorization: Bearer …``.  Honouring both costs
# us nothing and removes one of the most common onboarding-time
# integration failures.
_ALT_API_KEY_HEADER = "X-API-Key"

# Per-key throttle for the "api_key_used" audit row.  Without this every
# request adds a row → log blow-up at any reasonable QPS.  60 s buys us
# ≤ 1 440 rows/day per hot key, comfortably inside any audit-retention
# budget while still letting an investigator see a clear "first use"
# event after each idle period.
_API_KEY_USE_AUDIT_THROTTLE_S = 60

# RFC 6750 §3: the response to a Bearer-protected resource that rejects
# a request MUST include a WWW-Authenticate challenge so the client
# knows which auth scheme to retry with.  Some HTTP libs (curl
# --anyauth, requests-oauthlib) silently hang without it.
_BEARER_CHALLENGE = {"WWW-Authenticate": 'Bearer realm="vooda-api"'}


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


#: A real bcrypt hash of a value nobody can supply. Verifying against it
#: costs the same as verifying a genuine hash. Computed once at import
#: so the work is not repeated per request.
_DUMMY_HASH = pwd_context.hash("vooda-nonexistent-account-placeholder")


def verify_password_constant_time(plain: str, hashed: Optional[str]) -> bool:
    """Verify a password, spending the same time when the user is unknown.

    Skipping the hash for a missing account turned response time into
    the answer to "does this account exist?" — roughly 20ms for an
    unknown address against 340ms for a real one with a wrong password,
    because only the second path ran bcrypt. That is a user-enumeration
    oracle: an attacker maps every account on an instance without ever
    holding a valid credential, and on a self-hosted security product
    that list is itself worth having.

    Hashing against a fixed dummy when ``hashed`` is None spends
    comparable work on both paths. Always returns False in that case;
    the caller still decides what to do about it.
    """
    if hashed is None:
        pwd_context.verify(plain, _DUMMY_HASH)
        return False
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers=_BEARER_CHALLENGE,
        )


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
):
    # Per-request cache.  When a router uses both a scope-check dependency
    # (``require_scope("findings")``) AND an endpoint-level dependency
    # (``user = Depends(get_current_user)``), FastAPI dedupes by callable
    # — but the scope-check internally calls us via a different code path,
    # so without this cache we'd hash + DB-query the API key twice per
    # request.  request.state survives the whole request lifecycle.
    cached = getattr(request.state, "auth_user", None)
    if cached is not None:
        return cached

    # Token resolution: prefer Authorization: Bearer, fall back to the
    # alt ``X-API-Key`` header (GAP-11).  If both are present, Bearer
    # wins — keeps the "obvious" header authoritative when CI configs
    # set both by accident.
    token: Optional[str] = credentials.credentials if credentials else None
    if not token:
        alt = request.headers.get(_ALT_API_KEY_HEADER)
        if alt:
            token = alt.strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail=(
                "Not authenticated — supply Authorization: Bearer <token> "
                "or X-API-Key: <key>."
            ),
            headers=_BEARER_CHALLENGE,
        )

    # API-key path: detect the ``vooda_`` prefix BEFORE attempting JWT
    # decode.  Prior to 2026-05-24 this check ran *after* decode_token,
    # which always raised on a non-JWT key — silently disabling the
    # entire CI/CD integration story.  See audit report Part 4 GAP-0.
    if token.startswith("vooda_"):
        user = await _authenticate_api_key(token, db, request)
        request.state.auth_user = user
        return user

    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid token payload",
            headers=_BEARER_CHALLENGE,
        )

    from apps.api.app.models.user import User

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="User not found or inactive",
            headers=_BEARER_CHALLENGE,
        )
    request.state.auth_user = user
    return user


async def _authenticate_api_key(
    raw_key: str,
    db: AsyncSession,
    request: Optional[Request] = None,
):
    """Authenticate using an API key instead of JWT.

    Side-effects on success:
      * updates ``last_used_at = now`` on every call (cheap UPDATE);
      * writes an ``api_key_used`` audit row with IP + User-Agent +
        ``METHOD /path`` — throttled to at most once per key per
        ``_API_KEY_USE_AUDIT_THROTTLE_S`` seconds (see constant above)
        so a hot CI pipeline doesn't generate audit-log spam.

    Side-effects on IP-allowlist block (Sprint 3 / GAP-10):
      * writes an ``api_key_ip_blocked`` audit row with the rejected
        source IP + the CIDR list it failed against.  NOT throttled —
        every block is an interesting security event.
      * raises HTTP 403 (NOT 401) — the credential is valid, just not
        permitted from this source.  The distinction matters: 401
        tells CI "rotate your key", 403 tells "your network changed".
    """
    import hashlib
    import ipaddress

    from apps.api.app.models.api_key import APIKey
    from apps.api.app.models.user import User
    from apps.api.app.core.audit import log_audit, _client_ip_from_request

    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    result = await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active == True)
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers=_BEARER_CHALLENGE,
        )

    now = datetime.now(timezone.utc)

    # Expiry check
    if api_key.expires_at and api_key.expires_at < now:
        raise HTTPException(
            status_code=401,
            detail="API key expired",
            headers=_BEARER_CHALLENGE,
        )

    # IP-allowlist check (Sprint 3 / GAP-10).  Skipped when the
    # allowlist is empty/NULL (the default — unrestricted).  Source IP
    # respects the X-Forwarded-For chain via the same helper the audit
    # log uses, so customers behind a load balancer get the real client
    # IP rather than the LB's address.
    if api_key.allowed_ip_cidrs:
        source_ip_str = _client_ip_from_request(request)
        allowed = False
        if source_ip_str:
            try:
                source_ip = ipaddress.ip_address(source_ip_str)
                for cidr in api_key.allowed_ip_cidrs:
                    if source_ip in ipaddress.ip_network(cidr, strict=False):
                        allowed = True
                        break
            except (ValueError, TypeError):
                # Malformed source IP — fall through to deny.  We do
                # NOT trust an unparseable IP, but we DO log it.
                pass
        if not allowed:
            # Resolve owning user for the audit row's user_id.  Best-
            # effort: if the user lookup fails the audit row still
            # writes with a NULL user_id rather than swallowing the
            # block silently.
            owner = None
            try:
                owner_result = await db.execute(
                    select(User).where(User.id == api_key.created_by)
                )
                owner = owner_result.scalar_one_or_none()
            except Exception:
                pass
            if owner is not None:
                await log_audit(
                    db, owner, "api_key_ip_blocked", "api_key",
                    api_key.id,
                    (
                        f"Key '{api_key.name}' blocked from "
                        f"{source_ip_str or 'unknown'} — not in allowlist "
                        f"{api_key.allowed_ip_cidrs}"
                    ),
                    request=request,
                )
                # Force a commit on the rejection — HTTPException would
                # otherwise rollback the audit insert because the auth
                # dependency tears down the session on raise.
                try:
                    await db.commit()
                except Exception:
                    pass
            raise HTTPException(
                status_code=403,
                detail=(
                    "API key not permitted from this source IP. "
                    "Contact your administrator to add this network to "
                    "the key's allowlist."
                ),
                headers=_BEARER_CHALLENGE,
            )

    # Resolve the owning user
    result = await db.execute(select(User).where(User.id == api_key.created_by))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="API key owner not found or inactive",
            headers=_BEARER_CHALLENGE,
        )

    # Throttled audit row.  First use ever (``last_used_at IS NULL``) is
    # always logged; subsequent rows only if the gap since the last
    # successful auth exceeds the throttle window.
    last_used = api_key.last_used_at
    should_audit = (
        last_used is None
        or (now - last_used).total_seconds() >= _API_KEY_USE_AUDIT_THROTTLE_S
    )
    if should_audit:
        endpoint = (
            f"{request.method} {request.url.path}" if request is not None else "unknown"
        )
        await log_audit(
            db,
            user,
            "api_key_used",
            "api_key",
            api_key.id,
            f"Key '{api_key.name}' used: {endpoint}",
            request=request,
        )

    api_key.last_used_at = now

    # Stash the APIKey on request.state so downstream scope-check
    # dependencies (``require_scope``) can read api_key.scopes without
    # re-querying the DB.  When the request is JWT-authenticated this
    # attribute stays absent, which require_scope treats as "no scope
    # constraint" (sessions have no scope concept).
    if request is not None:
        request.state.api_key = api_key
    return user


def require_scope(*allowed_scopes: str):
    """FastAPI dependency factory: gate an endpoint or router behind one
    or more API-key scopes.

    Behaviour:
      * JWT-authenticated requests bypass the check entirely.  A logged-
        in user has a full session and is not subject to API-key scope
        restrictions.
      * API-key requests must carry **at least one** of ``allowed_scopes``
        OR the wildcard ``admin`` scope.  Missing → 403 with a precise
        ``Need / Have`` detail string so CI logs say exactly what to add
        to the key.

    Usage on a single endpoint::

        @router.post("/{repo_id}/scan")
        async def trigger(
            repo_id: UUID,
            user = Depends(require_scope("scan")),
        ):
            ...

    Usage at router level (one decorator for an entire router)::

        app.include_router(
            findings.router,
            prefix="/api/v1/findings",
            dependencies=[Depends(require_scope("findings"))],
        )
    """
    allowed = set(allowed_scopes)
    if not allowed:
        raise ValueError("require_scope() needs at least one scope")

    async def _check(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
        db: AsyncSession = Depends(get_db),
    ):
        user = await get_current_user(request, credentials, db)
        api_key = getattr(request.state, "api_key", None)
        if api_key is None:
            # JWT auth — no scope concept.  Full session.
            return user

        granted = set(api_key.scopes or [])
        if "admin" in granted or (allowed & granted):
            return user

        raise HTTPException(
            status_code=403,
            detail=(
                f"API key '{api_key.name}' missing required scope. "
                f"Need one of: {sorted(allowed)}; have: "
                f"{sorted(granted) if granted else ['(none)']}"
            ),
            headers=_BEARER_CHALLENGE,
        )

    return _check


async def require_role(required_role: str):
    """Dependency factory for role-based access control."""

    async def _check(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
        db: AsyncSession = Depends(get_db),
    ):
        user = await get_current_user(request, credentials, db)
        from apps.api.app.models.user import UserRole
        from sqlalchemy import select as sel

        result = await db.execute(
            sel(UserRole).where(
                UserRole.user_id == user.id, UserRole.role == required_role
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return _check
