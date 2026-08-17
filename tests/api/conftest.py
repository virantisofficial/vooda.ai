"""Raise the login rate limit for the integration suite.

POST /auth/login is capped at 10/minute per client IP. Every test in
this directory logs in through the same in-process ASGI transport, so
they all share one budget — and a second run inside the same minute
answered 429 before reaching any assertion. That is how
test_api_key_auth.py came to report 31 errors that had nothing to do
with the code under test.

Raised here rather than removed: the limiter still runs, so a genuine
regression in the limiting path still shows up. Production keeps the
10/minute default from Settings.
"""

import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from apps.api.app.core.config import settings


@pytest.fixture(scope="session", autouse=True)
def relax_login_rate_limit():
    original = settings.AUTH_LOGIN_RATE_LIMIT
    settings.AUTH_LOGIN_RATE_LIMIT = "10000/minute"
    yield
    settings.AUTH_LOGIN_RATE_LIMIT = original


# ── Shared API-integration fixtures ──────────────────────────
# Moved here from test_api_key_auth.py so every test in tests/api can
# stand up the real app, provision a throwaway admin, and get an
# authenticated client — not just the api-key suite.


@pytest.fixture(scope="module")
def app():
    """Import the real FastAPI app once per module."""
    from apps.api.app.main import app as _app
    return _app


#: Credentials for a throwaway admin the suite provisions itself. The
#: password is random per run and never leaves the process.
#:
#: A real TLD, deliberately. The API validates with email-validator,
#: which rejects reserved names — .test, .invalid, .local and .example
#: all 422 at the login endpoint. seed.py carries the same warning
#: after the same mistake shipped once already.
_TEST_ADMIN_EMAIL = "pytest-apikey-suite@vooda-ci.dev"


@pytest.fixture(scope="module")
def provisioned_admin():
    """Create a dedicated admin for the suite, and remove it after.

    Makes the integration tests self-contained: no env var, no
    dependency on what the operator chose at seed time, and no risk of a
    test mutating the real admin account. VOODA_TEST_ADMIN_PASSWORD
    still wins if set, for running against a remote deployment.
    """
    import secrets as _secrets
    import uuid as _uuid

    override_pw = os.environ.get("VOODA_TEST_ADMIN_PASSWORD")
    if override_pw:
        yield os.environ.get("VOODA_TEST_ADMIN_EMAIL", "admin@vooda.ai"), override_pw
        return

    from sqlalchemy import create_engine, select, delete
    from sqlalchemy.orm import Session

    from apps.api.app.core.security import hash_password
    from apps.api.app.models.user import Tenant, User, UserRole, RoleType

    password = _secrets.token_urlsafe(24)
    engine = create_engine(settings.DATABASE_URL_SYNC)

    def _purge(db) -> None:
        """Delete the throwaway user and everything pointing at it.

        Called before creating as well as after. A crash between the two
        leaves the row behind, and the next run then dies on the unique
        email index instead of reporting whatever actually broke.
        """
        from apps.api.app.models.api_key import APIKey
        from apps.api.app.models.audit import AuditEvent

        prior = db.execute(
            select(User).where(User.email == _TEST_ADMIN_EMAIL)
        ).scalar_one_or_none()
        if prior is None:
            return
        # Logging in writes audit rows, and audit_events.user_id has no
        # ON DELETE behaviour, so the user cannot be removed until they
        # are cleared.
        db.execute(delete(AuditEvent).where(AuditEvent.user_id == prior.id))
        db.execute(delete(APIKey).where(APIKey.created_by == prior.id))
        db.execute(delete(UserRole).where(UserRole.user_id == prior.id))
        db.execute(delete(User).where(User.id == prior.id))
        db.commit()

    with Session(engine) as db:
        tenant = db.execute(select(Tenant).limit(1)).scalar_one_or_none()
        if tenant is None:
            pytest.skip("no tenant in the database — run the seed first")
        _purge(db)
        user = User(
            id=_uuid.uuid4(),
            tenant_id=tenant.id,
            email=_TEST_ADMIN_EMAIL,
            hashed_password=hash_password(password),
            full_name="pytest api integration suite",
            is_active=True,
        )
        db.add(user)
        db.flush()
        db.add(UserRole(user_id=user.id, role=RoleType.ADMIN))
        db.commit()

    try:
        yield _TEST_ADMIN_EMAIL, password
    finally:
        with Session(engine) as db:
            _purge(db)


async def _login(client: AsyncClient, creds: tuple[str, str]) -> str:
    email, pwd = creds
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": pwd})
    assert r.status_code == 200, f"admin login failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client(app):
    # Module-scoped so the asyncpg pool created inside the ASGI app is
    # reused across tests in the module — recreating it per test races
    # against the previous loop's connection teardown and produces
    # spurious "Event loop is closed" errors on alternate runs.
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

    # Dispose the shared async engine on the loop that created its
    # connections. Each api test module runs on its own module-scoped
    # loop; without this, the first module leaves asyncpg connections in
    # the global pool bound to a loop that is about to close, and the
    # next module's pool ping fails ("another operation is in progress").
    # This only became visible once a second async-DB module existed.
    from apps.api.app.core.database import engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def admin_jwt(client: AsyncClient, provisioned_admin) -> str:
    return await _login(client, provisioned_admin)
