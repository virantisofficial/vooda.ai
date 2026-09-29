# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Point the suite at its own database, before anything opens one.

These are integration tests: they stand up the real app and talk to a
real Postgres. What they did not do was talk to a *separate* one. The
configured database is the deployment's, so running pytest against an
install wrote to it — and not only in throwaway rows. The inbound
webhook tests set signing secrets through the real config endpoint, so
a full run replaced the GitHub, GitLab and Bitbucket webhook secrets of
whatever install was configured, leaving deliveries failing signature
verification with nothing to say why.

So the suite now uses `<database>_test`, created on demand beside the
real one and populated with the schema and a single tenant. Nothing
else changes: the fixtures still provision their own admin, and tests
that need seeded content still skip when it is absent.

This runs at import, not in a fixture, because
`apps.api.app.core.database` builds its engine at module scope — by the
time a fixture could run, the connection is already bound to whatever
the environment said.

Set VOODA_TEST_USE_CONFIGURED_DB=1 to opt out and run against the
configured database, which is what you want when testing a remote
deployment on purpose. It is opt-in because the failure mode of the
old default was silent.
"""
from __future__ import annotations

import os
import re

_OPT_OUT = os.environ.get("VOODA_TEST_USE_CONFIGURED_DB") == "1"

#: Mirrors the defaults in apps/api/app/core/config.py. Read from the
#: environment rather than from Settings, because importing Settings is
#: the thing this has to happen before.
_DEFAULT_SYNC = "postgresql://vooda:vooda_dev_password@localhost:5432/vooda"
_DEFAULT_ASYNC = "postgresql+asyncpg://vooda:vooda_dev_password@localhost:5432/vooda"


def _with_database(url: str, name: str) -> str:
    """Swap the database name, leaving query parameters alone."""
    head, _, tail = url.rpartition("/")
    query = ""
    if "?" in tail:
        _, _, query = tail.partition("?")
        query = "?" + query
    return f"{head}/{name}{query}"


def _database_of(url: str) -> str:
    return re.split(r"[?]", url.rpartition("/")[2])[0]


def _ensure_database(admin_url: str, name: str) -> None:
    """CREATE DATABASE if it is not there yet.

    Connects to `postgres` rather than the target, since you cannot
    create a database from inside itself.
    """
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

    conn = psycopg2.connect(_with_database(admin_url, "postgres"))
    try:
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
            if cur.fetchone() is None:
                cur.execute(f'CREATE DATABASE "{name}"')
    finally:
        conn.close()


if not _OPT_OUT:
    _live_sync = os.environ.get("DATABASE_URL_SYNC") or _DEFAULT_SYNC
    _live_async = os.environ.get("DATABASE_URL") or _DEFAULT_ASYNC
    _test_name = f"{_database_of(_live_sync)}_test"

    _ensure_database(_live_sync, _test_name)

    # Before any import of Settings, so the engine that
    # apps.api.app.core.database builds at module scope points here.
    os.environ["DATABASE_URL_SYNC"] = _with_database(_live_sync, _test_name)
    os.environ["DATABASE_URL"] = _with_database(_live_async, _test_name)


import pytest  # noqa: E402  — after the environment is settled


@pytest.fixture(scope="session", autouse=True)
def _schema_and_tenant():
    """Give the test database a schema and something to belong to.

    `create_all` rather than alembic: the suite asserts against the
    models it imports, and a migration chain adds minutes to every run
    for a schema that is rebuilt from those same models anyway. A
    migration that does not match its model is caught by the migration
    tests, which is where that belongs.
    """
    if _OPT_OUT:
        yield
        return

    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from apps.api.app.core.config import settings
    from apps.api.app.core.database import Base
    import apps.api.app.models  # noqa: F401 — registers every table

    engine = create_engine(settings.DATABASE_URL_SYNC)
    Base.metadata.create_all(engine)

    from apps.api.app.models.user import Tenant

    with Session(engine) as db:
        if db.execute(select(Tenant).limit(1)).scalar_one_or_none() is None:
            db.add(Tenant(name="pytest", slug="pytest"))
            db.commit()
    engine.dispose()
    yield
