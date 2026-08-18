# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import os
import sys
from logging.config import fileConfig

import sqlalchemy as sa
from alembic import context
from alembic.script import ScriptDirectory
from sqlalchemy import engine_from_config, pool

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))

from apps.api.app.core.database import Base
from apps.api.app.models import *  # noqa: F401, F403 — import all models for autogenerate

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

db_url = os.environ.get("DATABASE_URL_SYNC", config.get_main_option("sqlalchemy.url"))


def run_migrations_offline():
    context.configure(
        url=db_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _is_virgin_database(connection) -> bool:
    """True only for a database with no Alembic history AND no tables.

    Three states have to be told apart:

    * **Virgin** — no application tables and no recorded revision. A
      brand-new Postgres, i.e. every fresh self-hosted install.
    * **Legacy manual bootstrap** — application tables exist but there
      is no ``alembic_version``. This is what the initial-schema
      migration (a0b1c2d3e4f5) was written for: databases created by
      hand from init-db.sql before Alembic was wired in.
    * **Alembic-managed** — a revision is recorded. The normal case.

    Only the first is virgin. A legacy bootstrap still needs the full
    replay to pick up everything added since, so it must not take the
    stamp shortcut below.
    """
    tables = set(sa.inspect(connection).get_table_names())
    app_tables = tables - {"alembic_version"}
    if app_tables:
        return False
    if "alembic_version" not in tables:
        return True
    # Empty schema but the version table exists (e.g. a previous run
    # aborted before creating anything) — virgin unless a revision is
    # actually recorded.
    recorded = connection.execute(
        sa.text("SELECT 1 FROM alembic_version LIMIT 1")
    ).first()
    return recorded is None


def _bootstrap_virgin_database(connection) -> None:
    """Create the schema directly from the models and stamp it at heads.

    The initial migration builds the schema with
    ``Base.metadata.create_all()`` — the models as they look TODAY,
    already including every change the later migrations describe.
    Replaying that history on top of it makes each subsequent migration
    re-apply work that is already present: ``add_column`` raises
    DuplicateColumn, an ``ON CONFLICT`` names a constraint create_all
    never created, and so on. Most of those migrations carry no
    IF NOT EXISTS guard, so ``alembic upgrade heads`` aborted partway
    through and no fresh install could bootstrap at all.

    For a virgin database the correct end state is exactly what
    create_all produces, so build it and record the revision table at
    heads rather than replaying history. Existing databases never reach
    this path and still migrate incrementally, which is what keeps
    upgrades honest.
    """
    import apps.api.app.models  # noqa: F401  (registers all model tables)

    # Both extensions are required before create_all: every primary key
    # defaults to gen_random_uuid() (pgcrypto). init-db.sql also creates
    # them, but only on a container's first boot — managed Postgres
    # (RDS, Neon, Supabase) never runs it.
    connection.execute(sa.text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'))
    connection.execute(sa.text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))

    Base.metadata.create_all(bind=connection, checkfirst=True)

    # Stamp every head. The tree has merge branches, so there can be
    # more than one; alembic_version holds one row per head.
    heads = ScriptDirectory.from_config(config).get_heads()
    connection.execute(
        sa.text(
            "CREATE TABLE IF NOT EXISTS alembic_version ("
            "  version_num VARCHAR(32) NOT NULL, "
            "  CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
        )
    )
    connection.execute(sa.text("DELETE FROM alembic_version"))
    for head in heads:
        connection.execute(
            sa.text("INSERT INTO alembic_version (version_num) VALUES (:rev)"),
            {"rev": head},
        )
    connection.commit()


def run_migrations_online():
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = db_url
    connectable = engine_from_config(
        configuration, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with connectable.connect() as connection:
        if _is_virgin_database(connection):
            _bootstrap_virgin_database(connection)
            return

        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
        # SQLAlchemy 2.0 connections roll back on close unless committed.
        # The virgin-bootstrap path above commits explicitly; the
        # incremental path must too, or an online `alembic upgrade` logs
        # "Running upgrade ..." and returns 0 while silently discarding
        # both the DDL and the alembic_version bump. Fresh installs take
        # the virgin path, so this only ever bit the first real
        # incremental migration on an existing database.
        connection.commit()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
