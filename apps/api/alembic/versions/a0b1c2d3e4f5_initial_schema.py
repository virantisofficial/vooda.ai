# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""initial schema — create every table from SQLAlchemy models

Revision ID: a0b1c2d3e4f5
Revises:
Create Date: 2026-05-03 14:00:00.000000

Why this migration exists
-------------------------
Vooda's database was originally bootstrapped manually (init-db.sql +
hand-applied DDL) BEFORE Alembic was wired in. The first "real"
migration (``bc0423892c95_add_correlation_and_suppression``) was
auto-generated against an already-populated database and therefore
assumed all base tables (``users``, ``tenants``, ``repositories``,
``normalized_findings``, ``integration_configs``, etc.) already
existed — it only adds new columns / new tables on top.

That assumption breaks every fresh deploy: a clean Postgres has no
tables, so ``op.add_column('normalized_findings', ...)`` fails with
``relation "normalized_findings" does not exist``.

This migration is the missing prelude. It calls
``Base.metadata.create_all(checkfirst=True)`` so:

  - On a fresh database: every table from ``apps.api.app.models.*``
    is created in one go (~50 tables, all with their indexes / FKs /
    server defaults from the model definitions).
  - On an existing database that was bootstrapped manually before
    Alembic: ``checkfirst=True`` means existing tables are skipped,
    no errors. Idempotent.

After this runs, ``bc0423892c95`` (which now lists this revision as
its ``down_revision``) is free to add its incremental columns +
suppression_rules table because every base table it references
exists.

We deliberately use ``Base.metadata.create_all`` instead of writing
out the DDL by hand — the model definitions are the source of
truth, and re-deriving them in this migration would create a drift
problem (any model change would also need a migration update).

The downgrade is intentionally a no-op: dropping every table on
``downgrade()`` would discard the entire database. Use
``alembic downgrade base`` only if you also intend to ``DROP
DATABASE`` — there is no safe partial undo for "create everything".
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "a0b1c2d3e4f5"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Required Postgres extensions — must exist BEFORE the table
    # creates because every primary key uses
    # `server_default=sa.text("gen_random_uuid()")` (provided by
    # pgcrypto). On the standard docker-compose setup these are also
    # created by infra/scripts/init-db.sql when the postgres
    # container first initialises its data directory, but that script
    # only runs once. Customers who connect to a managed Postgres
    # (RDS, Neon, Supabase, Coolify external DB) won't have init-db
    # run at all — so we defensively create the extensions here too.
    # IF NOT EXISTS makes it a no-op when they're already present.
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute('CREATE EXTENSION IF NOT EXISTS pgcrypto')

    # Import every model so SQLAlchemy registers the tables on the
    # shared ``Base.metadata``. The `*` import in
    # ``apps/api/app/models/__init__.py`` already loads them all,
    # but we re-import here defensively so the migration works even
    # if a future refactor breaks the package-level convenience
    # re-export.
    from apps.api.app.core.database import Base
    import apps.api.app.models  # noqa: F401  (registers all model tables)

    # Create every table that doesn't already exist. ``checkfirst``
    # is the magic that makes this safe on existing databases —
    # Postgres CREATE TABLE IF NOT EXISTS is the underlying primitive.
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, checkfirst=True)


def downgrade() -> None:
    """Intentionally no-op.

    Dropping every table here would destroy the entire database
    including operational data from every tenant. If you genuinely
    need to start over, use Postgres-level commands (``DROP DATABASE
    vooda; CREATE DATABASE vooda;``) instead of an Alembic downgrade.
    """
    pass
