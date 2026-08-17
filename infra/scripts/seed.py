# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Database seed script — creates default tenant + admin user + dev user.

Idempotent: safe to run multiple times. Detects existing rows by
email and skips creation if the user is already there. Useful for
both fresh deploys (creates everything) and re-runs on existing
databases (no-op if seeded already).

Usage
-----
    docker compose exec api python -m infra.scripts.seed

Environment variables
---------------------
    DATABASE_URL_SYNC          required — synchronous Postgres URL
                               (sqlalchemy.create_engine compatible)
    SEED_ADMIN_EMAIL           default: admin@vooda.ai
    SEED_ADMIN_PASSWORD        no default — generated if unset
    SEED_DEV_EMAIL             default: dev@vooda.ai
    SEED_DEV_PASSWORD          no default — the dev user is only
                               created when this is set
    SEED_TENANT_NAME           default: Default Org
    SEED_TENANT_SLUG           default: default

Credentials
-----------
There is no default password. Previously the admin account was
created as ``Adwin@123`` unless overridden, which meant every
install that skipped the override shared one publicly-documented
credential — on a product whose whole job is finding exactly that
mistake in other people's code. Any internet-facing deployment was
one search away from compromise.

If SEED_ADMIN_PASSWORD is unset, a 24-character password is
generated with `secrets` and printed once. It is never written to
disk or logged, so if the operator loses it the remedy is to reset
the account, not to look it up.

The dev user is no longer created unless SEED_DEV_PASSWORD is
explicitly set: a second standing account is a second thing to
forget about, and nothing in a fresh install needs it.
"""
from __future__ import annotations

import os
import sys
import uuid

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session


# ── Configuration (env-driven, with explicit defaults) ────────

DATABASE_URL = os.environ.get("DATABASE_URL_SYNC")
if not DATABASE_URL:
    # Fall back to the dev default, but loudly. A production deploy
    # should always set this via docker-compose env.
    DATABASE_URL = "postgresql://vooda:vooda_dev_password@db:5432/vooda"
    print(
        "[seed] WARNING: DATABASE_URL_SYNC not set, using dev default. "
        "This is only safe inside a docker-compose dev environment.",
        file=sys.stderr,
    )

# Default emails use a real-looking TLD because the API's Pydantic
# `EmailStr` validator (backed by email-validator / RFC 6762)
# REJECTS reserved/special-use TLDs like `.local` with a 422 at the
# login endpoint. Earlier defaults of `admin@vooda.local` looked
# clean for "local dev" but the user couldn't actually log in —
# discovered 2026-05-04 mid-deploy. Override via env if your org
# wants a real domain in dev too.
ADMIN_EMAIL = os.environ.get("SEED_ADMIN_EMAIL", "admin@vooda.ai")
DEV_EMAIL = os.environ.get("SEED_DEV_EMAIL", "dev@vooda.ai")
TENANT_NAME = os.environ.get("SEED_TENANT_NAME", "Default Org")
TENANT_SLUG = os.environ.get("SEED_TENANT_SLUG", "default")


def _generate_password(length: int = 24) -> str:
    """A password strong enough that publishing the generator is fine.

    `secrets.choice` over an unambiguous alphabet — no O/0 or l/1/I,
    because this gets read off a terminal and retyped. 24 characters
    from a 60-character set is ~141 bits, so nothing about knowing the
    method helps an attacker.
    """
    import secrets
    import string

    alphabet = (
        "".join(c for c in string.ascii_letters + string.digits if c not in "O0lI1")
        + "!@#%^&*-_=+"
    )
    return "".join(secrets.choice(alphabet) for _ in range(length))


# No fallback default. An unset password means "generate one", never
# "use the one written in the docs" — see the module docstring.
ADMIN_PASSWORD = os.environ.get("SEED_ADMIN_PASSWORD") or _generate_password()
ADMIN_PASSWORD_GENERATED = not os.environ.get("SEED_ADMIN_PASSWORD")

# The dev account is opt-in. Creating a second standing login that
# nobody asked for is a liability, not a convenience.
DEV_PASSWORD = os.environ.get("SEED_DEV_PASSWORD")


def _hash_pw(pw: str) -> str:
    """Bcrypt hash a password.

    We import bcrypt directly rather than passlib because of a
    long-standing bcrypt 4.x / passlib version detection mismatch
    that breaks `passlib.hash.bcrypt.hash()`. Direct bcrypt works
    on every supported python+bcrypt combo.
    """
    import bcrypt

    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def _ensure_tenant(db: Session, name: str, slug: str):
    """Find-or-create the seed tenant. Returns the Tenant row."""
    from apps.api.app.models.user import Tenant

    existing = db.execute(
        select(Tenant).where(Tenant.slug == slug)
    ).scalar_one_or_none()
    if existing:
        return existing

    tenant = Tenant(id=uuid.uuid4(), name=name, slug=slug)
    db.add(tenant)
    db.flush()
    return tenant


def _ensure_user(db: Session, *, tenant_id, email: str, password: str,
                 full_name: str, role) -> bool:
    """Find-or-create a user with the given email + role assignment.

    Returns True when a new user was created, False if the user
    already existed (in which case password/role are NOT updated —
    this keeps the seed idempotent without surprising operators).
    """
    from apps.api.app.models.user import User, UserRole

    existing = db.execute(
        select(User).where(User.email == email)
    ).scalar_one_or_none()
    if existing:
        return False

    user_id = uuid.uuid4()
    user = User(
        id=user_id,
        tenant_id=tenant_id,
        email=email,
        hashed_password=_hash_pw(password),
        full_name=full_name,
        is_active=True,
    )
    db.add(user)
    db.flush()

    # Role assignment is per-user, not part of the User row itself.
    db.add(UserRole(user_id=user_id, role=role))
    return True


def seed() -> None:
    engine = create_engine(DATABASE_URL)

    # Import models so SQLAlchemy registers them on the shared
    # metadata. The models package's __init__ already does this,
    # but the import keeps tooling honest.
    from apps.api.app.models.user import RoleType  # noqa: F401

    created_tenant = False
    created_admin = False
    created_dev = False

    with Session(engine) as db:
        tenant = _ensure_tenant(db, TENANT_NAME, TENANT_SLUG)
        # First-time create vs found?
        # _ensure_tenant only inserts when missing — we can detect
        # creation by checking the row's UUID against the existing
        # ones, but a cheaper signal is whether the session has
        # pending objects.
        created_tenant = bool(db.new)

        created_admin = _ensure_user(
            db,
            tenant_id=tenant.id,
            email=ADMIN_EMAIL,
            password=ADMIN_PASSWORD,
            full_name="Administrator",
            role=RoleType.ADMIN,
        )
        created_dev = DEV_PASSWORD and _ensure_user(
            db,
            tenant_id=tenant.id,
            email=DEV_EMAIL,
            password=DEV_PASSWORD,
            full_name="Developer",
            role=RoleType.DEVELOPER,
        )
        db.commit()

    # ── Operator-facing summary ──
    print("─" * 60)
    print(" Vooda seed complete")
    print("─" * 60)
    print(f"  Tenant : {TENANT_NAME} ({TENANT_SLUG})  [{'created' if created_tenant else 'exists'}]")
    print(f"  Admin  : {ADMIN_EMAIL}                [{'created' if created_admin else 'exists'}]")
    if DEV_PASSWORD:
        print(f"  Dev    : {DEV_EMAIL}                  [{'created' if created_dev else 'exists'}]")
    print()

    if created_admin and ADMIN_PASSWORD_GENERATED:
        # Printed exactly once. Nothing writes it down, so an operator
        # who loses it resets the account rather than looking it up.
        print("  ┌" + "─" * 56 + "┐")
        print("  │ Generated admin password — copy it now, it is not")
        print("  │ stored anywhere and will not be shown again:")
        print("  │")
        print(f"  │   {ADMIN_EMAIL}")
        print(f"  │   {ADMIN_PASSWORD}")
        print("  └" + "─" * 56 + "┘")
        print()
        print("  Set SEED_ADMIN_PASSWORD before seeding to choose your own.")
    elif created_admin:
        print(f"  Admin password: taken from SEED_ADMIN_PASSWORD.")

    if created_dev:
        print(f"  Dev password:   taken from SEED_DEV_PASSWORD.")
    elif not DEV_PASSWORD:
        print("  Dev user:       skipped (set SEED_DEV_PASSWORD to create one).")
    print("─" * 60)


if __name__ == "__main__":
    seed()
