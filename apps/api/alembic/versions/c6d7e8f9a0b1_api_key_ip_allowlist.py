# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""api_keys: per-key IP allowlist (CIDR-based)

Revision ID: c6d7e8f9a0b1
Revises: b5c6d7e8f9a0
Create Date: 2026-05-24 18:00:00.000000

Why
---
Sprint 3 of the API-key audit follow-up.  Enterprise SOC 2 / FedRAMP
buyers consistently RFP for "credential scoping by source network" —
i.e. the ability to lock a CI/CD key so that it only authenticates
when presented from the static egress IPs of the CI runner.  Without
this, a key copied to a developer laptop (or leaked into a public
repo) is immediately abusable from anywhere.

Stripe, AWS IAM, GitHub Apps and Cloudflare API tokens all expose
the same control.  Vooda needs it to pass enterprise procurement.

Column
------
  api_keys.allowed_ip_cidrs  JSONB  NULL
      list[str] of CIDR blocks (IPv4 or IPv6).  NULL or [] = no
      restriction (preserves pre-migration auth behaviour).  Non-
      empty = the request's source IP MUST fall inside at least one
      listed CIDR or auth returns 403.

Why JSONB instead of inet[] or text[]
-------------------------------------
JSONB matches the existing ``scopes`` column convention on the same
table — keeps a single serialization pattern for "list-shaped per-key
config".  Postgres' inet[] would force the API to translate types on
every read; JSONB is just strings round-tripped through Pydantic
which can validate them deterministically with ``ipaddress``.

Why no index
------------
The allowlist check happens inline during auth (one key already
identified by hash), so we're never scanning the table by allowlist
contents.  A GIN index on the JSONB would be pure overhead.
"""
from alembic import op
import sqlalchemy as sa


revision = "c6d7e8f9a0b1"
down_revision = "b5c6d7e8f9a0"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "api_keys",
        sa.Column(
            "allowed_ip_cidrs",
            sa.dialects.postgresql.JSONB(),
            nullable=True,
        ),
    )


def downgrade():
    op.drop_column("api_keys", "allowed_ip_cidrs")
