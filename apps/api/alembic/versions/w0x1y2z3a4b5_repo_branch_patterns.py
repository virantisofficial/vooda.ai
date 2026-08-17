# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add branch_patterns to repositories

Revision ID: w0x1y2z3a4b5
Revises: v9w0x1y2z3a4
Create Date: 2026-05-16 13:30:00.000000

Why
---
Per-repo branch-monitoring configuration.  Until now every push event
on every branch triggered a scan, which is unworkable for customers
with high-traffic feature branches or monorepos.

The new column stores a list of fnmatch glob patterns
(``["main"]``, ``["main", "release/*"]``, ``["*"]`` etc.).  Resolution
rules:

  - ``NULL`` or empty list → scan every branch.  Preserves the existing
    "scan everything via webhook" behaviour so the migration is
    non-breaking — every repo created before this migration keeps
    scanning all branches by default.
  - Non-empty list → only scan a branch if its name matches at least
    one pattern.  Empty strings inside the list are ignored.

Pattern syntax is fnmatch (``*`` matches any chars, ``?`` matches one
char, ``[seq]`` matches a character set).  No regex — customers don't
want to write regex in a Settings form.  Examples:

  ["main"]                  → only main
  ["main", "release/*"]     → main + any release/X branch
  ["*"]                     → all branches (same as NULL but explicit)
  ["feature-*", "develop"]  → develop and any feature-X branch

Column
------
  repositories.branch_patterns  JSONB  NULL

JSONB chosen over ARRAY(TEXT) because the FE may eventually want to
store metadata per pattern (e.g. "scope: push-only").  JSONB gives us
that headroom without another migration.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision = "w0x1y2z3a4b5"
down_revision = "v9w0x1y2z3a4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "repositories",
        sa.Column("branch_patterns", JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("repositories", "branch_patterns")
