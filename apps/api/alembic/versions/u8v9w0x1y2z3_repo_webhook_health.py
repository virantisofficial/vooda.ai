# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""add per-repo webhook health + push/PR scan toggles

Revision ID: u8v9w0x1y2z3
Revises: t7u8v9w0x1y2
Create Date: 2026-05-16 10:00:00.000000

Why
---
Three new dashboard-grade features land on the /repositories surface:

  1. Per-repo push-scan and PR-scan toggles.  Today every connected
     repo with a webhook scans EVERY push.  Customers running monorepos
     or noisy default branches want fine-grained control: "scan pushes
     yes, scan PRs no" (and vice-versa).  Without per-repo flags the
     scanner can't honour those choices.

  2. Webhook health indicator on the list view.  Today the worker
     processes webhook events but doesn't persist a "last delivered"
     timestamp per repository, so the UI can't show whether a webhook
     is silently dead (a real ops issue — Aikido and Snyk both surface
     this).  Three new columns track when the most recent webhook
     event arrived, what kind it was, and whether it succeeded.

  3. Mini severity-trend sparkline on the list view (no new columns —
     served by a new endpoint, /api/v1/repositories/{id}/severity-trend,
     that aggregates NormalizedFinding.severity over the past 30 days).

Columns added on `repositories`:

  - push_scan_enabled         BOOLEAN  default TRUE   — gates the worker
                                                       from scanning every
                                                       push event
  - pr_scan_enabled           BOOLEAN  default TRUE   — gates the worker
                                                       from scanning PR
                                                       events
  - last_webhook_event_at     TIMESTAMPTZ NULL        — when the most
                                                       recent webhook
                                                       event arrived
  - last_webhook_event_type   VARCHAR(20) NULL        — push / pull_request
                                                       / merge_request
  - last_webhook_event_status VARCHAR(20) NULL        — success / failed

The defaults (`TRUE` for both toggles) preserve existing behaviour —
every repo currently scanning continues to scan after the migration.
Customers who want fine-grained control toggle them off explicitly.

Indexes
-------
  - ix_repositories_last_webhook_event_at — supports the "stale repos"
    filter (`WHERE last_webhook_event_at < NOW() - INTERVAL '14 days'`)
    that the list view will eventually expose as a saved view.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "u8v9w0x1y2z3"
down_revision = "t7u8v9w0x1y2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "repositories",
        sa.Column("push_scan_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    op.add_column(
        "repositories",
        sa.Column("pr_scan_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    op.add_column(
        "repositories",
        sa.Column("last_webhook_event_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "repositories",
        sa.Column("last_webhook_event_type", sa.String(length=20), nullable=True),
    )
    op.add_column(
        "repositories",
        sa.Column("last_webhook_event_status", sa.String(length=20), nullable=True),
    )
    op.create_index(
        "ix_repositories_last_webhook_event_at",
        "repositories",
        ["last_webhook_event_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_repositories_last_webhook_event_at", table_name="repositories")
    op.drop_column("repositories", "last_webhook_event_status")
    op.drop_column("repositories", "last_webhook_event_type")
    op.drop_column("repositories", "last_webhook_event_at")
    op.drop_column("repositories", "pr_scan_enabled")
    op.drop_column("repositories", "push_scan_enabled")
