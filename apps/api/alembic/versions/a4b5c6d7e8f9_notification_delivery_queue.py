# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""notification_deliveries table — retry queue for failed dispatches

Revision ID: a4b5c6d7e8f9
Revises: z3a4b5c6d7e8
Create Date: 2026-05-22 11:00:00.000000

Why
---
Notification dispatcher (services/notifications/dispatcher.py) had
no retry: a transient Slack 503 or Jira blip silently lost the
alert.  Track-A P1.5 closes that gap with a persisted retry queue.

Schema
------
notification_deliveries:
  id, tenant_id, created_at, updated_at     (mixins)
  channel               VARCHAR(50)   — slack | teams | email | ...
  event_type            VARCHAR(50)
  severity              VARCHAR(20) NULL
  resource_type         VARCHAR(50) NULL
  resource_id           VARCHAR(255) NULL
  payload               JSONB         — full NotificationPayload dump
  integration_config_id UUID NULL FK  — channel destination
  status                VARCHAR(30)   — pending_retry | succeeded | dead_lettered | permanent_failure
  attempt_count         INT
  next_retry_at         TIMESTAMPTZ NULL
  last_attempted_at     TIMESTAMPTZ NULL
  last_error            TEXT NULL
  succeeded_at          TIMESTAMPTZ NULL
  dead_lettered_at      TIMESTAMPTZ NULL
  version               INT — optimistic-lock counter

Indexes
-------
- (tenant_id, status, next_retry_at) — the worker's hot query
  ("show me due retries for this tenant").  Composite index supports
  both the WHERE filter and the ORDER BY next_retry_at.
- (channel) — observability ("how many Slack retries are pending")
- (resource_id) — debugging ("show all delivery attempts for this
  finding")
- (integration_config_id) — for FK lookup performance + per-config
  health dashboards
"""
from alembic import op
import sqlalchemy as sa


revision = "a4b5c6d7e8f9"
down_revision = "z3a4b5c6d7e8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", sa.dialects.postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),

        sa.Column("channel", sa.String(50), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", sa.String(255), nullable=True),

        sa.Column("payload", sa.dialects.postgresql.JSONB, nullable=False),
        sa.Column(
            "integration_config_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("integration_configs.id", ondelete="SET NULL"),
            nullable=True,
        ),

        sa.Column("status", sa.String(30), nullable=False, server_default="pending_retry"),
        sa.Column("attempt_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.Column("succeeded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dead_lettered_at", sa.DateTime(timezone=True), nullable=True),

        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
    )

    # ── Composite index supports the worker's hot query ──
    # "Find pending_retry rows whose next_retry_at <= now, oldest first."
    # The (tenant_id, status, next_retry_at) order lets the planner do
    # an index range scan instead of a full sort.
    op.create_index(
        "ix_notif_delivery_due",
        "notification_deliveries",
        ["tenant_id", "status", "next_retry_at"],
    )
    op.create_index("ix_notif_delivery_channel", "notification_deliveries", ["channel"])
    op.create_index("ix_notif_delivery_resource_id", "notification_deliveries", ["resource_id"])
    op.create_index("ix_notif_delivery_config", "notification_deliveries", ["integration_config_id"])
    op.create_index("ix_notif_delivery_status", "notification_deliveries", ["status"])


def downgrade() -> None:
    op.drop_index("ix_notif_delivery_status", table_name="notification_deliveries")
    op.drop_index("ix_notif_delivery_config", table_name="notification_deliveries")
    op.drop_index("ix_notif_delivery_resource_id", table_name="notification_deliveries")
    op.drop_index("ix_notif_delivery_channel", table_name="notification_deliveries")
    op.drop_index("ix_notif_delivery_due", table_name="notification_deliveries")
    op.drop_table("notification_deliveries")
