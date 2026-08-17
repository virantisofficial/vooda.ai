# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""NotificationDelivery — per-attempt persistence for the retry queue.

Why this model exists
=====================
Pre-2026-05-22 the notification dispatcher (services/notifications/
dispatcher.py) did fire-and-forget: ``dispatch()`` attempted each
channel once, collected ``DispatchResult`` objects, and returned them.
A transient Slack 503 or a Jira blip silently lost the notification
— users had to discover missing alerts by their absence.

Track-A P1.5 (2026-05-22) closes that gap by persisting every FAILED
dispatch attempt as a row in this table.  A periodic Celery task
(``apps.worker.tasks.process_notification_retries`` — fires every
60s) picks up due rows, re-attempts via the dispatcher's channel
handlers, and applies exponential backoff:

  attempt 1 failed → next_retry_at = now + 60s
  attempt 2 failed → next_retry_at = now + 5m
  attempt 3 failed → next_retry_at = now + 15m
  attempt 4 failed → next_retry_at = now + 1h
  attempt 5 failed → status = "dead_lettered" + audit event

Successful retry sets status = "succeeded" — the row is kept for
forensics (compliance audit can answer "did we ever try to send
this alert?").

Status state machine
--------------------
    pending_retry → succeeded         (retry attempt worked)
    pending_retry → pending_retry     (still failing, attempt < 5)
    pending_retry → dead_lettered     (5 attempts exhausted)
    pending_retry → permanent_failure (caller flagged unretryable
                                        error, e.g. 4xx auth)

Channels included
-----------------
All channels managed by NotificationDispatcher: Slack, Teams, Email,
Custom Webhook, PagerDuty, Jira, ServiceNow, Linear, Splunk HEC,
Sentinel, Datadog.

Ticketing channels (Jira / ServiceNow / Linear) rely on their
existing dedup tag logic to avoid double-creating tickets on retry —
the retry POSTs the same payload and the channel handler's idempotency
guard does the right thing.
"""
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


# Status enum kept as plain strings (matches the rest of the codebase's
# convention of string columns for low-cardinality state) to dodge the
# PostgreSQL enum migration cost on incremental status additions.
NOTIFICATION_DELIVERY_STATUSES = (
    "pending_retry",      # in queue, awaiting retry
    "succeeded",          # retried successfully — kept for audit
    "dead_lettered",      # exhausted retry budget
    "permanent_failure",  # caller-flagged unretryable (e.g. 401)
)


class NotificationDelivery(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """One row per (notification × channel × attempt-batch).

    Created when ``dispatch()`` records a transient failure and
    updated by ``process_notification_retries`` as the row passes
    through the retry state machine.  See module docstring for the
    full lifecycle.
    """
    __tablename__ = "notification_deliveries"

    # ── Identity of the notification being delivered ──
    # We don't FK to a single "notification" table because the
    # dispatcher emits both in-app Notification rows AND external
    # channel deliveries from one logical event.  payload + channel
    # together are the natural key.
    channel = Column(String(50), nullable=False, index=True)        # slack|teams|email|webhook|...
    event_type = Column(String(50), nullable=False, index=True)     # scan_complete|critical_finding|...
    severity = Column(String(20), nullable=True)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(255), nullable=True, index=True)

    # ── The original payload, serialised so retry can reconstruct ──
    # Stored as JSONB so the retry task can rebuild NotificationPayload
    # without re-running the original notification-generation pipeline
    # (which may have looked at since-changed state).
    payload = Column(JSONB, nullable=False)

    # ── Which IntegrationConfig (channel destination) we're sending to ──
    # FK is intentionally NULLABLE: if the config is deleted between
    # original failure and retry, the row is preserved with the
    # last-known config_id so audit can reconstruct intent.  Retry
    # task that sees a NULL config_id marks the row dead_lettered.
    integration_config_id = Column(
        UUID(as_uuid=True),
        ForeignKey("integration_configs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ── State machine ──
    status = Column(String(30), nullable=False, default="pending_retry", index=True)
    attempt_count = Column(Integer, nullable=False, default=1)
    next_retry_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_attempted_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)         # truncated provider error string
    succeeded_at = Column(DateTime(timezone=True), nullable=True)
    dead_lettered_at = Column(DateTime(timezone=True), nullable=True)

    # ── Optimistic-lock guard (matches the pattern from P0 #1) ──
    # Prevents two retry workers from clobbering each other if Celery
    # delivers the same task to two consumers.  SQLAlchemy folds this
    # into UPDATE's WHERE clause; concurrent stale write raises
    # StaleDataError which the retry task handles by skipping.
    version = Column(Integer, nullable=False, default=1, server_default="1")
    __mapper_args__ = {"version_id_col": version}


# Backoff schedule applied by the retry task — exposed as a constant
# so tests can verify the contract without re-implementing it.
# Tuned for "give transient blips a chance to resolve without
# hammering the provider": short first re-attempt (1 min) for fast
# self-heal, then exponential to avoid retry storms.
RETRY_BACKOFF_SECONDS = (
    60,        # 1m  — most transient blips clear within a minute
    300,       # 5m  — provider rate-limit windows
    900,       # 15m — modest backoff for sustained issues
    3600,      # 1h  — long backoff before declaring DLQ
    21600,     # 6h  — final attempt before dead-lettering
)
MAX_RETRY_ATTEMPTS = len(RETRY_BACKOFF_SECONDS)
