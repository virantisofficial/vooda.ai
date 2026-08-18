# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import os

from celery import Celery
from celery.signals import worker_process_init, beat_init

from apps.api.app.core.config import settings
from packages.common.logging_config import configure_logging

celery_app = Celery(
    "vooda_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["apps.worker.tasks"],
)


# Configure logging in every Celery process (master + each forked
# pool worker + the beat scheduler).  Hooking these signals — rather
# than calling configure_logging() at module-load — makes sure each
# process gets its own handlers; otherwise the master's handlers
# would be cloned across forks and double-emit each line.  Bug fix
# 2026-05-09 — same centralized pipeline as api/main.py.

@worker_process_init.connect  # type: ignore[misc]
def _configure_worker_logging(**_kwargs):
    configure_logging(
        service="worker",
        version=settings.APP_VERSION,
        env=os.environ.get("VOODA_ENV", "production"),
    )
    # The worker decrypts the same integration credentials the API does,
    # so it needs the same key and the same refusal to start without
    # one. Checked after logging is configured so the non-production
    # warning is actually visible.
    from apps.api.app.core.config import assert_production_secret_key

    assert_production_secret_key()


@beat_init.connect  # type: ignore[misc]
def _configure_beat_logging(**_kwargs):
    configure_logging(
        service="beat",
        version=settings.APP_VERSION,
        env=os.environ.get("VOODA_ENV", "production"),
    )

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    # Sprint G-4 — if a worker child is SIGKILL'd (hard time limit,
    # OOM, container restart) the task it was running is REJECTED
    # back to the queue instead of silently lost. Combined with
    # task_acks_late above and stability_id-based dedup, a killed
    # scan retries and completes on the second worker rather than
    # vanishing. Trade-off: a task that legitimately killed its
    # worker (memory bomb) will be retried — bounded by max_retries
    # on the task. Standard Celery prod pattern.
    task_reject_on_worker_lost=True,
    # Sprint G-4 — recycle worker children after N tasks so any
    # accumulated state (memory creep, leaked file handles, stuck
    # thread) clears on a regular cadence. Standard Celery/Gunicorn
    # production setting; chosen value matches the Celery docs'
    # default-prod recommendation.
    worker_max_tasks_per_child=50,
    # Sprint G-4 — and recycle on memory pressure (KB). A long-
    # running worker that creeps past ~500 MB resident set gets
    # replaced before it OOMs the host. Idempotent: child exits
    # cleanly after its current task, parent spawns a replacement.
    worker_max_memory_per_child=500_000,
    # Global time limits — 2h soft / 2h15m hard. Per-task overrides
    # land on individual @celery_app.task() decorators (Sprint G-1
    # puts run_scan_job at 25m soft / 30m hard so a deadlocked code
    # scan can't squat for two hours). The soft-limit handler in
    # run_scan_job writes a useful FAILED row before SIGKILL closes
    # the door.
    task_soft_time_limit=7200,
    task_time_limit=8100,
    # ── Queue routing (scan-slot isolation) ──────────────────────────
    # User-facing scans get their own `scans` queue + dedicated worker
    # pool (docker-compose `worker-scans`), so a backlog of best-effort
    # background jobs (generate_remediation, create_fix_pr, ticket
    # dispatch, notifications, …) on the default `celery` queue can
    # never occupy every prefork slot and starve a scan — the live
    # failure observed when 2 generate_remediation tasks pinned both
    # slots and a queued scan sat PENDING at 0%.
    #
    # Routing is by task NAME, so every dispatch path is covered with
    # zero call-site changes: `.delay()` from the API/scheduler and
    # `send_task("apps.worker.tasks.run_webhook_scan", …)` from the
    # webhook router both honour this map. Anything not listed stays on
    # the default `celery` queue (unchanged). The existing worker also
    # consumes `scans` as a safety-net (compose `-Q celery,scans`), so a
    # routed scan can never pile up unconsumed even if worker-scans is
    # down — worst case it runs on the default worker (today's
    # behaviour), never silently lost.
    task_routes={
        "apps.worker.tasks.run_scan_job": {"queue": "scans"},
        "apps.worker.tasks.run_source_scan": {"queue": "scans"},
        "apps.worker.tasks.run_webhook_scan": {"queue": "scans"},
        # P0 two-way sync — CLI/CI findings import runs on the same
        # dedicated scans pool so a burst of CI imports can't starve the
        # default queue (and vice-versa).
        "apps.worker.tasks.ingest_imported_findings": {"queue": "scans"},
    },
    # Celery Beat schedule for recurring tasks.
    #
    # Beat runs in its own container (see docker-compose.yml `beat`
    # service). The 5-minute cadence below means hourly/daily/weekly
    # schedules from the scheduler engine are honored within ±5 min,
    # which is the right balance between freshness and not pounding
    # upstream APIs. The engine itself decides "is this entity
    # overdue?" — Beat just wakes it up regularly enough to ask.
    beat_schedule={
        "check-scheduled-scans": {
            "task": "apps.worker.tasks.run_scheduled_scans_task",
            "schedule": 300.0,  # 5 min — finest cadence we honor
        },
        # Belt-and-braces against stranded source-scan locks: if a
        # worker dies (SIGKILL, OOM, prefork-pool revoke) the in-
        # process release in `_run_source_scan` doesn't run. The lock
        # TTL eventually clears the key, but until then duplicate-
        # scan attempts for the source see a stale LockNotAcquired.
        # 5 min keeps the worst-case stranded window short without
        # putting meaningful load on Redis (the lock keyspace is
        # bounded by source count).
        "cleanup-stale-source-scan-locks": {
            "task": "apps.worker.tasks.cleanup_stale_source_scan_locks_task",
            "schedule": 300.0,
        },
        # Force-fail scan_jobs that have outlived the staleness
        # threshold (Sprint G-1: 15 min default, configurable via
        # STALE_SCAN_THRESHOLD_MINUTES env). These zombies happen when
        # a worker dies mid-scan (SIGKILL, OOM, container restart) OR
        # an asyncio deadlock pins the slot indefinitely (the failure
        # mode observed on aws-cdk step 7). After marking the row
        # FAILED the sweep also issues
        # `celery_app.control.revoke(terminate=True, signal='SIGKILL')`
        # against the holding task so the prefork slot actually frees,
        # not just the DB row.
        # 60s cadence so the worst-case stuck window is ~16 min
        # (15m threshold + one beat tick). Bug fix 2026-05-08;
        # tightened Sprint G-1.
        "cleanup-stale-running-scans": {
            "task": "apps.worker.tasks.cleanup_stale_running_scans_task",
            "schedule": 60.0,
        },
        # Daily TTL eviction for the per-file scanner-output cache.
        # The cache accumulates rows across rule-pack versions and
        # repository file churn — without this prune it would grow
        # unboundedly.
        #
        # 03:00 UTC chosen empirically: lowest scan volume window
        # across global tenants (US-Pacific evening, EU pre-dawn,
        # APAC mid-morning), so the DELETE pressure overlaps with
        # quiet I/O. Falls back to interval scheduling if Beat
        # restarts mid-day — the prune is idempotent so missing or
        # double-running it is harmless.
        "prune-file-scan-cache": {
            "task": "apps.worker.tasks.prune_file_scan_cache_task",
            "schedule": 86400.0,  # 24h — daily cadence
        },
        # Weekly source full-sync sweep — drift recovery + deletion
        # detection for source adapters (Slack, Jira, Confluence, …).
        # Runs every 6 hours; the task itself filters to sources
        # whose last_full_sweep_at is older than the per-source TTL
        # (default 7 days, configurable via FULL_SWEEP_INTERVAL_DAYS
        # env var).
        #
        # Why 6h cadence not "weekly" Beat: Beat doesn't natively
        # express weekly intervals, and a once-a-week task that
        # missed a fire (Beat restart, container redeploy) would
        # delay a sweep by days. The 6h re-check is a self-healing
        # window: a sweep missed at hour 0 fires at hour 6.
        "weekly-source-full-sweep": {
            "task": "apps.worker.tasks.weekly_source_full_sweep_task",
            "schedule": 21600.0,  # 6h — re-check window
        },
        # Track-A P1.5 (2026-05-22): notification + ticket retry queue.
        # Picks up rows in `notification_deliveries` whose
        # next_retry_at <= now, re-attempts via the dispatcher's
        # channel handlers, applies exponential backoff (1m→5m→15m→
        # 1h→6h), and dead-letters after 5 attempts.
        # 60-second cadence so the first retry of a 1-min-backoff
        # row lands within ~1m of the original failure — fast
        # enough that a transient blip clears before a human
        # notices the missing alert.
        "process-notification-retries": {
            "task": "apps.worker.tasks.process_notification_retries_task",
            "schedule": 60.0,
        },
    },
)
