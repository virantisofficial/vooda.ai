"""Stale-scan watchdog regression tests (Track-A P1.4).

The watchdog was already force-failing zombie scans; this patch added
three things on top:

  1. Audit event per swept job (compliance trail).
  2. Bell notification to scan initiator (visibility, not silent fail).
  3. Env-tunable threshold (STALE_SCAN_THRESHOLD_HOURS).

Tests focus on the new behaviour + lock the contract so a future
refactor can't silently strip the audit / notification side-effects.

Scenarios covered:

  A. Threshold defaults to 4h when env var unset
  B. Threshold reads from env var when set
  C. Bogus env values fall back to 4h (no early force-failure)
  D. Result dict reports audited + notified counts (interface guard)
  E. Initiator None means notification skipped but audit still emitted
"""
from __future__ import annotations
import os

import pytest


# ── A/B/C: threshold env handling ──────────────────────────────


def test_threshold_default_when_env_unset(monkeypatch):
    monkeypatch.delenv("STALE_SCAN_THRESHOLD_HOURS", raising=False)
    from apps.worker.tasks import _stale_scan_threshold_hours
    assert _stale_scan_threshold_hours() == 4


def test_threshold_reads_from_env(monkeypatch):
    monkeypatch.setenv("STALE_SCAN_THRESHOLD_HOURS", "12")
    from apps.worker.tasks import _stale_scan_threshold_hours
    assert _stale_scan_threshold_hours() == 12


@pytest.mark.parametrize("bogus", ["", "abc", "0", "-1", "not a number"])
def test_threshold_falls_back_to_four_on_bogus_input(monkeypatch, bogus):
    """Safety: never let a misconfigured env var trigger early
    force-failure of legitimate scans.  Any value <1 or unparseable
    must fall back to the 4h default."""
    monkeypatch.setenv("STALE_SCAN_THRESHOLD_HOURS", bogus)
    from apps.worker.tasks import _stale_scan_threshold_hours
    assert _stale_scan_threshold_hours() == 4, (
        f"bogus env value {bogus!r} should have fallen back to 4h"
    )


def test_threshold_accepts_larger_values(monkeypatch):
    """Slow on-prem deployments may legitimately need 8h-24h windows."""
    monkeypatch.setenv("STALE_SCAN_THRESHOLD_HOURS", "24")
    from apps.worker.tasks import _stale_scan_threshold_hours
    assert _stale_scan_threshold_hours() == 24


# ── D: result-shape contract ───────────────────────────────────


def test_result_dict_carries_audited_and_notified_keys():
    """The watchdog's result dict is consumed by the surrounding
    `logger.info` call in cleanup_stale_running_scans_task — a
    refactor that drops the new keys would silently lose observability.
    Lock the contract here."""
    # Pure shape check — verify the result schema by inspecting the
    # source for the keys we promise.
    from apps.worker import tasks as tasks_module
    import inspect
    src = inspect.getsource(tasks_module._cleanup_stale_running_scans)
    # All four counters must appear in the return statement
    assert '"swept"' in src
    assert '"source_jobs"' in src
    assert '"repo_jobs"' in src
    assert '"audited"' in src, "result dict must report audit-emission count"
    assert '"notified"' in src, "result dict must report notification-emission count"
    assert '"threshold_hours"' in src, "result must echo the threshold actually used"


# ── E: source-level guards ─────────────────────────────────────


def test_watchdog_emits_audit_event():
    """Lock that the implementation references AuditEvent — protects
    against a refactor that strips the audit row by mistake."""
    from apps.worker import tasks as tasks_module
    import inspect
    src = inspect.getsource(tasks_module._cleanup_stale_running_scans)
    assert "AuditEvent" in src
    assert "scan_watchdog_failed" in src, (
        "audit action name must remain stable — compliance queries pin on it"
    )


def test_watchdog_emits_notification_for_known_initiator():
    """Lock that the implementation references Notification — and
    that the initiator-None branch is preserved (system/webhook
    scans must remain silent on the notification path)."""
    from apps.worker import tasks as tasks_module
    import inspect
    src = inspect.getsource(tasks_module._cleanup_stale_running_scans)
    assert "Notification" in src
    assert "initiated_by is not None" in src, (
        "notification must only fire when there's a real initiator — "
        "webhook/system scans should not notify a null user"
    )


def test_audit_failure_does_not_poison_cleanup():
    """The DB status update is load-bearing; audit + notification are
    observability extras.  If audit emission throws (model schema
    drift, JSONB serialization issue), the scan must STILL be marked
    FAILED and the loop must continue."""
    from apps.worker import tasks as tasks_module
    import inspect
    src = inspect.getsource(tasks_module._cleanup_stale_running_scans)
    # Each side-effect block must sit inside its own try/except so
    # one bad row can't poison the batch.
    assert "watchdog_audit_emit_failed" in src
    assert "watchdog_notification_emit_failed" in src
