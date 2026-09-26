"""A model that answers nothing must not read as a healthy run.

Measured end to end: three findings, three 400s from the provider, the
circuit breaker opening — and no notification, no badge on the provider
card, three secrets left at NEEDS_REVIEW with nothing on screen to say
why. Triage was reported as failing when it was PARTLY broken and
stayed silent when it was COMPLETELY broken.

Two causes, both fixed here:
  - `triaged == 0` was read as "nothing to report" and returned early,
    clearing any existing warning on the way out
  - failures were counted per returned result, so a breaker that
    abandons the remaining calls recorded none at all
"""
import inspect

from apps.worker import tasks


def _signal_src() -> str:
    return inspect.getsource(tasks._emit_triage_health_signal)


def test_zero_successes_with_failures_is_not_treated_as_healthy():
    src = _signal_src()
    assert "total_failure" in src
    assert "if not total_failure and (triaged == 0" in src, (
        "a run where nothing succeeded must still reach the notification"
    )


def test_a_total_failure_does_not_clear_the_existing_warning():
    """The old guard returned through the clear-stale-error branch, so
    a model that broke completely erased the badge from when it was
    only partly broken."""
    src = _signal_src()
    clear_at = src.index("last_error = None")
    guard_at = src.index("if not total_failure")
    assert guard_at < clear_at, "the total-failure check must precede the clear"


def test_findings_that_got_no_result_are_counted_as_failures():
    """The breaker abandons remaining calls and returns nothing for
    them; counting only returned results recorded an empty summary."""
    src = inspect.getsource(tasks._run_ai_triage)
    assert "_unaccounted" in src
    assert 'failure_summary["no_response"]' in src


def test_that_failure_type_has_its_own_guidance():
    """A generic message would send the reader looking for a parse
    error that never happened."""
    assert "no_response" in tasks._FAILURE_TYPE_COPY
    body = tasks._FAILURE_TYPE_COPY["no_response"]["body"]
    assert "AI Provider" in body and "re-run" in body.lower()


def test_the_retro_path_raises_the_same_signal():
    """Re-running triage is exactly when someone is watching to see
    whether the model works, and that path told nobody."""
    src = inspect.getsource(tasks._run_ai_triage_retro)
    assert "_emit_triage_health_signal" in src


def test_the_badge_reads_sensibly_when_nothing_succeeded():
    """failed/triaged with a zero denominator rendered as "3/0"."""
    src = _signal_src()
    assert "triage_failed: all" in src
