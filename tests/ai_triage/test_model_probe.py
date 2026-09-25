"""The probe's whole job is to stop a green tick from lying.

Graded without a network call, because the branches that matter are the
ones a live model will not reliably reproduce on demand — an overloaded
provider, a starved budget, a model answering "maybe".
"""
import json

import pytest

from services.ai_triage import model_probe as mp
from services.ai_triage.model_probe import (
    READY, NEEDS_SETUP, UNUSABLE, UNVERIFIED, grade_reply, _verdict_for, _looks_transient,
)

GOOD = json.dumps({"classification": "TRUE_POSITIVE", "confidence": 0.9, "reasoning": "live key"})


def g(content, stop="complete", out=50, ms=900):
    return grade_reply(content, stop, out, ms)


def test_a_clean_answer_is_ready():
    outcome, parsed, _ = g(GOOD)
    assert outcome == "ok"
    assert parsed["classification"] == "TRUE_POSITIVE"
    assert _verdict_for(outcome, {}, False).state == READY


def test_the_exact_reply_that_used_to_report_success():
    """gemini-3.5-flash, measured: empty body, truncated, reported OK."""
    outcome, parsed, _ = g("", stop="truncated", out=0)
    assert outcome == "empty_truncated"
    assert parsed is None
    assert _verdict_for(outcome, {}, retried_ok=False).state == UNUSABLE


def test_starved_model_that_recovers_is_fixable_not_broken():
    res = _verdict_for("empty_truncated", {}, retried_ok=True, retry_at=2000)
    assert res.state == NEEDS_SETUP
    assert res.suggested_config == {"max_tokens": 2000}
    assert "2000" in res.remedy


def test_the_remedy_never_tells_a_user_to_lower_their_budget():
    """A flat retry of 2000 would be a REDUCTION on the 4096 default,
    so the fix would have read as 'set this smaller' on a model that
    needed more room."""
    for configured in (300, 1024, 4096, 8192):
        assert mp.retry_budget(configured) >= configured


def test_retry_budget_scales_but_stays_bounded():
    assert mp.retry_budget(300) == 2000, "floor applies to small budgets"
    assert mp.retry_budget(4096) == mp._RETRY_CEILING, "scales up to the cap"
    # Past the cap the answer is "keep what you have", never a smaller
    # number — a budget that big is not what is holding the model back.
    assert mp.retry_budget(100_000) == 100_000


def test_prose_wrapped_answer_counts_as_working():
    """gemma writes reasoning first. Usable — just wasteful."""
    outcome, parsed, ev = g("Here is the JSON:\n```json\n" + GOOD + "\n```")
    assert outcome == "ok_salvaged"
    assert ev["salvaged"] is True
    res = _verdict_for(outcome, ev, False)
    assert res.state == NEEDS_SETUP
    assert res.suggested_config == {"supports_json_mode": True}


def test_a_verdict_we_cannot_store_is_not_a_pass():
    outcome, _, ev = g(json.dumps({"classification": "maybe", "confidence": 0.5}))
    assert outcome == "bad_vocabulary"
    assert _verdict_for(outcome, ev, False).state == NEEDS_SETUP


def test_slow_model_is_flagged_without_being_hidden():
    outcome, _, _ = g(GOOD, ms=25_000)
    assert outcome == "ok_slow"
    res = _verdict_for(outcome, {"latency_ms": 25_000}, False)
    assert res.state == NEEDS_SETUP
    assert "25s" in res.headline


@pytest.mark.parametrize("err", [
    "Google API error 503: overloaded", "HTTP 429 rate limit exceeded",
    "Read timed out", "model is temporarily unavailable",
])
def test_overloaded_is_never_called_broken(err):
    """Four healthy models 503'd in one sweep. Hiding them is the
    expensive failure — a customer concludes Vooda lacks their model."""
    assert _looks_transient(err) is True


@pytest.mark.parametrize("err", [
    "Google API error 404: model not found", "401 Unauthorized", "invalid model name",
])
def test_a_real_failure_is_not_excused_as_transient(err):
    assert _looks_transient(err) is False


def test_unverified_is_a_distinct_state_from_unusable():
    """'I don't know' must not collapse into 'no'."""
    assert UNVERIFIED != UNUSABLE
    assert len({READY, NEEDS_SETUP, UNVERIFIED, UNUSABLE}) == 4


def test_evidence_is_captured_but_headline_stays_plain():
    """Numbers belong behind Details, not on the settings screen."""
    outcome, _, ev = g("", stop="truncated", out=0)
    assert ev["output_tokens"] == 0 and ev["stop_reason"] == "truncated"
    res = _verdict_for(outcome, ev, retried_ok=True)
    assert not any(ch.isdigit() for ch in res.headline), res.headline


def test_every_outcome_maps_to_a_real_state():
    """A new outcome must not fall through to a silent default."""
    outcomes = ["ok", "ok_slow", "ok_salvaged", "empty", "empty_truncated",
                "truncated_partial", "unparseable", "bad_vocabulary"]
    for o in outcomes:
        for retried in (True, False):
            st = _verdict_for(o, {"latency_ms": 1000}, retried).state
            assert st in {READY, NEEDS_SETUP, UNUSABLE}, (o, retried, st)


def test_a_fixable_state_always_carries_a_remedy():
    for o in ["ok_slow", "ok_salvaged", "bad_vocabulary"]:
        res = _verdict_for(o, {"latency_ms": 1000}, False)
        assert res.remedy, o
    fixed = _verdict_for("empty_truncated", {}, True, 2000)
    assert fixed.remedy and fixed.suggested_config


def test_an_unrecognised_error_is_not_evidence_of_a_broken_model():
    """Measured: gemma-4-31b-it failed one call with an unclassified
    error and was marked unusable; the next probe graded it needs_setup.
    Unusable hides the model — that verdict needs positive evidence."""
    from services.ai_triage.model_probe import _definitive_failure
    assert _definitive_failure("Connection reset by peer") is None
    assert _definitive_failure("Google API error 500: internal") is None
    assert _definitive_failure("unexpected payload shape") is None


def test_only_missing_or_forbidden_models_are_called_unusable():
    from services.ai_triage.model_probe import _definitive_failure
    assert _definitive_failure("Google API error 404: model not found") is not None
    assert _definitive_failure("401 Unauthorized") is not None
    assert _definitive_failure("403 permission denied") is not None


def test_a_fix_is_never_offered_for_a_setting_already_applied():
    """Seen live: JSON mode was on, the model wrapped its answer
    anyway, and the remedy still read "Turning on JSON mode…" — a Fix
    button that changes nothing and then reports success. Some models
    accept the flag and ignore it."""
    already_on = _verdict_for("ok_salvaged", {}, False, json_mode_on=True)
    assert already_on.state == NEEDS_SETUP
    assert already_on.suggested_config == {}, "nothing to apply"
    assert "ignores" in already_on.remedy

    was_off = _verdict_for("ok_salvaged", {}, False, json_mode_on=False)
    assert was_off.suggested_config == {"supports_json_mode": True}


def test_every_offered_fix_actually_changes_something():
    """A suggested_config that matches the current setting is not a
    fix. Each one here must differ from the state it was probed in."""
    for on in (True, False):
        res = _verdict_for("ok_salvaged", {}, False, json_mode_on=on)
        if res.suggested_config:
            assert res.suggested_config.get("supports_json_mode") != on
