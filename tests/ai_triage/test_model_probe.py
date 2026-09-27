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
            assert st in {READY, NEEDS_SETUP, UNVERIFIED, UNUSABLE}, (o, retried, st)


def test_our_own_parser_failing_does_not_disqualify_a_model():
    """UNUSABLE is reserved for what the provider told us.

    A 404, a refusal, a reply still cut short at a larger budget — those
    are the provider's answers. A reply Vooda simply could not read is
    our reader coming up empty, and rejecting a model on that basis
    rules it out on our own limitation. It stays unresolved.
    """
    res = _verdict_for("unparseable", {"latency_ms": 1000}, retried_ok=False)
    assert res.state == UNVERIFIED, res.state
    assert res.remedy, "an unresolved verdict has to say what to do next"

    # What the provider did state still disqualifies.
    cut_short = _verdict_for("empty_truncated", {"latency_ms": 1000},
                             retried_ok=False)
    assert cut_short.state == UNUSABLE, cut_short.state


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


def test_only_a_missing_model_is_condemned():
    """A 404 is about the model. A 401 is about the key, and lumping
    them together let one mistyped credential mark a whole catalogue
    permanently broken."""
    from services.ai_triage.model_probe import _definitive_failure
    assert _definitive_failure("Google API error 404: model not found") is not None
    assert _definitive_failure("401 Unauthorized") is None
    assert _definitive_failure("403 permission denied") is None


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


def test_a_selected_model_is_always_re_checked():
    """Reachability is the volatile part — a provider retires a model,
    a key is revoked, a quota runs out. Reusing last week's verdict
    saves one request and risks showing Ready for a model that stopped
    working days ago, at the moment someone is choosing."""
    from pathlib import Path
    page = (Path(__file__).resolve().parents[2]
            / "apps/web/src/app/integrations/page.tsx").read_text()
    # The effect BODY only. RECHECK_AFTER_MS is still declared nearby
    # and still used by Check All, which is a bulk run where re-probing
    # hundreds of already-known models is pure waste. The point is that
    # selecting one model does not consult it.
    start = page.index("// Selecting a model always re-checks it.")
    block = page[page.index("useEffect(", start):page.index("}, [form.model_id", start)]
    assert "RECHECK_AFTER_MS" not in block, (
        "the selection check must not skip a model on age")
    assert "setTimeout" in block, "but it must still wait for the selection to settle"
    assert "silent: true" in block, "and fail quietly while someone is browsing"


def test_probing_a_batch_runs_concurrently_under_a_ceiling():
    """Sequential took forty minutes across a provider listing
    hundreds, which is not a button anyone presses twice. Unbounded
    would trip rate limits, and a 429 recorded as a verdict marks a
    working model broken — so it runs together, but with a ceiling."""
    import inspect
    from apps.api.app.routers import ai_models as R
    src = inspect.getsource(R.probe_models)
    assert "asyncio.gather" in src, "requests must run together"
    assert "Semaphore(_PROBE_CONCURRENCY)" in src, "and under a ceiling"
    assert 1 < R._PROBE_CONCURRENCY <= 16, "modest enough not to throttle"


def test_the_rows_are_written_after_the_requests_finish():
    """A shared AsyncSession is not safe to use from several tasks at
    once; the probes run together and the writes follow on one task."""
    import inspect
    from apps.api.app.routers import ai_models as R
    src = inspect.getsource(R.probe_models)
    assert src.index("asyncio.gather") < src.index("_store_probe(")


def test_a_probe_that_raises_does_not_lose_the_rest_of_the_batch():
    """return_exceptions keeps one bad model from discarding fifteen
    good answers the customer just paid for."""
    import inspect
    from apps.api.app.routers import ai_models as R
    assert "return_exceptions=True" in inspect.getsource(R.probe_models)


def test_an_auth_failure_is_flagged_not_judged():
    """Alone, a 401 is ambiguous: the key may be wrong, or fine but
    lacking access to this model. Only a caller that can see whether
    anything else answered can tell the two apart."""
    from services.ai_triage.model_probe import _verdict_for  # noqa: F401
    import inspect
    from services.ai_triage import model_probe as mp
    src = inspect.getsource(mp.probe_model)
    assert '"auth_failure": True' in src
    assert 'UNVERIFIED' in src


def test_the_caller_decides_what_a_rejection_means():
    """Measured: one key produced 165 working models and 267
    rejections. Calling all 267 "the provider rejected the key" pointed
    the reader at a credential that was demonstrably working."""
    import inspect
    from apps.api.app.routers import ai_models as R
    src = inspect.getsource(R.probe_models)
    assert "key_works" in src
    assert "Not available on this account." in src
    # Both halves must be consulted: this batch, and what is on record.
    assert "ok_now" in src and "ok_before" in src
