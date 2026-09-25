"""probe_model's full path, including the retry, with no API key.

The retry is the part worth guarding: it is what turns "this model is
broken" into "raise the output limit", and it is the difference between
a customer switching models and a customer changing one number.
"""
import asyncio

import pytest

from services.ai_triage import model_probe as mp
from services.ai_triage.model_probe import probe_model, READY, NEEDS_SETUP, UNUSABLE, UNVERIFIED
from services.ai_triage.provider import AIResponse

GOOD = '{"classification": "TRUE_POSITIVE", "confidence": 0.9, "reasoning": "a real key"}'


class FakeProvider:
    """Replays a scripted reply per budget, and counts the calls."""
    calls: list = []

    def __init__(self, script):
        self.script = script

    async def complete(self, system_prompt, user_prompt, max_tokens=300, **kw):
        FakeProvider.calls.append(max_tokens)
        out = self.script(max_tokens)
        if isinstance(out, Exception):
            raise out
        content, stop, tokens = out
        return AIResponse(content=content, model="fake", output_tokens=tokens,
                          latency_ms=120, stop_reason=stop)


def _install(monkeypatch, script):
    FakeProvider.calls = []
    monkeypatch.setattr(mp, "create_provider",
                        lambda *a, **k: FakeProvider(script), raising=False)
    import services.ai_triage.provider as prov
    monkeypatch.setattr(prov, "create_provider",
                        lambda *a, **k: FakeProvider(script), raising=False)


def run(coro):
    return asyncio.run(coro)


def test_a_working_model_costs_exactly_one_call(monkeypatch):
    _install(monkeypatch, lambda budget: (GOOD, "complete", 40))
    res = run(probe_model("google", "k", "m"))
    assert res.state == READY
    assert res.calls_used == 1, "a good model must not pay for a retry"


def test_the_starved_model_is_retried_and_becomes_fixable(monkeypatch):
    """Reasoning burns the budget at 300 and answers fine at 2000."""
    _install(monkeypatch, lambda budget:
             (GOOD, "complete", 40) if budget >= 2000 else ("", "truncated", 0))
    res = run(probe_model("google", "k", "m"))
    assert res.state == NEEDS_SETUP
    assert res.suggested_config == {"max_tokens": mp._RETRY_MAX_TOKENS}
    assert FakeProvider.calls == [300, 2000]


def test_a_model_that_fails_at_any_budget_is_unusable(monkeypatch):
    _install(monkeypatch, lambda budget: ("", "truncated", 0))
    res = run(probe_model("google", "k", "m"))
    assert res.state == UNUSABLE
    assert FakeProvider.calls == [300, 2000], "must actually try harder before condemning"


def test_an_overloaded_provider_never_yields_a_judgment(monkeypatch):
    _install(monkeypatch, lambda budget: RuntimeError("Google API error 503: overloaded"))
    res = run(probe_model("google", "k", "m"))
    assert res.state == UNVERIFIED


def test_an_unknown_error_leaves_the_model_visible(monkeypatch):
    _install(monkeypatch, lambda budget: RuntimeError("connection reset"))
    res = run(probe_model("google", "k", "m"))
    assert res.state == UNVERIFIED, "unknown is not evidence of broken"


def test_a_missing_model_is_condemned_without_a_retry(monkeypatch):
    _install(monkeypatch, lambda budget: RuntimeError("Google API error 404: not found"))
    res = run(probe_model("google", "k", "m"))
    assert res.state == UNUSABLE
    assert FakeProvider.calls == [300], "no point retrying a model that does not exist"


def test_overload_during_the_retry_does_not_become_unusable(monkeypatch):
    def script(budget):
        if budget >= 2000:
            return RuntimeError("503 overloaded")
        return ("", "truncated", 0)
    _install(monkeypatch, script)
    res = run(probe_model("google", "k", "m"))
    assert res.state == UNVERIFIED


def test_an_empty_reply_is_never_reported_as_ready(monkeypatch):
    """The whole point. Measured live, two models returned nothing and
    the old test endpoint called both 'Connected successfully'."""
    for content, stop, toks in [("", "truncated", 0), ("", "complete", 0), ("   ", "complete", 1)]:
        _install(monkeypatch, lambda b, c=content, s=stop, t=toks: (c, s, t))
        assert run(probe_model("google", "k", "m")).state != READY
