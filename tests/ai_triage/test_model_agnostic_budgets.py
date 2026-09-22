# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Prompt budgets must fit the configured model, not a constant.

Vooda can be pointed at anything from a 3B local model to a 200K-context
frontier one. The triage prompt used fixed character caps
(2000/4000/3000/1000) that ignored the model entirely — identical on
both — and the retry path asked for 150 output tokens against a primary
call of 4096, so the rescue was more constrained than the thing it was
rescuing.
"""
import pytest

from packages.prompts.strategies import OUTPUT_BUDGET_RATIO, get_auto_config
from services.ai_triage.engine import TriageEngine
from services.ai_triage.provider import OpenAIProvider


class _Engine(TriageEngine):
    def __init__(self, config):
        self._config = config


def _budget(**cfg):
    return _Engine(cfg)._input_budget_chars()


def test_a_small_model_gets_a_smaller_prompt():
    small = _budget(context_window=4096, max_tokens=1024)
    large = _budget(context_window=32768, max_tokens=4096)
    assert sum(small.values()) < sum(large.values())


def test_an_unconfigured_model_keeps_the_previous_behaviour():
    """No window configured must not mean a new arbitrary number."""
    assert _budget() == {
        "code_snippet": 2000, "file_context": 4000,
        "related_context": 3000, "framework_context": 1000,
    }


def test_a_huge_window_does_not_mean_a_huge_prompt():
    """Triaging one secret is a local question. A 200K window is not a
    reason to send 200K of a repository to decide whether one string is
    a credential — past a point it stops changing the verdict and only
    costs latency and money."""
    huge = _budget(context_window=200_000, max_tokens=4096)
    mid = _budget(context_window=32_768, max_tokens=4096)
    assert sum(huge.values()) == sum(mid.values())
    assert sum(huge.values()) <= TriageEngine._MAX_USEFUL_INPUT_CHARS


def test_no_section_is_starved():
    for window in (2048, 4096, 8192, 32768, 200_000):
        b = _budget(context_window=window, max_tokens=min(1024, window // 4))
        assert all(v >= 200 for v in b.values()), (window, b)


def _code_lines(obj) -> str:
    """Source with comments stripped.

    A plain substring check also matches the comment explaining why a
    value was REMOVED — so the first version of these two tests passed
    against the bug and failed against the fix.
    """
    import inspect
    kept = []
    for line in inspect.getsource(obj).splitlines():
        if line.strip().startswith("#"):
            continue
        kept.append(line.split("  #")[0])
    return "\n".join(kept)


def test_the_retry_does_not_shrink_the_budget():
    """It used to retry at max_tokens=150 against a primary call of
    4096 — the path that exists to rescue a truncated response was the
    likeliest to truncate."""
    assert "max_tokens=150" not in _code_lines(TriageEngine)


def test_the_retry_sends_no_stop_sequence():
    """Removed twice already elsewhere in this codebase, both times
    documented as truncating modern models mid-response."""
    assert 'stop_sequences=["\\n\\n"]' not in _code_lines(TriageEngine)


@pytest.mark.parametrize("window,out,expected_ceiling", [
    (4096, None, 1024),
    (32768, None, 4096),
    (200_000, None, 4096),
])
def test_output_budget_never_exceeds_its_share_of_the_window(window, out, expected_ceiling):
    cfg = get_auto_config("custom", "some/model", None, "recommended", window, out)
    assert cfg["max_tokens"] <= max(1024, int(window * OUTPUT_BUDGET_RATIO))
    assert cfg["max_tokens"] == expected_ceiling


def test_provider_reported_window_beats_the_default_table():
    """PROVIDER_DEFAULTS gives every `custom` provider 8192 regardless of
    model. When OpenRouter reports the real number, that wins."""
    guessed = get_auto_config("custom", "qwen/qwen3-27b")
    reported = get_auto_config("custom", "qwen/qwen3-27b", None, "recommended", 32768)
    assert guessed["context_window"] == 8192
    assert reported["context_window"] == 32768


def test_deadline_uses_measured_throughput_when_available():
    """output_tokens and latency_ms are on every response already; the
    deadline assumed a flat 15 tok/s for a CPU-bound local model and a
    frontier API alike."""
    floor = OpenAIProvider.deadline_for(4096)
    OpenAIProvider.record_throughput("contract-fast", 800, 4000.0)   # 200 tok/s
    measured = OpenAIProvider.deadline_for(4096, "contract-fast")
    assert measured < floor


def test_a_slow_model_is_never_given_less_than_the_floor():
    OpenAIProvider.record_throughput("contract-slow", 100, 20000.0)  # 5 tok/s
    assert OpenAIProvider.deadline_for(4096, "contract-slow") == OpenAIProvider.deadline_for(4096)


def test_a_tiny_sample_is_not_treated_as_a_measurement():
    before = dict(OpenAIProvider._observed_tps)
    OpenAIProvider.record_throughput("contract-tiny", 3, 10.0)
    assert "contract-tiny" not in OpenAIProvider._observed_tps
    OpenAIProvider._observed_tps.clear()
    OpenAIProvider._observed_tps.update(before)
