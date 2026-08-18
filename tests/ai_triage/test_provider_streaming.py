# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Streaming SSE consumption and timeout-model math in OpenAIProvider.

The provider streams completions so that timeouts can follow the
industry-standard shape: connect fast-fail, an IDLE timeout between
chunks, and a total deadline derived from the effective max_tokens —
instead of one fixed wall-clock number that kills healthy-but-slow
generations (the qwen3.8-max incident: 47/92 findings silently
untriaged behind a flat 120 s cap).

`_consume_sse` is a pure consumer over an async line iterator, so these
tests need no network and no httpx.
"""
import asyncio

import pytest

from services.ai_triage.provider import OpenAIProvider


async def _lines(items):
    for i in items:
        yield i


def _run(coro):
    return asyncio.run(coro)


def test_content_accumulates_across_chunks():
    acc = _run(OpenAIProvider._consume_sse(_lines([
        'data: {"choices":[{"delta":{"content":"{\\"class"}}]}',
        'data: {"choices":[{"delta":{"content":"ification\\": \\"fp\\"}"}}]}',
        'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}',
        "data: [DONE]",
    ])))
    assert acc["content"] == '{"classification": "fp"}'
    assert acc["finish_reason"] == "stop"
    assert acc["upstream_err"] is None


def test_keepalive_comments_and_blank_lines_are_ignored():
    acc = _run(OpenAIProvider._consume_sse(_lines([
        ": OPENROUTER PROCESSING",
        "",
        'data: {"choices":[{"delta":{"content":"ok"}}]}',
        ": OPENROUTER PROCESSING",
        "data: [DONE]",
    ])))
    assert acc["content"] == "ok"


def test_reasoning_deltas_counted_but_not_mixed_into_content():
    acc = _run(OpenAIProvider._consume_sse(_lines([
        'data: {"choices":[{"delta":{"reasoning":"thinking hard..."}}]}',
        'data: {"choices":[{"delta":{"reasoning_content":"more thought"}}]}',
        'data: {"choices":[{"delta":{"content":"answer"}}]}',
        "data: [DONE]",
    ])))
    assert acc["content"] == "answer"
    assert acc["reasoning_len"] == len("thinking hard...") + len("more thought")


def test_usage_captured_from_final_chunk():
    acc = _run(OpenAIProvider._consume_sse(_lines([
        'data: {"choices":[{"delta":{"content":"x"},"finish_reason":"stop"}]}',
        'data: {"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":7}}',
        "data: [DONE]",
    ])))
    assert acc["usage"] == {"prompt_tokens": 11, "completion_tokens": 7}


def test_upstream_error_chunk_is_surfaced_not_swallowed():
    # OpenRouter surfaces upstream provider failures as a nested
    # choices[0].error even on streams; the partial content before it must
    # not masquerade as a legitimate (truncated) response.
    acc = _run(OpenAIProvider._consume_sse(_lines([
        'data: {"choices":[{"delta":{"content":"partial"}}]}',
        'data: {"provider":"SomeUpstream","choices":[{"error":{"message":"overloaded"}}]}',
        'data: {"choices":[{"delta":{"content":"never-read"}}]}',
    ])))
    assert acc["upstream_err"] == "overloaded"
    assert acc["provider"] == "SomeUpstream"
    assert "never-read" not in acc["content"]


def test_malformed_chunk_skipped_stream_continues():
    acc = _run(OpenAIProvider._consume_sse(_lines([
        "data: {not json",
        'data: {"choices":[{"delta":{"content":"survived"}}]}',
        "data: [DONE]",
    ])))
    assert acc["content"] == "survived"


@pytest.mark.parametrize(
    "max_tokens,expected",
    [
        (0, 4096 / 15.0 + 60.0),  # degenerate input falls back to the 4096 default
        (300, 120.0),      # tiny budget clamps to the floor
        (4096, 4096 / 15.0 + 60.0),   # scales with budget
        (16384, 900.0),    # huge budget clamps to the ceiling
        (10**7, 900.0),
    ],
)
def test_deadline_scales_with_token_budget_and_clamps(max_tokens, expected):
    assert OpenAIProvider.deadline_for(max_tokens) == pytest.approx(expected)


def test_deadline_bounds_ordering():
    # The invariant callers rely on: every deadline lives in [MIN, MAX].
    for mt in (1, 100, 1000, 4096, 8192, 16384, 65536):
        d = OpenAIProvider.deadline_for(mt)
        assert OpenAIProvider.MIN_DEADLINE_S <= d <= OpenAIProvider.MAX_DEADLINE_S
