# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""The contract every AI provider adapter must satisfy.

Vooda lets a customer point it at any model from any provider, but only
the OpenAI-compatible path (`custom` → OpenRouter) has ever actually
run here. ClaudeProvider and GoogleProvider had zero tests and no
configured tenant, so nobody knew whether they worked at all.

These tests need no API key and cost nothing: each adapter is fed a
response in its provider's real documented shape and must produce the
same normalised AIResponse. What they cannot prove is that the provider
ACCEPTS our request — a 400 on a wrong field name needs one real call.
They do prove that what we send is shaped right and what we parse is
read right, which is where the bugs turn out to be.

Adding a fifth provider means satisfying this file.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from services.ai_triage.provider import (
    ClaudeProvider,
    GoogleProvider,
    OpenAIProvider,
)


def _run(coro):
    # A fresh loop per call. get_event_loop() picks up whatever loop a
    # neighbouring pytest-asyncio test left behind — these passed alone
    # and failed as a directory until this changed.
    return asyncio.run(coro)


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx
            raise httpx.HTTPStatusError(
                f"{self.status_code}", request=None, response=None  # type: ignore[arg-type]
            )


class _FakeClient:
    """Captures the outbound request and returns a canned response."""

    def __init__(self, payload, status_code=200, capture=None):
        self._payload = payload
        self._status = status_code
        self._capture = capture if capture is not None else {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None, **kw):
        self._capture["url"] = url
        self._capture["json"] = json
        self._capture["headers"] = headers or {}
        return _FakeResponse(self._payload, self._status)


def _patch(monkeypatch, payload, status_code=200):
    capture: dict = {}
    import httpx

    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda *a, **kw: _FakeClient(payload, status_code, capture),
    )
    return capture


# ── Real documented response shapes ──────────────────────────────────

CLAUDE_OK = {
    "content": [{"type": "text", "text": '{"classification":"likely_true_positive"}'}],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 120, "output_tokens": 18},
}

#: Extended thinking puts a non-text block FIRST. This is the shape that
#: breaks naive content[0]["text"] extraction.
CLAUDE_THINKING_FIRST = {
    "content": [
        {"type": "thinking", "thinking": "Let me consider the file path..."},
        {"type": "text", "text": '{"classification":"likely_false_positive"}'},
    ],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 300, "output_tokens": 40},
}

CLAUDE_TRUNCATED = {
    "content": [{"type": "text", "text": '{"classification":"likely_true_'}],
    "stop_reason": "max_tokens",
    "usage": {"input_tokens": 120, "output_tokens": 150},
}

GOOGLE_OK = {
    "candidates": [{
        "content": {"parts": [{"text": '{"classification":"needs_review"}'}]},
        "finishReason": "STOP",
    }],
    "usageMetadata": {"promptTokenCount": 90, "candidatesTokenCount": 12},
}

GOOGLE_TRUNCATED = {
    "candidates": [{
        "content": {"parts": [{"text": '{"classification":"needs_'}]},
        "finishReason": "MAX_TOKENS",
    }],
    "usageMetadata": {"promptTokenCount": 90, "candidatesTokenCount": 256},
}


# ── Clause 1: the request is shaped the way the provider requires ────

def test_claude_sends_system_as_a_top_level_field(monkeypatch):
    """Anthropic takes `system` as a top-level parameter, NOT as a
    message with role=system. Sending the OpenAI shape is a 400."""
    cap = _patch(monkeypatch, CLAUDE_OK)
    _run(ClaudeProvider(api_key="k", model="m").complete("SYS", "USER"))
    assert cap["json"]["system"] == "SYS"
    assert cap["json"]["messages"] == [{"role": "user", "content": "USER"}]
    assert cap["headers"]["x-api-key"] == "k"
    assert cap["headers"]["anthropic-version"]
    assert cap["url"].endswith("/v1/messages")


def test_claude_requires_max_tokens(monkeypatch):
    """Anthropic rejects a request without max_tokens."""
    cap = _patch(monkeypatch, CLAUDE_OK)
    _run(ClaudeProvider(api_key="k", model="m").complete("s", "u"))
    assert isinstance(cap["json"].get("max_tokens"), int)


# ── Clause 2: content extraction survives real response shapes ───────

def test_claude_reads_text_even_when_it_is_not_the_first_block(monkeypatch):
    """Extended thinking emits a `thinking` block first. Taking
    content[0]["text"] yields "" — which the engine reports as
    'AI model returned no content', the same symptom that lost a
    private key to silent triage failure on the qwen path.
    """
    _patch(monkeypatch, CLAUDE_THINKING_FIRST)
    resp = _run(ClaudeProvider(api_key="k", model="m").complete("s", "u"))
    assert "likely_false_positive" in resp.content, (
        "adapter must find the text block, not assume it is first"
    )


def test_google_reads_text_from_the_first_candidate(monkeypatch):
    _patch(monkeypatch, GOOGLE_OK)
    resp = _run(GoogleProvider(api_key="k", model="m").complete("s", "u"))
    assert "needs_review" in resp.content


# ── Clause 3: an upstream failure reaches the engine as RuntimeError ─

@pytest.mark.parametrize("factory", [
    lambda: ClaudeProvider(api_key="k", model="m"),
    lambda: GoogleProvider(api_key="k", model="m"),
])
def test_upstream_http_error_is_raised_as_runtime_error(monkeypatch, factory):
    """engine.py catches RuntimeError to classify an upstream failure.
    OpenAIProvider raises RuntimeError; an adapter that lets
    httpx.HTTPStatusError escape bypasses that handler entirely, so a
    429 becomes an unhandled exception instead of a typed failure.
    """
    _patch(monkeypatch, {"error": {"message": "rate limited"}}, status_code=429)
    with pytest.raises(RuntimeError):
        _run(factory().complete("s", "u"))


# ── Clause 4: truncation is reported in ONE vocabulary ───────────────

@pytest.mark.parametrize("factory,payload", [
    (lambda: ClaudeProvider(api_key="k", model="m"), CLAUDE_TRUNCATED),
    (lambda: GoogleProvider(api_key="k", model="m"), GOOGLE_TRUNCATED),
])
def test_truncation_is_normalised_across_providers(monkeypatch, factory, payload):
    """Anthropic says stop_reason="max_tokens", Google says
    finishReason="MAX_TOKENS", OpenAI says finish_reason="length".
    Three names, three values. The engine must not have to know which
    provider it is talking to, so each adapter normalises.
    """
    _patch(monkeypatch, payload)
    resp = _run(factory().complete("s", "u"))
    assert getattr(resp, "stop_reason", None) == "truncated", (
        "adapter must map its provider's truncation signal onto the "
        "shared vocabulary"
    )


@pytest.mark.parametrize("factory,payload", [
    (lambda: ClaudeProvider(api_key="k", model="m"), CLAUDE_OK),
    (lambda: GoogleProvider(api_key="k", model="m"), GOOGLE_OK),
])
def test_a_complete_response_is_not_reported_as_truncated(monkeypatch, factory, payload):
    _patch(monkeypatch, payload)
    resp = _run(factory().complete("s", "u"))
    assert getattr(resp, "stop_reason", None) == "complete"


# ── Clause 5: token usage is captured ────────────────────────────────

@pytest.mark.parametrize("factory,payload,tin,tout", [
    (lambda: ClaudeProvider(api_key="k", model="m"), CLAUDE_OK, 120, 18),
    (lambda: GoogleProvider(api_key="k", model="m"), GOOGLE_OK, 90, 12),
])
def test_usage_is_captured(monkeypatch, factory, payload, tin, tout):
    """Providers name these differently (input_tokens vs
    promptTokenCount); the adapter normalises."""
    _patch(monkeypatch, payload)
    resp = _run(factory().complete("s", "u"))
    assert resp.input_tokens == tin
    assert resp.output_tokens == tout


# ── The OpenAI-compatible path (custom / OpenRouter / Ollama / vLLM) ──

OPENAI_OK = {
    "choices": [{
        "message": {"content": '{"classification":"needs_review"}'},
        "finish_reason": "stop",
    }],
    "usage": {"prompt_tokens": 80, "completion_tokens": 10},
}

OPENAI_TRUNCATED = {
    "choices": [{
        "message": {"content": '{"classification":"needs_'},
        "finish_reason": "length",
    }],
    "usage": {"prompt_tokens": 80, "completion_tokens": 150},
}


@pytest.mark.parametrize("payload,expected", [
    (OPENAI_OK, "complete"),
    (OPENAI_TRUNCATED, "truncated"),
])
def test_openai_blocking_path_normalises_too(monkeypatch, payload, expected):
    """The non-streaming fallback dropped finish_reason entirely, so a
    server that rejects streaming lost truncation detection silently."""
    _patch(monkeypatch, payload)
    prov = OpenAIProvider(api_key="k", model="m")
    resp = _run(prov._complete_blocking({"model": "m"}, {}, 0.0))
    assert resp.stop_reason == expected


def test_every_provider_exposes_the_same_vocabulary():
    """A fifth provider must map onto these and nothing else."""
    from services.ai_triage.provider import (
        STOP_COMPLETE, STOP_FILTERED, STOP_TRUNCATED, STOP_UNKNOWN,
        normalize_stop_reason,
    )
    # each provider's own spelling of "I hit the limit"
    for raw in ("max_tokens", "length", "MAX_TOKENS", "max_output_tokens"):
        assert normalize_stop_reason(raw) == STOP_TRUNCATED, raw
    for raw in ("end_turn", "stop", "STOP"):
        assert normalize_stop_reason(raw) == STOP_COMPLETE, raw
    for raw in ("content_filter", "SAFETY", "RECITATION"):
        assert normalize_stop_reason(raw) == STOP_FILTERED, raw
    # absence of a signal is not success
    assert normalize_stop_reason(None) == STOP_UNKNOWN
    assert normalize_stop_reason("") == STOP_UNKNOWN
