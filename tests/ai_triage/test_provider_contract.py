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


# ── Clause 6: every provider is asked for JSON its own way ───────────

CLAUDE_PREFILL_REPLY = {
    # A prefilled reply CONTINUES from "{" — the brace is not echoed.
    "content": [{"type": "text", "text": '"classification":"likely_true_positive"}'}],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 100, "output_tokens": 12},
}


def test_claude_is_asked_for_json_by_prefill(monkeypatch):
    """Anthropic has no response_format. supports_json_mode was simply
    DEAD for Claude, so it fell back to asking in the prompt and got the
    weakest handling of any provider despite prefill being available.
    """
    from services.ai_triage.provider import JSON_PREFILL
    cap = _patch(monkeypatch, CLAUDE_PREFILL_REPLY)
    prov = ClaudeProvider(api_key="k", model="m", json_strategy=JSON_PREFILL)
    resp = _run(prov.complete("s", "u", json_mode=True))

    msgs = cap["json"]["messages"]
    assert msgs[-1] == {"role": "assistant", "content": "{"}, (
        "the assistant turn must be seeded so the model cannot open with "
        "prose or a markdown fence"
    )
    # and the brace must be restored, or every reply fails to parse
    assert resp.content.startswith("{")
    assert json.loads(resp.content)["classification"] == "likely_true_positive"


def test_claude_is_not_prefilled_when_json_was_not_requested(monkeypatch):
    cap = _patch(monkeypatch, CLAUDE_OK)
    _run(ClaudeProvider(api_key="k", model="m").complete("s", "u", json_mode=False))
    assert all(m["role"] != "assistant" for m in cap["json"]["messages"])


def test_openrouter_is_not_sent_response_format(monkeypatch):
    """Forcing it there was observed to truncate mid-JSON, which is why
    the custom default is prompt-only. Silently enabling it would
    reintroduce a bug somebody already fixed."""
    from services.ai_triage.provider import JSON_PROMPT_ONLY
    prov = OpenAIProvider(api_key="k", model="m", json_strategy=JSON_PROMPT_ONLY)
    payload = prov._build_payload("s", "u", 1024, 0.0, None, json_mode=True)
    assert "response_format" not in payload


def test_openai_proper_is_sent_response_format():
    from services.ai_triage.provider import JSON_NATIVE
    prov = OpenAIProvider(api_key="k", model="m", json_strategy=JSON_NATIVE)
    payload = prov._build_payload("s", "u", 1024, 0.0, None, json_mode=True)
    assert payload["response_format"] == {"type": "json_object"}


def test_every_provider_resolves_to_a_known_strategy():
    """A new provider must land on one of the four, not on None."""
    from services.ai_triage.provider import (
        JSON_MIME, JSON_NATIVE, JSON_PREFILL, JSON_PROMPT_ONLY,
        create_provider, resolve_json_strategy,
    )
    known = {JSON_MIME, JSON_NATIVE, JSON_PREFILL, JSON_PROMPT_ONLY}
    for name in ("claude", "anthropic", "openai", "azure_openai", "google",
                 "ollama", "custom", "vllm", "lm_studio", "localai",
                 "huggingface_tgi", "aws_bedrock"):
        for flag in (None, True, False):
            assert resolve_json_strategy(name, flag) in known, (name, flag)
        prov = create_provider(name, "k", "m", "http://x")
        assert getattr(prov, "json_strategy", None) in known, name


def test_the_legacy_flag_cannot_disable_prefill():
    """supports_json_mode=False exists because response_format broke
    OpenRouter. Prefill has no such failure mode, so switching the flag
    off must not silently downgrade Claude."""
    from services.ai_triage.provider import JSON_PREFILL, resolve_json_strategy
    assert resolve_json_strategy("anthropic", False) == JSON_PREFILL
    assert resolve_json_strategy("claude", False) == JSON_PREFILL


def test_the_engine_does_not_decide_the_json_mechanism():
    """It used to pass supports_json_mode straight through as
    `json_mode`, so a tenant with the flag off — the default for every
    custom provider — also lost Claude's prefill, which has none of the
    failure modes that flag exists to avoid.

    Triage always wants JSON. How to ask is the adapter's business.
    """
    import inspect
    from services.ai_triage.engine import TriageEngine
    src = inspect.getsource(TriageEngine)
    assert 'json_mode = self._config.get("supports_json_mode"' not in src
    assert "json_mode = True" in src


# ── Clause 7: request field names match each provider's documentation ─

def test_google_request_uses_the_documented_field_names(monkeypatch):
    """Verified against ai.google.dev/api/generate-content.

    We sent `system_instruction`. The documented name is
    `systemInstruction`. Proto3 JSON generally accepts snake_case as
    well, so this may have worked — but if it were ever ignored, Gemini
    would triage with NO system prompt and still return a confident
    answer. Silent degradation, not a crash.
    """
    _patch(monkeypatch, GOOGLE_OK)
    cap = _patch(monkeypatch, GOOGLE_OK)
    _run(GoogleProvider(api_key="k", model="m").complete("SYS", "USER"))
    body = cap["json"]
    assert "systemInstruction" in body, "documented spelling is camelCase"
    assert body["systemInstruction"] == {"parts": [{"text": "SYS"}]}
    assert body["contents"] == [{"parts": [{"text": "USER"}]}]
    # generationConfig keys are camelCase per the same reference
    gc = body["generationConfig"]
    assert "maxOutputTokens" in gc and "temperature" in gc
    assert cap["url"].startswith(
        "https://generativelanguage.googleapis.com/v1beta/models/")
    assert "key=" in cap["url"], "Gemini takes the key as a query param"


def test_claude_request_matches_the_documented_shape(monkeypatch):
    """Verified against platform.claude.com/docs/en/api/messages:
    `system` is top-level (there is no system ROLE), `stop_sequences`
    is the field name, and a final assistant message makes the response
    continue from it — which is what prefill relies on.
    """
    cap = _patch(monkeypatch, CLAUDE_OK)
    _run(ClaudeProvider(api_key="k", model="m").complete(
        "SYS", "USER", stop_sequences=["END"]))
    body = cap["json"]
    assert body["system"] == "SYS"
    assert all(m["role"] != "system" for m in body["messages"]), (
        "the Messages API has no system role for input messages"
    )
    assert body["stop_sequences"] == ["END"]
    assert isinstance(body["max_tokens"], int)
    assert cap["headers"]["anthropic-version"] == "2023-06-01"
