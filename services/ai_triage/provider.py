# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
AI provider abstraction layer.
Supports Claude, OpenAI, Azure OpenAI, Google Gemini, and custom OpenAI-compatible endpoints.
Includes task-based routing to select the correct model per task.
"""

import json
import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

import structlog

logger = structlog.get_logger()


#: HOW a provider is asked for JSON. `supports_json_mode` was a single
#: boolean that meant three different things and, for one provider,
#: nothing at all:
#:
#:   OpenAI / Azure   response_format={"type":"json_object"}
#:   Google           responseMimeType="application/json"
#:   Anthropic        NO equivalent — the flag was simply dead, so Claude
#:                    fell back to asking in the prompt and got the
#:                    WEAKEST handling of any provider despite having one
#:                    of the strongest available to it
#:   OpenRouter/vLLM  honoured inconsistently; forcing it was observed to
#:                    cause mid-JSON truncation, which is why the custom
#:                    default is off
#:
#: Each adapter declares its own, so the engine keeps asking a single
#: question — "give me JSON" — and never learns which provider answered.
JSON_NATIVE = "native_response_format"   # OpenAI-compatible response_format
JSON_MIME = "mime_type"                  # Google responseMimeType
JSON_PREFILL = "prefill"                 # Anthropic: open the reply with "{"
JSON_PROMPT_ONLY = "prompt_only"         # no mechanism; the prompt asks

#: Providers whose upstream route does not reliably honour
#: `response_format`. Kept as data so a deployment that knows its route
#: DOES support it can say so, rather than editing a branch.
_PROMPT_ONLY_PROVIDERS = {
    "custom", "openrouter", "vllm", "lm_studio", "localai",
    "huggingface_tgi", "aws_bedrock",
}


def resolve_json_strategy(provider_name: str, explicit: bool | None = None) -> str:
    """Pick how this provider should be asked for JSON.

    `explicit` is the legacy supports_json_mode flag. False still means
    "do not use a native mechanism" — that setting exists because
    forcing response_format through OpenRouter truncated responses, and
    silently overriding it would reintroduce a bug somebody already
    fixed. It does NOT disable prefill, which has no such failure mode
    and costs nothing.
    """
    name = (provider_name or "").lower()
    if name in ("claude", "anthropic"):
        return JSON_PREFILL
    if explicit is False:
        return JSON_PROMPT_ONLY
    if name == "google":
        return JSON_MIME
    if name in _PROMPT_ONLY_PROVIDERS and explicit is not True:
        return JSON_PROMPT_ONLY
    return JSON_NATIVE


#: Why generation stopped, normalised across providers. Anthropic says
#: stop_reason="max_tokens", Google says finishReason="MAX_TOKENS",
#: OpenAI says finish_reason="length" — three names, three values, for
#: one fact. Each adapter maps its own onto this so the engine never
#: has to know which provider answered.
STOP_COMPLETE = "complete"
STOP_TRUNCATED = "truncated"
STOP_FILTERED = "filtered"
STOP_UNKNOWN = "unknown"

_TRUNCATION_SIGNALS = {"max_tokens", "length", "MAX_TOKENS", "max_output_tokens"}
_FILTER_SIGNALS = {"content_filter", "SAFETY", "RECITATION", "refusal"}


def normalize_stop_reason(raw: str | None) -> str:
    """Any provider's stop signal -> the shared vocabulary."""
    if raw is None:
        return STOP_UNKNOWN
    v = str(raw).strip()
    if v in _TRUNCATION_SIGNALS or v.lower() in {s.lower() for s in _TRUNCATION_SIGNALS}:
        return STOP_TRUNCATED
    if v in _FILTER_SIGNALS or v.lower() in {s.lower() for s in _FILTER_SIGNALS}:
        return STOP_FILTERED
    if not v:
        return STOP_UNKNOWN
    return STOP_COMPLETE


@dataclass
class AIResponse:
    content: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0
    cost_estimate: float = 0.0
    raw_response: dict = field(default_factory=dict)
    #: Normalised stop signal — see normalize_stop_reason.
    stop_reason: str = STOP_UNKNOWN


class AIProvider(ABC):
    @abstractmethod
    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        stop_sequences: list[str] | None = None,
        json_mode: bool = False,
    ) -> AIResponse:
        ...


class ClaudeProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514",
                 json_strategy: str = JSON_PREFILL):
        self._api_key = api_key
        self.model = model
        self.json_strategy = json_strategy

    async def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096, temperature: float = 0.1, stop_sequences: list[str] | None = None, json_mode: bool = False) -> AIResponse:
        """Use httpx directly to avoid async client event loop issues in Celery workers."""
        import httpx
        start = time.monotonic()

        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        messages = [{"role": "user", "content": user_prompt}]
        # Anthropic has no response_format. Its equivalent is PREFILL:
        # seed the assistant turn with "{" and the model continues from
        # there, so it cannot open with prose, a markdown fence or a
        # preamble. Stronger than asking in the prompt, and it was not
        # being used at all — supports_json_mode simply did nothing here.
        prefilled = json_mode and self.json_strategy == JSON_PREFILL
        if prefilled:
            messages.append({"role": "assistant", "content": "{"})

        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system_prompt,
            "messages": messages,
        }
        if stop_sequences:
            payload["stop_sequences"] = stop_sequences

        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(url, json=payload, headers=headers)
            # engine.py classifies an upstream failure by catching
            # RuntimeError. Letting httpx.HTTPStatusError escape bypasses
            # that handler, so a 429 becomes an unhandled exception
            # rather than a typed, reported failure.
            if r.status_code >= 400:
                raise RuntimeError(
                    f"Anthropic API error {r.status_code}: "
                    f"{(r.text or '')[:300]}"
                )
            data = r.json()

        latency = (time.monotonic() - start) * 1000
        # Anthropic returns a LIST of content blocks and the text one is
        # not necessarily first — extended thinking emits a `thinking`
        # block ahead of it. Indexing [0] yields "" there, which the
        # engine reports as "AI model returned no content": the exact
        # symptom that lost a private key to silent triage failure on
        # the qwen path.
        content = "".join(
            b.get("text", "")
            for b in (data.get("content") or [])
            if isinstance(b, dict) and b.get("type") == "text"
        )
        # The prefill is not echoed back — the response CONTINUES from
        # it — so the opening brace has to be restored or every reply
        # fails to parse. Guarded in case a future model does echo it.
        if prefilled and content and not content.lstrip().startswith("{"):
            content = "{" + content
        usage = data.get("usage", {})

        return AIResponse(
            content=content, model=self.model,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            latency_ms=latency,
            raw_response={"stop_reason": data.get("stop_reason")},
            stop_reason=normalize_stop_reason(data.get("stop_reason")),
        )


class OpenAIProvider(AIProvider):
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        base_url: Optional[str] = None,
        timeout: int = 120,
        extra_payload: Optional[dict] = None,
        json_strategy: str = JSON_NATIVE,
    ):
        #: How this route should be asked for JSON. Defaults to the
        #: native field; create_provider resolves the right one for
        #: OpenRouter and friends, where it is not reliably honoured.
        self.json_strategy = json_strategy
        self._api_key = api_key
        self._base_url = (base_url or "https://api.openai.com").rstrip("/")
        self._timeout = timeout  # 120s default — accommodates both fast cloud and slow local models
        self.model = model
        # Extra top-level fields to merge into the OpenAI-compatible payload.
        # Used for provider-specific knobs that aren't part of the stock OpenAI
        # spec — most notably OpenRouter's `{"provider": {"ignore": [...]}}`
        # upstream-routing controls. Scoped per-model via ai_model_configs
        # .provider_config (JSONB) so setting/clearing it is a single SQL
        # UPDATE — no code deploys required to toggle it on or off.
        self._extra_payload: dict = extra_payload or {}

    # ── Streaming timeout model (the industry-standard shape) ─────────────
    # One fixed wall-clock number is wrong for someone: too short for a slow
    # frontier model, needlessly long for detecting a dead socket. Instead:
    #   - CONNECT fast-fails an unreachable host,
    #   - IDLE (httpx `read` on a stream) bounds the gap BETWEEN chunks, so a
    #     healthy-but-slow generation never trips it while a stalled upstream
    #     dies in seconds, and
    #   - a total deadline derived from the EFFECTIVE max_tokens (a floor
    #     decode rate + slack) backstops a pathological trickle stream.
    CONNECT_TIMEOUT_S = 10.0
    IDLE_TIMEOUT_S = 60.0
    MIN_DEADLINE_S = 120.0
    MAX_DEADLINE_S = 900.0
    DEADLINE_FLOOR_TPS = 15.0  # decode floor used until this model has been measured

    #: Observed decode rate per model, learned from completed calls.
    #: AIResponse already carries output_tokens and latency_ms on EVERY
    #: response — the throughput was being measured all along and used
    #: for nothing, while the deadline assumed a flat 15 tok/s for a
    #: CPU-bound local model and a frontier API alike.
    _observed_tps: dict[str, float] = {}

    @classmethod
    def record_throughput(cls, model: str, output_tokens: int, latency_ms: float) -> None:
        """Fold one completed call into the rolling estimate for a model."""
        if not model or output_tokens < 20 or latency_ms <= 0:
            return  # too small a sample to say anything about decode rate
        tps = output_tokens / (latency_ms / 1000.0)
        if tps <= 0:
            return
        prior = cls._observed_tps.get(model)
        # Exponential moving average: adapts to a provider slowing down
        # without letting one slow call dominate.
        cls._observed_tps[model] = tps if prior is None else (prior * 0.7 + tps * 0.3)
    DEADLINE_SLACK_S = 60.0    # prompt processing + network slack

    @classmethod
    def deadline_for(cls, max_tokens: int, model: str | None = None) -> float:
        """Total-call deadline scaled to the token budget, clamped to sane bounds."""
        # Measured rate when we have one, never faster than the floor —
        # a model that has been quick so far must still be allowed to be
        # slow once without being cut off.
        rate = cls.DEADLINE_FLOOR_TPS
        observed = cls._observed_tps.get(model or "")
        if observed:
            rate = max(cls.DEADLINE_FLOOR_TPS, observed)
        est = (max_tokens or 4096) / rate + cls.DEADLINE_SLACK_S
        return max(cls.MIN_DEADLINE_S, min(cls.MAX_DEADLINE_S, est))

    @staticmethod
    async def _consume_sse(lines) -> dict:
        """Accumulate an OpenAI-compatible SSE stream from an async line iterator.

        Pure consumer (no I/O of its own) so it is unit-testable. Returns
        {content, reasoning, usage, finish_reason, upstream_err, provider}.
        Ignores keepalive comment lines (": ..."), stops at [DONE], captures a
        nested choices[0].error chunk (OpenRouter surfaces upstream provider
        failures that way even on streams).
        """
        content_parts: list = []
        reasoning_len = 0
        usage: dict = {}
        finish_reason = None
        upstream_err = None
        up_provider = None
        async for raw in lines:
            line = raw.strip()
            if not line or line.startswith(":"):
                continue
            if not line.startswith("data:"):
                continue
            data_str = line[5:].strip()
            if data_str == "[DONE]":
                break
            try:
                chunk = json.loads(data_str)
            except Exception:
                continue  # malformed keepalive/partial line — skip, stream goes on
            if chunk.get("usage"):
                usage = chunk["usage"]
            choices = chunk.get("choices") or []
            if not choices:
                continue
            ch = choices[0] or {}
            if isinstance(ch, dict) and ch.get("error"):
                upstream_err = ch["error"].get("message", "Upstream model error")
                up_provider = chunk.get("provider") or "unknown"
                break
            delta = ch.get("delta") or {}
            piece = delta.get("content")
            if piece:
                content_parts.append(piece)
            rpiece = delta.get("reasoning") or delta.get("reasoning_content")
            if rpiece:
                reasoning_len += len(rpiece)
            if ch.get("finish_reason"):
                finish_reason = ch["finish_reason"]
        return {
            "content": "".join(content_parts),
            "reasoning_len": reasoning_len,
            "usage": usage,
            "finish_reason": finish_reason,
            "upstream_err": upstream_err,
            "provider": up_provider,
        }

    def _build_payload(self, system_prompt, user_prompt, max_tokens, temperature, stop_sequences, json_mode) -> dict:
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if stop_sequences:
            payload["stop"] = stop_sequences
        # Only when this route actually honours it. OpenRouter and some
        # self-hosted gateways accept the field and then truncate
        # mid-JSON, which is why the custom default resolves to
        # prompt-only — the prompt still asks for JSON either way.
        if json_mode and self.json_strategy == JSON_NATIVE:
            payload["response_format"] = {"type": "json_object"}
        # Merge per-model extra fields last so they can override anything above
        # if explicitly specified (rare; typically additive top-level keys like
        # `provider`, `transforms`, `route`, or a `max_tokens`/`reasoning`
        # override from ai_model_configs.provider_config).
        if self._extra_payload:
            for k, v in self._extra_payload.items():
                payload[k] = v
        return payload

    def _chat_url(self) -> str:
        url = f"{self._base_url}/v1/chat/completions"
        if self._base_url.endswith("/v1") or "/v1/" in self._base_url:
            url = f"{self._base_url}/chat/completions" if self._base_url.endswith("/v1") else f"{self._base_url}chat/completions"
        return url

    async def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096, temperature: float = 0.1, stop_sequences: list[str] | None = None, json_mode: bool = False) -> AIResponse:
        """Stream the completion (SSE) with idle-timeout semantics.

        Falls back to the legacy blocking request only if the server rejects
        the streaming request synchronously (some older OpenAI-compatible
        local servers) — never on a mid-stream stall, which is exactly what
        the idle timeout exists to catch.
        """
        import httpx
        start = time.monotonic()

        payload = self._build_payload(system_prompt, user_prompt, max_tokens, temperature, stop_sequences, json_mode)
        effective_max = payload.get("max_tokens") or max_tokens
        deadline = self.deadline_for(effective_max, self.model)
        payload["stream"] = True
        # Ask for usage accounting in the final chunk (OpenAI-compat standard).
        payload.setdefault("stream_options", {"include_usage": True})

        timeouts = httpx.Timeout(
            connect=self.CONNECT_TIMEOUT_S,
            read=self.IDLE_TIMEOUT_S,  # on a stream: max gap BETWEEN chunks
            write=30.0,
            pool=10.0,
        )
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        try:
            async with httpx.AsyncClient(timeout=timeouts) as client:
                async def _run_stream():
                    async with client.stream("POST", self._chat_url(), json=payload, headers=headers) as r:
                        if r.status_code >= 400:
                            await r.aread()
                            r.raise_for_status()
                        return await self._consume_sse(r.aiter_lines())
                acc = await asyncio.wait_for(_run_stream(), timeout=deadline)
        except httpx.HTTPStatusError as e:
            if e.response is not None and e.response.status_code == 400:
                # Server rejected the streaming request itself (some local
                # OpenAI-compatible servers) — retry once, blocking.
                return await self._complete_blocking(payload, headers, start)
            raise
        except asyncio.TimeoutError:
            raise RuntimeError(
                f"Generation exceeded total deadline of {deadline:.0f}s "
                f"(max_tokens={effective_max}); upstream kept streaming too slowly."
            )

        if acc["upstream_err"]:
            raise RuntimeError(
                f"Upstream model error: {acc['upstream_err']} (upstream_provider={acc['provider']})"
            )

        usage = acc["usage"] or {}
        _latency_ms = (time.monotonic() - start) * 1000
        self.record_throughput(
            self.model, usage.get("completion_tokens", 0) or 0, _latency_ms
        )
        return AIResponse(
            content=acc["content"], model=self.model,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=_latency_ms,
            raw_response={
                "finish_reason": acc["finish_reason"],
                "reasoning_len": acc["reasoning_len"],
                "streamed": True,
            },
            # Captured since the streaming path was written, but read by
            # nothing — truncation was inferred from trailing punctuation
            # instead, which misses a response cut off mid-string.
            stop_reason=normalize_stop_reason(acc["finish_reason"]),
        )

    async def _complete_blocking(self, payload: dict, headers: dict, start: float) -> AIResponse:
        """Legacy non-streaming request — fallback for servers without SSE."""
        import httpx
        payload = dict(payload)
        payload.pop("stream", None)
        payload.pop("stream_options", None)

        url = self._chat_url()

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.post(url, json=payload, headers=headers)
            r.raise_for_status()
            data = r.json()

        latency = (time.monotonic() - start) * 1000
        choices = data.get("choices", [{}])
        choice = choices[0] if choices else {}

        # ── Generic upstream-error detection ─────────────────
        # Some OpenAI-compatible proxies (notably OpenRouter) return HTTP 200
        # with a nested `choices[0].error` when their upstream provider failed
        # mid-generation. Without this check the partial `message.content`
        # looks like a truncated legitimate response and misleads the parse
        # layer. Surface the real cause so batch retry + telemetry can act on
        # it correctly. This is generic — it works for any OpenAI-compatible
        # endpoint, not just OpenRouter.
        upstream_err = choice.get("error") if isinstance(choice, dict) else None
        if upstream_err:
            up_msg = upstream_err.get("message", "Upstream model error")
            up_provider = data.get("provider") or "unknown"
            raise RuntimeError(
                f"Upstream model error: {up_msg} (upstream_provider={up_provider})"
            )

        content = choice.get("message", {}).get("content", "") if choice else ""
        usage = data.get("usage", {})

        return AIResponse(
            content=content, model=self.model,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=latency,
            raw_response={"finish_reason": (choice or {}).get("finish_reason")},
            stop_reason=normalize_stop_reason((choice or {}).get("finish_reason")),
        )


class GoogleProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash",
                 json_strategy: str = JSON_MIME):
        self.api_key = api_key
        self.model = model
        self.json_strategy = json_strategy

    async def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096, temperature: float = 0.1, stop_sequences: list[str] | None = None, json_mode: bool = False) -> AIResponse:
        import httpx
        start = time.monotonic()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        gen_config: dict = {"maxOutputTokens": max_tokens, "temperature": temperature}
        if stop_sequences:
            gen_config["stopSequences"] = stop_sequences
        if json_mode and self.json_strategy == JSON_MIME:
            gen_config["responseMimeType"] = "application/json"
        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_prompt}]}],
            "generationConfig": gen_config,
        }
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(url, json=payload)
            # Same contract as every other adapter: the engine classifies
            # upstream failures by catching RuntimeError.
            if r.status_code >= 400:
                raise RuntimeError(
                    f"Google API error {r.status_code}: {(r.text or '')[:300]}"
                )
            data = r.json()

        latency = (time.monotonic() - start) * 1000
        candidate = (data.get("candidates") or [{}])[0]
        # Concatenate every text part rather than assuming one — Gemini
        # may split a response across parts.
        content = "".join(
            part.get("text", "")
            for part in ((candidate.get("content") or {}).get("parts") or [])
            if isinstance(part, dict)
        )
        usage = data.get("usageMetadata", {})
        return AIResponse(
            content=content, model=self.model,
            input_tokens=usage.get("promptTokenCount", 0),
            output_tokens=usage.get("candidatesTokenCount", 0),
            latency_ms=latency,
            raw_response={"finishReason": candidate.get("finishReason")},
            # finishReason was captured nowhere before, so truncation on
            # Gemini was undetectable by construction.
            stop_reason=normalize_stop_reason(candidate.get("finishReason")),
        )


def create_provider(
    provider_name: str,
    api_key: str,
    model: Optional[str] = None,
    endpoint_url: Optional[str] = None,
    extra_payload: Optional[dict] = None,
    supports_json_mode: Optional[bool] = None,
) -> AIProvider:
    """Create an AI provider instance from configuration.

    `extra_payload` is merged into the request body on each call (OpenAI-
    compatible providers only). Used for provider-specific knobs like
    OpenRouter's `{"provider": {"ignore": [...]}}` routing controls.
    """
    strategy = resolve_json_strategy(provider_name, supports_json_mode)

    if provider_name in ("claude", "anthropic"):
        return ClaudeProvider(
            api_key=api_key, model=model or "claude-sonnet-4-20250514",
            json_strategy=strategy)
    elif provider_name == "openai":
        return OpenAIProvider(api_key=api_key, model=model or "gpt-4o", extra_payload=extra_payload, json_strategy=strategy)
    elif provider_name == "azure_openai":
        return OpenAIProvider(api_key=api_key, model=model or "gpt-4o", base_url=endpoint_url, extra_payload=extra_payload, json_strategy=strategy)
    elif provider_name == "google":
        return GoogleProvider(api_key=api_key, model=model or "gemini-2.0-flash", json_strategy=strategy)
    elif provider_name == "ollama":
        # Ollama uses OpenAI-compatible API at /v1/chat/completions — no API key needed
        return OpenAIProvider(api_key=api_key or "ollama", model=model or "phi3.5", base_url=endpoint_url or "http://localhost:11434", extra_payload=extra_payload, json_strategy=strategy)
    elif provider_name in ("custom", "aws_bedrock", "lm_studio", "vllm", "localai", "huggingface_tgi"):
        # Custom / self-hosted endpoints use OpenAI-compatible API
        return OpenAIProvider(api_key=api_key or "none", model=model or "default", base_url=endpoint_url, extra_payload=extra_payload, json_strategy=strategy)
    else:
        raise ValueError(f"Unknown AI provider: {provider_name}")


async def get_provider_for_task(task: str, tenant_id: str, db=None) -> Optional[AIProvider]:
    """
    Return a provider for the tenant's AI model — there is exactly one per
    tenant — falling back to env vars when none is configured or it is
    disabled. Triage is the only AI task; `task` is kept for callers.
    Pass `db` session when calling from Celery workers to avoid event loop issues.
    """
    from apps.api.app.models.ai_model import AIModelConfig
    from sqlalchemy import select

    query = select(AIModelConfig).where(
        AIModelConfig.tenant_id == tenant_id,
        AIModelConfig.is_active == True,
    ).limit(1)
    if db:
        # Use provided session (from worker's own event loop)
        m = (await db.execute(query)).scalar_one_or_none()
    else:
        # Create own session (for API context)
        from apps.api.app.core.database import async_session_factory
        async with async_session_factory() as session:
            m = (await session.execute(query)).scalar_one_or_none()

    if m:
        return create_provider(
            m.provider, m.api_key_encrypted, m.model_id, m.endpoint_url,
            extra_payload=m.provider_config or None,
            # The tenant's legacy flag still steers the NATIVE mechanism
            # (it exists because forcing response_format through
            # OpenRouter truncated responses). It has never had any
            # effect on Anthropic, which resolves to prefill regardless.
            supports_json_mode=m.supports_json_mode,
        )

    # Fallback: env vars
    from apps.api.app.core.config import settings
    if settings.ANTHROPIC_API_KEY:
        return create_provider("claude", settings.ANTHROPIC_API_KEY, settings.AI_MODEL)
    if settings.OPENAI_API_KEY:
        return create_provider("openai", settings.OPENAI_API_KEY)

    return None
