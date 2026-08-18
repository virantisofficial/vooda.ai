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


@dataclass
class AIResponse:
    content: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0
    cost_estimate: float = 0.0
    raw_response: dict = field(default_factory=dict)


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
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self._api_key = api_key
        self.model = model

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
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        if stop_sequences:
            payload["stop_sequences"] = stop_sequences

        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(url, json=payload, headers=headers)
            r.raise_for_status()
            data = r.json()

        latency = (time.monotonic() - start) * 1000
        content = data.get("content", [{}])[0].get("text", "")
        usage = data.get("usage", {})

        return AIResponse(
            content=content, model=self.model,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            latency_ms=latency,
            raw_response={"stop_reason": data.get("stop_reason")},
        )


class OpenAIProvider(AIProvider):
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        base_url: Optional[str] = None,
        timeout: int = 120,
        extra_payload: Optional[dict] = None,
    ):
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
    DEADLINE_FLOOR_TPS = 15.0  # conservative decode floor used for the deadline
    DEADLINE_SLACK_S = 60.0    # prompt processing + network slack

    @classmethod
    def deadline_for(cls, max_tokens: int) -> float:
        """Total-call deadline scaled to the token budget, clamped to sane bounds."""
        est = (max_tokens or 4096) / cls.DEADLINE_FLOOR_TPS + cls.DEADLINE_SLACK_S
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
        if json_mode:
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
        deadline = self.deadline_for(effective_max)
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
        return AIResponse(
            content=acc["content"], model=self.model,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=(time.monotonic() - start) * 1000,
            raw_response={
                "finish_reason": acc["finish_reason"],
                "reasoning_len": acc["reasoning_len"],
                "streamed": True,
            },
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
        )


class GoogleProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
        self.api_key = api_key
        self.model = model

    async def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096, temperature: float = 0.1, stop_sequences: list[str] | None = None, json_mode: bool = False) -> AIResponse:
        import httpx
        start = time.monotonic()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        gen_config: dict = {"maxOutputTokens": max_tokens, "temperature": temperature}
        if stop_sequences:
            gen_config["stopSequences"] = stop_sequences
        if json_mode:
            gen_config["responseMimeType"] = "application/json"
        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_prompt}]}],
            "generationConfig": gen_config,
        }
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()

        latency = (time.monotonic() - start) * 1000
        content = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        usage = data.get("usageMetadata", {})
        return AIResponse(
            content=content, model=self.model,
            input_tokens=usage.get("promptTokenCount", 0),
            output_tokens=usage.get("candidatesTokenCount", 0),
            latency_ms=latency,
        )


def create_provider(
    provider_name: str,
    api_key: str,
    model: Optional[str] = None,
    endpoint_url: Optional[str] = None,
    extra_payload: Optional[dict] = None,
) -> AIProvider:
    """Create an AI provider instance from configuration.

    `extra_payload` is merged into the request body on each call (OpenAI-
    compatible providers only). Used for provider-specific knobs like
    OpenRouter's `{"provider": {"ignore": [...]}}` routing controls.
    """
    if provider_name in ("claude", "anthropic"):
        return ClaudeProvider(api_key=api_key, model=model or "claude-sonnet-4-20250514")
    elif provider_name == "openai":
        return OpenAIProvider(api_key=api_key, model=model or "gpt-4o", extra_payload=extra_payload)
    elif provider_name == "azure_openai":
        return OpenAIProvider(api_key=api_key, model=model or "gpt-4o", base_url=endpoint_url, extra_payload=extra_payload)
    elif provider_name == "google":
        return GoogleProvider(api_key=api_key, model=model or "gemini-2.0-flash")
    elif provider_name == "ollama":
        # Ollama uses OpenAI-compatible API at /v1/chat/completions — no API key needed
        return OpenAIProvider(api_key=api_key or "ollama", model=model or "phi3.5", base_url=endpoint_url or "http://localhost:11434", extra_payload=extra_payload)
    elif provider_name in ("custom", "aws_bedrock", "lm_studio", "vllm", "localai", "huggingface_tgi"):
        # Custom / self-hosted endpoints use OpenAI-compatible API
        return OpenAIProvider(api_key=api_key or "none", model=model or "default", base_url=endpoint_url, extra_payload=extra_payload)
    else:
        raise ValueError(f"Unknown AI provider: {provider_name}")


async def get_provider_for_task(task: str, tenant_id: str, db=None) -> Optional[AIProvider]:
    """
    Look up the configured model for a specific task and return a provider.
    Falls back to env vars if no DB config exists.
    Pass `db` session when calling from Celery workers to avoid event loop issues.
    """
    from apps.api.app.models.ai_model import AIModelConfig
    from sqlalchemy import select

    if db:
        # Use provided session (from worker's own event loop)
        result = await db.execute(
            select(AIModelConfig).where(
                AIModelConfig.tenant_id == tenant_id,
                AIModelConfig.is_active == True,
            ).order_by(AIModelConfig.is_primary.desc())
        )
        models = result.scalars().all()
    else:
        # Create own session (for API context)
        from apps.api.app.core.database import async_session_factory
        async with async_session_factory() as session:
            result = await session.execute(
                select(AIModelConfig).where(
                    AIModelConfig.tenant_id == tenant_id,
                    AIModelConfig.is_active == True,
                ).order_by(AIModelConfig.is_primary.desc())
            )
            models = result.scalars().all()

    # Find model assigned to this task
    for m in models:
        if task in (m.tasks or []):
            return create_provider(
                m.provider, m.api_key_encrypted, m.model_id, m.endpoint_url,
                extra_payload=m.provider_config or None,
            )

    # Fallback: primary model regardless of task
    for m in models:
        if m.is_primary and m.api_key_encrypted:
            return create_provider(
                m.provider, m.api_key_encrypted, m.model_id, m.endpoint_url,
                extra_payload=m.provider_config or None,
            )

    # Final fallback: env vars
    from apps.api.app.core.config import settings
    if settings.ANTHROPIC_API_KEY:
        return create_provider("claude", settings.ANTHROPIC_API_KEY, settings.AI_MODEL)
    if settings.OPENAI_API_KEY:
        return create_provider("openai", settings.OPENAI_API_KEY)

    return None
