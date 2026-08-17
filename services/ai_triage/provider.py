# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
AI provider abstraction layer.
Supports Claude, OpenAI, Azure OpenAI, Google Gemini, and custom OpenAI-compatible endpoints.
Includes task-based routing to select the correct model per task.
"""

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

    async def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096, temperature: float = 0.1, stop_sequences: list[str] | None = None, json_mode: bool = False) -> AIResponse:
        """Use httpx directly to avoid AsyncOpenAI event loop issues in Celery workers."""
        import httpx
        start = time.monotonic()

        url = f"{self._base_url}/v1/chat/completions"
        # Handle base URLs that already include /v1
        if self._base_url.endswith("/v1") or "/v1/" in self._base_url:
            url = f"{self._base_url}/chat/completions" if self._base_url.endswith("/v1") else f"{self._base_url}chat/completions"

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
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
        # `provider`, `transforms`, `route`).
        if self._extra_payload:
            for k, v in self._extra_payload.items():
                payload[k] = v

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
