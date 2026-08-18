# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
AI Model Configuration API — CRUD + test connection + task routing.
"""

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.ai_model import AIModelConfig

router = APIRouter()


# ── Schemas ───────────────────────────────────────────

class AIModelCreate(BaseModel):
    name: str
    provider: str
    model_id: str
    api_key: Optional[str] = None
    endpoint_url: Optional[str] = None
    tasks: list[str] = []
    is_primary: bool = False
    max_tokens: int = 4096
    temperature: float = 0.1
    context_window: int = 4096
    stop_sequences: list[str] = []
    supports_json_mode: bool = False
    system_prompt_override: Optional[str] = None
    use_compact_prompt: bool = False
    prompt_strategy: str = "recommended"
    model_size_class: Optional[str] = None
    provider_config: dict = {}


class AIModelUpdate(BaseModel):
    name: Optional[str] = None
    model_id: Optional[str] = None
    api_key: Optional[str] = None
    endpoint_url: Optional[str] = None
    tasks: Optional[list[str]] = None
    is_primary: Optional[bool] = None
    is_active: Optional[bool] = None
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    context_window: Optional[int] = None
    stop_sequences: Optional[list[str]] = None
    supports_json_mode: Optional[bool] = None
    system_prompt_override: Optional[str] = None
    use_compact_prompt: Optional[bool] = None
    prompt_strategy: Optional[str] = None
    model_size_class: Optional[str] = None
    provider_config: Optional[dict] = None


class AIModelResponse(BaseModel):
    id: UUID
    name: str
    provider: str
    model_id: str
    endpoint_url: Optional[str]
    tasks: list[str]
    is_primary: bool
    is_active: bool
    api_key_set: bool
    max_tokens: int
    temperature: float
    context_window: int
    stop_sequences: list[str]
    supports_json_mode: bool
    system_prompt_override: Optional[str]
    use_compact_prompt: bool
    prompt_strategy: str
    model_size_class: Optional[str]
    total_requests: int
    total_input_tokens: int
    total_output_tokens: int
    total_cost_usd: float
    last_used_at: Optional[str]
    last_error: Optional[str]
    provider_config: dict
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class TestConnectionRequest(BaseModel):
    model_config_id: Optional[UUID] = None
    # Or inline test (for new models before saving)
    provider: Optional[str] = None
    model_id: Optional[str] = None
    api_key: Optional[str] = None
    endpoint_url: Optional[str] = None


class TestConnectionResponse(BaseModel):
    status: str  # success, error
    message: str
    latency_ms: Optional[float] = None
    model_response_preview: Optional[str] = None


class TaskRoutingResponse(BaseModel):
    task: str
    assigned_models: list[dict]


# ── Helper ────────────────────────────────────────────

def _to_response(m: AIModelConfig) -> dict:
    return {
        "id": m.id,
        "name": m.name,
        "provider": m.provider,
        "model_id": m.model_id,
        "endpoint_url": m.endpoint_url,
        "tasks": m.tasks or [],
        "is_primary": m.is_primary,
        "is_active": m.is_active,
        "api_key_set": bool(m.api_key_encrypted),
        "max_tokens": m.max_tokens or 4096,
        "temperature": m.temperature if m.temperature is not None else 0.1,
        "context_window": m.context_window or 4096,
        "stop_sequences": m.stop_sequences or [],
        "supports_json_mode": m.supports_json_mode or False,
        "system_prompt_override": m.system_prompt_override,
        "use_compact_prompt": m.use_compact_prompt or False,
        "prompt_strategy": m.prompt_strategy or "recommended",
        "model_size_class": m.model_size_class,
        "total_requests": m.total_requests or 0,
        "total_input_tokens": m.total_input_tokens or 0,
        "total_output_tokens": m.total_output_tokens or 0,
        "total_cost_usd": m.total_cost_usd or 0.0,
        "last_used_at": m.last_used_at,
        "last_error": m.last_error,
        "provider_config": m.provider_config or {},
        "created_at": str(m.created_at),
        "updated_at": str(m.updated_at),
    }


# ── Endpoints ─────────────────────────────────────────

@router.get("/status")
async def ai_status(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Check if AI is configured and ready for triage and remediation."""
    from apps.api.app.core.config import settings

    # Check DB-configured models
    result = await db.execute(
        select(AIModelConfig).where(
            AIModelConfig.tenant_id == user.tenant_id,
            AIModelConfig.is_active == True,
        )
    )
    db_models = result.scalars().all()
    has_db_models = any(m.api_key_encrypted for m in db_models)

    # Check env vars
    has_env_key = bool(settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY)

    is_ready = has_db_models or has_env_key

    return {
        "ai_configured": is_ready,
        "has_db_models": has_db_models,
        "has_env_key": has_env_key,
        "active_models": len(db_models),
        "message": "AI is ready for false positive analysis and auto-remediation" if is_ready
                   else "No AI model configured. Configure an API key in Integration Hub → AI Models to enable false positive analysis and auto-remediation.",
    }


@router.get("", response_model=list[AIModelResponse])
async def list_models(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(AIModelConfig)
        .where(AIModelConfig.tenant_id == user.tenant_id)
        .order_by(AIModelConfig.is_primary.desc(), AIModelConfig.created_at)
    )
    return [_to_response(m) for m in result.scalars().all()]


@router.post("", response_model=AIModelResponse, status_code=201)
async def create_model(
    body: AIModelCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # If marking as primary, unset other primaries
    if body.is_primary:
        await db.execute(
            update(AIModelConfig)
            .where(AIModelConfig.tenant_id == user.tenant_id, AIModelConfig.is_primary == True)
            .values(is_primary=False)
        )

    model = AIModelConfig(
        tenant_id=user.tenant_id,
        name=body.name,
        provider=body.provider,
        model_id=body.model_id,
        api_key_encrypted=body.api_key,  # In production, encrypt this
        endpoint_url=body.endpoint_url,
        tasks=body.tasks,
        is_primary=body.is_primary,
        max_tokens=body.max_tokens,
        temperature=body.temperature,
        context_window=body.context_window,
        stop_sequences=body.stop_sequences,
        supports_json_mode=body.supports_json_mode,
        system_prompt_override=body.system_prompt_override,
        use_compact_prompt=body.use_compact_prompt,
        prompt_strategy=body.prompt_strategy,
        model_size_class=body.model_size_class,
        provider_config=body.provider_config,
    )
    db.add(model)
    await db.flush()

    # Auto-primary: if this is the only model, make it primary automatically
    count_result = await db.execute(
        select(func.count(AIModelConfig.id)).where(AIModelConfig.tenant_id == user.tenant_id)
    )
    total_models = count_result.scalar() or 0
    if total_models == 1:
        model.is_primary = True

    await db.refresh(model)
    return _to_response(model)


# ── AI Engine Settings (must be before /{model_id} to avoid route conflict) ──

class AIEngineSettingsSchema(BaseModel):
    context_mode: str = "smart"
    analysis_mode: str = "batch_similar"
    skip_ai_for_info: bool = True
    ai_confidence_threshold: float = 0.6
    max_tokens_per_finding: int = 4096
    batch_size: int = 5
    max_concurrent: int = 10
    rate_limit_rpm: int = 60
    auto_verify_credentials: bool = True
    deprioritize_test_files: str = "normal"   # normal, deprioritize, exclude
    scan_scope: str = "standard"              # standard, extended, minimal


@router.get("/engine-settings")
async def get_engine_settings(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from apps.api.app.models.ai_engine_settings import AIEngineSettings
    result = await db.execute(select(AIEngineSettings).where(AIEngineSettings.tenant_id == user.tenant_id).limit(1))
    s = result.scalar_one_or_none()
    if not s:
        return AIEngineSettingsSchema().model_dump()
    return {k: getattr(s, k) for k in AIEngineSettingsSchema.model_fields.keys()}


@router.put("/engine-settings")
async def update_engine_settings(
    body: AIEngineSettingsSchema,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from apps.api.app.models.ai_engine_settings import AIEngineSettings
    result = await db.execute(select(AIEngineSettings).where(AIEngineSettings.tenant_id == user.tenant_id).limit(1))
    s = result.scalar_one_or_none()
    if s:
        for field, value in body.model_dump().items():
            setattr(s, field, value)
    else:
        s = AIEngineSettings(tenant_id=user.tenant_id, **body.model_dump())
        db.add(s)
    await db.flush()
    return {"status": "ok", **body.model_dump()}


@router.get("/{model_id}", response_model=AIModelResponse)
async def get_model(
    model_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(AIModelConfig).where(
            AIModelConfig.id == model_id, AIModelConfig.tenant_id == user.tenant_id
        )
    )
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    return _to_response(model)


@router.put("/{model_id}", response_model=AIModelResponse)
async def update_model(
    model_id: UUID,
    body: AIModelUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(AIModelConfig).where(
            AIModelConfig.id == model_id, AIModelConfig.tenant_id == user.tenant_id
        )
    )
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")

    update_data = body.model_dump(exclude_unset=True)

    # Handle primary flag
    if update_data.get("is_primary"):
        await db.execute(
            update(AIModelConfig)
            .where(AIModelConfig.tenant_id == user.tenant_id, AIModelConfig.is_primary == True)
            .values(is_primary=False)
        )

    # Handle api_key separately
    if "api_key" in update_data:
        api_key = update_data.pop("api_key")
        if api_key:
            model.api_key_encrypted = api_key  # In production, encrypt

    for field, value in update_data.items():
        setattr(model, field, value)

    await db.flush()
    await db.refresh(model)
    return _to_response(model)


@router.delete("/{model_id}", status_code=204)
async def delete_model(
    model_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(AIModelConfig).where(
            AIModelConfig.id == model_id, AIModelConfig.tenant_id == user.tenant_id
        )
    )
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    was_primary = model.is_primary
    await db.delete(model)
    await db.flush()

    # Auto-promote: if deleted model was primary, promote remaining model
    if was_primary:
        remaining = await db.execute(
            select(AIModelConfig).where(
                AIModelConfig.tenant_id == user.tenant_id, AIModelConfig.is_active == True
            ).limit(1)
        )
        next_model = remaining.scalar_one_or_none()
        if next_model:
            next_model.is_primary = True
            await db.flush()


@router.post("/test", response_model=TestConnectionResponse)
async def test_model_connection(
    body: TestConnectionRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Test an AI model connection by sending a trivial prompt."""
    provider = body.provider
    model_id = body.model_id
    api_key = body.api_key
    endpoint_url = body.endpoint_url

    # Load from existing config if ID provided
    if body.model_config_id:
        result = await db.execute(
            select(AIModelConfig).where(
                AIModelConfig.id == body.model_config_id,
                AIModelConfig.tenant_id == user.tenant_id,
            )
        )
        model = result.scalar_one_or_none()
        if not model:
            raise HTTPException(status_code=404, detail="Model not found")
        provider = model.provider
        model_id = model.model_id
        api_key = model.api_key_encrypted
        endpoint_url = model.endpoint_url

    # Local providers (Ollama, vLLM, etc.) don't need an API key
    local_providers = {"ollama", "lm_studio", "vllm", "localai", "custom"}
    if not provider or not model_id:
        return TestConnectionResponse(status="error", message="Provider and model ID are required")
    if not api_key and provider not in local_providers:
        return TestConnectionResponse(status="error", message="API key is required for cloud providers")

    try:
        from services.ai_triage.provider import create_provider
        ai_provider = create_provider(provider, api_key, model_id, endpoint_url)
        response = await ai_provider.complete(
            system_prompt="You are a test assistant. Reply with exactly: CONNECTION_OK",
            user_prompt="Test connection. Reply with exactly: CONNECTION_OK",
            max_tokens=20,
            temperature=0,
        )

        # Update last_used if testing an existing model
        if body.model_config_id:
            from datetime import datetime, timezone
            result2 = await db.execute(
                select(AIModelConfig).where(AIModelConfig.id == body.model_config_id)
            )
            m = result2.scalar_one_or_none()
            if m:
                m.last_used_at = datetime.now(timezone.utc).isoformat()
                m.last_error = None
                m.total_requests = (m.total_requests or 0) + 1
                m.total_input_tokens = (m.total_input_tokens or 0) + response.input_tokens
                m.total_output_tokens = (m.total_output_tokens or 0) + response.output_tokens
                await db.flush()

        return TestConnectionResponse(
            status="success",
            message=f"Connected to {provider}/{model_id} successfully",
            latency_ms=round(response.latency_ms, 1),
            model_response_preview=response.content[:100],
        )

    except Exception as e:
        # Store error if testing existing model
        if body.model_config_id:
            result2 = await db.execute(
                select(AIModelConfig).where(AIModelConfig.id == body.model_config_id)
            )
            m = result2.scalar_one_or_none()
            if m:
                m.last_error = str(e)[:500]
                await db.flush()

        return TestConnectionResponse(
            status="error",
            message=f"Connection failed: {str(e)[:200]}",
        )


class DiscoverModelsRequest(BaseModel):
    provider: Optional[str] = None
    api_key: Optional[str] = None  # Optional for self-hosted/local models (Ollama, vLLM, LM Studio)
    endpoint_url: Optional[str] = None
    model_config_id: Optional[UUID] = None  # Reuse stored credentials for an existing config


class DiscoveredModel(BaseModel):
    model_id: str
    name: str
    description: str = ""
    context_window: Optional[int] = None
    max_output: Optional[int] = None


@router.post("/auto-config")
async def get_auto_configuration(
    body: dict,
    user: User = Depends(get_current_user),
):
    """Get recommended auto-configuration based on provider, model, and strategy."""
    from packages.prompts.strategies import get_auto_config, classify_model_size, PROMPT_STRATEGIES
    provider = body.get("provider", "custom")
    model_id = body.get("model_id", "")
    strategy = body.get("prompt_strategy", "recommended")
    param_size = body.get("parameter_size")  # From Ollama discovery: "3.8B" etc.

    # Parse parameter size string to int
    param_count = None
    if param_size:
        ps = str(param_size).upper().replace(",", "")
        if "B" in ps:
            try:
                param_count = int(float(ps.replace("B", "")) * 1_000_000_000)
            except ValueError:
                pass
        elif "M" in ps:
            try:
                param_count = int(float(ps.replace("M", "")) * 1_000_000)
            except ValueError:
                pass

    model_size = classify_model_size(param_count, model_id)
    config = get_auto_config(provider, model_id, model_size, strategy)
    config["model_size_class"] = model_size

    return {
        "config": config,
        "strategies": {k: {"label": v["label"], "description": v["description"]} for k, v in PROMPT_STRATEGIES.items()},
    }


class DiscoverModelsResponse(BaseModel):
    status: str  # "success" | "error"
    message: str = ""
    provider: str = ""
    models: list[DiscoveredModel] = []


@router.post("/discover-models", response_model=DiscoverModelsResponse)
async def discover_available_models(
    body: DiscoverModelsRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Validate an API key and return the list of models the key has access to.

    For cloud providers (Anthropic, OpenAI, Google, Azure): API key is required.
    For self-hosted/local (Custom, Ollama, vLLM, LM Studio): API key is optional, endpoint URL is required.

    When `model_config_id` is provided, the stored credentials for that config are
    used — letting the edit UI list alternative models without the user re-typing the key.
    """
    provider = (body.provider or "").lower()
    api_key = body.api_key or ""
    endpoint_url = body.endpoint_url

    # Reuse stored credentials when editing an existing model
    if body.model_config_id:
        result = await db.execute(
            select(AIModelConfig).where(
                AIModelConfig.id == body.model_config_id,
                AIModelConfig.tenant_id == user.tenant_id,
            )
        )
        stored = result.scalar_one_or_none()
        if not stored:
            return DiscoverModelsResponse(status="error", message="Model configuration not found", provider=provider)
        provider = (provider or stored.provider or "").lower()
        if not api_key:
            api_key = stored.api_key_encrypted or ""
        if not endpoint_url:
            endpoint_url = stored.endpoint_url

    if not provider:
        return DiscoverModelsResponse(status="error", message="Provider is required", provider="")

    # Validate requirements per provider
    CLOUD_PROVIDERS = {"anthropic", "claude", "openai", "google", "azure_openai", "aws_bedrock"}
    LOCAL_PROVIDERS = {"custom", "ollama", "lm_studio", "vllm", "localai", "huggingface_tgi"}

    if provider in CLOUD_PROVIDERS and not api_key:
        return DiscoverModelsResponse(
            status="error",
            message=f"API key is required for {provider}",
            provider=provider,
        )
    if provider in LOCAL_PROVIDERS and not endpoint_url:
        return DiscoverModelsResponse(
            status="error",
            message="Endpoint URL is required for self-hosted models (e.g., http://localhost:11434 for Ollama)",
            provider=provider,
        )

    try:
        if provider in ("anthropic", "claude"):
            return await _discover_anthropic(api_key)
        elif provider == "openai":
            return await _discover_openai(api_key)
        elif provider == "azure_openai":
            return await _discover_openai(api_key, endpoint_url)
        elif provider == "google":
            return await _discover_google(api_key)
        elif provider in ("aws_bedrock",):
            return await _discover_openai_compatible(api_key, endpoint_url, provider)
        elif provider in LOCAL_PROVIDERS or provider == "custom":
            return await _discover_local(endpoint_url, api_key, provider)
        else:
            return DiscoverModelsResponse(status="error", message=f"Unknown provider: {provider}", provider=provider)
    except Exception as e:
        return DiscoverModelsResponse(status="error", message=f"Failed to discover models: {str(e)[:200]}", provider=provider)


async def _discover_anthropic(api_key: str) -> DiscoverModelsResponse:
    import httpx

    async with httpx.AsyncClient(timeout=15) as client:
        # Validate key with a minimal request
        r = await client.get(
            "https://api.anthropic.com/v1/models",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
        )

        if r.status_code == 401:
            return DiscoverModelsResponse(status="error", message="Invalid API key", provider="anthropic")
        if r.status_code == 403:
            return DiscoverModelsResponse(status="error", message="API key does not have permission to list models", provider="anthropic")

        if r.status_code == 200:
            data = r.json()
            models = []
            for m in data.get("data", []):
                model_id = m.get("id", "")
                display_name = m.get("display_name", model_id)
                # Filter to chat/completion models only
                if any(x in model_id for x in ["claude"]):
                    models.append(DiscoveredModel(
                        model_id=model_id,
                        name=display_name,
                        description=m.get("description", ""),
                        context_window=m.get("context_window"),
                        max_output=m.get("max_output_tokens"),
                    ))

            # Sort: newest first (higher version numbers first)
            models.sort(key=lambda x: x.model_id, reverse=True)

            return DiscoverModelsResponse(
                status="success",
                message=f"Found {len(models)} models",
                provider="anthropic",
                models=models,
            )

        # Fallback: key works but can't list — return known models
        return DiscoverModelsResponse(
            status="success",
            message="API key validated. Showing known models (model listing not available).",
            provider="anthropic",
            models=[
                DiscoveredModel(model_id="claude-sonnet-4-20250514", name="Claude Sonnet 4", description="Best balance of speed and intelligence"),
                DiscoveredModel(model_id="claude-opus-4-20250514", name="Claude Opus 4", description="Highest intelligence"),
                DiscoveredModel(model_id="claude-3-5-haiku-20241022", name="Claude 3.5 Haiku", description="Fastest and most compact"),
                DiscoveredModel(model_id="claude-3-5-sonnet-20241022", name="Claude 3.5 Sonnet", description="Previous generation balanced model"),
            ],
        )


async def _discover_openai(api_key: str, base_url: str | None = None) -> DiscoverModelsResponse:
    import httpx

    url = (base_url.rstrip("/") if base_url else "https://api.openai.com") + "/v1/models"
    headers = {"Authorization": f"Bearer {api_key}"}

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(url, headers=headers)

        if r.status_code == 401:
            return DiscoverModelsResponse(status="error", message="Invalid API key", provider="openai")
        if r.status_code != 200:
            return DiscoverModelsResponse(status="error", message=f"API returned {r.status_code}", provider="openai")

        data = r.json()
        models = []
        # Filter to GPT and chat models
        chat_prefixes = ("gpt-4", "gpt-3.5", "o1", "o3", "chatgpt")
        for m in data.get("data", []):
            mid = m.get("id", "")
            if any(mid.startswith(p) for p in chat_prefixes):
                models.append(DiscoveredModel(
                    model_id=mid,
                    name=mid,
                    description=f"Owned by {m.get('owned_by', 'openai')}",
                ))

        models.sort(key=lambda x: x.model_id, reverse=True)

        return DiscoverModelsResponse(
            status="success",
            message=f"Found {len(models)} chat models",
            provider="openai",
            models=models,
        )


async def _discover_google(api_key: str) -> DiscoverModelsResponse:
    import httpx

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}",
        )

        if r.status_code == 400 or r.status_code == 403:
            return DiscoverModelsResponse(status="error", message="Invalid API key", provider="google")
        if r.status_code != 200:
            return DiscoverModelsResponse(status="error", message=f"API returned {r.status_code}", provider="google")

        data = r.json()
        models = []
        for m in data.get("models", []):
            name = m.get("name", "").replace("models/", "")
            if "generateContent" in str(m.get("supportedGenerationMethods", [])):
                models.append(DiscoveredModel(
                    model_id=name,
                    name=m.get("displayName", name),
                    description=m.get("description", "")[:100],
                    context_window=m.get("inputTokenLimit"),
                    max_output=m.get("outputTokenLimit"),
                ))

        models.sort(key=lambda x: x.model_id, reverse=True)

        return DiscoverModelsResponse(
            status="success",
            message=f"Found {len(models)} models",
            provider="google",
            models=models,
        )


async def _discover_openai_compatible(api_key: str, endpoint_url: str | None, provider: str) -> DiscoverModelsResponse:
    if not endpoint_url:
        return DiscoverModelsResponse(status="error", message="Endpoint URL required for custom providers", provider=provider)

    # Try OpenAI-compatible /v1/models
    result = await _discover_openai(api_key, endpoint_url)
    result.provider = provider
    return result


async def _discover_local(endpoint_url: str, api_key: str, provider: str) -> DiscoverModelsResponse:
    """Discover models on a local/self-hosted endpoint (Ollama, vLLM, LM Studio, etc.)."""
    import httpx

    base = endpoint_url.rstrip("/")
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    async with httpx.AsyncClient(timeout=10) as client:
        # Try multiple discovery paths that different local servers use

        # 1. Try Ollama native API: /api/tags
        try:
            r = await client.get(f"{base}/api/tags", headers=headers)
            if r.status_code == 200:
                data = r.json()
                models = []
                for m in data.get("models", []):
                    name = m.get("name", "")
                    models.append(DiscoveredModel(
                        model_id=name,
                        name=name.split(":")[0] if ":" in name else name,
                        description=f"Size: {m.get('size', 0) / 1e9:.1f}GB" if m.get("size") else "",
                        context_window=m.get("details", {}).get("parameter_size"),
                    ))
                if models:
                    return DiscoverModelsResponse(
                        status="success",
                        message=f"Connected to Ollama. Found {len(models)} models.",
                        provider=provider,
                        models=models,
                    )
        except Exception:
            pass

        # 2. Try OpenAI-compatible /v1/models
        try:
            r = await client.get(f"{base}/v1/models", headers=headers)
            if r.status_code == 200:
                data = r.json()
                models = []
                for m in data.get("data", []):
                    mid = m.get("id", "")
                    models.append(DiscoveredModel(
                        model_id=mid,
                        name=mid,
                        description=f"Owned by {m.get('owned_by', 'local')}",
                    ))
                if models:
                    return DiscoverModelsResponse(
                        status="success",
                        message=f"Connected. Found {len(models)} models.",
                        provider=provider,
                        models=models,
                    )
        except Exception:
            pass

        # 3. Try /models (no /v1 prefix)
        try:
            r = await client.get(f"{base}/models", headers=headers)
            if r.status_code == 200:
                data = r.json()
                items = data.get("data", data.get("models", []))
                if isinstance(items, list) and items:
                    models = [DiscoveredModel(
                        model_id=m.get("id", m.get("name", str(i))),
                        name=m.get("id", m.get("name", f"model-{i}")),
                    ) for i, m in enumerate(items) if isinstance(m, dict)]
                    return DiscoverModelsResponse(
                        status="success",
                        message=f"Connected. Found {len(models)} models.",
                        provider=provider,
                        models=models,
                    )
        except Exception:
            pass

        # 4. Check if server is reachable at all
        try:
            r = await client.get(base, headers=headers)
            if r.status_code < 500:
                return DiscoverModelsResponse(
                    status="success",
                    message="Server reachable but model listing not supported. Enter model ID manually.",
                    provider=provider,
                    models=[],  # Empty — user must type model ID manually
                )
        except Exception:
            pass

    return DiscoverModelsResponse(
        status="error",
        message=f"Cannot reach {endpoint_url}. Check the URL and ensure the server is running.",
        provider=provider,
    )


@router.get("/routing/tasks")
async def get_task_routing(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return which models are assigned to which tasks."""
    result = await db.execute(
        select(AIModelConfig).where(
            AIModelConfig.tenant_id == user.tenant_id,
            AIModelConfig.is_active == True,
        )
    )
    models = result.scalars().all()

    # Only the two task keywords the worker actually dispatches on.
    # `code_analysis` / `summarization` were placeholder strings that no
    # code path calls — returning them here encouraged admins to configure
    # routing that didn't take effect.
    tasks = ["triage", "remediation"]
    routing = {}
    for task in tasks:
        assigned = [
            {"id": str(m.id), "name": m.name, "provider": m.provider, "model_id": m.model_id, "is_primary": m.is_primary}
            for m in models if task in (m.tasks or [])
        ]
        routing[task] = assigned

    return routing


# Engine settings moved before /{model_id} routes to avoid route conflict
