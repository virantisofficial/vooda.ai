# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
AI Model Configuration API — CRUD + test connection + task routing.
"""

import re
from datetime import datetime, timezone
from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from apps.api.app.schemas.strict import StrictModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.ai_model import AIModelConfig, AIModelProbeResult
from packages.common.encryption import encrypt_value

router = APIRouter()


# ── Schemas ───────────────────────────────────────────

class AIModelCreate(StrictModel):
    name: str
    provider: str
    model_id: str
    api_key: Optional[str] = None
    endpoint_url: Optional[str] = None
    tasks: list[str] = []
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


class AIModelUpdate(StrictModel):
    name: Optional[str] = None
    model_id: Optional[str] = None
    api_key: Optional[str] = None
    endpoint_url: Optional[str] = None
    tasks: Optional[list[str]] = None
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

#: Fields worth recording when they change. The API key is absent on
#: purpose — an audit trail that carries the credential it is meant to
#: protect is worse than none, and "the key was changed" is the fact a
#: reviewer needs, not its value.
_AUDITED_FIELDS = (
    "name", "provider", "model_id", "endpoint_url", "max_tokens",
    "temperature", "context_window", "supports_json_mode",
    "use_compact_prompt", "prompt_strategy", "model_size_class",
    "system_prompt_override", "is_active",
)


def _audit_snapshot(m: AIModelConfig) -> dict:
    return {f: getattr(m, f, None) for f in _AUDITED_FIELDS}


def _describe_changes(before: dict, after: dict) -> tuple[str, dict]:
    """A sentence for a reader, and the before/after pairs for a query.

    The model itself is called out by name rather than listed among the
    other fields: "who changed the model that triages our secrets" is
    the question this exists to answer, and it should be readable
    without opening the metadata.
    """
    changed = {k: {"from": before.get(k), "to": after.get(k)}
               for k in _AUDITED_FIELDS if before.get(k) != after.get(k)}
    if not changed:
        return "No changes", {}
    if "model_id" in changed:
        lead = f"Model changed from {changed['model_id']['from']} to {changed['model_id']['to']}"
        rest = [k for k in changed if k != "model_id"]
        if rest:
            lead += f"; also {', '.join(sorted(rest))}"
        return lead, changed
    return f"Updated {', '.join(sorted(changed))}", changed


def _to_response(m: AIModelConfig) -> dict:
    return {
        "id": m.id,
        "name": m.name,
        "provider": m.provider,
        "model_id": m.model_id,
        "endpoint_url": m.endpoint_url,
        "tasks": m.tasks or [],
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
    """Check if AI is configured and ready for triage."""
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
        "triage_enabled": is_ready,
        "message": "AI triage is enabled." if is_ready else "No AI model configured.",
    }


@router.get("", response_model=list[AIModelResponse])
async def list_models(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(AIModelConfig)
        .where(AIModelConfig.tenant_id == user.tenant_id)
        .order_by(AIModelConfig.created_at)
    )
    return [_to_response(m) for m in result.scalars().all()]


@router.post("", response_model=AIModelResponse, status_code=201)
async def create_model(
    body: AIModelCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # One AI model per tenant (also enforced by uq_ai_model_configs_tenant_id).
    existing = await db.execute(
        select(AIModelConfig.id).where(AIModelConfig.tenant_id == user.tenant_id).limit(1)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=409,
            detail="An AI provider is already configured. Edit or remove it instead of adding another.",
        )

    model = AIModelConfig(
        tenant_id=user.tenant_id,
        name=body.name,
        provider=body.provider,
        model_id=body.model_id,
        # Encrypted at rest. The column has always been named for it;
        # until now it held the key verbatim, so a database backup, a
        # read replica or a support dump carried the customer's
        # provider credential in the clear.
        api_key_encrypted=encrypt_value(body.api_key) if body.api_key else body.api_key,
        api_key_set_at=datetime.now(timezone.utc) if body.api_key else None,
        endpoint_url=body.endpoint_url,
        tasks=body.tasks,
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

    from apps.api.app.core.audit import log_audit
    await log_audit(
        db, user, "ai_model_created", "ai_model", model.id,
        f"Configured {model.provider}/{model.model_id} for AI triage",
        request=request,
        metadata={"provider": model.provider, "model_id": model.model_id,
                  "endpoint_url": model.endpoint_url,
                  "api_key_set": bool(model.api_key_encrypted)},
    )

    await db.refresh(model)
    return _to_response(model)


# ── AI Engine Settings (must be before /{model_id} to avoid route conflict) ──

class AIEngineSettingsSchema(BaseModel):
    """Tenant-level AI engine configuration.

    Every field here MUST change scan behaviour. Fields that were stored
    and echoed back but never consumed were removed rather than left
    looking functional:

      * ``context_mode``           — Smart/Full/Minimal were never built;
        ``extract_rich_context()`` takes no mode argument. Vooda always
        sends the enclosing function plus imports.
      * ``max_tokens_per_finding`` — duplicated ``ai_model_configs.max_tokens``
        and only the per-model value was ever honoured. Token ceilings are
        per-model, so the model editor owns that.
      * ``batch_size``             — an artifact of the old fixed-batch
        dispatcher. Triage now dispatches in completion order, so there
        are no batches; ``max_concurrent`` and ``rate_limit_rpm`` are the
        only real levers.
      * ``analysis_mode``          — grouping only collapsed identical
        findings, which share a verdict; triage now always groups.

    Pydantic ignores unknown keys, so an older client still sending the
    removed fields keeps working — they are simply no longer persisted.
    """
    skip_ai_for_info: bool = True
    ai_confidence_threshold: float = 0.6
    # Defaults MUST equal the option the UI marks "recommended", or a
    # a fresh install is not self-consistent. These are Balanced:
    # 300 calls/min, 10 in flight.
    #
    # A rate limit only binds when the provider is FASTER than the
    # limit, so this ceiling costs slow and local models nothing; it
    # only avoids throttling fast ones.
    max_concurrent: int = 10
    rate_limit_rpm: int = 300
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
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from apps.api.app.models.ai_engine_settings import AIEngineSettings
    result = await db.execute(select(AIEngineSettings).where(AIEngineSettings.tenant_id == user.tenant_id).limit(1))
    s = result.scalar_one_or_none()
    fields = list(AIEngineSettingsSchema.model_fields.keys())
    before = {f: getattr(s, f, None) for f in fields} if s else {}
    if s:
        for field, value in body.model_dump().items():
            setattr(s, field, value)
    else:
        s = AIEngineSettings(tenant_id=user.tenant_id, **body.model_dump())
        db.add(s)
    await db.flush()

    # These decide what reaches the AI and what a verdict must score to
    # be accepted — a confidence threshold quietly raised changes which
    # secrets get shown to a human.
    after = {f: getattr(s, f, None) for f in fields}
    changed = {k: {"from": before.get(k), "to": after.get(k)}
               for k in fields if before.get(k) != after.get(k)}
    if changed:
        from apps.api.app.core.audit import log_audit
        await log_audit(
            db, user, "ai_engine_settings_updated", "ai_engine_settings", s.id,
            f"Updated {', '.join(sorted(changed))}",
            request=request, metadata={"changed": changed},
        )
    return {"status": "ok", **body.model_dump()}


# NOTE: these routes MUST stay above `GET /{model_id}`.
#
# FastAPI matches in definition order, so with the catch-all first,
# GET /ai-models/probe-results was parsed as model_id="probe-results",
# failed UUID validation and returned 422. Nothing errored loudly —
# the screen simply never loaded a cached verdict, so every badge was
# missing and the caching this feature depends on did nothing.

# ── Model readiness probe ─────────────────────────────
#
# Discovery answers "what models exist". This answers the only question
# a customer actually has: "will this one do the job?" They are separate
# calls because listing is free and unlimited, while asking a model to
# triage costs a request — and doing that for every model each time the
# screen opens would bill the customer for opening a settings page.


#: How many models to probe at once.
#:
#: Sequential took forty minutes for a provider listing hundreds.
#: Unbounded trips rate limits, and a 429 recorded as a verdict marks a
#: working model broken — so this is deliberately modest, and a
#: throttled reply still lands as unverified rather than a judgment.
_PROBE_CONCURRENCY = 8

#: Per request. The caller sends chunks so progress stays visible, and
#: a single request cannot tie up the pool indefinitely.
_PROBE_BATCH_LIMIT = 50


class ProbeRequest(StrictModel):
    provider: str
    #: One model, or several for "Verify all". Kept as a list so the
    #: batch path is the same code as the single path.
    model_ids: list[str]
    api_key: Optional[str] = None
    endpoint_url: Optional[str] = None
    model_config_id: Optional[UUID] = None
    supports_json_mode: bool = True
    #: What discovery concluded about these models. Passed through so
    #: the verdict is stored alongside the probe result rather than
    #: living only in the response that produced it.
    suitability: Optional[dict] = None
    #: The budget triage will actually use. engine.py calls with the
    #: tenant's configured max_tokens, so probing at anything else tests
    #: a request Vooda never makes — and probing low would fail models
    #: that work in production.
    max_tokens: int = 4096


class AccuracyVerdict(BaseModel):
    total: int
    correct: int
    missed_secrets: int
    unanswered: int
    headline: str
    checked_at: Optional[str] = None
    #: Per-case outcomes for the breakdown. Carries no secret material —
    #: the corpus snippets stay server-side; only ids and outcomes travel.
    cases: list = []


class ProbeVerdict(BaseModel):
    model_id: str
    state: str
    headline: str = ""
    remedy: str = ""
    suggested_config: dict = {}
    detail: dict = {}
    latency_ms: float = 0
    probed_at: Optional[str] = None
    #: What discovery concluded, kept with the probe result.
    suitability: Optional[str] = None
    suitability_reason: Optional[str] = None
    #: Null until someone runs it. An unscored model must not read as
    #: one that scored zero.
    accuracy: Optional[AccuracyVerdict] = None


class ProbeResponse(BaseModel):
    status: str
    message: str = ""
    results: list[ProbeVerdict] = []


def _stored_key(stored: str | None) -> str:
    """The provider key held for a config, in the clear, for one call.

    Refuses rather than returning something unusable: handing a
    provider an unreadable value would come back as 401 on every model
    and read as a revoked key, sending an operator to rotate a
    credential that was fine.
    """
    from packages.common.encryption import CredentialUnreadable, decrypt_credential
    try:
        return decrypt_credential(stored or "")
    except CredentialUnreadable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _accuracy_from_row(row) -> Optional[AccuracyVerdict]:
    if row is None or row.accuracy_total is None:
        return None
    return AccuracyVerdict(
        total=row.accuracy_total, correct=row.accuracy_correct or 0,
        missed_secrets=row.accuracy_missed_secrets or 0,
        unanswered=row.accuracy_unanswered or 0,
        headline=row.accuracy_headline or "",
        checked_at=row.accuracy_checked_at,
        cases=(row.accuracy_detail or {}).get("cases", []),
    )


def _probe_to_verdict(r, probed_at: str) -> ProbeVerdict:
    return ProbeVerdict(
        model_id=r.model_id, state=r.state, headline=r.headline,
        remedy=r.remedy, suggested_config=r.suggested_config or {},
        detail=r.detail or {}, latency_ms=round(r.latency_ms, 1),
        probed_at=probed_at,
    )


async def _store_probe(db: AsyncSession, tenant_id, provider: str, r, probed_at: str,
                       suitability: dict | None = None):
    """Upsert by (tenant, provider, model) — one current answer per model."""
    existing = (await db.execute(
        select(AIModelProbeResult).where(
            AIModelProbeResult.tenant_id == tenant_id,
            AIModelProbeResult.provider == provider,
            AIModelProbeResult.model_id == r.model_id,
        )
    )).scalar_one_or_none()
    row = existing or AIModelProbeResult(
        tenant_id=tenant_id, provider=provider, model_id=r.model_id)
    row.state = r.state
    row.headline = (r.headline or "")[:500]
    row.remedy = (r.remedy or "")[:500]
    row.suggested_config = r.suggested_config or {}
    row.detail = r.detail or {}
    row.latency_ms = round(r.latency_ms, 1)
    row.probed_at = probed_at
    if suitability:
        row.suitability = suitability.get("tier")
        row.suitability_reason = (suitability.get("reason") or "")[:200] or None
        row.suitability_may_exclude = bool(suitability.get("may_exclude"))
    if existing is None:
        db.add(row)


@router.post("/probe", response_model=ProbeResponse)
async def probe_models(
    body: ProbeRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Ask each model to triage one finding, and grade the answer.

    Concurrent, with a ceiling. Fully sequential took forty minutes
    across a provider offering hundreds of models, which is not a
    button anyone presses twice. Unbounded would trip rate limits, and
    a 429 read as a verdict says "this model is broken" when the truth
    is "we asked too fast" — so the ceiling is modest and a throttled
    response still lands as unverified rather than a judgment.

    Requests run together; the rows are written afterwards on the one
    session, because a shared AsyncSession is not safe to use from
    several tasks at once.
    """
    from datetime import datetime, timezone
    from services.ai_triage.model_probe import probe_model

    provider = body.provider
    api_key = body.api_key
    endpoint_url = body.endpoint_url
    extra_payload = None

    cfg = None
    if body.model_config_id:
        cfg = (await db.execute(
            select(AIModelConfig).where(
                AIModelConfig.id == body.model_config_id,
                AIModelConfig.tenant_id == user.tenant_id,
            )
        )).scalar_one_or_none()
        if not cfg:
            raise HTTPException(status_code=404, detail="Model config not found")
        provider = cfg.provider
        api_key = _stored_key(cfg.api_key_encrypted)
        endpoint_url = cfg.endpoint_url
        extra_payload = cfg.provider_config or None

    local_providers = {"ollama", "lm_studio", "vllm", "localai", "custom"}
    if not api_key and provider not in local_providers:
        return ProbeResponse(status="error", message="API key is required to verify a model")
    if not body.model_ids:
        return ProbeResponse(status="error", message="No models to verify")

    import asyncio

    model_ids = body.model_ids[:_PROBE_BATCH_LIMIT]
    gate = asyncio.Semaphore(_PROBE_CONCURRENCY)

    async def one(model_id: str):
        async with gate:
            return model_id, await probe_model(
                provider, api_key, model_id, endpoint_url,
                max_tokens=body.max_tokens,
                supports_json_mode=body.supports_json_mode,
                extra_payload=extra_payload,
            )

    probed = await asyncio.gather(*(one(m) for m in model_ids),
                                  return_exceptions=True)

    # A rejected request means different things depending on whether
    # anything else worked.
    #
    # If no model answers, the key is the problem and every verdict is
    # "we could not check". If others answered on the same key, the key
    # is fine and these particular models are not available to this
    # account — which an aggregator also reports as 401. Measured: one
    # key produced 165 working models and 267 rejections, and calling
    # all 267 "the provider rejected the key" pointed the reader at a
    # credential that was demonstrably working.
    ok_now = any(not isinstance(i, Exception) and i[1].state in ("ready", "needs_setup")
                 for i in probed)
    # Only what this key proved.
    #
    # A stored result is evidence about the credential that produced
    # it. Counting them all meant a replaced key inherited the previous
    # one's reputation: a key that authenticated nothing was reported
    # as working "for other models", and every refusal was dressed up
    # as a billing or availability problem on the model.
    #
    # A caller who passed a key inline rather than naming a stored
    # config gets nothing from history either — those results belong to
    # whatever is saved, which is not what is being tested.
    ok_before = False
    if cfg is not None:
        prior = select(AIModelProbeResult.id).where(
            AIModelProbeResult.tenant_id == user.tenant_id,
            AIModelProbeResult.provider == provider,
            AIModelProbeResult.state.in_(("ready", "needs_setup")),
        )
        if cfg.api_key_set_at is not None:
            prior = prior.where(AIModelProbeResult.updated_at >= cfg.api_key_set_at)
        ok_before = bool(
            (await db.execute(prior.limit(1))).scalar_one_or_none())
    key_works = ok_now or ok_before

    results: list[ProbeVerdict] = []
    for item in probed:
        if isinstance(item, Exception):
            # A probe that raised outside its own handling is still a
            # result — silently dropping it would leave the model
            # looking unchecked after the customer asked for a check.
            continue
        model_id, r = item
        if key_works and (r.detail or {}).get("auth_failure"):
            # The key answers elsewhere, so this is about the model's
            # availability — a fact the customer can act on, and one
            # that should not read as a broken credential.
            r.state = "unusable"
            r.headline = "Not available on this account."
            r.remedy = ("The key works for other models. This one may need to be "
                        "enabled, funded, or may require your own provider key.")
        now = datetime.now(timezone.utc).isoformat()
        await _store_probe(db, user.tenant_id, provider, r, now,
                           suitability=(body.suitability or {}).get(model_id))
        results.append(_probe_to_verdict(r, now))

    await db.flush()
    return ProbeResponse(status="success", results=results)


class AccuracyRequest(StrictModel):
    provider: str
    model_id: str
    api_key: Optional[str] = None
    endpoint_url: Optional[str] = None
    model_config_id: Optional[UUID] = None
    supports_json_mode: bool = True
    max_tokens: int = 4096


@router.post("/accuracy", response_model=ProbeVerdict)
async def check_model_accuracy(
    body: AccuracyRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Score one model against findings whose answer is already known.

    One model per call, deliberately. The probe costs a request per
    model and can reasonably run across a list; this costs twenty, and
    running it over a provider offering hundreds would take hours to
    answer a question about models nobody is going to configure.

    The corpus never leaves the server. Only case ids and outcomes are
    returned, so the sample secrets stay out of the browser and out of
    anything a customer can read.
    """
    from datetime import datetime, timezone
    from services.ai_triage.accuracy_check import run_accuracy_check

    provider = body.provider
    api_key = body.api_key
    endpoint_url = body.endpoint_url
    extra_payload = None

    if body.model_config_id:
        cfg = (await db.execute(
            select(AIModelConfig).where(
                AIModelConfig.id == body.model_config_id,
                AIModelConfig.tenant_id == user.tenant_id,
            )
        )).scalar_one_or_none()
        if not cfg:
            raise HTTPException(status_code=404, detail="Model config not found")
        provider = cfg.provider
        api_key = _stored_key(cfg.api_key_encrypted)
        endpoint_url = cfg.endpoint_url
        extra_payload = cfg.provider_config or None

    local_providers = {"ollama", "lm_studio", "vllm", "localai", "custom"}
    if not api_key and provider not in local_providers:
        raise HTTPException(status_code=400, detail="API key is required to score a model")

    result = await run_accuracy_check(
        provider, api_key, body.model_id, endpoint_url,
        max_tokens=body.max_tokens, supports_json_mode=body.supports_json_mode,
        extra_payload=extra_payload,
    )
    now = datetime.now(timezone.utc).isoformat()

    # Stored on the same row as the probe verdict — same model, same
    # tenant, two halves of one question.
    row = (await db.execute(
        select(AIModelProbeResult).where(
            AIModelProbeResult.tenant_id == user.tenant_id,
            AIModelProbeResult.provider == provider,
            AIModelProbeResult.model_id == body.model_id,
        )
    )).scalar_one_or_none()
    if row is None:
        row = AIModelProbeResult(
            tenant_id=user.tenant_id, provider=provider,
            model_id=body.model_id, state="unverified",
            headline="Not checked.", remedy="",
        )
        db.add(row)

    row.accuracy_total = result.total
    row.accuracy_correct = result.correct
    row.accuracy_missed_secrets = result.missed_secrets
    row.accuracy_unanswered = result.unanswered
    row.accuracy_headline = result.headline[:300]
    # Ids and outcomes only — the snippets stay server-side.
    row.accuracy_detail = {"cases": [
        {"case_id": c.case_id, "expected": c.expected, "answered": c.answered,
         "correct": c.correct, "missed_secret": c.missed_secret, "note": c.note}
        for c in result.cases
    ]}
    row.accuracy_checked_at = now
    await db.flush()

    return ProbeVerdict(
        model_id=body.model_id, state=row.state, headline=row.headline or "",
        remedy=row.remedy or "", suggested_config=row.suggested_config or {},
        detail=row.detail or {}, latency_ms=round(result.latency_ms, 1),
        probed_at=row.probed_at, accuracy=_accuracy_from_row(row),
    )


@router.get("/probe-results", response_model=ProbeResponse)
async def get_probe_results(
    provider: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Verdicts already on record, so badges render without a call."""
    rows = (await db.execute(
        select(AIModelProbeResult).where(
            AIModelProbeResult.tenant_id == user.tenant_id,
            AIModelProbeResult.provider == provider,
        )
    )).scalars().all()
    return ProbeResponse(status="success", results=[
        ProbeVerdict(
            model_id=r.model_id, state=r.state, headline=r.headline or "",
            remedy=r.remedy or "", suggested_config=r.suggested_config or {},
            detail=r.detail or {}, latency_ms=r.latency_ms or 0,
            probed_at=r.probed_at, accuracy=_accuracy_from_row(r),
            suitability=r.suitability, suitability_reason=r.suitability_reason,
        ) for r in rows
    ])


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
    request: Request,
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
    before = _audit_snapshot(model)

    # Handle api_key separately
    key_replaced = False
    if "api_key" in update_data:
        api_key = update_data.pop("api_key")
        if api_key:
            model.api_key_encrypted = encrypt_value(api_key)
            # Everything learned about the old key stops counting here.
            model.api_key_set_at = datetime.now(timezone.utc)
            key_replaced = True

    for field, value in update_data.items():
        setattr(model, field, value)

    await db.flush()

    summary, changed = _describe_changes(before, _audit_snapshot(model))
    if key_replaced:
        summary = f"{summary}; API key replaced" if changed else "API key replaced"
    if changed or key_replaced:
        from apps.api.app.core.audit import log_audit
        await log_audit(
            db, user, "ai_model_updated", "ai_model", model.id, summary,
            request=request,
            metadata={"changed": changed, "api_key_replaced": key_replaced,
                      "provider": model.provider, "model_id": model.model_id},
        )

    await db.refresh(model)
    return _to_response(model)


@router.delete("/{model_id}", status_code=204)
async def delete_model(
    model_id: UUID,
    request: Request,
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

    # Recorded BEFORE the delete — afterwards there is nothing left to
    # describe, and "which model was removed" is the whole point.
    removed = _audit_snapshot(model)
    from apps.api.app.core.audit import log_audit
    await log_audit(
        db, user, "ai_model_deleted", "ai_model", model.id,
        f"Removed {model.provider}/{model.model_id}; AI triage is now unconfigured",
        request=request, metadata={"removed": removed},
    )

    await db.delete(model)
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
        api_key = _stored_key(model.api_key_encrypted)
        endpoint_url = model.endpoint_url

    # Local providers (Ollama, vLLM, etc.) don't need an API key
    local_providers = {"ollama", "lm_studio", "vllm", "localai", "custom"}
    if not provider or not model_id:
        return TestConnectionResponse(status="error", message="Provider and model ID are required")
    if not api_key and provider not in local_providers:
        return TestConnectionResponse(status="error", message="API key is required for cloud providers")

    try:
        # Ask for a real triage rather than the word CONNECTION_OK.
        #
        # The old test sent a 20-token budget and reported success on
        # whatever returned, without reading it. Measured against live
        # Gemini, two models came back EMPTY with stop_reason=truncated
        # and both were reported "Connected successfully" — neither can
        # produce a single verdict. Reachability is not fitness, and a
        # green tick that means nothing is worse than no tick at all.
        from services.ai_triage.model_probe import probe_model, READY, UNVERIFIED, UNUSABLE
        probe = await probe_model(provider, api_key, model_id, endpoint_url)

        if probe.state == UNUSABLE:
            if body.model_config_id:
                r3 = await db.execute(
                    select(AIModelConfig).where(AIModelConfig.id == body.model_config_id))
                m3 = r3.scalar_one_or_none()
                if m3:
                    m3.last_error = f"{probe.headline} {probe.remedy}".strip()[:500]
                    await db.flush()
            return TestConnectionResponse(
                status="error",
                message=f"{probe.headline} {probe.remedy}".strip(),
                latency_ms=round(probe.latency_ms, 1),
            )
        if probe.state == UNVERIFIED:
            return TestConnectionResponse(
                status="error",
                message=f"{probe.headline} {probe.remedy}".strip(),
                latency_ms=round(probe.latency_ms, 1),
            )

        class _R:
            latency_ms = probe.latency_ms
            content = probe.headline
            input_tokens = 0
            output_tokens = 0
        response = _R()

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

        msg = (f"{provider}/{model_id} is ready to triage."
               if probe.state == READY
               else f"{provider}/{model_id} answered, but needs a change: {probe.remedy}")
        return TestConnectionResponse(
            status="success",
            message=msg,
            latency_ms=round(probe.latency_ms, 1),
            model_response_preview=probe.headline[:100],
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
    #: Provider-specific settings, sent before a config exists to save.
    #: Anthropic's workspace id lives here and an organisation-level key
    #: is refused on every request without it, so listing models needs
    #: it just as much as triaging does.
    provider_config: Optional[dict] = None


def _int_or_none(v) -> Optional[int]:
    """Coerce a provider's value to int, or None.

    Providers report these inconsistently — ints, numeric strings, or
    things that are not lengths at all. A bad value must not fail the
    whole discovery call; the user just falls back to the default.
    """
    if v is None:
        return None
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


class DiscoveredModel(BaseModel):
    model_id: str
    name: str
    description: str = ""
    #: Real context window as the PROVIDER reports it. When present this
    #: beats any guess — it is the single value that most affects how
    #: much context a triage prompt can carry, and asking a user to look
    #: it up per model is work the provider can do for us.
    context_window: Optional[int] = None
    max_output: Optional[int] = None
    #: e.g. "8B" — drives size classification, not the context window.
    parameter_size: Optional[str] = None
    #: candidate | other_modality | cannot_serve — see model_suitability,
    #: which owns this vocabulary. Rows are never dropped on it; the UI
    #: decides what to show, so any grouping stays reversible.
    suitability: str = "candidate"
    suitability_reason: str = ""
    #: True only when the provider DECLARED it, so hiding is safe.
    suitability_may_exclude: bool = False
    #: Settings the provider stated outright (e.g. JSON-mode support),
    #: so the user is not asked to reason about a checkbox.
    declared_config: dict = {}


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
    config = get_auto_config(
        provider, model_id, model_size, strategy,
        # Passed through from discovery when the provider told us.
        discovered_context_window=_int_or_none(body.get("context_window")),
        discovered_max_output=_int_or_none(body.get("max_output")),
    )
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
        # The stored provider wins. A caller that names a config is
        # asking about THAT config, so its provider is a fact rather
        # than a suggestion — and the caller's copy can be stale. The
        # UI read it from form state one render too early and sent
        # "anthropic" for a Google config on every edit, which queried
        # Anthropic with a Google key and reported "Invalid API key"
        # about a key that was fine.
        provider = (stored.provider or provider or "").lower()
        if not api_key:
            api_key = _stored_key(stored.api_key_encrypted) or ""
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

    # Provider-specific settings the operator saved — Anthropic's
    # workspace id lives here, and an org-level key is refused on every
    # request without it.
    extra_cfg = (body.provider_config or {}) if getattr(body, "provider_config", None) else {}
    if body.model_config_id and stored is not None:
        extra_cfg = {**(stored.provider_config or {}), **extra_cfg}

    try:
        if provider in ("anthropic", "claude"):
            return await _discover_anthropic(api_key, workspace_id=extra_cfg.get("workspace_id"))
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


def _plain_description(text: str) -> str:
    """Provider prose, with its markup taken out.

    Discovery used to store "Owned by openrouter" and nobody noticed
    what the real field held. Passing the provider's own description
    through put "[Kimi K3](https://openrouter.ai/moonshotai/kimi-k3)"
    on seventeen model cards, where the link cannot be clicked and the
    brackets read as a typo.

    The URL goes rather than the link text: the words are what tell a
    reader what the model is, and a URL full of vendor and product
    names is also noise to the suitability classifier, which reads this
    same string.
    """
    if not text:
        return ""
    # [label](url) -> label
    out = re.sub(r"\[([^\]]*)\]\((?:[^)]*)\)", r"\1", text)
    # Bare URLs, and the backticks around inline code.
    out = re.sub(r"https?://\S+", "", out)
    out = out.replace("`", "")
    return re.sub(r"\s+", " ", out).strip()


def _apply_suitability(model: "DiscoveredModel", **meta) -> "DiscoveredModel":
    """Attach a suitability verdict without ever dropping the row.

    Discovery returns everything the provider listed. What the customer
    sees by default is a UI decision, which keeps a wrong guess
    recoverable — the point of separating these at all.
    """
    from services.ai_triage.model_suitability import classify
    s = classify(**meta)
    model.suitability = s.tier
    model.suitability_reason = s.reason
    model.suitability_may_exclude = s.may_exclude
    model.declared_config = s.declared_config
    return model


async def _discover_anthropic(api_key: str, workspace_id: str | None = None) -> DiscoverModelsResponse:
    import httpx

    # An organisation-level key must name a workspace on every request.
    # The provider already sent this header; discovery did not, so a
    # perfectly good org key failed here while triage would have worked.
    headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
    if workspace_id:
        headers["anthropic-workspace-id"] = workspace_id

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get("https://api.anthropic.com/v1/models", headers=headers)

        if r.status_code == 401:
            return DiscoverModelsResponse(status="error", message="Invalid API key", provider="anthropic")
        if r.status_code == 403:
            return DiscoverModelsResponse(status="error", message="API key does not have permission to list models", provider="anthropic")
        if r.status_code == 400 and "workspace" in r.text.lower():
            # Say what to do. The provider's own message is accurate but
            # does not mention where the id goes in Vooda.
            return DiscoverModelsResponse(
                status="error",
                message=("This is an organisation-level key, so Anthropic needs a workspace id "
                         "on every request. Add {\"workspace_id\": \"wrkspc_...\"} under "
                         "Provider Config in Advanced Settings, or use a workspace-scoped key."),
                provider="anthropic",
            )

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

        # No hardcoded model list here any more.
        #
        # This used to answer any other status with "API key validated.
        # Showing known models" and four Claude ids written into the
        # source. Measured against a real org-level key it reported
        # success on a 400, offered four models, and every one of them
        # would have failed at triage — the provider had refused the
        # request outright. A list of one vendor's model names also
        # goes stale on their next release.
        #
        # The screen already handles not being able to list: it offers
        # a Model ID field and says so. An honest error reaches that
        # path; a fabricated success does not.
        return DiscoverModelsResponse(
            status="error",
            message=f"Could not list models (provider returned {r.status_code}).",
            provider="anthropic",
        )


async def _discover_openai(api_key: str, base_url: str | None = None) -> DiscoverModelsResponse:
    import httpx

    # Same rule the completion path uses. An operator pastes the base
    # URL their provider documents, which includes /v1, and appending
    # another one 404s on a perfectly correct endpoint.
    from services.ai_triage.provider import openai_compatible_root
    url = openai_compatible_root(base_url) + "/v1/models"
    headers = {"Authorization": f"Bearer {api_key}"}

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(url, headers=headers)

        if r.status_code == 401:
            return DiscoverModelsResponse(status="error", message="Invalid API key", provider="openai")
        if r.status_code != 200:
            return DiscoverModelsResponse(status="error", message=f"API returned {r.status_code}", provider="openai")

        data = r.json()
        models = []
        # This list mixes embeddings, TTS and moderation in with the
        # chat models, so it needs sorting out — but not by an allowlist
        # of name prefixes. That was ("gpt-4", "gpt-3.5", "o1", "o3",
        # "chatgpt"), and its own comment recorded the failure: an
        # OpenAI-COMPATIBLE endpoint serves ids like "qwen/qwen3-27b",
        # none of which start with gpt-*, so the filter returned an
        # EMPTY list for every one of them and the user typed the model
        # id by hand. A new OpenAI family would have broken it the same
        # way.
        #
        # The classifier reads whatever the endpoint offers instead.
        # Where that is only an id, the id is read as text — so "tts-1"
        # groups on "tts" — and grouping never hides a row.
        for m in data.get("data", []):
            mid = m.get("id", "")
            if not mid:
                continue
            # OpenRouter reports the real window as `context_length`, and
            # the output cap under `top_provider`. Taking them here is
            # what makes the budget correct without asking the user to
            # look anything up.
            top = m.get("top_provider") or {}
            arch = m.get("architecture") or {}
            models.append(_apply_suitability(DiscoveredModel(
                model_id=mid,
                name=m.get("name") or mid,
                description=(
                    m.get("description")
                    or f"Owned by {m.get('owned_by', 'provider')}"
                )[:200],
                context_window=_int_or_none(
                    m.get("context_length") or m.get("context_window")
                ),
                max_output=_int_or_none(
                    top.get("max_completion_tokens") or m.get("max_output_tokens")
                ),
            ),
                identifier=mid,
                # OpenRouter states both; plain OpenAI states neither,
                # and the classifier simply has less to go on.
                output_modalities=arch.get("output_modalities"),
                supported_parameters=m.get("supported_parameters"),
                description=m.get("description", ""),
                display_name=m.get("name", ""),
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

    base = "https://generativelanguage.googleapis.com/v1beta/models"

    async with httpx.AsyncClient(timeout=15) as client:
        # Follow the pages. This endpoint returns 50 per page and hands
        # back a nextPageToken; asking for one page and ignoring the
        # token silently truncated the catalogue at 50 of 61. Which 11
        # vanished was decided by the provider's ordering, so as new
        # models ship, real triage candidates fall off the end and the
        # user never learns the list was cut short.
        all_raw: list[dict] = []
        token = None
        for _ in range(20):  # bounded: a token loop must not hang discovery
            url = f"{base}?key={api_key}&pageSize=200" + (f"&pageToken={token}" if token else "")
            r = await client.get(url)

            if r.status_code == 400 or r.status_code == 403:
                return DiscoverModelsResponse(status="error", message="Invalid API key", provider="google")
            if r.status_code != 200:
                return DiscoverModelsResponse(status="error", message=f"API returned {r.status_code}", provider="google")

            data = r.json()
            all_raw.extend(data.get("models", []))
            token = data.get("nextPageToken")
            if not token:
                break

        models = []
        for m in all_raw:
            name = m.get("name", "").replace("models/", "")
            # Exact membership, not `"generateContent" in str(list)`.
            # That substring test passes for bidiGenerateContent and
            # batchGenerateContent too — it only ever worked because of
            # how those happen to be capitalised.
            models.append(_apply_suitability(
                DiscoveredModel(
                    model_id=name,
                    name=m.get("displayName", name),
                    description=m.get("description", "")[:100],
                    context_window=m.get("inputTokenLimit"),
                    max_output=m.get("outputTokenLimit"),
                ),
                identifier=name,
                methods=m.get("supportedGenerationMethods"),
                required_method="generateContent",
                description=m.get("description", ""),
                display_name=m.get("displayName", ""),
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

    from services.ai_triage.provider import openai_compatible_root

    base = endpoint_url.rstrip("/")
    # The same rule the completion path uses. An operator pastes the
    # base URL their provider documents, which ends in /v1, and asking
    # for "{base}/v1/models" made that ".../v1/v1/models" — a 404 on a
    # URL copied from the provider's own page. This fell through to the
    # bare "/models" attempt below, which answered, so discovery looked
    # like it worked while quietly taking a lesser path.
    root = openai_compatible_root(base)
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
                    models.append(_apply_suitability(DiscoveredModel(
                        model_id=name,
                        name=name.split(":")[0] if ":" in name else name,
                        description=f"Size: {m.get('size', 0) / 1e9:.1f}GB" if m.get("size") else "",
                        # parameter_size is "3.8B" — the PARAMETER COUNT,
                        # not the context window. Feeding it to an int
                        # field raised ValidationError for every model
                        # Ollama reported, so discovery returned an error
                        # instead of a list.
                        parameter_size=(m.get("details", {}) or {}).get("parameter_size"),
                        context_window=_int_or_none(
                            (m.get("details", {}) or {}).get("context_length")
                        ),
                    ), identifier=name,
                        # Ollama names the architecture, which is the
                        # only structural signal a self-hosted catalogue
                        # offers — an encoder cannot answer a prompt,
                        # whatever the model is called.
                        architecture_families=(
                            (m.get("details", {}) or {}).get("families")
                            or [(m.get("details", {}) or {}).get("family")]
                        ),
                        description=name))
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
            r = await client.get(f"{root}/v1/models", headers=headers)
            if r.status_code == 200:
                data = r.json()
                models = []
                for m in data.get("data", []):
                    mid = m.get("id", "")
                    arch = m.get("architecture") or {}
                    top = m.get("top_provider") or {}
                    models.append(_apply_suitability(DiscoveredModel(
                        model_id=mid,
                        name=m.get("name") or mid,
                        description=(_plain_description(m.get("description"))
                                     or f"Owned by {m.get('owned_by', 'local')}"),
                        context_window=_int_or_none(m.get("context_length")),
                        max_output=_int_or_none(top.get("max_completion_tokens")),
                    ), identifier=mid,
                        description=_plain_description(m.get("description", "")),
                        display_name=m.get("name", "") or "",
                        # What the provider DECLARED, which outranks
                        # anything read out of prose. A model that takes
                        # images and answers in text is a triage model;
                        # judged on its description alone it reads as an
                        # image model and gets struck off.
                        output_modalities=arch.get("output_modalities"),
                        supported_parameters=m.get("supported_parameters"),
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
                    # Classified, like every other discovery path. This
                    # one built its rows bare, so whatever reached it
                    # was returned as a candidate whatever it was — an
                    # embedding endpoint, a reranker, an asynchronous
                    # batch variant that cannot answer a request at all.
                    # A fallback that silently drops the filter is worse
                    # than a fallback that fails.
                    models = [_apply_suitability(
                        DiscoveredModel(
                            model_id=m.get("id", m.get("name", str(i))),
                            name=m.get("id", m.get("name", f"model-{i}")),
                            description=_plain_description(m.get("description", "")),
                            context_window=_int_or_none(m.get("context_length")),
                        ),
                        identifier=m.get("id", m.get("name", "")),
                        description=_plain_description(m.get("description", "")),
                        display_name=m.get("name", "") or "",
                        # Same declared signals as the versioned route.
                        # Reading them on one route and not the other is
                        # how a model ends up usable or struck off
                        # depending on which URL a server happens to
                        # answer on.
                        output_modalities=(m.get("architecture") or {}).get("output_modalities"),
                        supported_parameters=m.get("supported_parameters"),
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

    # Only the task keyword the worker actually dispatches on.
    # `code_analysis` / `summarization` were placeholder strings that no
    # code path calls — returning them here encouraged admins to configure
    # routing that didn't take effect.
    tasks = ["triage"]
    routing = {}
    for task in tasks:
        assigned = [
            {"id": str(m.id), "name": m.name, "provider": m.provider, "model_id": m.model_id}
            for m in models if task in (m.tasks or [])
        ]
        routing[task] = assigned

    return routing


# Engine settings moved before /{model_id} routes to avoid route conflict
