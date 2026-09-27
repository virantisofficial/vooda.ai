# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, Boolean, Float, Integer, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class AIModelConfig(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """The tenant's AI model configuration — exactly one per tenant."""
    __tablename__ = "ai_model_configs"
    __table_args__ = (UniqueConstraint("tenant_id", name="uq_ai_model_configs_tenant_id"),)

    name = Column(String(255), nullable=False)              # Display name
    provider = Column(String(50), nullable=False)           # anthropic, openai, azure_openai, aws_bedrock, google, ollama, custom
    model_id = Column(String(255), nullable=False)          # claude-sonnet-4-20250514, gpt-4o, phi3.5, etc.
    api_key_encrypted = Column(String(1024), nullable=True) # Encrypted API key (never returned to frontend; optional for local models)
    endpoint_url = Column(String(1024), nullable=True)      # Custom endpoint for self-hosted / Azure / Bedrock / Ollama
    tasks = Column(JSONB, default=list)                     # ["triage"] — the task keyword the worker dispatches on. Column is kept flexible so additional task types can be added without a migration if product scope grows.
    is_active = Column(Boolean, default=True)

    # Model parameters
    max_tokens = Column(Integer, default=4096)
    temperature = Column(Float, default=0.1)
    context_window = Column(Integer, default=4096)          # Model's max context window (for prompt adaptation)
    stop_sequences = Column(JSONB, default=list)            # e.g. ["}\\n", "\\n\\n"] — stops generation at these tokens
    supports_json_mode = Column(Boolean, default=False)     # If True, send response_format={"type":"json_object"}
    system_prompt_override = Column(Text, nullable=True)    # Custom system prompt (overrides default triage.py)
    use_compact_prompt = Column(Boolean, default=False)     # Use simplified prompt template for small models
    prompt_strategy = Column(String(50), default="recommended")  # recommended, strict, sensitive, custom
    model_size_class = Column(String(20), nullable=True)    # small, medium, large — auto-detected or manual

    # Usage tracking
    total_requests = Column(Integer, default=0)
    total_input_tokens = Column(Integer, default=0)
    total_output_tokens = Column(Integer, default=0)
    total_cost_usd = Column(Float, default=0.0)
    last_used_at = Column(String(50), nullable=True)
    last_error = Column(String(500), nullable=True)

    # Provider-specific config (region, deployment name, etc.)
    provider_config = Column(JSONB, default=dict)


class AIModelProbeResult(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """The last time Vooda asked this model to actually triage something.

    Cached so the provider screen can show a badge per model the moment
    it loads. Probing on load was the obvious design and the wrong one:
    it bills the customer for opening a settings page, trips free-tier
    rate limits, and — worst — brands a briefly overloaded model as
    broken and then hides it behind the filter.

    Keyed by (tenant, provider, model_id) rather than by config id,
    because the interesting question is asked about models the customer
    has NOT saved yet.
    """
    __tablename__ = "ai_model_probe_results"
    __table_args__ = (
        UniqueConstraint("tenant_id", "provider", "model_id",
                         name="uq_ai_model_probe_tenant_provider_model"),
    )

    provider = Column(String(50), nullable=False)
    model_id = Column(String(255), nullable=False)

    #: ready | needs_setup | unverified | unusable — see model_probe.py,
    #: which owns this vocabulary.
    state = Column(String(20), nullable=False)
    headline = Column(String(500), nullable=False, default="")
    remedy = Column(String(500), nullable=False, default="")
    #: Applied verbatim by the Fix button.
    suggested_config = Column(JSONB, default=dict)
    #: Token counts and stop reasons — shown only behind "Details".
    detail = Column(JSONB, default=dict)
    latency_ms = Column(Float, default=0.0)
    probed_at = Column(String(50), nullable=True)

    # ── What the provider's own metadata said about this model ──
    #
    # Computed from a discovery response, which is a moment in time: a
    # provider can reword a description or change what it declares, and
    # then nothing records what Vooda actually acted on. Kept so the
    # reason a model was set aside survives the response that produced
    # it, and so a stored verdict can be read without re-listing.
    suitability = Column(String(20), nullable=True)
    suitability_reason = Column(String(200), nullable=True)
    suitability_may_exclude = Column(Boolean, nullable=True)

    # ── Accuracy, when the operator has asked for it ──
    #
    # Lives beside the probe result because it answers the other half
    # of the same question about the same model: the probe says whether
    # it answers, this says how often it is right. Null until someone
    # runs it — an unmeasured model must not read as a scored one.
    accuracy_total = Column(Integer, nullable=True)
    accuracy_correct = Column(Integer, nullable=True)
    #: Real secrets the model called noise. Kept as its own column
    #: because "17 of 20" hides whether the three misses were harmless.
    accuracy_missed_secrets = Column(Integer, nullable=True)
    accuracy_unanswered = Column(Integer, nullable=True)
    accuracy_headline = Column(String(300), nullable=True)
    #: Per-case outcomes, for the breakdown behind Details.
    accuracy_detail = Column(JSONB, nullable=True)
    accuracy_checked_at = Column(String(50), nullable=True)
