# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from sqlalchemy import Column, String, Boolean, Float, Integer, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY

from apps.api.app.core.database import Base
from apps.api.app.models.base import UUIDMixin, TimestampMixin, TenantMixin


class AIModelConfig(Base, UUIDMixin, TimestampMixin, TenantMixin):
    """Registered AI model configuration with task routing."""
    __tablename__ = "ai_model_configs"

    name = Column(String(255), nullable=False)              # Display name
    provider = Column(String(50), nullable=False)           # anthropic, openai, azure_openai, aws_bedrock, google, ollama, custom
    model_id = Column(String(255), nullable=False)          # claude-sonnet-4-20250514, gpt-4o, phi3.5, etc.
    api_key_encrypted = Column(String(1024), nullable=True) # Encrypted API key (never returned to frontend; optional for local models)
    endpoint_url = Column(String(1024), nullable=True)      # Custom endpoint for self-hosted / Azure / Bedrock / Ollama
    tasks = Column(JSONB, default=list)                     # ["triage", "remediation"] — the two task keywords the worker dispatches on. Column is kept flexible so additional task types can be added without a migration if product scope grows.
    is_primary = Column(Boolean, default=False)
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
