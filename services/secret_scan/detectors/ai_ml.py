# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""AI/ML platform detectors (OpenAI, Anthropic, Cohere, Replicate, HuggingFace, etc.)."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-OPENAI-001", title="OpenAI API Key", secret_type="openai_api_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?:[^A-Za-z0-9]|$)',
        keywords=["sk-", "T3BlbkFJ"], confidence=0.95, description="OpenAI API key.", fix_hint="Rotate at platform.openai.com → API keys."),
    SecretRule(rule_id="VOODA-SEC-OPENAI-002", title="OpenAI Project API Key", secret_type="openai_project_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(sk-proj-[A-Za-z0-9\-_]{40,})(?:[^A-Za-z0-9]|$)',
        keywords=["sk-proj-"], confidence=0.95, description="OpenAI project-scoped API key.", fix_hint="Rotate at platform.openai.com → API keys."),
    SecretRule(rule_id="VOODA-SEC-ANTHROPIC-001", title="Anthropic API Key", secret_type="anthropic_api_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(sk-ant-[A-Za-z0-9\-_]{40,})(?:[^A-Za-z0-9]|$)',
        keywords=["sk-ant-"], confidence=0.98, description="Anthropic Claude API key.", fix_hint="Regenerate at console.anthropic.com → API keys."),
    SecretRule(rule_id="VOODA-SEC-COHERE-001", title="Cohere API Key", secret_type="cohere_api_key", severity="high",
        pattern=r'(?:cohere[_-]?api[_-]?key|COHERE_API_KEY|CO_API_KEY)\s*[=:]\s*["\']?([A-Za-z0-9]{40})["\']?',
        keywords=["cohere", "COHERE", "CO_API_KEY"], confidence=0.80, description="Cohere API key.", fix_hint="Regenerate at dashboard.cohere.ai."),
    SecretRule(rule_id="VOODA-SEC-REPLICATE-001", title="Replicate API Token", secret_type="replicate_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(r8_[A-Za-z0-9]{36,})(?:[^A-Za-z0-9]|$)',
        keywords=["r8_"], confidence=0.95, description="Replicate ML platform API token.", fix_hint="Regenerate at replicate.com → Account → API tokens."),
    SecretRule(rule_id="VOODA-SEC-HF-001", title="HuggingFace Token", secret_type="huggingface_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(hf_[A-Za-z0-9]{34,})(?:[^A-Za-z0-9]|$)',
        keywords=["hf_"], confidence=0.98, description="HuggingFace access token.", fix_hint="Revoke at huggingface.co → Settings → Access Tokens."),
    SecretRule(rule_id="VOODA-SEC-PINECONE-001", title="Pinecone API Key", secret_type="pinecone_api_key", severity="high",
        pattern=r'(?:pinecone[_-]?api[_-]?key|PINECONE_API_KEY)\s*[=:]\s*["\']?([a-f0-9\-]{36})["\']?',
        keywords=["pinecone", "PINECONE"], confidence=0.80, description="Pinecone vector DB API key.", fix_hint="Regenerate at app.pinecone.io → API Keys."),
    SecretRule(rule_id="VOODA-SEC-WEAVIATE-002", title="Weaviate API Key", secret_type="weaviate_api_key", severity="high",
        pattern=r'(?:weaviate[_-]?api[_-]?key|WEAVIATE_API_KEY|WCS_API_KEY)\s*[=:]\s*["\']?([A-Za-z0-9]{30,})["\']?',
        keywords=["weaviate", "WEAVIATE", "WCS_API_KEY"], confidence=0.75, description="Weaviate vector DB API key.", fix_hint="Regenerate at console.weaviate.cloud."),
]
