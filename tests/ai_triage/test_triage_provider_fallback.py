# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Triage runs on the tenant's single AI model.

Vooda has exactly one AI model per tenant — no primary, no task routing.
Triage uses the tenant's active model and falls back to the env-var model
when none is configured. AI code-fix (auto-remediation) was removed, so
nothing routes on a "remediation" task any more.
"""
import inspect

from services.ai_triage import provider as prov
from apps.api.app.models.ai_model import AIModelConfig
from apps.api.app.routers import ai_models


def test_triage_uses_the_tenants_active_model():
    src = inspect.getsource(prov.get_provider_for_task)
    assert "AIModelConfig.is_active == True" in src
    assert "is_primary" not in src


def test_triage_falls_back_to_the_env_model():
    src = inspect.getsource(prov.get_provider_for_task)
    assert "settings.ANTHROPIC_API_KEY" in src
    assert "settings.OPENAI_API_KEY" in src


def test_one_model_per_tenant():
    constraints = {c.name for c in AIModelConfig.__table__.constraints}
    assert "uq_ai_model_configs_tenant_id" in constraints
    assert not hasattr(AIModelConfig, "is_primary")
    assert "status_code=409" in inspect.getsource(ai_models.create_model)


def test_no_remediation_task_routing():
    assert '"remediation"' not in inspect.getsource(prov.get_provider_for_task)
    assert '"remediation"' not in inspect.getsource(ai_models.ai_status)
    assert '"remediation"' not in inspect.getsource(ai_models)
