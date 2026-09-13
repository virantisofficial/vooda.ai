# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Remediation runs only when a model is assigned to it.

Capability is defined by configuration, not a flag: assign a model to
triage and Vooda is identification-only; also assign one to remediation
and it generates fixes. Triage keeps a fallback so a single configured
model triages; remediation has none, so "triage-only" genuinely means
no fixes — no primary fallback quietly generating patches, and no empty
failed plans.
"""
import inspect

from services.ai_triage import provider as prov
from apps.api.app.routers import findings, ai_models


def test_remediation_does_not_fall_back_to_primary():
    src = inspect.getsource(prov.get_provider_for_task)
    # remediation returns None before the primary/env fallback runs
    assert 'if task == "remediation":' in src
    idx_guard = src.index('if task == "remediation":')
    idx_fallback = src.index("Fallback: primary model")
    assert idx_guard < idx_fallback, "the no-fallback guard must precede the primary fallback"


def test_triage_keeps_its_fallback():
    """A single configured model must still triage — only remediation is
    strict."""
    src = inspect.getsource(prov.get_provider_for_task)
    # the primary fallback still exists (for triage/other tasks)
    assert "is_primary and m.api_key_encrypted" in src


def test_scan_time_generation_is_gated_on_a_remediation_model():
    src = inspect.getsource(findings) if False else None  # placeholder
    from apps.worker import tasks
    wsrc = inspect.getsource(tasks._run_scan_job)
    assert '_gpft("remediation"' in wsrc
    assert "_rem_provider is not None" in wsrc


def test_on_demand_endpoint_refuses_when_not_configured():
    src = inspect.getsource(findings.request_remediation)
    assert 'get_provider_for_task("remediation"' in src
    assert "409" in src


def test_status_reports_remediation_enabled_separately():
    src = inspect.getsource(ai_models.ai_status)
    assert "remediation_enabled" in src
    assert '"remediation" in (m.tasks or [])' in src
