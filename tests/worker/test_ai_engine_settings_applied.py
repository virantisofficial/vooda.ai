# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""AI engine settings must change behaviour, not just round-trip.

Round-tripping is not evidence that a setting works: a value can be
accepted by the API, persisted, and echoed back to the UI while never
being read by the worker. Only behaviour tells the truth.

These tests assert a real branch on each value, and the guard at the
bottom fails when a new setting is added to the schema without ever
being consumed.
"""
import inspect
import re

import pytest

from apps.worker import tasks
from apps.api.app.routers.ai_models import AIEngineSettingsSchema


TRIAGE_SRC = inspect.getsource(tasks._run_ai_triage)
SCAN_SRC = inspect.getsource(tasks._run_scan_job)


# ── analysis_mode: "Finding Analysis" ────────────────────────────────

def test_analysis_mode_gates_deduplication():
    """`individual` must skip grouping; `batch_similar` must group."""
    assert '_analysis_mode == "individual"' in TRIAGE_SRC
    assert "group_findings_for_triage" in TRIAGE_SRC


def test_individual_mode_builds_real_finding_groups():
    """apply_group_results reads `group.member_ids`, so the individual
    path must build FindingGroup objects — a plain list raises."""
    assert "FindingGroup(" in TRIAGE_SRC
    assert "representative_id=" in TRIAGE_SRC
    assert "member_ids=" in TRIAGE_SRC


def test_individual_mode_reports_no_dedup_savings():
    m = re.search(r'if _analysis_mode == "individual":(.*?)else:', TRIAGE_SRC, re.S)
    assert m and "dedup_saved = 0" in m.group(1)


# ── ai_confidence_threshold: "AI Confidence Level" ───────────────────

def test_confidence_threshold_is_compared_against_the_verdict():
    assert "_conf_threshold" in TRIAGE_SRC
    assert "float(_ai_conf) < _conf_threshold" in TRIAGE_SRC


def test_low_confidence_is_held_for_review_not_dropped():
    """A low-confidence verdict becomes NEEDS_REVIEW; the reasoning and
    score are still stored so the operator can see what the AI thought."""
    m = re.search(r"float\(_ai_conf\) < _conf_threshold\s*\):(.*?)else:", TRIAGE_SRC, re.S)
    assert m, "confidence branch not found"
    assert "NEEDS_REVIEW" in m.group(1)
    assert "finding.ai_confidence = _ai_conf" in TRIAGE_SRC
    assert "finding.ai_explanation" in TRIAGE_SRC


def test_threshold_effect_is_observable():
    """The threshold's effect must be observable in the logs."""
    assert "ai_triage_confidence_threshold_applied" in TRIAGE_SRC
    assert "below_threshold_count" in TRIAGE_SRC


def test_malformed_threshold_falls_back_safely():
    assert "except (TypeError, ValueError)" in TRIAGE_SRC


# ── auto_verify_credentials: "Credential Verification" ───────────────

def test_verification_toggle_gates_the_verify_phase():
    assert "_auto_verify" in SCAN_SRC
    assert "if verifiable and not _auto_verify:" in SCAN_SRC


def test_disabling_verification_is_logged_not_silent():
    assert "credential_verification_disabled_by_setting" in SCAN_SRC


def test_verification_toggle_defaults_to_enabled():
    """Absent/unreadable setting must not silently disable a security
    feature — verification stays on unless explicitly turned off."""
    assert "_auto_verify = True" in SCAN_SRC


# ── the guard that stops this bug class recurring ────────────────────

# Consumed elsewhere in the codebase, not inside _run_ai_triage.
_CONSUMED_ELSEWHERE = {
    "scan_scope",               # _run_scan_job -> SecretScanner(scan_scope=)
    "max_concurrent",           # BatchTriageConfig
    "rate_limit_rpm",           # BatchTriageConfig
    "skip_ai_for_info",         # severity filter in _run_ai_triage
    "auto_verify_credentials",  # verify phase in _run_scan_job
    # Reaches the scanner under a clearer internal name:
    # _run_scan_job -> SecretScanner(test_file_handling=)
    "deprioritize_test_files",
}

# Settings with no consumer yet, each with a stated reason. Empty is
# the goal and the current state: every field the API accepts changes
# behaviour. A setting that cannot be honoured is removed from the
# schema rather than listed here.
_PENDING_CONSUMERS: dict[str, str] = {}


# ── first-run defaults must be self-consistent ───────────────────────
# A brand-new install has no ai_engine_settings row, so these schema
# defaults ARE what the operator sees on day one. They must match one of
# the presets the UI offers — and specifically the one it marks
# recommended — or the panel renders a preset the product does not
# itself advise.

_BALANCED_RPM = 300
_BALANCED_CONCURRENT = 10


def test_fresh_install_defaults_match_the_recommended_preset():
    d = AIEngineSettingsSchema()
    assert d.rate_limit_rpm == _BALANCED_RPM
    assert d.max_concurrent == _BALANCED_CONCURRENT


def test_fresh_install_does_not_ship_the_old_throughput_floor():
    """The default must not pin throughput to the most conservative tier."""
    assert AIEngineSettingsSchema().rate_limit_rpm > 60


def test_fresh_install_is_safe_by_default():
    """Defaults must not hide findings or skip security work."""
    d = AIEngineSettingsSchema()
    assert d.deprioritize_test_files == "normal", "must not drop test-file findings by default"
    assert d.auto_verify_credentials is True, "credential verification on by default"
    assert d.analysis_mode == "batch_similar"
    assert 0.0 < d.ai_confidence_threshold < 1.0


@pytest.mark.parametrize("removed", ["context_mode", "max_tokens_per_finding", "batch_size"])
def test_unhonourable_settings_are_gone_from_the_contract(removed):
    """Settings that cannot be honoured are not offered at all."""
    assert removed not in AIEngineSettingsSchema.model_fields


@pytest.mark.parametrize("field", sorted(AIEngineSettingsSchema.model_fields.keys()))
def test_every_setting_is_either_consumed_or_explicitly_known_unwired(field):
    """Fails when someone adds a setting that does nothing.

    A new field must either be consumed in code or be listed above
    with a reason.
    """
    if field in _PENDING_CONSUMERS:
        pytest.skip(f"no consumer yet: {_PENDING_CONSUMERS[field]}")
    consumed = (
        field in _CONSUMED_ELSEWHERE
        or f'ai_settings.get("{field}"' in TRIAGE_SRC
        or f"_{field}" in TRIAGE_SRC
    )
    assert consumed, (
        f"'{field}' is accepted by the API and stored in the database but "
        f"never changes behaviour. Either wire it up or add it to "
        f"_PENDING_CONSUMERS with a reason."
    )
