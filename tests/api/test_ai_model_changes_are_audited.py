"""Changing the model that triages your secrets must leave a record.

The audit infrastructure already existed — a helper, a table, IP and
user-agent capture — and the AI models router never called it. "Who
changed the model that triages our secrets, and when?" had no answer,
which is a compliance question rather than a nice-to-have in a tool
whose whole job is judging findings.
"""
import inspect
import re

import pytest

from apps.api.app.routers import ai_models as R


def _src(fn) -> str:
    return inspect.getsource(fn)


@pytest.mark.parametrize("fn,action", [
    (R.create_model, "ai_model_created"),
    (R.update_model, "ai_model_updated"),
    (R.delete_model, "ai_model_deleted"),
    (R.update_engine_settings, "ai_engine_settings_updated"),
])
def test_every_state_changing_endpoint_records_one(fn, action):
    src = _src(fn)
    assert "log_audit(" in src, f"{fn.__name__} records nothing"
    assert action in src


@pytest.mark.parametrize("fn", [R.create_model, R.update_model,
                                R.delete_model, R.update_engine_settings])
def test_the_source_ip_is_captured(fn):
    """The helper takes a Request for exactly this, and a handler that
    does not accept one silently logs a NULL address."""
    assert "request" in inspect.signature(fn).parameters, fn.__name__
    assert "request=request" in _src(fn), fn.__name__


def test_the_api_key_is_not_among_the_audited_fields():
    """An audit trail carrying the credential it exists to protect is
    worse than none. "The key was changed" is the fact a reviewer
    needs, not its value."""
    assert "api_key" not in R._AUDITED_FIELDS
    assert "api_key_encrypted" not in R._AUDITED_FIELDS


def test_a_key_replacement_is_still_recorded_as_a_fact():
    src = _src(R.update_model)
    assert "key_replaced" in src and "API key replaced" in src


def test_the_model_change_leads_the_description():
    """It is the question this exists to answer, so it must be
    readable without opening the metadata."""
    before = {"model_id": "old-model", "max_tokens": 1024}
    after = {"model_id": "new-model", "max_tokens": 2048}
    summary, changed = R._describe_changes(before, after)
    assert summary.startswith("Model changed from old-model to new-model")
    assert "max_tokens" in summary
    assert changed["model_id"] == {"from": "old-model", "to": "new-model"}


def test_a_change_that_is_not_the_model_reads_plainly():
    summary, changed = R._describe_changes({"max_tokens": 1024}, {"max_tokens": 2048})
    assert summary == "Updated max_tokens"
    assert set(changed) == {"max_tokens"}


def test_no_change_produces_no_record():
    """Re-saving an unchanged form must not fill the trail with noise
    that hides the changes someone is looking for."""
    summary, changed = R._describe_changes({"model_id": "x"}, {"model_id": "x"})
    assert changed == {}
    assert summary == "No changes"
    assert "if changed or key_replaced:" in _src(R.update_model)


def test_the_delete_is_recorded_before_the_row_is_gone():
    """Afterwards there is nothing left to describe, and which model
    was removed is the whole point."""
    src = _src(R.delete_model)
    assert src.index("log_audit(") < src.index("db.delete(model)")
