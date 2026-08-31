# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Admin request schemas reject unknown fields.

A UI form shipped sending field names the API does not define. Pydantic
ignores extras by default, so the request succeeded and the value was
discarded: the Suppressions form sent `reason`, the model said
`description`, and every justification anyone typed was dropped on the
floor. Nothing errored on either side, which is why it survived.

`extra="forbid"` turns that into a 422 at the first request. It is
applied only where our own UI is the sole client — the CLI posts to
/repositories and /findings, and an older client sending a field a newer
server does not know must keep working. Forward compatibility matters
more there than strictness does.

/imports/scan is the exception in the other direction: CLI-facing and
strict, because there an undeclared field is somewhere a raw secret
value could ride in. That refusal is a redaction control, not form
validation, and it is worth the compatibility cost.
"""
import ast
import pathlib

import pytest
from pydantic import ValidationError

from apps.api.app.routers.access import AccessGrantCreate, BUCreate
from apps.api.app.routers.ai_models import AIModelCreate, AIModelUpdate
from apps.api.app.routers.api_keys import APIKeyCreate, APIKeyUpdate
from apps.api.app.routers.custom_detectors import (
    CustomDetectorCreate, CustomDetectorUpdate,
)
from apps.api.app.routers.roles import RoleCreate, RoleUpdate
from apps.api.app.routers.saved_views import SavedViewCreate
from apps.api.app.routers.suppressions import (
    SuppressionRuleCreate, SuppressionRuleUpdate,
)
from apps.api.app.schemas.strict import StrictModel


STRICT_MODELS = [
    BUCreate, AccessGrantCreate, AIModelCreate, AIModelUpdate,
    APIKeyCreate, APIKeyUpdate, CustomDetectorCreate, CustomDetectorUpdate,
    RoleCreate, RoleUpdate, SavedViewCreate,
    SuppressionRuleCreate, SuppressionRuleUpdate,
]

PERMISSIVE_ROUTERS = ["repositories", "findings"]


def _router_path(name: str) -> pathlib.Path:
    import apps.api.app.routers as pkg
    return pathlib.Path(pkg.__file__).parent / f"{name}.py"


# ── the defect ───────────────────────────────────────────────────────

def test_the_form_payload_that_shipped_broken_is_now_rejected():
    """`type` and `reason` are not fields on this model. They were
    accepted and dropped, and the rule saved with no description."""
    with pytest.raises(ValidationError) as exc:
        SuppressionRuleCreate(name="x", type="manual", reason="known FP")
    bad = {".".join(str(p) for p in d["loc"]) for d in exc.value.errors()}
    assert {"type", "reason"} <= bad


def test_the_corrected_payload_still_works():
    # A criterion is required since rules with none can match nothing.
    m = SuppressionRuleCreate(
        name="x", suppression_type="manual", description="known FP",
        scanner_rule_id="AWS-001",
    )
    assert m.description == "known FP"


# ── the rule, checked by behaviour rather than by grep ───────────────

@pytest.mark.parametrize("model", STRICT_MODELS, ids=lambda m: m.__name__)
def test_admin_models_refuse_unknown_fields(model):
    assert model.model_config.get("extra") == "forbid", (
        f"{model.__name__} accepts unknown fields, so a renamed form "
        f"field is discarded instead of reported"
    )


@pytest.mark.parametrize("model", STRICT_MODELS, ids=lambda m: m.__name__)
def test_strictness_comes_from_the_shared_base(model):
    """One definition, so this cannot be half-applied across routers."""
    assert issubclass(model, StrictModel)


def test_a_local_config_dict_does_not_silently_drop_the_base_config():
    """Three of these models carry their own `model_config` for
    `json_schema_extra`. Pydantic merges parent and child config, so the
    inherited `forbid` survives — this pins that, because a child config
    that replaced the parent's would disable strictness while looking
    entirely correct in review."""
    assert "json_schema_extra" in SuppressionRuleCreate.model_config
    assert SuppressionRuleCreate.model_config["extra"] == "forbid"


# ── the deliberate exceptions ────────────────────────────────────────

@pytest.mark.parametrize("router", PERMISSIVE_ROUTERS)
def test_client_facing_routers_stay_permissive(router):
    """The CLI and CI action post here. Forbidding extras would break an
    older client against a newer server for no safety gain — we do not
    control both sides of that wire."""
    p = _router_path(router)
    if not p.exists():
        pytest.skip(f"{router} router not present")
    src = p.read_text()
    assert "StrictModel" not in src and 'extra="forbid"' not in src, (
        f"{router} is posted to by the CLI; strictness here is a "
        f"compatibility break, not a safety improvement"
    )


def test_the_import_endpoint_stays_strict_for_a_different_reason():
    """Strictness on /imports/scan is a redaction control: an unexpected
    field is somewhere a raw secret could ride in. That outranks the
    forward compatibility the other CLI-facing routers keep."""
    src = _router_path("imports").read_text()
    assert 'extra="forbid"' in src, (
        "the import allowlist schema is how raw secret values are kept "
        "out of the platform; relaxing it opens an undeclared field to "
        "carry one"
    )


# ── the trap that hid the first attempt ──────────────────────────────

def test_no_class_declares_model_config_twice():
    """A second assignment replaces the first outright. That is how an
    `extra="forbid"` added above an existing `json_schema_extra` block
    did nothing at all while looking correct in review."""
    import apps.api.app.routers as pkg
    offenders = []
    for f in pathlib.Path(pkg.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text())):
            if not isinstance(node, ast.ClassDef):
                continue
            n = sum(
                1 for b in node.body
                if isinstance(b, ast.Assign)
                and any(getattr(t, "id", None) == "model_config" for t in b.targets)
            )
            if n > 1:
                offenders.append(f"{f.name}:{node.name}")
    assert not offenders, f"model_config assigned twice — the last wins: {offenders}"
