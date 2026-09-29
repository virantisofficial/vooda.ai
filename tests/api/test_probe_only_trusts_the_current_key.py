"""Evidence about a credential is evidence about THAT credential.

When a provider refuses a probe, what it means depends on whether
anything else answered on the same key. If other models worked, this
model is unavailable to the account — a billing or entitlement fact.
If nothing worked, the key is the problem.

That inference read every stored probe result without asking which key
produced it. So a replaced key inherited the previous one's reputation:
an invalid key that authenticated nothing was reported as working "for
other models", and every refusal was dressed up as a model-availability
problem. The operator is sent to fund a model while the real fault is
the credential they just entered.

The fix records when the key was set and counts only results observed
since. These tests pin the query's shape rather than its results,
because the bug was in what the query failed to ask.
"""
from __future__ import annotations

import ast
import pathlib

_ROUTER = pathlib.Path("apps/api/app/routers/ai_models.py")


def _probe_source() -> str:
    """The probe endpoint's executable body, comments and docstring gone.

    Read as code, not prose: an explanation naming the thing a test
    looks for has counted as the thing itself here before.
    """
    tree = ast.parse(_ROUTER.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == "probe_models":
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)):
                node.body = body[1:]
            return ast.unparse(node)
    raise AssertionError("probe endpoint not found")


def test_prior_results_are_filtered_by_when_the_key_was_set():
    src = _probe_source()
    assert "api_key_set_at" in src, (
        "prior probe results are being trusted without asking which key "
        "produced them")
    assert "AIModelProbeResult.updated_at >= cfg.api_key_set_at" in src


def test_an_inline_key_inherits_no_history():
    """A key typed into the form is not the key the stored results used."""
    src = _probe_source()
    assert "ok_before = False" in src
    assert "if cfg is not None:" in src


def test_replacing_the_key_restamps_the_config():
    tree = ast.parse(_ROUTER.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == "update_model":
            src = ast.unparse(node)
            assert "model.api_key_set_at = datetime.now(timezone.utc)" in src, (
                "a replaced key must reset what counts as current evidence")
            return
    raise AssertionError("update_model not found")


def test_a_new_config_is_stamped_when_it_carries_a_key():
    tree = ast.parse(_ROUTER.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == "create_model":
            src = ast.unparse(node)
            assert "api_key_set_at=" in src
            return
    raise AssertionError("create_model not found")
