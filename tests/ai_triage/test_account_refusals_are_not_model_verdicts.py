"""A provider refusing the account says nothing about the model.

Seen live: an OpenRouter account ran out of credit mid-run. Eleven of
twenty cases came back 402 Payment Required, and the Accuracy Check
published "Good — missed no real secrets, flagged some harmless
findings" off the nine that survived. That grade described a billing
state. Worse, the nine were not a sample of anything — whichever calls
happened to land before the refusals.

The same conflation reached the scan path. A 402 was classified as
``upstream_error``, whose notification tells the operator to "switch
the model_id to a different provider/route, or retry once the upstream
recovers". Both are dead ends when the account is refused: every model
fails, and nothing recovers by itself.

So the three surfaces — probe, accuracy check, triage engine — share
one definition of an account-level refusal, and none of them lets it
become a verdict about a model.
"""
from __future__ import annotations

import ast
import pathlib

from services.ai_triage.account_errors import (
    PAYMENT_REQUIRED, RATE_LIMITED, REMEDY, UNAUTHORIZED, refusal_reason,
)
from services.ai_triage.accuracy_check import AccuracyResult

_REAL_402 = ("Client error '402 Payment Required' for url "
             "'https://openrouter.ai/api/v1/chat/completions'")


def test_the_error_seen_live_is_recognised():
    assert refusal_reason(_REAL_402) == PAYMENT_REQUIRED


def test_a_refusal_about_the_model_is_not_about_the_account():
    """A 404 is the provider talking about the model, and must pass through."""
    assert refusal_reason("Client error '404 Not Found'") is None
    assert refusal_reason("model produced no output") is None
    assert refusal_reason("") is None
    assert refusal_reason(None) is None


def test_payment_is_tested_before_permissions():
    """Providers often report no credit with permission-shaped wording.

    Sending someone to check a key that is perfectly valid throws away
    the one useful thing the error said.
    """
    assert refusal_reason("403: insufficient credit on this account") == PAYMENT_REQUIRED


def test_a_refused_run_publishes_no_grade():
    res = AccuracyResult("m", total=20, correct=9, unanswered=11,
                         refused=PAYMENT_REQUIRED)
    assert "Couldn't score" in res.headline
    for word in ("Strong", "Good", "Weak", "missed no real secrets"):
        assert word not in res.headline, res.headline


def test_a_refused_run_names_the_remedy_that_works():
    for reason in (PAYMENT_REQUIRED, UNAUTHORIZED, RATE_LIMITED):
        res = AccuracyResult("m", total=20, correct=9, unanswered=11, refused=reason)
        assert REMEDY[reason] in res.headline
    # Never the advice that cannot help: no model change fixes a
    # refusal that reaches every model.
    funded = AccuracyResult("m", total=20, correct=9, unanswered=11,
                            refused=PAYMENT_REQUIRED).headline
    assert "switch" not in funded.lower()
    assert "different model" not in funded.lower()


def test_a_run_that_mostly_failed_is_not_a_low_score():
    """Even with no refusal, too little coverage is not a grade."""
    thin = AccuracyResult("m", total=20, correct=10, unanswered=8, false_alarms=2)
    assert "Couldn't score reliably" in thin.headline

    # A couple of gaps is still a result about the model.
    ok = AccuracyResult("m", total=20, correct=16, unanswered=2, false_alarms=2)
    assert "Couldn't score" not in ok.headline


def test_the_scan_path_gives_a_refusal_its_own_copy():
    """upstream_error's advice is wrong for a refused account."""
    src = pathlib.Path("apps/worker/tasks.py").read_text()
    tree = ast.parse(src)
    copy = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == "_FAILURE_TYPE_COPY" for t in node.targets):
            copy = ast.literal_eval(node.value)
    assert copy is not None, "_FAILURE_TYPE_COPY not found"

    for key in ("payment_required", "credential_rejected", "rate_limited"):
        assert key in copy, key
        body = copy[key]["body"].lower()
        assert "re-run ai analysis" in body, key

    funded = copy["payment_required"]["body"].lower()
    assert "add credit" in funded
    assert "will not help" in funded, "it must say that changing model cannot fix this"
