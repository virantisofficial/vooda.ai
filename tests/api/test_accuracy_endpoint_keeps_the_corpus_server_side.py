"""The sample secrets must not leave the server.

They are the answer key. Anything that travels to the browser can be
read by the customer, cached, or scraped — and a corpus a model has
seen is one it can recognise rather than judge. Only case ids and
outcomes are returned, which is all the breakdown needs.
"""
import inspect

from apps.api.app.routers import ai_models as R
from services.ai_triage.accuracy_corpus import load_cases


def test_only_ids_and_outcomes_are_persisted():
    src = inspect.getsource(R.check_model_accuracy)
    stored = src[src.index("row.accuracy_detail"):src.index("row.accuracy_checked_at")]
    for field in ("snippet", "file_path", "line", "rule_id"):
        assert field not in stored, f"{field} would put corpus material in the row"
    for field in ("case_id", "expected", "answered", "correct", "missed_secret"):
        assert field in stored, f"{field} is needed for the breakdown"


def test_the_response_model_carries_no_snippet_field():
    assert "snippet" not in R.AccuracyVerdict.model_fields


def test_one_model_at_a_time():
    """Twenty requests per model. Accepting a list would invite running
    it across a provider's whole catalogue — hours, for models nobody
    is going to configure."""
    fields = R.AccuracyRequest.model_fields
    assert "model_id" in fields
    assert "model_ids" not in fields


def test_the_corpus_has_something_to_measure():
    cases = load_cases()
    assert len(cases) >= 10
    assert all(c.snippet.strip() for c in cases)
