"""A correct verdict wrapped in chatter is still a correct verdict.

Observed live on gemini-3.5-flash, which answers with
'Here is the JSON requested:' and *then* the fenced block. The fence
strip only fired when the fence was the first thing in the reply, so a
single line of preamble turned a usable triage into a parse failure —
and the model looked broken when it was not.

Vooda connects to whatever model the customer configured, so tolerating
this shape is the difference between a model working and being unusable.
"""
import json

import pytest

from services.ai_triage.engine import TriageEngine, _extract_json_object
from services.ai_triage.provider import AIResponse

VERDICT = {"classification": "TRUE_POSITIVE", "confidence": 0.9, "reasoning": "live key"}


def _parse(content: str) -> dict:
    engine = TriageEngine.__new__(TriageEngine)
    return TriageEngine._parse_response(engine, AIResponse(content=content, model="test"))


@pytest.mark.parametrize(
    "content,label",
    [
        (json.dumps(VERDICT), "bare json"),
        ("```json\n" + json.dumps(VERDICT) + "\n```", "fence first"),
        ("Here is the JSON requested:\n```json\n" + json.dumps(VERDICT) + "\n```", "prose then fence"),
        ("Sure! " + json.dumps(VERDICT) + "\nHope that helps.", "prose both sides"),
    ],
)
def test_verdict_survives_however_the_model_wraps_it(content, label):
    assert _parse(content)["classification"] == "TRUE_POSITIVE", label


def test_salvage_is_recorded_not_hidden():
    """A model needing salvage every time is one to replace — so say so."""
    clean = _parse(json.dumps(VERDICT))
    assert "_salvage" not in clean, "a well-behaved model must not be flagged"

    wrapped = _parse("Here is the JSON:\n```json\n" + json.dumps(VERDICT) + "\n```")
    assert wrapped.get("_salvage") == "wrapped_in_prose"


def test_truncated_json_is_not_salvaged_into_a_verdict():
    """Guessing at a half-written answer would invent a triage decision."""
    assert _extract_json_object('{"classification": "TRUE_POSIT') is None


def test_prose_with_no_json_is_not_salvaged():
    assert _extract_json_object("I cannot help with that request.") is None
