"""A model that refuses a field is not a model that cannot work.

Measured against claude-opus-5-5, the first live call this adapter ever
made. It returned 400 twice, for two different reasons:

    `temperature` is deprecated for this model.
    This model does not support assistant message prefill.

Both were fields Vooda had always sent — temperature on every request,
and the prefill that is how this adapter asks for JSON at all. Either
one made the model unusable, and prefill would have broken every
current Claude model.

Dropping what the provider names and asking again costs a request and
keeps working against an API that changes underneath us.
"""
import pytest

from services.ai_triage.provider import rejected_parameter


@pytest.mark.parametrize("body,expected", [
    ('{"error":{"message":"`temperature` is deprecated for this model."}}', "temperature"),
    ('{"error":{"message":"`top_p` is not supported for this model."}}', "top_p"),
    ('{"error":{"message":"stop_sequences is unsupported here"}}', "stop_sequences"),
    ('{"error":{"message":"`max_tokens` is invalid for this endpoint"}}', "max_tokens"),
])
def test_the_refused_parameter_is_identified(body, expected):
    assert rejected_parameter(body) == expected


@pytest.mark.parametrize("body", [
    '{"error":{"message":"credit balance is too low"}}',
    '{"error":{"message":"model not found"}}',
    '{"error":{"message":"overloaded"}}',
    "",
])
def test_an_unrelated_error_names_no_parameter(body):
    """Guessing a field name out of an unrelated 400 would strip
    something the request needs and hide the real problem."""
    assert rejected_parameter(body) is None


def test_the_adapter_keeps_adapting_while_the_provider_keeps_refusing():
    """One retry was not enough. The first fixed `temperature`, the
    second request then failed on prefill, and a single-shot retry
    reported the model unusable when two changes would have worked."""
    import inspect
    from services.ai_triage.provider import ClaudeProvider
    src = inspect.getsource(ClaudeProvider.complete)
    assert "for _ in range(" in src, "adaptation must loop, not fire once"
    assert "if not adapted:" in src, "and must stop when nothing new is named"


def test_dropping_prefill_does_not_drop_the_json_request():
    """Prefill is an optimisation, not the only ask. The prompt still
    requests JSON, and the engine salvages a fenced reply — measured:
    Claude answered with ```json and the verdict parsed."""
    from services.ai_triage.engine import _extract_json_object
    fenced = '```json\n{"classification": "TRUE_POSITIVE", "confidence": 0.6}\n```'
    assert _extract_json_object(fenced) is not None
