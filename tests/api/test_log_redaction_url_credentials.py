"""A credential in a URL must not reach the log file.

The fixture below is invented. It is shaped like the real thing
because the redactor is being asked to handle a shape, but nothing
here is or was a working credential — a regression test does not need
a live key to prove a redactor works, and a repository is the wrong
place to keep one.

Every other rule in the redactor matches a credential by its SHAPE, so
a key in a format nobody anticipated goes straight to disk. Measured:
66 log lines from a single session carried a live Google API key in
clear text into the container's json.log, because Google passes the key
as ?key=... and httpx logs request URLs at INFO. Nothing was
misconfigured — the credential simply had a shape no rule described.

Matching the parameter NAME instead holds for any provider that puts a
secret in a URL, and for key formats that do not exist yet.
"""
import pytest

from packages.common.logging_config import _redact_string, redact_secrets_processor

SECRET = "test-fixture-value-not-a-credential-0000000000000000"


def test_the_exact_line_that_leaked():
    line = (f"HTTP Request: GET https://generativelanguage.googleapis.com"
            f"/v1beta/models?key={SECRET} \"HTTP/1.1 200 OK\"")
    out = _redact_string(line)
    assert SECRET not in out
    assert "<redacted>" in out


@pytest.mark.parametrize("param", [
    "key", "api_key", "api-key", "apikey", "token", "access_token",
    "auth", "password", "secret", "client_secret", "signature", "sig",
    "KEY", "Api_Key",
])
def test_any_credential_parameter_name_is_covered(param):
    assert SECRET not in _redact_string(f"https://x.test/v1?{param}={SECRET}")


def test_the_endpoint_is_still_readable():
    """A log line that no longer says which endpoint was called has
    been made useless, not safe."""
    out = _redact_string(
        f"GET https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite"
        f":generateContent?key={SECRET}")
    assert "generativelanguage.googleapis.com" in out
    assert "gemini-3.5-flash-lite" in out
    assert "generateContent" in out


def test_ordinary_parameters_are_left_alone():
    """Redacting pageSize would hide why a listing was truncated."""
    out = _redact_string("GET https://x.test/v1beta/models?pageSize=200&pageToken=abc123")
    assert "pageSize=200" in out
    assert "pageToken=abc123" in out


def test_a_credential_is_redacted_when_it_is_not_the_last_parameter():
    out = _redact_string(f"https://x.test/v1?key={SECRET}&pageSize=200")
    assert SECRET not in out
    assert "pageSize=200" in out, "the parameter after it must survive"


def test_redaction_runs_on_the_whole_event_not_just_the_message():
    """httpx logs the URL as the event text; our middleware logs paths
    as fields. Both go through the same processor."""
    ev = redact_secrets_processor(None, "info", {
        "event": f"HTTP Request: GET https://x.test/v1?key={SECRET}",
        "path": f"/proxy?access_token={SECRET}",
        "nested": {"url": f"https://y.test?apikey={SECRET}"},
    })
    flat = repr(ev)
    assert SECRET not in flat
    assert flat.count("<redacted>") >= 3
