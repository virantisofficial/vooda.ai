"""Tier 1b — pure value-shape non-secrets in the UNIVERSAL filter.

Unlike the CONFIG-ASSIGN context filters, these apply to every rule, so the
critical property is that they must NOT suppress any specific rule's own secret.
The decisive recall guard: a real JWT (`eyJ.eyJ.sig`) has a dotted shape but is
NOT a SCREAMING_SNAKE constant or a placeholder, so it must still fire.
"""
from __future__ import annotations

import base64
import json

import pytest

from services.secret_scan.engine import SecretScanner, _value_is_nonsecret_universal


# ── Unit: the shape predicate ──
@pytest.mark.parametrize("value", [
    "GRANT_TYPE_REFRESH_TOKEN", "CONTENT_TYPE_JSON", "DEFAULT_CACHE_TTL_SECONDS",  # SCREAMING_SNAKE
    "MYAWSACCESSKEYGOESHERE", "your_api_key", "your-secret-token", "<your-token>",  # placeholders
])
def test_nonsecret_shapes_are_filtered(value):
    assert _value_is_nonsecret_universal(value) is True, f"shape not recognized as non-secret: {value}"


@pytest.mark.parametrize("value", [
    "aB3dEf9hIjKlMnOpQrStUvWx",            # mixed-case random secret
    "AKIAIOSFODNN7EXAMPLE",                # all-caps but NO underscore (AWS shape)
    "wJax2FbN7pQ9rLm4kT6yH8vC1dG3sE5u",   # secret-access-key shape
    "ghp_aB3dEf9hIjKlMnOpQrStUvWx012345",  # provider token
])
def test_real_secret_shapes_not_filtered(value):
    assert _value_is_nonsecret_universal(value) is False, (
        f"RECALL REGRESSION: real-secret shape wrongly filtered: {value}"
    )


# ── E2E recall guard: a real JWT must still fire (the trap we avoided) ──
def _mk_jwt(payload):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64(payload)}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def test_real_jwt_still_fires(scanner):
    jwt = _mk_jwt({"sub": "u_9f2a7b3c4d", "role": "admin", "iat": 1700000000})
    fs = scanner.scan_file("src/auth.py", f'token = "{jwt}"\n')
    assert any((f.rule_id or "") == "VOODA-SEC-JWT-001" for f in fs), (
        "RECALL REGRESSION: a real JWT was suppressed by the universal value-shape filter"
    )


def test_provider_token_still_fires(scanner):
    # AWS access key id (AKIA + 16) — a clean provider shape, all-caps but no
    # underscore, so it must NOT be caught by the SCREAMING_SNAKE filter.
    fs = scanner.scan_file("src/cfg.py", 'aws = "AKIAQWERTYUIOPASDFGH"\n')
    assert len(fs) > 0, "RECALL REGRESSION: a provider token was suppressed"


# ── FP dropped across rule types (not just CONFIG-ASSIGN) ──
@pytest.mark.parametrize("content", [
    'api_key = "GRANT_TYPE_REFRESH_TOKEN"',
    'password = "MYPASSWORDGOESHERE"',
    'secret = "<your-client-secret>"',
])
def test_shape_nonsecrets_dropped_everywhere(scanner, content):
    assert len(scanner.scan_file("src/app.py", content)) == 0, (
        f"a value-shape non-secret still produced a finding: {content!r}"
    )
