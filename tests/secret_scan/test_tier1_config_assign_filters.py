"""Tier 1 — recall-safe value/context filters for CONFIG-ASSIGN.

From the 100-repo FP ground-truth dissection: CONFIG-ASSIGN fired on code
constructs and structural values that aren't literal secrets — variable
self-references, boolean/env fallbacks, attribute refs, SCREAMING_SNAKE
constants, and documentation placeholders. Each filter added here is provably a
non-secret. A real secret assigned to a config key still fires (recall=1.0).
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner

CFG = "VOODA-SEC-CONFIG-ASSIGN"


def _config_fires(scanner, content):
    return any((f.rule_id or "") == CFG for f in scanner.scan_file("src/config.py", content))


def _any_fires(scanner, content):
    return len(scanner.scan_file("src/config.py", content)) > 0


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


# ── TP kept: a real secret assigned to a config key still fires ──
@pytest.mark.parametrize("content", [
    'API_KEY = "aB3dEf9hIjKlMnOpQrStUvWx"',
    'DATABASE_PASSWORD = "Xq9kP2mNvR7sLwT3yB8hZ1c"',
    'AWS_SECRET_KEY = "wJax2FbN7pQ9rLm4kT6yH8vC1dG3sE5u"',
])
def test_real_secret_under_config_key_still_fires(scanner, content):
    # Recall = the secret is DETECTED. CONFIG-ASSIGN may not be the attributing
    # rule (GEN-001/002/003 fire on the same line and win the overlap dedup) —
    # asserting CONFIG-ASSIGN specifically would be brittle to rule overlap.
    assert _any_fires(scanner, content), (
        f"RECALL REGRESSION: real secret under a config key not detected: {content!r}"
    )


# ── FP dropped: non-secret values/contexts ──
@pytest.mark.parametrize("content,why", [
    ('secret_key = secret_key or os.environ.get("KEY")', "(a) value==key self-ref"),
    ('api_token = access_token or os.environ.get("TOK")', "(b) bare-id fallback operand"),
    ('apiKey = cfgKey || process.env.API_KEY', "(b) JS fallback operand"),
    ("apiKey = process.env['API_KEY']", "(c) attribute ref w/ trailing bracket"),
    ('REFRESH_TOKEN = GRANT_TYPE_REFRESH_TOKEN', "(d) SCREAMING_SNAKE constant"),
    ('AWS_SECRET_KEY = MYAWSACCESSKEYGOESHERE', "(e) GOESHERE placeholder"),
    ('API_KEY = your_api_key_value', "(e) your_ placeholder"),
    ('access_key = AKIAIOSFODNN7EXAMPLE', "(e) AWS documented EXAMPLE"),
])
def test_non_secret_config_value_dropped(scanner, content, why):
    assert not _config_fires(scanner, content), (
        f"CONFIG-ASSIGN still fires on a non-secret {why}: {content!r}"
    )
