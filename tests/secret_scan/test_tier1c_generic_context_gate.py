"""Tier 1c — uniform context/structural gate for GENERIC catch-all rules.

The CONFIG-ASSIGN context filters (value==key, bare-id boolean/env fallback,
attribute ref, url-path/number/bool) are now consolidated into
`_generic_context_is_nonsecret` and applied to EVERY generic rule in the regex
loop, closing the coverage gap (GEN-*/ENTROPY-*/K8S-* used to get only the
value-shape filter). Specific anchored provider/crypto rules are excluded — their
match is a real secret even in these contexts.
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import (
    SecretScanner,
    _is_generic_rule,
    _generic_context_is_nonsecret,
)


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


# ── Unit: generic vs specific classification ──
@pytest.mark.parametrize("rid,expected", [
    ("VOODA-SEC-GEN-003", True), ("VOODA-SEC-CONFIG-ASSIGN", True),
    ("VOODA-SEC-STRUCT-JSON", True), ("VOODA-SEC-ENTROPY-HEX", True),
    ("VOODA-SEC-K8S-001", True), ("VOODA-SEC-GEN-003-WEAK", True),
    ("VOODA-SEC-HELM-001", True),
    ("VOODA-SEC-AWS-001", False), ("VOODA-SEC-GITHUB-001", False),
    ("VOODA-SEC-JWT-001", False), ("VOODA-SEC-CRYPTO-001", False),
    ("VOODA-SEC-STRIPE-001", False),
])
def test_generic_classification(rid, expected):
    assert _is_generic_rule(rid) is expected


# ── Unit: the context filter drops constructs ──
@pytest.mark.parametrize("val,line,key", [
    ("access_token", 'api_key = access_token or os.environ.get("K")', "api_key"),
    ("secret_key", "secret_key = secret_key or getenv()", "secret_key"),
    ("process.env.SECRET", "key = process.env.SECRET", ""),
    ("settings.db_password", "pw = settings.db_password", ""),
    ("/var/run/secrets/db", "db_password = /var/run/secrets/db", ""),
    ("8080", "port = 8080", ""),
    ("true", "tls_enabled = true", ""),
])
def test_context_drops_constructs(val, line, key):
    assert _generic_context_is_nonsecret(val, line, key) is True, f"not dropped: {val!r}"


# ── Unit: the context filter KEEPS real literal secrets ──
@pytest.mark.parametrize("val,line,key", [
    ("RealP4ssw0rdXyz123", 'password = "RealP4ssw0rdXyz123"', "password"),
    ("Rb7kP2mNvR9sLwT3yZ8q", 'api_key: "Rb7kP2mNvR9sLwT3yZ8q"', "api_key"),
])
def test_context_keeps_real(val, line, key):
    assert _generic_context_is_nonsecret(val, line, key) is False, f"wrongly dropped real secret: {val!r}"


# ── E2E: generic rule constructs suppressed end-to-end ──
@pytest.mark.parametrize("content", [
    'api_key = access_token or os.environ.get("KEY")',
    'password = password or getenv("PW")',
    'secret_key = settings.secret_key',
])
def test_generic_context_dropped_e2e(scanner, content):
    findings = scanner.scan_file("src/app.py", content)
    assert len(findings) == 0, f"generic context construct still flagged: {content!r} -> {[f.rule_id for f in findings]}"


# ── E2E recall: a specific rule is NOT affected by the generic gate ──
def test_specific_rule_unaffected(scanner):
    findings = scanner.scan_file("src/cfg.py", 'aws_key = "AKIAQWERTYUIOPASDFGH"')
    assert len(findings) > 0, "RECALL REGRESSION: a specific provider rule was suppressed"


# ── E2E recall: a real generic secret still fires ──
def test_real_generic_secret_fires(scanner):
    findings = scanner.scan_file("src/cfg.py", 'password = "Rb7$kP2mNvR9sLwT3yZ8"')
    assert len(findings) > 0, "RECALL REGRESSION: a real quoted password was suppressed"
