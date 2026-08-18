r"""R1 — escaped-CRLF (\r\n) single-line PEM private keys must be detected.

A private key serialized as a one-line string literal with escaped CRLF —
``'-----BEGIN RSA PRIVATE KEY-----\r\n…\r\n-----END…'`` — is how OWASP
juice-shop ships its RS256 JWT-signing key in ``lib/insecurity.ts``. The
engine's escaped-newline handling (WS2) normalized ``\n`` but not ``\r\n``, so
the key was mis-categorized as a generic CONFIG-ASSIGN instead of CRYPTO-001 —
a recall miss surfaced by the 20-repo Opus×Vooda benchmark. scan_file now
normalizes escaped ``\r\n`` -> ``\n`` INSIDE PEM private-key blocks so the
existing escaped-``\n`` path detects it (line numbers stay stable; scoped to
BEGIN…PRIVATE KEY…END blocks so nothing else is touched).
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner

# Realistic RSA key body: base64 segment long enough to clear the PEM-body gate.
_SEG = "MIICXAIBAAKBgQDQ7Wb9j8K2mNvX1pL5rT3yU8wZ4aB6cD0eF7gH9iJ1kL2mN3oPqR"
_BODY = _SEG * 4


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def _rule_ids(scanner, content):
    return [f.rule_id for f in scanner.scan_file("lib/insecurity.ts", content)]


def _line(esc: str, key_type: str = "RSA") -> str:
    return (f"const privateKey = '-----BEGIN {key_type} PRIVATE KEY-----"
            f"{esc}{_BODY}{esc}-----END {key_type} PRIVATE KEY-----'\n")


# ── the fix: escaped \r\n is now detected as the correct key type ──
def test_escaped_crlf_rsa_key_detected(scanner):
    rids = _rule_ids(scanner, _line("\\r\\n"))
    assert any("CRYPTO" in r for r in rids), (
        f"RECALL REGRESSION: escaped-\\r\\n RSA private key not detected: {rids}"
    )


def test_escaped_crlf_openssh_key_detected(scanner):
    rids = _rule_ids(scanner, _line("\\r\\n", "OPENSSH"))
    assert any("CRYPTO" in r for r in rids), (
        f"escaped-\\r\\n OPENSSH private key not detected: {rids}"
    )


def test_multi_segment_crlf_key_detected(scanner):
    # Real key shape: many \r\n-separated 64-char lines on one physical source line.
    body = "\\r\\n".join([_SEG] * 6)
    content = ("k = '-----BEGIN RSA PRIVATE KEY-----\\r\\n" + body +
               "\\r\\n-----END RSA PRIVATE KEY-----'\n")
    assert any("CRYPTO" in r for r in _rule_ids(scanner, content))


# ── no regression: the escaped-\n and real-newline paths still detect ──
def test_escaped_lf_key_still_detected(scanner):
    assert any("CRYPTO" in r for r in _rule_ids(scanner, _line("\\n")))


def test_real_newline_key_still_detected(scanner):
    content = ("-----BEGIN RSA PRIVATE KEY-----\n" + _BODY +
               "\n-----END RSA PRIVATE KEY-----\n")
    assert any("CRYPTO" in r for r in _rule_ids(scanner, content))


# ── precision guard: a non-PEM line containing escaped \r\n is untouched ──
def test_non_pem_crlf_value_not_flagged_as_key(scanner):
    rids = _rule_ids(scanner, "message = 'line1\\r\\nline2 some normal text here'\n")
    assert not any("CRYPTO" in r for r in rids), (
        f"escaped-\\r\\n in a non-PEM value spuriously produced a crypto finding: {rids}"
    )
