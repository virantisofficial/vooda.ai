"""Private-key (PEM) block-capture regression guard.

Background — the bug this locks down
------------------------------------
The PEM private-key rules (CRYPTO-001..005, GEN-007, DSAPRIVKEY-001,
ENCPRIVKEY-001) used to match only the *header* line::

    pattern = r'-----BEGIN RSA PRIVATE KEY-----'

So the captured value was just the header. The "PEM header without a
matching END or body" dampener in ``context.adjust_confidence`` then
multiplied confidence by 0.05 (because the captured span had no END
marker and no base64 body), pushing every hit below the 0.10 emission
floor. Result: real, committed private keys were detected by the regex
but **silently dropped** before they ever surfaced — a false negative on
the single most critical secret class a scanner exists to catch.

The fix made every PEM rule a *block-capture*::

    pattern = r'-----BEGIN RSA PRIVATE KEY-----[\\s\\S]*?-----END RSA PRIVATE KEY-----'

so the captured value is the whole BEGIN..END block → the dampener sees a
real END marker + base64 body and leaves the finding alone. The same
change also kills the classic false positive of a bare header *string
constant* (``X = "-----BEGIN PRIVATE KEY-----"``): with no END line there
is simply nothing to match.

These tests assert BOTH halves so the rules can't silently revert to the
header-only form:
  1. every PEM family in realistic multi-line form is detected and KEPT
     (confidence at/above the 0.10 emission floor — i.e. NOT dampened);
  2. a bare header string literal is NOT reported as a private key.
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner

# Every rule that exists to catch a PEM private key. A family counts as
# "detected" if ANY of these fires — overlap/last-wins between, say,
# CRYPTO-001 and the GitHub-App RSA rule GH-005 is expected and fine.
PRIVATE_KEY_RULE_IDS = {
    "VOODA-SEC-CRYPTO-001",   # RSA
    "VOODA-SEC-CRYPTO-002",   # EC
    "VOODA-SEC-CRYPTO-003",   # PGP
    "VOODA-SEC-CRYPTO-004",   # OpenSSH
    "VOODA-SEC-CRYPTO-005",   # PKCS#8
    "VOODA-SEC-GEN-007",      # generic PEM
    "VOODA-SEC-DSAPRIVKEY-001",
    "VOODA-SEC-ENCPRIVKEY-001",
    "VOODA-SEC-GH-005",       # GitHub App key — a more-specific RSA rule
}

# Realistic-looking base64 body lines (64 chars, valid base64 alphabet).
# Two lines so the block clears any minimum-length body requirement.
_B64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDFa0Kq9bN7sQv1"
_B64_2 = "kZ8mT2pYwR4nL6jH0gFdScVbNzXcMqPoIuYtReWqAsDfGhJkLzXcVbNmQwErTyU0"

# The emission floor in context.adjust_confidence. Anything below this is
# effectively dropped, which is exactly what the bug did to these keys.
EMIT_FLOOR = 0.10


def _pem(kind: str) -> str:
    return f"-----BEGIN {kind}-----\n{_B64}\n{_B64_2}\n-----END {kind}-----"


@pytest.fixture(scope="module")
def scanner() -> SecretScanner:
    return SecretScanner()


def _privkey_findings(scanner: SecretScanner, content: str):
    # A non-test, non-doc path so generic test/.md/.txt dampeners don't
    # confound the "is it kept?" assertion. A committed key really does
    # live somewhere like secrets/server.key.
    findings = scanner.scan_file("secrets/server.key", content)
    return [f for f in findings if (f.rule_id or "") in PRIVATE_KEY_RULE_IDS]


@pytest.mark.parametrize("kind", [
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
    "OPENSSH PRIVATE KEY",
    "PRIVATE KEY",              # PKCS#8
    "DSA PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
])
def test_multiline_private_key_is_detected_and_kept(scanner, kind):
    """A realistic multi-line PEM block must surface as a private-key
    finding ABOVE the emission floor (i.e. the PEM dampener did not nuke
    it). This is the exact false-negative the block-capture fix closes."""
    content = f"# deploy key\nKEY = '''\n{_pem(kind)}\n'''\n"
    hits = _privkey_findings(scanner, content)
    assert hits, f"{kind}: no private-key rule fired (dampener regression?)"
    best = max(hits, key=lambda f: f.confidence)
    assert best.confidence >= EMIT_FLOOR, (
        f"{kind}: detected as {best.rule_id} but confidence "
        f"{best.confidence:.3f} < emit floor {EMIT_FLOOR} — the PEM "
        f"dampener is nuking it again (header-only pattern regression)."
    )


def test_bare_header_string_literal_is_not_flagged(scanner):
    """A bare BEGIN header as a string constant (no END line) is naming
    the delimiter, not leaking a key. Block-capture can't match it, so it
    must NOT be reported as a private key — no resurrected false positive."""
    content = 'PEM_HEADER = "-----BEGIN PRIVATE KEY-----"\nfooter = "stuff"\n'
    hits = _privkey_findings(scanner, content)
    assert not hits, (
        f"bare PEM header literal wrongly flagged as a private key: "
        f"{[f.rule_id for f in hits]}"
    )


def test_header_without_end_marker_is_not_flagged(scanner):
    """Defense in depth: a header + body but NO END marker (truncated
    paste / placeholder block) must also stay unmatched under
    block-capture — the END marker is required by the pattern."""
    content = f"x = '''\n-----BEGIN RSA PRIVATE KEY-----\n{_B64}\n'''\n"
    hits = _privkey_findings(scanner, content)
    assert not hits, (
        f"PEM block without END marker wrongly flagged: "
        f"{[f.rule_id for f in hits]}"
    )
