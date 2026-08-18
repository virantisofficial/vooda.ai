"""B1 — extension-agnostic key/token content-promotion (recall net).

The false negative this closes
------------------------------
``_should_scan_file`` is a NAME-only allowlist: a file whose extension is not
in the scan set is dropped by the directory walk BEFORE the rule engine ever
sees its bytes. The 100-repo Opus-vs-Vooda benchmark confirmed real private
keys silently skipped for exactly that reason — they merely carried the
"wrong" extension:

    flux2          ecdsa.private        (.private)
    step-ca        ca.priv              (.priv)
    trivy/checkov  *.txt / *.log        (PEM block in a text / log file)
    zeromq         *.cpp                (PEM block in a C++ string literal)

The fix adds a CONTENT-driven promotion net (``_content_promotes_scan`` +
``CONTENT_PROMOTE_RE``): when the extension gate rejects a file, it is scanned
anyway iff its bytes carry a high-signal marker (PEM/SSH/PGP private-key header
or a canonical provider-token prefix). It is format-driven — generic, no
repo-specific path or name logic — and strictly ADDITIVE: it can only ever
cause MORE files to be scanned, so recall cannot regress.

Why these tests drive the FULL walk
-----------------------------------
The gate that caused the FN lives in ``scan_directory`` / the parallel walk,
NOT in ``scan_file``. A ``scan_file``-only test would pass even with the bug
present (it bypasses the gate). So the end-to-end cases below write real files
to a temp tree and call ``scan_directory``, exercising gate → promotion →
scan_file → emit as one chain. (Empirically verified against the live engine:
a PEM block survives the WS7 test-path dampener on every path — the most-damped
case, ``testdata/fixtures/*.txt``, lands at exactly the 0.10 emit floor — so
promotion is sufficient; no crypto-floor exemption is needed.)
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import (
    SecretScanner,
    _should_scan_file,
    _content_promotes_scan,
)
from services.secret_scan.config import _ALWAYS_SCAN_EXTENSIONS

# Realistic multi-line PEM body (valid base64 alphabet, two lines) — the same
# shape proven by test_private_key_block_capture.py to clear the body-length
# requirement and the PEM dampener.
_B64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDFa0Kq9bN7sQv1"
_B64_2 = "kZ8mT2pYwR4nL6jH0gFdScVbNzXcMqPoIuYtReWqAsDfGhJkLzXcVbNmQwErTyU0"
_PEM = f"-----BEGIN RSA PRIVATE KEY-----\n{_B64}\n{_B64_2}\n-----END RSA PRIVATE KEY-----"

# Canonical AWS access-key id shape (AKIA + 16 [A-Z0-9]). Not a documented
# placeholder, so the AWS rule fires; what matters here is that the *walk*
# reaches it despite the .log extension.
_AKIA = "AKIA" + "QWERTYUIOPASDFGH"

# Rule ids that count as "a private key was caught" (any one firing is enough).
PRIVATE_KEY_RULE_IDS = {
    "VOODA-SEC-CRYPTO-001", "VOODA-SEC-CRYPTO-002", "VOODA-SEC-CRYPTO-003",
    "VOODA-SEC-CRYPTO-004", "VOODA-SEC-CRYPTO-005", "VOODA-SEC-GEN-007",
    "VOODA-SEC-DSAPRIVKEY-001", "VOODA-SEC-ENCPRIVKEY-001", "VOODA-SEC-GH-005",
}


# ── Layer 1: the extension belt (.private / .priv pass the gate directly) ──
def test_private_priv_extensions_in_always_scan():
    for ext in (".private", ".priv"):
        assert ext in _ALWAYS_SCAN_EXTENSIONS, f"{ext} missing from always-scan belt"


@pytest.mark.parametrize("filename,rel_path", [
    ("ecdsa.private", "secrets/ecdsa.private"),     # flux2 FN
    ("ca.priv", "pki/ca.priv"),                     # step-ca FN
])
def test_belt_extensions_pass_the_gate(filename, rel_path):
    assert _should_scan_file(filename, rel_path) is True, (
        f"RECALL REGRESSION: {rel_path} excluded from the walk by the gate"
    )


# ── Layer 2: content promotion rescues gate-rejected extensions ──
@pytest.mark.parametrize("name,body", [
    ("keys.txt", f"leaked key dump:\n{_PEM}\n"),            # trivy/checkov .txt
    ("boot.log", f"2026-06-07 ERROR key=\n{_PEM}\n"),       # checkov .log
    ("embed.cpp", f'static const char* k =\n"{_PEM}";\n'),  # zeromq .cpp
    ("creds.log", f"aws_access_key_id={_AKIA}\n"),           # provider token in .log
    ("weird.xyz", f"{_PEM}\n"),                              # arbitrary unknown ext
])
def test_content_promotes_rejected_extension(tmp_path, name, body):
    # Pre-condition: the gate alone would drop it (proves promotion is doing
    # the work, not a coincidental allowlist hit).
    assert _should_scan_file(name, name) is False, f"{name} unexpectedly allowlisted"
    fp = tmp_path / name
    fp.write_text(body)
    assert _content_promotes_scan(str(fp)) is True, (
        f"{name} carries a key/token marker but was NOT promoted for scanning"
    )


@pytest.mark.parametrize("name,body", [
    ("README.md", "Generate your private key with `openssl genrsa`. No secret here.\n"),
    ("notes.txt", "the password is in the vault, not here\n"),
    ("data.csvx", "id,name,value\n1,foo,bar\n"),
])
def test_content_promotion_does_not_fire_without_a_marker(tmp_path, name, body):
    # Prose mentioning "private key"/"password" must NOT promote — promotion is
    # marker-anchored (-----BEGIN…-----), not keyword-based, so it adds ~0 FP.
    assert _should_scan_file(name, name) is False
    fp = tmp_path / name
    fp.write_text(body)
    assert _content_promotes_scan(str(fp)) is False, f"{name} promoted with no marker"


def test_binary_file_with_marker_bytes_is_not_promoted(tmp_path):
    # A binary blob (null bytes in the screen window) that happens to contain
    # the literal marker must be rejected — a text key can't live in a binary.
    fp = tmp_path / "blob.bin"
    fp.write_bytes(b"\x00\x01\x02" + b"-----BEGIN RSA PRIVATE KEY-----" + b"\x00" * 10)
    assert _content_promotes_scan(str(fp)) is False


def test_empty_file_is_not_promoted(tmp_path):
    fp = tmp_path / "empty.priv2"
    fp.write_text("")
    assert _content_promotes_scan(str(fp)) is False


# ── Layer 3: end-to-end — the full walk recalls every confirmed-FN shape ──
@pytest.fixture(scope="module")
def walked_findings(tmp_path_factory):
    """Build one tree mixing secret-bearing rejected-extension files with
    inert controls, run the real directory walk once, and return the set of
    rel-paths that produced any finding."""
    root = tmp_path_factory.mktemp("b1_walk")
    layout = {
        # MUST be recalled (each hides exactly one secret behind a rejected ext)
        "certs/ecdsa.private": f"# flux2-shape\n{_PEM}\n",
        "pki/ca.priv": f"{_PEM}\n",
        "testdata/keys.txt": f"dumped key:\n{_PEM}\n",
        "logs/boot.log": f"boot key=\n{_PEM}\n",
        "src/embed.cpp": f'const char* k =\n"{_PEM}";\n',
        "scripts/deploy.log": f"export AWS_ACCESS_KEY_ID={_AKIA}\n",
        # Inert controls — no marker, must NOT be promoted/scanned into findings
        "docs/README.md": "How to make a private key: openssl genrsa.\n",
        "data/values.unknownext": "color: blue\nsize: large\n",
    }
    for rel, content in layout.items():
        fp = root / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content)
    findings = SecretScanner().scan_directory(str(root))
    return {f.file_path for f in findings}, {
        f.file_path for f in findings
        if (f.rule_id or "") in PRIVATE_KEY_RULE_IDS
    }


@pytest.mark.parametrize("rel", [
    "certs/ecdsa.private",
    "pki/ca.priv",
    "testdata/keys.txt",
    "logs/boot.log",
    "src/embed.cpp",
])
def test_walk_recalls_private_key_behind_rejected_extension(walked_findings, rel):
    all_paths, key_paths = walked_findings
    assert rel in key_paths, (
        f"RECALL REGRESSION: private key in {rel} not recalled by the walk — "
        f"the extension gate dropped it and promotion failed to rescue it. "
        f"(files with findings: {sorted(all_paths)})"
    )


def test_walk_recalls_provider_token_in_log(walked_findings):
    all_paths, _ = walked_findings
    assert "scripts/deploy.log" in all_paths, (
        "RECALL REGRESSION: AWS token in a .log file not recalled by the walk"
    )


def test_walk_does_not_invent_findings_in_inert_controls(walked_findings):
    # Promotion is marker-anchored: a markdown doc that merely *mentions* keys
    # and an unknown-extension config with no secret must stay unscanned (no
    # finding), so the recall net costs ~0 precision.
    all_paths, _ = walked_findings
    assert "docs/README.md" not in all_paths
    assert "data/values.unknownext" not in all_paths
