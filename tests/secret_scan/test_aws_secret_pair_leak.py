"""AWS secret-access-key recall + the snippet-leak it caused.

Live finding (log-upload.php): an AWS SDK credential array exposed the access
key id (caught by AWS-001) but the *secret* access key on the next line —
``'secret' => "<40 b64>"`` — was MISSED, so the snippet redactor never masked it
and it rendered RAW in the Code tab. This locks both halves:

  * recall  — the secret surfaces as its own AWS-005 finding (own line, not
    same-line-deduped against the AKIA id); labelled forms hit AWS-002.
  * leak    — ``redact_with_scanner`` masks the secret in the snippet even when
    detection is bypassed (the context-anchored residual scrub).
  * precision — the bare-``secret`` rule is keyword-gated to AWS files (needs a
    co-located AKIA id), so an unrelated ``secret: "<40>"`` config never fires.
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import (
    SecretScanner, redact_with_scanner, redact_snippet_for_storage,
)

# A 40-char base64 AWS-secret-shaped value (synthetic).
_SECRET = "IqHCweAXZOi8WJlQrhuQulSuGnUO51HFgy7ZShoB"
_AKIA = "AKIAQYXMP3R7VWN2TLIY"

# Canonical AWS SDK credential array (PHP / boto-ish), the exact leak shape.
_SDK_BLOCK = (
    "$s3 = new Aws\\S3\\S3Client([\n"
    "    'credentials' => [\n"
    f"        'key'    => \"{_AKIA}\",\n"
    f"        'secret' => \"{_SECRET}\",\n"
    "    ]\n"
    "]);\n"
)


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def _values(scanner, path, content):
    return {
        (f.raw_data or {}).get("_raw_value_for_verification")
        for f in scanner.scan_file(path, content)
    }


# ── recall: the secret half is detected ──
def test_sdk_array_secret_surfaces(scanner):
    assert _SECRET in _values(scanner, "log-upload.php", _SDK_BLOCK), (
        "AWS secret access key in an SDK credential array must be detected, "
        "not just the AKIA id"
    )


@pytest.mark.parametrize("path,content", [
    ("oauth.php", f"'client_secret' => '{_SECRET}'\n"),       # quoted key + hashrocket
    ("creds.ini", f"'secret_access_key' => '{_SECRET}'\n"),
    ("sdk.js", f"secretAccessKey: '{_SECRET}'\n"),            # camelCase JS SDK
    ("app.yml", f"client_secret: '{_SECRET}'\n"),
])
def test_labelled_secret_forms_detected(scanner, path, content):
    assert _SECRET in _values(scanner, path, content), (
        f"labelled AWS/OAuth secret form missed: {content!r}"
    )


# ── the leak: redactor must mask the secret in the snippet ──
def test_secret_not_left_raw_in_snippet(scanner):
    redacted = redact_with_scanner(_SDK_BLOCK, scanner)
    assert _SECRET not in redacted, "AWS secret access key LEAKED raw in snippet"
    assert _AKIA not in redacted, "AWS access key id leaked raw in snippet"


# ── the leak, harder case: UNQUOTED credentials-INI form, via the real store
# path. The neighbour finding (the AKIA id) used to take the cheap residual-only
# redaction path, which left the co-located unquoted `aws_secret_access_key =
# <40>` on the next line RAW. redact_snippet_for_storage must mask it. ──
_INI_BLOCK = (
    "[default]\n"
    f"aws_access_key_id = {_AKIA}\n"
    f"aws_secret_access_key = {_SECRET}\n"
    "output = json\n"
    "region = us-east-2\n"
)


def test_unquoted_ini_neighbor_secret_not_leaked(scanner):
    # Store the snippet for the AKIA finding (raw = its OWN value, the id).
    stored = redact_snippet_for_storage(
        _INI_BLOCK, raw=_AKIA, masked="AKIA****MPLE", scanner=scanner)
    assert _SECRET not in stored, (
        "unquoted AWS secret access key LEAKED in the neighbour finding's snippet"
    )
    assert _AKIA not in stored, "AWS access key id leaked raw in snippet"


# ── precision: keyword-gated to AWS files; no over-firing ──
@pytest.mark.parametrize("path,content", [
    # bare `secret:` 40-char value but NO AWS access key id in the file
    ("config.yml", "service:\n  secret: \"abcdEFGH1234ijklMNOP5678qrstUVWX90ABcdEF\"\n"),
    # variable reference (no string literal) inside an AWS file
    ("sdk.php", f"'key' => \"{_AKIA}\",\n'secret' => $env_secret,\n"),
    # too-short value
    ("sdk.php", f"'key' => \"{_AKIA}\",\n'secret' => \"short\",\n"),
])
def test_aws005_does_not_overfire(scanner, path, content):
    rids = [f.rule_id for f in scanner.scan_file(path, content)]
    assert "VOODA-SEC-AWS-005" not in rids, f"AWS-005 false positive on {content!r}"
