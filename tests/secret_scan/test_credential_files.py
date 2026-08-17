"""R3 — classic credential-FILE detectors (recall + precision lock).

The 20-repo Opus×Vooda benchmark (leaky-repo) surfaced textbook credential files
that no rule covered. ``detectors/credential_files.py`` adds key-name /
structure-gated detectors for them. This test locks both recall (the canonical
leak forms fire) and precision (prose, placeholders, env-refs, booleans do NOT).
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner

_NEW = {
    "VOODA-SEC-AWS-CREDS-INI-001",
    "VOODA-SEC-NPMRC-TOKEN-001",
    "VOODA-SEC-NETRC-CREDS-001",
    "VOODA-SEC-WPCONFIG-SECRET-001",
}


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def _ids(scanner, path, content):
    return [f.rule_id for f in scanner.scan_file(path, content)]


# ── recall: the canonical credential-file forms fire ──
@pytest.mark.parametrize("rule_id,path,content", [
    ("VOODA-SEC-AWS-CREDS-INI-001", "cloud/.credentials",
     "[default]\naws_secret_access_key = nAH2VzKrMrRjySLlt8HCdFU3tM2TUuUZgh39NX\n"),
    ("VOODA-SEC-NPMRC-TOKEN-001", ".npmrc",
     "//registry.npmjs.org/:_authToken=26dfe8f1-9b2a-4c3d-8e7f-1a2b3c4d5e6f\n"),
    ("VOODA-SEC-NPMRC-TOKEN-001", ".npmrc", "_auth = YWRtaW46YWRtaW4=\n"),
    ("VOODA-SEC-NETRC-CREDS-001", ".netrc",
     "machine smtp.gmail.com\n  login me@example.com\n  password Sup3rs3cr3tPwd1\n"),
    ("VOODA-SEC-NETRC-CREDS-001", ".netrc",
     "machine api.example.com login user password Tok3nValue99\n"),
    ("VOODA-SEC-NETRC-CREDS-001", ".netrc",
     "machine ftp.example.com\npassword Sup3rs3cr3t99\n"),
    ("VOODA-SEC-WPCONFIG-SECRET-001", "wp-config.php",
     "define( 'DB_PASSWORD', 'admin' );\n"),
    ("VOODA-SEC-WPCONFIG-SECRET-001", "wp-config.php",
     "define('AUTH_KEY','MW1pxM2Fk8Yh3Lq9Zr7Tv2Wn5Bc0Dx');\n"),
])
def test_credential_file_form_detected(scanner, rule_id, path, content):
    assert rule_id in _ids(scanner, path, content), (
        f"RECALL: {rule_id} missed {path!r}: {content!r}"
    )


# ── precision: prose / placeholders / env-refs / booleans do NOT fire ──
@pytest.mark.parametrize("path,content", [
    ("docs.md", "machine foo.example.com is fast and the password manager rocks\n"),
    ("README.md", "the machine learning password reset flow is documented here\n"),
    ("wp-config.php", "define( 'AUTH_KEY', 'put your unique phrase here' );\n"),
    ("main.tf", "aws_secret_access_key = var.secret\n"),
    (".npmrc", "always-auth=true\npackage-lock=false\n"),
    # re-run regression: SCREAMING_SNAKE code constants must NOT match the npm
    # `_auth`/`_password` keys (WebGoat BasicAuthentication.java FP'd x6).
    ("src/main/java/BasicAuthentication.java",
     'private static final String BASIC_AUTH = "Zm9vOmJhcmJheg==";\n'),
    ("config/AppConfig.java", 'String WEBGOAT_PASSWORD = "s3cr3tPassValue";\n'),
])
def test_credential_file_no_false_positive(scanner, path, content):
    fired = set(_ids(scanner, path, content)) & _NEW
    assert not fired, f"FALSE POSITIVE on {path!r}: {fired}"
