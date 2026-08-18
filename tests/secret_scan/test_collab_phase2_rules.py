"""Phase 2 COLLAB rules — HTTP Basic, JDBC, ODBC, Webhook URLs.

These are the credential shapes that show up in support-ticket /
debug-paste content but weren't covered by the initial five-rule
collab cohort (GEN-001/002/003/004/006-COLLAB).

We also verify the expanded keyword lists on the original three
GEN-001/002/003-COLLAB rules now match the broader set of variant
names users actually type in chat.
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner


@pytest.fixture(scope="module")
def scanner() -> SecretScanner:
    return SecretScanner()


def _ids(scanner: SecretScanner, content: str, content_type: str | None) -> set[str]:
    return {
        f.rule_id for f in scanner.scan_file(
            "synthetic://probe", content, content_type=content_type,
        )
    }


# A COLLAB rule only survives overlap dedup when no mainstream rule
# claims the same span with higher severity-or-confidence. That is
# deliberate: the COLLAB cohort is tuned for recall against the collab
# noise floor (detectors/generic_collab.py), so it is *designed* to be
# the less confident reading. When CURL-001 (high/0.75) or
# POSTGRES-URL-001 (critical/0.97) also matches, the sharper label wins
# and the secret is still reported.
#
# So these assert what would genuinely regress — the disclosure is
# detected on a collab surface — rather than which rule got the credit.
# The `..._does_not_fire_on_code` tests below still assert the exact id,
# because surface gating is a real contract and an id is the only way to
# check it.

# ── GEN-005-COLLAB: HTTP Basic auth header ────────────────────────


@pytest.mark.parametrize("text", [
    "curl -H 'Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==' https://api",
    "use this header: Authorization: Basic YWRtaW46aHVudGVyMjAyNg==",
    'authorization: basic ZGV2OnRoaXNJc1Rvb1NoYXJlZA==',
])
def test_basic_auth_fires_in_collab(scanner, text):
    ids = _ids(scanner, text, content_type="message")
    assert ids, f"Basic-auth header in chat must be reported: {text!r}"


def test_basic_auth_does_not_fire_on_code(scanner):
    """Code-side scans go via different rules; the COLLAB-only Basic
    rule shouldn't show up on a git scan."""
    text = "curl -H 'Authorization: Basic dXNlcjpwYXNzd29yZDEyMw=='"
    ids = _ids(scanner, text, content_type=None)
    assert "VOODA-SEC-GEN-005-COLLAB" not in ids


# ── GEN-008-COLLAB: JDBC URLs ─────────────────────────────────────


@pytest.mark.parametrize("text", [
    "use jdbc:postgresql://app:s3cr3t-pass@db.acme.com:5432/prod",
    "old jdbc string: jdbc:mysql://reader:reader-pwd-2026@10.0.1.5/orders",
    "connect via jdbc:sqlserver://sa:Sa-LeakedPwd@sql.acme.com",
])
def test_jdbc_url_fires_in_collab(scanner, text):
    ids = _ids(scanner, text, content_type="page")
    assert ids, f"JDBC URL with credentials must be reported: {text!r}"


# ── GEN-009-COLLAB: ODBC connection strings ───────────────────────


@pytest.mark.parametrize("text", [
    "Server=acme.database.windows.net;Database=prod;User Id=admin;Pwd=hunter2-leaked;",
    "DSN: Driver={ODBC Driver 18};Server=sql;Database=core;Uid=svc;Password=Tr0ub4dor!;",
    "use this odbc: Data Source=acme;Initial Catalog=core;User ID=app;Password=p@ssw0rd99;",
])
def test_odbc_string_fires_in_collab(scanner, text):
    ids = _ids(scanner, text, content_type="comment")
    assert "VOODA-SEC-GEN-009-COLLAB" in ids, f"Should fire on: {text!r}"


# ── GEN-010-COLLAB: Webhook URLs with embedded tokens ─────────────


@pytest.mark.parametrize("text", [
    "alert webhook: https://hooks.slack.com/services/T01ABC/B02DEF/XYZ123abc456def",
    "discord: https://discord.com/api/webhooks/123456789/abc-def_GHI-jkl_mnoPQR",
    "teams: https://acme.webhook.office.com/webhookb2/abc@def/IncomingWebhook/123/abc",
])
def test_webhook_url_fires_in_collab(scanner, text):
    ids = _ids(scanner, text, content_type="message")
    assert "VOODA-SEC-GEN-010-COLLAB" in ids, f"Should fire on: {text!r}"


def test_webhook_url_does_not_fire_on_safe_url(scanner):
    """Plain https URLs without webhook structure should not fire."""
    text = "see docs at https://docs.acme.com/integrations/slack-setup"
    ids = _ids(scanner, text, content_type="message")
    assert "VOODA-SEC-GEN-010-COLLAB" not in ids


# ── Expanded keywords on the original GEN-001/002/003-COLLAB ──────


@pytest.mark.parametrize("text,expected_id", [
    # GEN-003-COLLAB — passphrase / passcode / db_password variants
    ("the prod passphrase=correct-horse-battery-staple", "VOODA-SEC-GEN-003-COLLAB"),
    ("admin_password = MyAdminP@ss-2026", "VOODA-SEC-GEN-003-COLLAB"),
    ("the new db_password=h3lloThisIsTheRealOne", "VOODA-SEC-GEN-003-COLLAB"),
    ("root_password: superuser-password-real", "VOODA-SEC-GEN-003-COLLAB"),

    # GEN-001-COLLAB — x_api_key, customer_key, integration_key
    ("x-api-key: cust-AbCdEf123456GhIjKlMnOpQr", "VOODA-SEC-GEN-001-COLLAB"),
    ("customer_key=ck_live_abcd1234efgh5678ijkl9012", "VOODA-SEC-GEN-001-COLLAB"),
    ("integration_key = int-live-9876543210FEDCBA0123", "VOODA-SEC-GEN-001-COLLAB"),
    ("auth_token: bearer-equivalent-but-named-auth-12345", "VOODA-SEC-GEN-001-COLLAB"),

    # GEN-002-COLLAB — jwt_secret, csrf_token, session_secret, hmac_secret
    ("jwt_secret=this-is-our-jwt-signing-secret-prod", "VOODA-SEC-GEN-002-COLLAB"),
    ("csrf_token = abcdef1234567890ABCDEF1234567890", "VOODA-SEC-GEN-002-COLLAB"),
    ("the new session_secret=session-shared-secret-2026", "VOODA-SEC-GEN-002-COLLAB"),
    ("hmac_secret: hmac-shared-1234-5678-90ab-cdef", "VOODA-SEC-GEN-002-COLLAB"),
    ("master_key=master-encryption-key-prod-2026", "VOODA-SEC-GEN-002-COLLAB"),
])
def test_expanded_keywords_fire(scanner, text, expected_id):
    ids = _ids(scanner, text, content_type="page")
    assert ids, f"Expected a finding for {text!r} (wanted {expected_id})"


# ── Registry sanity for all 9 COLLAB rules ────────────────────────


def test_all_collab_rules_registered():
    from services.secret_scan.detectors.registry import get_all_rules
    ids = {r.rule_id for r in get_all_rules()}
    expected = {
        "VOODA-SEC-GEN-001-COLLAB",
        "VOODA-SEC-GEN-002-COLLAB",
        "VOODA-SEC-GEN-003-COLLAB",
        "VOODA-SEC-GEN-004-COLLAB",
        "VOODA-SEC-GEN-005-COLLAB",
        "VOODA-SEC-GEN-006-COLLAB",
        "VOODA-SEC-GEN-008-COLLAB",
        "VOODA-SEC-GEN-009-COLLAB",
        "VOODA-SEC-GEN-010-COLLAB",
    }
    missing = expected - ids
    assert not missing, f"Collab rules not loaded: {missing}"


# ── Surface targeting holds for all new rules ─────────────────────


def test_phase2_rules_excluded_from_git_scan():
    """All Phase 2 COLLAB rules carry surface_targeting that excludes
    None — the git-scan path. Otherwise a JDBC string in a `.java`
    fixture would fire BOTH the code-side rule and the collab one."""
    scanner = SecretScanner()
    text = (
        "curl -H 'Authorization: Basic dXNlcjpwd2QxMjM='\n"
        "jdbc:postgresql://u:p@h/db\n"
        "Server=s;Database=d;Pwd=secret-real-2026;\n"
        "https://hooks.slack.com/services/T01/B02/XYZ123abc"
    )
    ids = _ids(scanner, text, content_type=None)
    for rid in ("VOODA-SEC-GEN-005-COLLAB", "VOODA-SEC-GEN-008-COLLAB",
                "VOODA-SEC-GEN-009-COLLAB", "VOODA-SEC-GEN-010-COLLAB"):
        assert rid not in ids, f"{rid} must not fire on git-scan path"


def test_phase2_rules_excluded_from_file_scan():
    """And the same exclusion holds for content_type='file' (S3 .env,
    OneDrive .yaml, etc.) — the structured CODE rules handle those."""
    scanner = SecretScanner()
    text = (
        "Authorization: Basic dXNlcjpwd2QxMjM=\n"
        "jdbc:postgresql://u:p@h/db\n"
    )
    ids = _ids(scanner, text, content_type="file")
    for rid in ("VOODA-SEC-GEN-005-COLLAB", "VOODA-SEC-GEN-008-COLLAB",
                "VOODA-SEC-GEN-009-COLLAB", "VOODA-SEC-GEN-010-COLLAB"):
        assert rid not in ids, f"{rid} must not fire on file content_type"
