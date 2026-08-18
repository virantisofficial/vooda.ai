"""A finding must name the provider whose credential it actually is.

Attribution is not cosmetic on a secret scanner. The reported rule
decides which console a responder opens to rotate the thing, which API
the verifier calls to check whether it is still live, and how findings
group in triage. Getting it wrong sends someone to the wrong vendor
holding a credential that is still valid.

Four vendor-branded rules had claimed the bare `client_secret` key —
the OAuth2 field name every provider uses — and outranked the
correctly-anchored rules on severity/confidence:

    mulesoft_client_secret=...  ->  AWS Secret Access Key (critical)
    anypoint_client_id=...      ->  GCP OAuth Client Secret
    alienvault_api_key=...      ->  Generic API Key

The AWS one is the sharpest example: a MuleSoft secret reported as a
critical AWS key would start an AWS incident response over a
credential that was never AWS.

`VOODA-SEC-OAUTH-001` is the rule that *should* own an unattributed
client_secret, and does now.
"""

import pytest

from services.secret_scan.engine import SecretScanner


@pytest.fixture(scope="module")
def scanner() -> SecretScanner:
    return SecretScanner()


def _ids(scanner: SecretScanner, text: str, path: str = "t.py") -> set[str]:
    return {f.rule_id for f in scanner.scan_file(path, text)}


@pytest.mark.parametrize(
    "text,expected",
    [
        # Vendor-anchored keys must win over generic catch-alls.
        (
            'alienvault_api_key = "1234567890abcdef1234567890abcdef'
            '1234567890abcdef1234567890abcdef"',
            "VOODA-SEC-ALIENVAULT-001",
        ),
        (
            'mulesoft_client_secret="aabbccddeeff0011223344556677889900'
            '11223344556677"',
            "VOODA-SEC-ANYPOINT-CLIENT-SECRET-001",
        ),
        (
            'anypoint_client_id = "0011223344556677889900aabbccddee"',
            "VOODA-SEC-ANYPOINT-CLIENT-ID-001",
        ),
        (
            'agora_app_certificate = "0011223344556677889900aabbccddee"',
            "VOODA-SEC-AGORA-001",
        ),
        # Vendor-named variables still reach their own rule.
        (
            'AZURE_CLIENT_SECRET="abc~def.ghi-jkl0123456789012345678901234"',
            "VOODA-SEC-AZ-002",
        ),
        (
            'GOOGLE_CLIENT_SECRET="abcdefghijklmnopqrstuvwx1234"',
            "VOODA-SEC-GCP-003",
        ),
        # Google's own token format, under any variable name.
        (
            'client_secret = "GOCSPX-abcdefghijklmnopqrstuvwxyz12"',
            "VOODA-SEC-GOOGLE-OAUTH-SECRET-001",
        ),
        # An unattributed client_secret belongs to the generic rule,
        # not to whichever vendor rule happens to rank highest.
        (
            'client_secret = "someopaquevalue1234567890abcdef"',
            "VOODA-SEC-OAUTH-001",
        ),
    ],
)
def test_credential_is_attributed_to_the_right_provider(scanner, text, expected):
    ids = _ids(scanner, text)
    assert expected in ids, f"expected {expected}, got {ids or 'nothing'} for {text!r}"


@pytest.mark.parametrize(
    "path,text",
    [
        ("oauth.php", "'client_secret' => 'IqHCweAXZOi8WJlQrhuQulSuGnUO51HFgy7ZShoB'"),
        ("app.yml", "client_secret: someopaquevalue1234567890"),
        ("cfg.py", "client_secret = 'someopaquevalue1234567890'"),
    ],
)
def test_client_secret_is_detected_in_every_assignment_form(scanner, path, text):
    """Narrowing the vendor rules must not lose the value entirely.

    Removing the bare `client_secret` alternative from AWS-002 briefly
    did exactly that: AWS-002 was the only rule handling PHP's `=>`, so
    `'client_secret' => '...'` went from mislabelled to undetected.
    A wrong label is a bad finding; a miss is no finding at all.
    """
    assert _ids(scanner, text, path), f"missed a client_secret in {path}"


#: Rules allowed to fire on an unattributed client_secret. Everything
#: else naming a specific vendor is, by definition, guessing.
_GENERIC_RULE_IDS = {
    "VOODA-SEC-OAUTH-001",
    "VOODA-SEC-GEN-009",
}


@pytest.mark.parametrize(
    "text",
    [
        'client_secret = "someopaquevalue1234567890abcdef"',
        "'client_secret' => 'IqHCweAXZOi8WJlQrhuQulSuGnUO51HFgy7ZShoB'",
        "client_secret: aabbccddeeff00112233445566778899",
        'CLIENT_SECRET="0123456789abcdef0123456789abcdef0123456789"',
    ],
)
def test_no_vendor_rule_claims_an_unattributed_client_secret(scanner, text):
    """Guard the class behaviourally, not by inspecting patterns.

    A structural check on the regex is easy to fool — an alternation
    like `(?:aws_key|client_secret|...)` reads as "anchored" because a
    vendor word appears before the field, while nothing actually
    requires it. Scanning real text asks the question directly: given a
    client_secret with no vendor anywhere near it, does any rule still
    claim a vendor?

    Verified to fail when the AWS alternative is put back.
    """
    fired = {f.rule_id for f in scanner.scan_file("cfg.php", text)}
    assert fired, f"an unattributed client_secret must still be reported: {text!r}"

    vendor_claims = {
        rid for rid in fired
        if rid not in _GENERIC_RULE_IDS and "GEN-" not in rid
    }
    assert not vendor_claims, (
        f"{sorted(vendor_claims)} attributed an unattributed client_secret to a "
        f"specific vendor — that sends a responder to the wrong console"
    )
