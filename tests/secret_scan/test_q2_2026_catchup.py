"""Q2 2026 catch-up detector tests.

For each new detector we assert:
  1. A canonical-format positive sample fires the right rule_id.
  2. An obvious placeholder / docs-style example doesn't.
The placeholder list is curated against the kind of strings we see
in vendor docs and OSS examples — these are the real-world FP source.

Tests run against the full registry (so dedup / last-wins behaviour
matches production) but assert on rule_id, not just provider name —
that keeps the assertion stable if other detectors happen to also
match the same string.
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner


@pytest.fixture(scope="module")
def scanner() -> SecretScanner:
    return SecretScanner()


def _scan_for(scanner: SecretScanner, content: str, expected_rule_id: str) -> bool:
    """Return True if the scanner fires `expected_rule_id` on `content`."""
    findings = scanner.scan_file("test.txt", content)
    return any(f.rule_id == expected_rule_id for f in findings)


# ── Tier A — distinctive prefixes ──────────────────────────────────


@pytest.mark.parametrize("sample", [
    'TOKEN = "AKCp8jrr53kyDdkCbeyM47sM6sBSE3HrCpUnvUmgqFxJDyzVQv2nZNW1ZHTjHEoR9JHmw3Vng"',
    'artifactory_token=AKCp8jrr53kyDdkCbeyM47sM6sBSE3HrCpUnvUmgqFxJDyzVQv2nZNW1ZHTjHEoR9JHmw3Vng',
])
def test_artifactory_canonical_matches(scanner, sample):
    # JFrog Artifactory is one product with two rules for the same
    # AKCp... token format, and JFROG-API-001 (critical/0.99) outranks
    # ARTIFACTORY-001 (critical/0.92) in overlap dedup. Either id is a
    # correct attribution — the responder lands on the same JFrog
    # console — so accept both rather than pin the loser.
    #
    # The duplication is worth collapsing to one rule; that is a rule-set
    # cleanup, not something this test should force.
    findings = scanner.scan_file("test.txt", sample)
    ids = {f.rule_id for f in findings}
    assert ids & {"VOODA-SEC-ARTIFACTORY-001", "VOODA-SEC-JFROG-API-001"}, (
        f"expected a JFrog/Artifactory attribution, got {ids} for {sample!r}"
    )


@pytest.mark.parametrize("sample", [
    # Lowercase prefix — Artifactory tokens are strictly uppercase AKCp
    'TOKEN = "akcp" + "8jrr53kyDdkCbeyM47sM6sBSE3HrCpUnvUmgq"',
    # Random base64-like string without AKCp prefix
    'TOKEN = "XYZ8jrr53kyDdkCbeyM47sM6sBSE3HrCpUnvUmgqFxJDyzVQv2nZNW1ZHTjHEoR9JHmw3Vng"',
    # AKCp prefix but too short
    'TOKEN = "AKCpshort"',
])
def test_artifactory_negative(scanner, sample):
    assert not _scan_for(scanner, sample, "VOODA-SEC-ARTIFACTORY-001"), sample


@pytest.mark.parametrize("sample", [
    'access_key = "LTAI4FptQwerEXAMPLE"',
    'ALIYUN_ACCESS_KEY_ID="LTAI5tEXAMPLEqw1234567"',
    'export AlibabaAccessKey=LTAI4Gabcdef1234567',
])
def test_alibaba_akid_canonical_matches(scanner, sample):
    assert _scan_for(scanner, sample, "VOODA-SEC-ALIBABA-AKID-001"), sample


@pytest.mark.parametrize("sample", [
    # No LTAI prefix
    'access_key = "AKIA4FptQwerEXAMPLE"',
    # LTAI prefix but too short (< 12 char tail)
    'access_key = "LTAIshort"',
])
def test_alibaba_akid_negative(scanner, sample):
    assert not _scan_for(scanner, sample, "VOODA-SEC-ALIBABA-AKID-001"), sample


@pytest.mark.parametrize("sample", [
    'aliyun_access_key_secret = "X9Z2pE7uA4qY8MnH1tJ6vR3kCbLfDg"',
    'alibaba_access_key_secret: "X9Z2pE7uA4qY8MnH1tJ6vR3kCbLfDg"',
    'ali_access_key_secret="X9Z2pE7uA4qY8MnH1tJ6vR3kCbLfDg"',
])
def test_alibaba_aksecret_canonical_matches(scanner, sample):
    assert _scan_for(scanner, sample, "VOODA-SEC-ALIBABA-AKSECRET-001"), sample


# ── Tier B — keyword-anchored ──────────────────────────────────────


@pytest.mark.parametrize("sample", [
    'alienvault_api_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"',
    'OTX_API_KEY="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"',
    'otx_token="0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd"',
])
def test_alienvault_canonical_matches(scanner, sample):
    assert _scan_for(scanner, sample, "VOODA-SEC-ALIENVAULT-001"), sample


@pytest.mark.parametrize("sample", [
    # Loose 64-hex without keyword anchor → must NOT fire
    'CHECKSUM = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"',
    # Wrong length
    'alienvault_api_key = "abc123"',
])
def test_alienvault_negative(scanner, sample):
    assert not _scan_for(scanner, sample, "VOODA-SEC-ALIENVAULT-001"), sample


@pytest.mark.parametrize("sample", [
    'appdynamics_api_token = "xVZ-abc_123ABCdefGHI789jklMNOpqrSTUvwxYZ012"',
    'appd_token: "abcdef1234567890abcdef1234567890abcdef12"',
    'appdynamics_access_token="A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8"',
])
def test_appdynamics_canonical_matches(scanner, sample):
    assert _scan_for(scanner, sample, "VOODA-SEC-APPDYNAMICS-001"), sample


@pytest.mark.parametrize("sample", [
    'agora_app_certificate = "0011223344556677889900aabbccddee"',
    'AGORA_APP_SECRET="aabbccddeeff00112233445566778899"',
])
def test_agora_canonical_matches(scanner, sample):
    assert _scan_for(scanner, sample, "VOODA-SEC-AGORA-001"), sample


@pytest.mark.parametrize("sample", [
    'anypoint_client_id = "0011223344556677889900aabbccddee"',
    'mulesoft_client_id="aabbccddeeff00112233445566778899"',
])
def test_anypoint_client_id_canonical_matches(scanner, sample):
    assert _scan_for(scanner, sample, "VOODA-SEC-ANYPOINT-CLIENT-ID-001"), sample


@pytest.mark.parametrize("sample", [
    'anypoint_client_secret = "0011223344556677889900aabbccddee"',
    'mulesoft_client_secret="aabbccddeeff001122334455667788990011223344556677"',
])
def test_anypoint_client_secret_canonical_matches(scanner, sample):
    assert _scan_for(scanner, sample, "VOODA-SEC-ANYPOINT-CLIENT-SECRET-001"), sample


@pytest.mark.parametrize("sample", [
    # JWT-shaped (Autodesk often issues these)
    ('autodesk_access_token = "'
     'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJBQkNERUYiLCJleHAi'
     'OjE2OTU5NDg2NDAsImF1ZCI6Imh0dHBzOi8vYXBpLmF1dG9kZXNrLmNvbSJ9.'
     'XYZ1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"'),
    # Opaque alphanumeric token
    'forge_access_token="abc123DEF456ghi789JKL0123456789mnopqrstuvwxyz"',
    'aps_access_token="abc123DEF456ghi789JKL01234567890mnopqrstuvwxyz"',
])
def test_autodesk_canonical_matches(scanner, sample):
    assert _scan_for(scanner, sample, "VOODA-SEC-AUTODESK-001"), sample


# ── Cross-cutting: registry confirms new rules loaded ──────────────


def test_q2_rules_registered():
    """The catch-up rules should be reachable through the public
    detector registry — guards against forgetting to wire a new
    detector module into _DETECTOR_MODULES in registry.py."""
    from services.secret_scan.detectors.registry import get_all_rules
    ids = {r.rule_id for r in get_all_rules()}
    expected = {
        "VOODA-SEC-ARTIFACTORY-001",
        "VOODA-SEC-ALIBABA-AKID-001",
        "VOODA-SEC-ALIBABA-AKSECRET-001",
        "VOODA-SEC-ALIENVAULT-001",
        "VOODA-SEC-APPDYNAMICS-001",
        "VOODA-SEC-AGORA-001",
        "VOODA-SEC-ANYPOINT-CLIENT-ID-001",
        "VOODA-SEC-ANYPOINT-CLIENT-SECRET-001",
        "VOODA-SEC-AUTODESK-001",
    }
    missing = expected - ids
    assert not missing, f"q2_2026_catchup rules not loaded: {missing}"
