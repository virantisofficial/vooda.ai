"""Tier B — credential-key gate for the generic STRUCT-* rule (recall-safe).

The generic STRUCT rule parses structured config and emits a finding for any
value that survives the value-level inverse-filter — REGARDLESS of the key name.
Value-level ground truth over the 100-repo benchmark (independent of the noisy
AI labels) showed ~3,232 of 3,930 STRUCT-JSON findings sit under NON-credential
keys (Keycloak clientIds, Mongo/OpenTelemetry field names, blockchain
addresses, *public* keys) and contain ~0 real secrets.

The gate: emit generic STRUCT only when the key is credential-ish, OR the value
itself carries a high-signal provider/PEM marker (escape hatch). Recall is held
two ways and pinned here:
  * a real secret under a credential key is kept (TP test + the committed
    test_secrets_in_config_recall.py corpus);
  * a real *format-recognizable* secret under any key is kept by the escape
    hatch AND independently caught by its specific provider/crypto rule.
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner, _struct_key_is_credential


def _struct_fires(scanner, path, content):
    return any("STRUCT-" in (f.rule_id or "") for f in scanner.scan_file(path, content))


def _any_fires(scanner, path, content):
    return len(scanner.scan_file(path, content)) > 0


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


# ── Unit: the credential-key classifier ──
@pytest.mark.parametrize("key", [
    "password", "db_password", "DATABASE_PASSWORD", "passphrase", "db_pwd",
    "secret", "client_secret", "aws_secret_access_key",
    "api_key", "apiKey", "access_key", "private_key", "signing_key",
    "access_token", "auth_token", "api_token", "refresh_token",  # snake_case \b regression guard
    "credential", "connection_string", "sasl_password", "bearer",
])
def test_credential_keys_match(key):
    assert _struct_key_is_credential(key) is True, f"credential key not recognized: {key}"


@pytest.mark.parametrize("key", [
    # the benchmark's structural-noise keys — must NOT be treated as credentials
    "clientId", "client_id", "version", "rabbit_version", "cidrBlock",
    "status_code", "loadBalancerArn", "modificationUuid", "name", "id", "type",
    "consentRequired", "standardFlowEnabled", "authenticationFlowBindingOverrides",
    "protocol", "optionalClientScopes", "ref",
    "key",      # bare "key" is the #1 FP key — must stay non-credential
    "monkey",   # substring trap for "key"
])
def test_structural_keys_do_not_match(key):
    assert _struct_key_is_credential(key) is False, f"structural key wrongly treated as credential: {key}"


# ── E2E: TP kept, structural FP dropped ──
def test_secret_under_credential_key_is_kept(scanner):
    content = '{\n  "database": {\n    "db_password": "Xq9$kP2mNvR7sLwT3yB8hZ1c"\n  }\n}\n'
    assert _struct_fires(scanner, "config/settings.json", content), (
        "RECALL REGRESSION: secret under a credential key dropped by the STRUCT gate"
    )


def test_structural_value_under_noncredential_key_is_dropped(scanner):
    # Keycloak clientId shape — high-entropy-ish identifier under a non-cred key.
    content = '{\n  "clients": [\n    { "clientId": "rabbitmq-proxy-7f3a9b2c1d4e5f6a8b9c0d1e" }\n  ]\n}\n'
    assert not _struct_fires(scanner, "realm-export.json", content), (
        "STRUCT still fires on a structural identifier under a non-credential key"
    )


def test_provider_format_value_under_odd_key_still_detected(scanner):
    # Escape hatch + specific-rule backstop: an AWS key under a non-credential
    # key ("blob") must still be detected (recall), even though the key isn't
    # credential-named.
    content = '{\n  "data": { "blob": "AKIAQWERTYUIOPASDFGH" }\n}\n'
    assert _any_fires(scanner, "dump.json", content), (
        "RECALL REGRESSION: provider-format secret under a non-credential key not detected"
    )


# ── YAML parity (same emission path) ──
def test_yaml_credential_key_kept_noncredential_dropped(scanner):
    # Recall = the secret is DETECTED. Under a credential key the generic gate
    # keeps the STRUCT candidate, but here the GEN-003 credential-assignment
    # regex fires first and dedup-claims the line — either way the secret is not
    # missed. (Asserting STRUCT specifically would be brittle to rule overlap.)
    kept = 'database:\n  password: "Zr4$tY7uI9oP2aS5dF8gH1jK"\n'
    assert _any_fires(scanner, "values.yaml", kept), (
        "RECALL REGRESSION: YAML secret under a credential key not detected by any rule"
    )
    dropped = 'spec:\n  clientId: "argo-cd-server-3f8a9b2c1d4e5f6a7b8c9d0e"\n'
    assert not _struct_fires(scanner, "k8s/manifest.yaml", dropped), (
        "STRUCT-YAML still fires on a structural identifier under a non-credential key"
    )


# ── Recall fix: crypto-key compounds the bare predicate missed must be KEPT ──
# (encryption_key / master_key / session_key / etc. — surfaced by the
# CONFIG-ASSIGN clone ground truth, e.g. authelia `encryption_key: <base64>`.)
@pytest.mark.parametrize("key", [
    "encryption_key", "master_key", "session_key", "hmac_key",
    "enc_key", "cipher_key", "ssh_key", "tls_key", "encryptionKey",
])
def test_crypto_key_compounds_are_credential(key):
    assert _struct_key_is_credential(key) is True, (
        f"RECALL REGRESSION: crypto key '{key}' treated as non-credential → would be gated out"
    )


@pytest.mark.parametrize("key", [
    "foreign_key", "primary_key", "partition_key", "sort_key", "row_key",
])
def test_db_schema_keys_stay_non_credential(key):
    # These are NOT secrets — the widening must not re-admit them.
    assert _struct_key_is_credential(key) is False, (
        f"DB-schema key '{key}' wrongly treated as credential (would re-open FP)"
    )


def test_encryption_key_secret_is_detected(scanner):
    content = 'storage:\n  encryption_key: "aB3dEf9hIjKlMnOpQrStUvWxYz012345"\n'
    assert _any_fires(scanner, "config/authelia.yaml", content), (
        "RECALL REGRESSION: a secret under encryption_key is not detected by any rule"
    )
