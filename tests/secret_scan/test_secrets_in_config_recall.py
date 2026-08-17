"""Phase A — the recall safety net for STRUCT / ENTROPY context-gating (lever 3).

Secrets-in-config (a literal credential under a sensitive key in JSON / YAML /
.env / .properties / TOML / K8s) is the scanner's CORE job, and several of these
are caught *only* by the broad structural rules (STRUCT-JSON, STRUCT-PROPERTIES,
HELM-001, K8S-001) that produce the bulk of the false positives. Before any gate
is added to those rules, this corpus pins that **every real config secret still
fires** — so the precision work (lever 3) is mathematically prevented from
dropping a true positive.

This file is the hard gate: it must be GREEN before and after every STRUCT /
ENTROPY change. A failure here = a recall regression = the change does not ship.

Values are fake but credential-SHAPED on purpose: high-entropy, not placeholders,
not references — i.e. exactly the values the inverse-filter must KEEP.
"""
import base64
import pytest

from services.secret_scan.engine import SecretScanner


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def _ids(scanner, name, content):
    return [h.rule_id for h in (scanner.scan_file(name, content) or [])]


_B64_PW = base64.b64encode(b"Sup3rS3cr3tDBpass99X").decode()

# A literal, credential-shaped value under a sensitive key — MUST be detected.
# label, filename, content
_CONFIG_SECRETS = [
    ("json_password", "config.json", '{"database": {"password": "Sup3rS3cr3tDBpass99X"}}'),
    ("json_api_token", "config.json", '{"api_token": "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV"}'),
    ("json_client_secret", "config.json", '{"oauth": {"client_secret": "Xy7Qm2Wp9Rt4Zb1Nc6Vd3Lf8Hk0Gj5"}}'),
    ("yaml_password", "config.yaml", "database:\n  password: Sup3rS3cr3tDBpass99X"),
    ("yaml_secret_key", "config.yaml", "app:\n  secret_key: aB3dE6gH9jK2mN5pQ8sT1vW4xZ7bC0dF"),
    ("yaml_aws_secret", "config.yaml", "aws_secret_access_key: wJalrXUtnFEMIK7MDENGbPxRfiCYz1234567890ab"),
    ("yaml_conn_str", "config.yaml", "url: postgres://admin:S3cr3tP4ssw0rd@db.host:5432/app"),
    ("yaml_private_key", "config.yaml",
     'tls_key: "-----BEGIN PRIVATE KEY-----\\n'
     'MC4CAQAwBQYDK2VwBCIEIOrZqzixETRBXsZl85d83N5nwb71ctTZ3mwu1TX90vG\\n'
     '-----END PRIVATE KEY-----\\n"'),
    ("env_password", ".env", "DB_PASSWORD=Sup3rS3cr3tDBpass99X"),
    ("env_api_key", ".env", "STRIPE_SECRET_KEY=sk_live_Ab3Def6Hij9Klm2Nop5Qrs8Tuv9Wxy"),
    ("properties_pw", "application.properties", "db.password=Sup3rS3cr3tDBpass99X"),
    ("properties_token", "application.properties", "auth.token=a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV"),
    ("toml_password", "config.toml", '[db]\npassword = "Sup3rS3cr3tDBpass99X"'),
    # K8s Secret whose base64 data decodes to a real credential — MUST fire.
    ("k8s_secret_b64", "secret.yaml", "apiVersion: v1\nkind: Secret\ndata:\n  password: " + _B64_PW),
]


@pytest.mark.parametrize("label,filename,content", _CONFIG_SECRETS, ids=[c[0] for c in _CONFIG_SECRETS])
def test_real_secret_in_config_is_detected(scanner, label, filename, content):
    """HARD GATE: a literal credential under a sensitive key MUST produce a
    finding. If a STRUCT / ENTROPY precision change breaks one of these, it is a
    recall regression and must not ship — fix the gate, not this test."""
    ids = _ids(scanner, filename, content)
    assert ids, (
        f"RECALL REGRESSION: real secret-in-config '{label}' produced NO finding. "
        f"A structural/entropy gate has become too aggressive."
    )


def test_config_secret_corpus_total_recall(scanner):
    """Summary: 100% of the config-secret corpus must be detected."""
    detected = sum(1 for _, fn, ct in _CONFIG_SECRETS if _ids(scanner, fn, ct))
    assert detected == len(_CONFIG_SECRETS), (
        f"config-secret recall {detected}/{len(_CONFIG_SECRETS)} — must be total"
    )


# Lever 3b recall safety net: the GENERIC structural heuristic is skipped on
# auto-generated snapshot files (where it only produces mock-value noise), but
# the SPECIFIC provider/crypto rules MUST still run there — a real key committed
# into a snapshot is still a real leak.
_SNAPSHOT_REAL_SECRETS = [
    ("snap_aws_json", "test_x.snapshot.json", '{"creds": {"key": "AKIAZX9QWMR7KP2DLY4N"}}'),
    ("snap_ghpat", "Component.snap", 'token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"'),
]


@pytest.mark.parametrize("label,filename,content", _SNAPSHOT_REAL_SECRETS,
                         ids=[c[0] for c in _SNAPSHOT_REAL_SECRETS])
def test_specific_rules_still_fire_in_snapshots(scanner, label, filename, content):
    """Snapshot-skip drops only the generic STRUCT heuristic, never the specific
    provider/crypto rules — so a real secret in a snapshot is still caught."""
    assert _ids(scanner, filename, content), (
        f"RECALL REGRESSION: real secret in snapshot '{label}' not caught — "
        f"the snapshot structured-skip must not disable specific rules"
    )
