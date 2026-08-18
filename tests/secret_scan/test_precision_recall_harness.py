"""Generic precision/recall harness — the committed gate for recall-bearing tuning.

Every accuracy fix to the scanner risks one of two regressions:
  * dropping a real secret (recall loss) — the unacceptable one, and
  * surfacing a non-secret (precision loss) — the noise the audit measured.

This harness pins both with SYNTHETIC, repo-agnostic fixtures so a precision
change can never be silently bought with recall (the failure mode that forced
the SEGMENT-rule revert). Fixtures are format-valid fake values — never real
credentials — and deliberately span the universal FP shapes the 61-repo audit
flagged as noise (git SHAs, checksums, UUIDs, base64 assets, doc examples,
CI/IaC references, code literals) plus realistic MULTI-LINE files that exercise
the structural / entropy detectors (lockfiles, checksum manifests, K8s YAML).

Contract:
  * RECALL == 1.0 is a HARD GATE — every TP fixture must produce ≥1 finding.
    A drop here blocks merge, full stop.
  * The FP set must stay empty — no fixture below may produce a finding. As new
    generic FP classes are fixed, add a fixture here so the win can't regress.

Run: ``pytest tests/secret_scan/test_precision_recall_harness.py``
"""
import pytest

from services.secret_scan.engine import SecretScanner


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def _rule_ids(scanner, name, content):
    return [h.rule_id for h in (scanner.scan_file(name, content) or [])]


# ── TP: real-format secrets (fake but FORMAT-VALID values) — must ALL detect ──
# label, filename, content
_TP_CASES = [
    ("aws_key", "config.py", 'AWS_ACCESS_KEY_ID = "AKIAZX9QWMR7KP2DLY4N"'),
    # AWS secret access key: rule needs the key-name connector + exactly 40 b64 chars
    ("aws_secret", "config.py",
     'aws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYz1234567890ab"'),
    ("github_pat", "auth.py", 'token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"'),
    ("gitlab_pat", "ci.yml", 'GL = "glpat-AbCdEf1234567890wxyz"'),
    # slack bare xoxb: last segment must be >=24 chars
    ("slack", "s.py", 'SLACK = "xoxb-2444556677-99001122334-AbCdEfGhIjKlMnOpQrStUvWx"'),
    ("google_api", "g.py", 'k = "AIzaBc3Def6Hij9Klm2Nop5Qrs8Tuv1Wxy4Zab7"'),
    # stripe bare sk_live_: needs >=27 chars after prefix
    ("stripe", "p.py", 'sk = "sk_live_Ab3Def6Hij9Klm2Nop5Qrs8Tuv9Wxy"'),
    ("pem_multiline", "key.txt",
     'k="""\n-----BEGIN RSA PRIVATE KEY-----\n'
     'MIIEpAIBAAKCAQEAabcdef0123456789ABCDEFhijklmnopqrstuvwxyz1234567\n'
     '-----END RSA PRIVATE KEY-----\n"""'),
    ("pem_escaped_newline", "defaults.py",
     '"secret_key": "-----BEGIN PRIVATE KEY-----\\n'
     'MC4CAQAwBQYDK2VwBCIEIOrZqzixETRBXsZl85d83N5nwb71ctTZ3mwu1TX90vG\\n'
     '-----END PRIVATE KEY-----\\n"'),
    ("openssh_key", ".ssh/id",
     "-----BEGIN OPENSSH PRIVATE KEY-----\n"
     "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2g\n"
     "-----END OPENSSH PRIVATE KEY-----"),
    ("generic_apikey", "c.py", 'api_key = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV"'),
    ("conn_string", "db.py",
     'DATABASE_URL = "postgres://admin:S3cr3tP4ssw0rd@db.host:5432/app"'),
]


# ── FP: must NOT detect ────────────────────────────────────────────────────
_FP_CASES = [
    # single-line shapes
    ("git_sha", "CHANGELOG", 'commit a1b2c3d4e5f67890abcdef1234567890abcdef12'),
    ("sha256_hash", "lock",
     '"integrity": "sha512-deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"'),
    ("uuid", "m.py", 'id = "550e8400-e29b-41d4-a716-446655440000"'),
    ("png_base64", "a.js", 'png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"'),
    # canonical published AWS doc example key — never a real credential
    ("aws_example", "ex.sh", 'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'),
    ("placeholder_your", "r.md", 'token = "YOUR_TOKEN_HERE"'),
    ("placeholder_angle", "r.md", 'password = "<your-password>"'),
    ("changeme", "cfg", 'password = "changeme"'),
    # base64 that decodes to the placeholder "example-app-secret" (K8s/Helm shape)
    ("example_b64", "config.yaml", 'secret: ZXhhbXBsZS1hcHAtc2VjcmV0'),
    ("ref_gha", ".github/w.yml", 'token: ${{ secrets.GITHUB_TOKEN }}'),
    ("ref_env", "s.py", 'key = os.environ.get("API_KEY")'),
    ("ref_option", "defaults.py", "password=Option(type='string')"),
    ("ref_credid", "Jenkinsfile",
     "withCredentials([string(credentialsId: 'x', variable: 'TOKEN')])"),
    ("pgp_sig", "f.prov",
     '-----BEGIN PGP SIGNATURE-----\nwsBcBAABCgAQBQJhAAAACRBK7hj4Ov3rIwAAdHEI\n'
     '-----END PGP SIGNATURE-----'),
    ("crypto_asset", "trade.py", 'for token in self.config.tokens:'),
    ("ts_schema", "types.ts", '  readonly secretAccessKey?: string;'),
    ("code_literal", "Challenge.java",
     'content = content.replace("-----BEGIN PRIVATE KEY-----", "")'),
    ("docs_text", "README.md",
     'The private key should begin with -----BEGIN RSA PRIVATE KEY-----'),
    # realistic MULTI-LINE files that exercise the STRUCT / ENTROPY detectors
    ("lockfile_integrity", "package-lock.json",
     '{\n  "dependencies": {\n'
     '    "lodash": {\n      "version": "4.17.21",\n'
     '      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",\n'
     '      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="\n'
     '    }\n  }\n}'),
    ("shasums_hex", "SHA256SUMS",
     'a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f70819 app-linux-amd64\n'
     'f0e1d2c3b4a5968778695a4b3c2d1e0fa9b8c7d6e5f4a3b2 app-darwin-arm64\n'
     '9988776655443322110aabbccddeeff00112233445566778 app-windows.exe\n'
     'deadbeefcafebabe0123456789abcdeffedcba9876543210 checksum.txt'),
    ("yaml_resource_ids", "deployment.yaml",
     'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n'
     '  uid: 7f3b9a12-4c5d-6e7f-8a9b-0c1d2e3f4a5b\nspec:\n  replicas: 3\n'
     '  template:\n    spec:\n      containers:\n      - name: app\n'
     '        image: registry.io/app@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n'),
    ("properties_build", "build.properties",
     'build.number=20260601\nbuild.commit=a1b2c3d4e5f67890abcdef1234567890abcdef12\n'
     'build.timestamp=1717200000\n'
     'artifact.checksum=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n'
     'java.version=17.0.2\n'),
    ("font_base64", "icons.css",
     '@font-face {\n  font-family: "icons";\n'
     '  src: url(data:font/woff2;base64,d09GMgABAAAAAALkAAoAAAAABXwAAAKWAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAABmAAg0wKgZ8YgVwBNgIkAxYLBgAEIAWHHgcgG3UEyB6XbA8VFZJ9kf1FQduYwxhFFQ2H) format("woff2");\n'
     '}'),
    # ---- WS1 file-selection: generated/vendored paths must be fully skipped ----
    # Each carries a non-example AWS key (which the aws_key TP proves is
    # detectable); a finding here would mean the skip-glob failed.
    ("pb_go_codegen", "api/v1/service.pb.go",
     'var x = "AKIAZX9QWMR7KP2DLY4N" // generated, do not edit'),
    ("third_party_vendored", "third_party/awssdk/client.go",
     'const key = "AKIAZX9QWMR7KP2DLY4N"'),
    ("pods_vendored", "Pods/AWSCore/AWSCredentials.m",
     'NSString *k = @"AKIAZX9QWMR7KP2DLY4N";'),
    ("min_css_bundle", "dist/app.min.css",
     '.x{background:url("AKIAZX9QWMR7KP2DLY4N")}'),
    # ---- universal non-secret value shapes (crypt hash / $VAR ref / insecure example) ----
    ("crypt_hash_sha512", "users.yml", "password: $6$rounds=5000$abcdefgh$Xyz9QmWpRt4Zb1Nc6Vd3Lf8Hk0Gj5aBcDeFgHiJkLmNoP"),
    ("crypt_hash_bcrypt", "shadow", "hash = \"$2b$12$R9h0Nc6Vd3Lf8Hk0Gj5aOeFgHiJkLmNoPqRsTuVwXyZ012345678\""),
    ("bash_var_ref", "deploy.sh", 'export DB_PASSWORD=$DOCKER_DB_PASSWORD'),
    ("insecure_example", "config.template.yml", "encryption_key: a_not_so_secure_encryption_key"),
]


@pytest.mark.parametrize("label,filename,content", _TP_CASES, ids=[c[0] for c in _TP_CASES])
def test_recall_every_real_secret_detected(scanner, label, filename, content):
    """HARD GATE: each format-valid real-shape secret must produce a finding.

    A failure here is a recall regression — a real secret the scanner would now
    miss. Never weaken this to land a precision change.
    """
    ids = _rule_ids(scanner, filename, content)
    assert ids, f"RECALL REGRESSION: {label} produced no finding (real secret missed)"


@pytest.mark.parametrize("label,filename,content", _FP_CASES, ids=[c[0] for c in _FP_CASES])
def test_precision_no_known_false_positive(scanner, label, filename, content):
    """Each known generic FP shape must produce NO finding.

    These are the universal non-secret shapes the 61-repo audit measured as
    noise. A failure here means a precision win regressed.
    """
    ids = _rule_ids(scanner, filename, content)
    assert not ids, f"PRECISION REGRESSION: {label} wrongly flagged as {ids}"


def test_aggregate_recall_is_total(scanner):
    """Defense-in-depth summary: recall across the whole TP corpus is exactly 1.0."""
    detected = sum(1 for _, fn, ct in _TP_CASES if _rule_ids(scanner, fn, ct))
    assert detected == len(_TP_CASES), (
        f"recall {detected}/{len(_TP_CASES)} — must be {len(_TP_CASES)}/{len(_TP_CASES)}"
    )


def test_escaped_newline_pem_categorized_as_private_key(scanner):
    """WS2: a PEM stored single-line with literal ``\\n`` separators (the #1
    real-world key-leak shape — keys in JSON/.env) must be reported as a
    private-key finding, NOT downgraded to a generic high-entropy string.
    Pins the categorization so the confidence crusher can't silently re-bury it.
    """
    content = ('"secret_key": "-----BEGIN PRIVATE KEY-----\\n'
               'MC4CAQAwBQYDK2VwBCIEIOrZqzixETRBXsZl85d83N5nwb71ctTZ3mwu1TX90vG\\n'
               '-----END PRIVATE KEY-----\\n"')
    ids = _rule_ids(scanner, "defaults.py", content)
    assert ids, "escaped-\\n PEM not detected at all (recall regression)"
    assert any(("CRYPTO" in r or "GEN-007" in r or "PRIVATE" in r) for r in ids), (
        f"escaped-\\n PEM should be a private-key finding, got {ids}"
    )
