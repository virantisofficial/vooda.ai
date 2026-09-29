"""Findings whose correct answer is already known.

The probe asks whether a model ANSWERS. This asks whether it answers
CORRECTLY, which is a different question and the one that decides
whether a real leaked credential reaches a human. Measured live, two
models both reporting Ready disagreed on two of three findings, and one
of them called a hardcoded encryption key a false positive at 0.75
confidence — a secret that would simply have been filed away.

Every case is invented for this file. None is copied from a public
repository, because a model may have seen such a repository during
training and would then be scored on recall rather than judgement.

The split is deliberately weighted towards false positives, which is
where real scan output sits: most of what a regex flags is a
placeholder, an example or a variable name. A model that answers "real
secret" to everything would score poorly here, as it should.

`expected` is TRUE_POSITIVE when a human reviewer should see the
finding, FALSE_POSITIVE when flagging it wastes their time. `critical`
marks the cases where a wrong answer hides a live credential — those
are counted separately, because dismissing a real secret is not the
same class of mistake as raising a harmless one.

Vooda Community ships this set. Commercial builds extend it via
`load_extended_cases()`, which keeps the larger corpus out of a public
repository where it could be memorised.
"""
from __future__ import annotations

from dataclasses import dataclass

TRUE_POSITIVE = "TRUE_POSITIVE"
FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass(frozen=True)
class AccuracyCase:
    case_id: str
    file_path: str
    line: int
    rule_id: str
    snippet: str
    expected: str
    #: True when answering wrongly hides a working credential.
    critical: bool = False
    #: Why this case exists — shown in the breakdown, never to pick the answer.
    note: str = ""


# ── Real secrets: a human must see these ────────────────────────
_REAL: tuple[AccuracyCase, ...] = (
    AccuracyCase(
        "aws-static", "deploy/config/production.yml", 14, "AWS-ACCESS-KEY",
        'aws_access_key_id: AKIA2Fq7KLMN3PQRSTUV\n'
        'aws_secret_access_key: wJz9Kq2Lm7Xr4Tp1Nb8Vc5Hd3Gf6Js0Ay',
        TRUE_POSITIVE, critical=True,
        note="Long-lived AWS credentials committed to a production config",
    ),
    AccuracyCase(
        "db-dsn", "services/billing/settings.py", 22, "DB-CONNECTION",
        'DATABASE_URL = "postgresql://billing_svc:Xr7$kQp2Lm@db.internal:5432/billing"',
        TRUE_POSITIVE, critical=True,
        note="Service account password inside a connection string",
    ),
    AccuracyCase(
        "private-key", "ops/keys/deploy_key", 1, "PRIVATE-KEY",
        '-----BEGIN RSA PRIVATE KEY-----\n'
        'MIIEowIBAAKCAQEAxQ2mVbK9tLpR4hN8wZcF1jD6sYvA3eG7uH0iJ5kM2nP9qT\n'
        '-----END RSA PRIVATE KEY-----',
        TRUE_POSITIVE, critical=True,
        note="Private key material in the repository",
    ),
    AccuracyCase(
        "const-token", "src/integrations/paging.ts", 8, "CONFIG-ASSIGN",
        'const PAGERDUTY_TOKEN = "u+9Hq3LmXr7TkVpN2wYe";',
        TRUE_POSITIVE, critical=True,
        note="Third-party API token hardcoded as a constant",
    ),
    AccuracyCase(
        "webhook", "scripts/notify_release.sh", 5, "SLACK-WEBHOOK",
        'curl -X POST https://hooks.slack.com/services/T04KQ9LMN/B07XR3TVW/9kLmQr2XtYpN4vZa7HdCbE',
        TRUE_POSITIVE, critical=True,
        note="Slack webhook URL — the path itself is the credential",
    ),
    AccuracyCase(
        "jwt-secret", "api/auth/tokens.go", 31, "JWT-SECRET",
        'var jwtSigningKey = []byte("r4Tm9QvXe2LpKs7WnYc1ZbHd")',
        TRUE_POSITIVE, critical=True,
        note="Signing key — anyone holding it can mint valid sessions",
    ),
    AccuracyCase(
        "basic-auth-url", "tools/sync_inventory.py", 47, "BASIC-AUTH-URL",
        'resp = requests.get("https://svc_sync:Qp4mRt8Lx@inventory.corp.internal/api/v2/items")',
        TRUE_POSITIVE, critical=True,
        note="Credentials embedded in a request URL",
    ),
    AccuracyCase(
        "ci-token", ".github/workflows/publish.yml", 19, "GENERIC-TOKEN",
        'env:\n  REGISTRY_TOKEN: npm_7KqXr2LmTvYp9WnZc4HdBe1QsAj3Rt',
        TRUE_POSITIVE, critical=True,
        note="Registry token written into CI config instead of a secret store",
    ),
)

# ── Not secrets: flagging these wastes a reviewer's time ────────
_NOISE: tuple[AccuracyCase, ...] = (
    AccuracyCase(
        "placeholder", "README.md", 63, "GENERIC-PASSWORD",
        'export DB_PASSWORD="your-database-password-here"',
        FALSE_POSITIVE, note="Placeholder in setup documentation"),
    AccuracyCase(
        "env-lookup", "app/config.py", 11, "GENERIC-PASSWORD",
        'DB_PASSWORD = os.environ["DB_PASSWORD"]',
        FALSE_POSITIVE, note="Reads from the environment; no value present"),
    AccuracyCase(
        "commented", "legacy/db_setup.php", 27, "DB-CONNECTION",
        '// $conn = pg_connect("host=old-db password=hunter2");',
        FALSE_POSITIVE, note="Commented-out line from a decommissioned host"),
    AccuracyCase(
        "test-fixture", "tests/fixtures/auth_test.py", 9, "AWS-ACCESS-KEY",
        'FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # documented example value',
        FALSE_POSITIVE, note="Vendor's published example key, used in a test"),
    AccuracyCase(
        "schema-field", "db/migrations/003_users.sql", 7, "GENERIC-PASSWORD",
        'password_hash VARCHAR(255) NOT NULL,',
        FALSE_POSITIVE, note="Column definition — a field name, not a value"),
    AccuracyCase(
        "redacted", "docs/troubleshooting.md", 118, "GENERIC-TOKEN",
        'Authorization: Bearer ****************************',
        FALSE_POSITIVE, note="Already redacted in documentation"),
    AccuracyCase(
        "public-key", "config/ssh/known_hosts", 3, "PRIVATE-KEY",
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vK2mXqLpR9tN build-agent',
        FALSE_POSITIVE, note="Public key — safe to publish by design"),
    AccuracyCase(
        "uuid", "src/telemetry/session.js", 42, "GENERIC-TOKEN",
        'const SESSION_NAMESPACE = "7c9e6679-7425-40de-944b-e07fc1f90ae7";',
        FALSE_POSITIVE, note="Namespace UUID, not a credential"),
    AccuracyCase(
        "checksum", "build/artifacts.lock", 88, "GENERIC-SECRET",
        'sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        FALSE_POSITIVE, note="Content digest — one-way, not a secret"),
    AccuracyCase(
        "flag-name", "src/features.ts", 15, "CONFIG-ASSIGN",
        'const SECRET_MENU_ENABLED = false;',
        FALSE_POSITIVE, note="Variable name contains 'secret'; the value is a flag"),
    AccuracyCase(
        "sample-config", "config/settings.example.yml", 21, "GENERIC-PASSWORD",
        'smtp_password: CHANGEME',
        FALSE_POSITIVE, note="Sample config shipped for the user to fill in"),
    AccuracyCase(
        "base64-asset", "web/static/icon.json", 2, "ENTROPY-BASE64",
        '"data": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAACXBIWXMAAA"',
        FALSE_POSITIVE, note="Base64-encoded image, high entropy but not a credential"),
)

BASE_CASES: tuple[AccuracyCase, ...] = _REAL + _NOISE


def load_cases() -> tuple[AccuracyCase, ...]:
    """The corpus to score against.

    Commercial builds drop in a larger set; when it is absent the
    Community cases are used on their own, so the feature works either
    way and the bigger corpus never has to live in a public repository.
    """
    try:
        from services.ai_triage.accuracy_corpus_extended import EXTENDED_CASES
        return BASE_CASES + tuple(EXTENDED_CASES)
    except ImportError:
        return BASE_CASES
