# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""DB-006: credential env keys catch what the generic floors exclude.

A benchmark compose file held the same credential twice: embedded in a
DB URL (caught, POSTGRES-URL-001) and as a bare
`POSTGRES_PASSWORD: devpass` (nothing fired). GEN-003 requires a quoted
value of 8+ characters, so the most common spelling in compose/.env/k8s
manifests fell through entirely.

The key IS the signal here: images define these variables to hold the
live credential, so short low-entropy values are exactly the weak
passwords worth surfacing. Precision comes from the curated key list,
not from value entropy.
"""
import pytest

from services.secret_scan.engine import SecretScanner


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def _hits(scanner, content, path="docker-compose.yml"):
    return [f.rule_id for f in scanner.scan_file(path, content)]


# ── the miss that prompted the rule ──────────────────────────────────

def test_unquoted_compose_value_fires(scanner):
    hits = _hits(scanner, "    environment:\n      POSTGRES_PASSWORD: devpass\n")
    assert "VOODA-SEC-DB-006" in hits


def test_the_original_fixture_catches_the_credential_once(scanner):
    """Both spellings of the same credential in one file: the engine's
    value-containment dedup keeps the higher-specificity URL finding
    and collapses the k=v occurrence into it (devpass is a substring of
    the URL match). One credential, one finding — the incident model
    aggregates occurrences. What DB-006 changes is the standalone case:
    a compose file with ONLY the k=v spelling used to yield nothing."""
    content = (
        "services:\n"
        "  api:\n"
        "    environment:\n"
        "      DB_URL: postgresql://paylite_app:devpass@db:5432/paylite\n"
        "  db:\n"
        "    environment:\n"
        "      POSTGRES_PASSWORD: devpass\n"
    )
    hits = _hits(scanner, content)
    assert "VOODA-SEC-POSTGRES-URL-001" in hits, "URL form must keep firing"
    assert len([h for h in hits if h in ("VOODA-SEC-POSTGRES-URL-001", "VOODA-SEC-DB-006")]) == 1, (
        "same credential must not double-bill triage"
    )


def test_kv_only_file_now_yields_a_finding(scanner):
    """The actual gap: no URL anywhere, just the env var. This shape
    produced zero findings before DB-006."""
    content = (
        "services:\n"
        "  db:\n"
        "    environment:\n"
        "      POSTGRES_USER: paylite_app\n"
        "      POSTGRES_PASSWORD: devpass\n"
    )
    assert "VOODA-SEC-DB-006" in _hits(scanner, content)


@pytest.mark.parametrize("line", [
    "MYSQL_ROOT_PASSWORD=s3cret1",
    "REDIS_PASSWORD: hunter2x",
    'RABBITMQ_DEFAULT_PASS: "guest123"',
    "GF_SECURITY_ADMIN_PASSWORD=admin1",
    "MSSQL_SA_PASSWORD: YourStrong1",
    "pgpassword=devpass",                      # lowercase .env style
])
def test_common_manifest_shapes_fire(scanner, line):
    assert "VOODA-SEC-DB-006" in _hits(scanner, line + "\n", path=".env")


# ── deliberate non-matches ───────────────────────────────────────────

@pytest.mark.parametrize("line", [
    # references, not literals — the #1 FP shape in compose files
    "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}",
    "POSTGRES_PASSWORD=$DB_PASS",
    # docker secrets — the RIGHT pattern must never be flagged
    "POSTGRES_PASSWORD_FILE: /run/secrets/pg_pass",
    # too short to be a value at all
    "POSTGRES_PASSWORD: abc",
    "POSTGRES_PASSWORD:",
])
def test_references_files_and_stubs_do_not_fire(scanner, line):
    assert "VOODA-SEC-DB-006" not in _hits(scanner, line + "\n")


def test_generic_password_floor_is_unchanged(scanner):
    """DB-006 exists so GEN-003's calibrated quoted+8-char floor does
    NOT need loosening. A bare `password: devpass` outside the curated
    key list should still not fire the generic rule."""
    hits = _hits(scanner, "password: devpass\n")
    assert "VOODA-SEC-GEN-003" not in hits
    assert "VOODA-SEC-DB-006" not in hits
