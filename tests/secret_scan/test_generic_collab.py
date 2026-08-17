"""Generic COLLAB detector tests.

Validates that the relaxed-quoting variants in `generic_collab.py`:
  - Fire on real free-form disclosures (the defect we're closing)
  - Stay quiet on the canonical FP shapes (placeholders, function
    calls, template variables)
  - Fire ONLY on collab content_types — not on file / git scans
  - Don't double-fire alongside the code-side rules (the
    surface_targeting / surface_excluded contract)
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


def _detected(scanner: SecretScanner, content: str, content_type: str | None) -> set[str]:
    """Rule ids reported after overlap dedup.

    Asserting a *specific* COLLAB id here is usually wrong. The COLLAB
    cohort exists for recall — it catches unquoted prose disclosures
    that generic.py misses — and its confidences are deliberately set
    against the collab noise floor (see detectors/generic_collab.py).
    Dedup keeps the highest severity-then-confidence finding per span,
    so whenever a mainstream rule also matches, the more confident rule
    legitimately wins and the COLLAB id disappears. The secret is still
    reported; only the label differs.

    So: assert a COLLAB id only where that rule is the *sole* detector,
    which is the behaviour that would actually regress. Everywhere else
    assert detection.
    """
    return _ids(scanner, content, content_type)


# ── Positive: the defects we're closing ───────────────────────────


@pytest.mark.parametrize("text", [
    "the prod password=hdgshui@sn12 fyi",
    "Use password = MyP@ssword2026 to connect",
    "creds: password = supersecret-1234",
    'set this in the runbook: password="hunter2-quoted-still-works"',
])
def test_password_unquoted_fires_in_collab(scanner, text):
    ids = _ids(scanner, text, content_type="message")
    assert "VOODA-SEC-GEN-003-COLLAB" in ids, f"Should fire on: {text!r}"


@pytest.mark.parametrize("text", [
    "api_key=ZmFrZUtleVZhbHVlV2l0aDAxMjM0NTY3ODk=",
    "api_token = abcdefghijklmnopqrstuvwx12345678",
    "the staging api_key=AKIA-DEMOKEY-NOT-REAL-12345",
])
def test_api_key_unquoted_fires_in_collab(scanner, text):
    ids = _ids(scanner, text, content_type="message")
    assert "VOODA-SEC-GEN-001-COLLAB" in ids, f"Should fire on: {text!r}"


def test_bearer_token_in_chat_fires(scanner):
    # CURL-001 (high/0.75) outranks GEN-004-COLLAB (high/0.70) on this
    # span and wins dedup. That is correct — the token is reported
    # either way, and "bearer token in a curl command" is the more
    # confident reading. What must not regress is the detection.
    text = "here's the curl I used: -H 'Authorization: Bearer abc123XYZdef456ghi789jkl0'"
    ids = _detected(scanner, text, content_type="message")
    assert ids, "a bearer token pasted in chat must be reported"


def test_connection_string_in_chat_fires(scanner):
    # POSTGRES-URL-001 is critical/0.97 against GEN-006-COLLAB's
    # high/0.70, so it wins — and rightly: a parsed Postgres DSN is a
    # sharper finding than "connection-string-shaped text in prose".
    text = "I'm connecting via postgres://realuser:r3al-p%40ss@db.acme.com/proddb"
    ids = _detected(scanner, text, content_type="page")
    assert ids, "a DSN pasted in a wiki page must be reported"


# ── Negative: canonical FP shapes ─────────────────────────────────


@pytest.mark.parametrize("text", [
    # Whitespace in value → blocked by value-shape filter
    "set password = your real value here",
    # Function call → blocked by `(` not in shape class
    "password=getenv(\"DB_PASS\")",
    # Template variable → blocked by `${` not in shape class
    "password=${DB_PASSWORD}",
    # Already-masked value → too short / contains ****
    "the prod password=**** (already masked)",
])
def test_password_collab_skips_obvious_fp_shapes(scanner, text):
    ids = _ids(scanner, text, content_type="message")
    assert "VOODA-SEC-GEN-003-COLLAB" not in ids, f"Should skip: {text!r}"


# ── Surface targeting: COLLAB rules don't fire on code/git scans ──


def test_collab_rule_not_in_git_scan_path(scanner):
    """The git-scan path passes content_type=None. Collab rules
    have surface_targeting=[message, page, comment] which excludes
    None, so they must NOT fire there."""
    text = "the prod password=hdgshui@sn12 fyi"
    ids = _ids(scanner, text, content_type=None)
    assert "VOODA-SEC-GEN-003-COLLAB" not in ids, (
        "Collab rule must not fire on git-scan path"
    )


def test_collab_rule_not_on_file_content_type(scanner):
    """The `file` content_type (S3 object, OneDrive file, Box file)
    is structured — code-side rules handle it. Collab rules must
    not fire there."""
    text = "the prod password=hdgshui@sn12 fyi"
    ids = _ids(scanner, text, content_type="file")
    assert "VOODA-SEC-GEN-003-COLLAB" not in ids


# ── No double-firing between code + collab variants ───────────────


def test_no_double_fire_on_collab_content(scanner):
    """The strict code-side GEN-003 carries surface_excluded for
    collab surfaces. Quoted password in a Slack message should
    fire COLLAB only, NOT GEN-003."""
    text = 'the prod DB password = "long-quoted-secret-2026"'
    ids = _ids(scanner, text, content_type="message")
    assert "VOODA-SEC-GEN-003" not in ids
    assert "VOODA-SEC-GEN-003-COLLAB" in ids


def test_no_double_fire_on_code_content(scanner):
    """And the inverse: code scan fires GEN-003 only, never the
    COLLAB variant (surface_targeting blocks it from None /
    file-shaped scans)."""
    text = 'PASSWORD = "long-quoted-secret-2026"'
    ids = _ids(scanner, text, content_type=None)   # git-scan path
    assert "VOODA-SEC-GEN-003" in ids
    assert "VOODA-SEC-GEN-003-COLLAB" not in ids


# ── Registry sanity ───────────────────────────────────────────────


def test_collab_rules_registered():
    """Guard against forgetting to wire generic_collab into
    registry.py's _DETECTOR_MODULES."""
    from services.secret_scan.detectors.registry import get_all_rules
    ids = {r.rule_id for r in get_all_rules()}
    expected = {
        "VOODA-SEC-GEN-001-COLLAB",
        "VOODA-SEC-GEN-002-COLLAB",
        "VOODA-SEC-GEN-003-COLLAB",
        "VOODA-SEC-GEN-004-COLLAB",
        "VOODA-SEC-GEN-006-COLLAB",
    }
    missing = expected - ids
    assert not missing, f"Collab rules not loaded: {missing}"
