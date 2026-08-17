"""Regression test for the _TEST_PATH_RE recogniser used by adjust_confidence.

Why this test exists
====================
The original `_TEST_PATH_PATTERNS` used `test[s_/\\\\]` which matched
`tests/`, `test_`, `test/`, but NOT `testing/` or `testdata/`.  The
Vooda Scan Intelligence audit of pulumi/pulumi (scan_id 03671f65,
2026-05-24) found 5 CRITICAL `GEN-003-WEAK` findings inside
`pkg/codegen/testing/utils/testdata/aws-5.16.2.json` — a 360 k-line
provider schema dump where the `password` matches are documentation
examples, not real secrets.

These specific paths are pinned here so a future refactor of the
patterns can't silently drop the coverage.  Adding new directory
recognisers is welcome; removing one of these triggers a regression
failure with a clear message.
"""
from __future__ import annotations

import pytest

from services.secret_scan.context import _TEST_PATH_RE


# Paths that MUST be recognised as test-context (motivated by the
# pulumi audit + the Go / Python / Ruby conventions Vooda customers
# use most often).
MUST_MATCH = [
    # ── pulumi audit findings (scan_id 03671f65) ──
    "pkg/codegen/testing/utils/testdata/aws-5.16.2.json",
    "pkg/codegen/testing/utils/testdata/aws-5.4.0.json",
    "pkg/codegen/testing/utils/testdata/azure-native-1.56.0.json",
    "pkg/cmd/pulumi/insights/aws_test.go",
    # ── Go-convention testdata + testing dirs (broader coverage) ──
    "internal/auth/testdata/sample.json",
    "cmd/server/testing/helpers.go",
    "internal/scanner_test.go",
    # ── snapshot / golden directories ──
    "src/components/__snapshots__/Button.test.tsx.snap",
    "tests/golden/expected_output.json",
    "spec/snapshots/api_response.yaml",
    # ── HTTP replay fixtures ──
    "test/cassettes/login_flow.yml",
    "tests/vcr/oauth_callback.yaml",
    # ── E2E + Cypress + Integration ──
    "frontend/e2e/login.spec.ts",
    "cypress/integration/login_spec.js",
    "backend/integration/test_db.py",
    # ── Pre-existing conventions still work ──
    "tests/test_foo.py",
    "src/__tests__/Button.test.tsx",
    "spec/models/user_spec.rb",
    "internal/fixtures/sample_user.json",
]

# Paths that MUST NOT be recognised — real production code that
# happens to contain test-like substrings.  These guard against
# regex drift introducing false-positive context matches.
MUST_NOT_MATCH = [
    "src/api/contesting_logic.go",   # has "test" but not at a path boundary
    "src/util/protests/manager.py",  # "protests" — not a test dir
    "internal/auth/login.go",
    "src/components/Button.tsx",
    "lib/database.py",
]


@pytest.mark.parametrize("path", MUST_MATCH)
def test_path_recognised_as_test_context(path: str) -> None:
    """Each path MUST be recognised — failures here mean the regex
    drifted and adjust_confidence will no longer reduce confidence
    on findings inside it."""
    assert _TEST_PATH_RE.search(path), (
        f"Expected {path!r} to match _TEST_PATH_RE but it did not. "
        f"adjust_confidence will NOT apply the test-context confidence "
        f"dampener on findings inside this path — likely re-introducing "
        f"the BUG-P2 from the pulumi audit (5 CRITICAL false TPs in "
        f"`testdata/` paths)."
    )


@pytest.mark.parametrize("path", MUST_NOT_MATCH)
def test_path_not_recognised_as_test_context(path: str) -> None:
    """Each path MUST NOT match — guards against over-eager pattern
    drift that would silently downgrade confidence on real findings
    in production code."""
    assert not _TEST_PATH_RE.search(path), (
        f"Expected {path!r} to NOT match _TEST_PATH_RE but it did. "
        f"adjust_confidence would now reduce confidence on findings "
        f"in production code — real secrets could slip below the "
        f"emission threshold."
    )
