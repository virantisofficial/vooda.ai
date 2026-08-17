"""History findings must report the CURRENT HEAD line, not the stale line from
the commit that introduced the secret.

Regression for the `.travis.yml` / `patterns.yml` reports: an AWS key introduced
in an old commit at line 20, then shifted to line 16 by later edits, was
highlighted at line 20 (a `skip_cleanup: true` line). The `added_line_nums` fix
maps to the *introducing commit's* layout; this test pins the layer above it —
re-locating in-HEAD secrets to their current line + snippet, and keeping (but
tagging) secrets that were scrubbed from HEAD.
"""
from __future__ import annotations

import subprocess

import pytest

from services.secret_scan.engine import SecretScanner, scan_git_history

_AKIA = "AKIAVWX7YZ12PQ34H5QA"


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def _git(d, *a):
    subprocess.run(["git", "-C", str(d), *a], check=True, capture_output=True)


def _init(d):
    _git(d, "init", "-q")
    _git(d, "config", "user.email", "t@t.com")
    _git(d, "config", "user.name", "t")


def _akia(findings):
    return next(
        (f for f in findings
         if _AKIA == (f.raw_data or {}).get("_raw_value_for_verification")),
        None,
    )


def test_line_relocated_to_head_after_file_shift(scanner, tmp_path):
    """Secret introduced at L20, file trimmed so HEAD holds it at L16 →
    the finding must report L16 (the current line), not L20."""
    d = tmp_path / "moved"; d.mkdir(); _init(d)
    p = d / ".travis.yml"
    p.write_text("\n".join("line%02d: x" % i for i in range(1, 18)) + "\n")
    _git(d, "add", "."); _git(d, "commit", "-qm", "ci")
    p.write_text(p.read_text() +
                 "deploy:\n  provider: s3\n  access_key_id: %s\n  bucket: b\n"
                 "  skip_cleanup: true\n  acl: public_read\n" % _AKIA)
    _git(d, "add", "."); _git(d, "commit", "-qm", "Push develop to s3")
    p.write_text("\n".join(p.read_text().splitlines()[4:]) + "\n")  # trim 4 lines above
    _git(d, "add", "."); _git(d, "commit", "-qm", "trim")

    head_line = next(i for i, l in enumerate(p.read_text().splitlines(), 1) if _AKIA in l)
    f = _akia(scan_git_history(str(d), scanner))
    assert f is not None, "AKIA must be detected in history"
    assert f.line_start == head_line, f"reported {f.line_start}, HEAD line is {head_line}"
    assert f.raw_data.get("line_relocated_to_head") is True


def test_history_only_secret_kept_and_tagged(scanner, tmp_path):
    """A secret scrubbed from HEAD is the whole point of history scanning — it
    must NOT be dropped, and must be tagged history_only (not relocated)."""
    d = tmp_path / "removed"; d.mkdir(); _init(d)
    p = d / ".env"
    p.write_text("DEBUG=1\nAWS_ACCESS_KEY_ID=%s\nPORT=8080\n" % _AKIA)
    _git(d, "add", "."); _git(d, "commit", "-qm", "add")
    p.write_text("DEBUG=1\nAWS_ACCESS_KEY_ID=__REMOVED__\nPORT=8080\n")
    _git(d, "add", "."); _git(d, "commit", "-qm", "scrub")

    f = _akia(scan_git_history(str(d), scanner))
    assert f is not None, "history-only secret must not be dropped (recall)"
    assert f.raw_data.get("history_only") is True
    assert not f.raw_data.get("line_relocated_to_head")


def test_unchanged_file_line_unaffected(scanner, tmp_path):
    """A secret still at its original line in HEAD must report that line."""
    d = tmp_path / "unchanged"; d.mkdir(); _init(d)
    p = d / ".env"
    p.write_text("X=1\nY=2\nAWS_ACCESS_KEY_ID=%s\nZ=3\n" % _AKIA)
    _git(d, "add", "."); _git(d, "commit", "-qm", "add")
    real = next(i for i, l in enumerate(p.read_text().splitlines(), 1) if _AKIA in l)
    f = _akia(scan_git_history(str(d), scanner))
    assert f is not None and f.line_start == real
