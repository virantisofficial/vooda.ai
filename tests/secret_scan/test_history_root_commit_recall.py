"""Recall regression — a secret introduced in the ROOT (first) commit must be
detected by the git-history scan.

There are two live history code paths, and they behaved differently:

  * Path A — worker "Scan Git History" + ``vooda scan --history``:
    ``scan_git_history`` → ``stream_git_history`` → ``git log -p``.
    Modern git (verified 2.47) ALREADY shows the root commit's creation diff
    in ``git log -p`` by default, so this path was not actually broken. We
    pin it anyway and pass ``--root`` in production as a cross-git-version
    guarantee (recall=1.0 must not depend on the customer's git build).

  * Path B — ``cli/main.py``: ``GitHistoryScanner.scan_history`` →
    ``_scan_commit`` → ``git diff-tree <sha>``. A parentless root commit
    yields an EMPTY diff-tree WITHOUT ``--root``, so a secret committed in
    the repo's very first commit was a silent false negative. THIS is the
    path the ``--root`` fix actually repairs (empirically: root-secret count
    0 → 1 with the flag; child commits unaffected).

Both paths are exercised against a REAL throwaway git repo (no mocks), and
the git-level behaviour that makes ``--root`` necessary for diff-tree is
pinned directly. Generic — nothing here is repo-specific.
"""
import os
import subprocess

import pytest

from services.secret_scan.engine import scan_git_history

# A fresh, format-valid AWS key. Deliberately NOT the AWS documentation
# EXAMPLE key (``AKIAIOSFODNN7EXAMPLE``) — that one is a known placeholder the
# engine intentionally suppresses, so a hit here proves REAL detection.
_ROOT_SECRET_FILE = "config/aws_credentials.ini"
_ROOT_AWS_KEY = "AKIAW4XK7NQZ2VBP9MLD"
_ROOT_AWS_SECRET = "wJalr5utnFEMI7K9SxMP2bPxRfiCYZ8nKzN3aQvd"
_ROOT_BLOB = (
    "[default]\n"
    f"aws_access_key_id = {_ROOT_AWS_KEY}\n"
    f"aws_secret_access_key = {_ROOT_AWS_SECRET}\n"
)


def _git(repo: str, *args: str) -> None:
    subprocess.run(
        ["git", "-C", repo, *args],
        check=True, capture_output=True, text=True,
    )


def _has_root_key(findings) -> bool:
    """True if any finding surfaces the root-commit AWS key."""
    for f in findings:
        if _ROOT_AWS_KEY in (getattr(f, "code_snippet", "") or ""):
            return True
        rd = getattr(f, "raw_data", None) or {}
        if "aws" in str(rd.get("secret_type", "")).lower():
            return True
        if "AWS" in (getattr(f, "rule_id", "") or ""):
            return True
    return False


@pytest.fixture
def repo_with_root_secret(tmp_path):
    """A git repo whose ROOT commit introduces an AWS key, followed by a
    clean second commit so the root is genuinely the first of several."""
    repo = str(tmp_path / "root_secret_repo")
    os.makedirs(repo)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.test")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "commit.gpgsign", "false")

    # ── ROOT commit: contains the secret ──
    secret_path = os.path.join(repo, _ROOT_SECRET_FILE)
    os.makedirs(os.path.dirname(secret_path), exist_ok=True)
    with open(secret_path, "w") as f:
        f.write(_ROOT_BLOB)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "initial import")

    # ── second commit: clean, so history has depth beyond the root ──
    with open(os.path.join(repo, "README.md"), "w") as f:
        f.write("# project\nno secrets here\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add readme")
    return repo


def test_path_a_scan_git_history_finds_root_secret(repo_with_root_secret):
    """Path A (worker + vooda_cli): scan_git_history surfaces the root secret.

    git log -p shows the root commit by default on modern git; this pins it so
    a future regression (or a path-limited/simplified log dropping the root)
    is caught."""
    findings = scan_git_history(repo_with_root_secret)
    assert _has_root_key(findings), (
        "RECALL REGRESSION (Path A): scan_git_history missed the AWS key in "
        "the ROOT commit."
    )


def test_path_b_git_history_scanner_finds_root_secret(repo_with_root_secret):
    """Path B (cli/main.py): GitHistoryScanner.scan_history surfaces the root
    secret. THIS is the path the --root fix repairs — without it, diff-tree on
    the parentless root commit returns an empty diff and the secret is missed."""
    from services.git_history.scanner import GitHistoryScanner

    result = GitHistoryScanner().scan_history(repo_with_root_secret)
    assert _has_root_key(result.findings), (
        "RECALL REGRESSION (Path B): GitHistoryScanner missed the AWS key in "
        "the ROOT commit — diff-tree needs --root for parentless commits."
    )


def test_diff_tree_needs_root_flag_for_initial_commit(repo_with_root_secret):
    """Documents WHERE --root matters: the exact production diff-tree command
    in GitHistoryScanner._scan_commit emits an EMPTY diff for the parentless
    root commit without --root (secret invisible), and the full creation diff
    with it (secret visible)."""
    root = subprocess.run(
        ["git", "-C", repo_with_root_secret, "rev-list", "--max-parents=0", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip()
    no_root = subprocess.run(
        ["git", "-C", repo_with_root_secret, "diff-tree", "--no-commit-id", "-p",
         "--unified=0", "--no-color", "-r", root],
        capture_output=True, text=True,
    ).stdout
    with_root = subprocess.run(
        ["git", "-C", repo_with_root_secret, "diff-tree", "--root", "--no-commit-id",
         "-p", "--unified=0", "--no-color", "-r", root],
        capture_output=True, text=True,
    ).stdout
    assert _ROOT_AWS_KEY not in no_root, (
        "Expected `git diff-tree <root>` to OMIT the root secret (the bug)."
    )
    assert _ROOT_AWS_KEY in with_root, (
        "Expected `git diff-tree --root <root>` to INCLUDE the root secret (the fix)."
    )
