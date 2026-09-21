# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Commit MESSAGE scanning in the git-history walk.

A credential pasted into a commit message never lands in a file, so
neither a working-tree scan nor a diff scan can see it — but it ships
in every clone exactly like the code does. These tests pin that
behaviour, plus the honesty signal that says when the walk did not
reach the whole history.
"""
import subprocess

import pytest

from services.secret_scan.engine import scan_git_history

# A GitHub-shaped PAT. Deliberately not a real credential, and not one
# of the documented example values the engine filters as placeholders.
FAKE_PAT = "ghp_A1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvWxYz"
FAKE_PAT_2 = "ghp_Z9y8X7w6V5u4T3s2R1q0PoNmLkJiHgFeDcBa"


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True)


@pytest.fixture()
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", ".")
    _git(r, "config", "user.email", "t@example.com")
    _git(r, "config", "user.name", "Test")
    (r / "app.py").write_text("print('hello')\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "initial commit")
    return r


def _messages(findings):
    return [f for f in findings if (f.raw_data or {}).get("in_commit_message")]


def test_secret_in_commit_subject_is_found(repo):
    (repo / "b.py").write_text("x = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", f"wip: temp key {FAKE_PAT} for testing")

    msgs = _messages(scan_git_history(str(repo)))
    assert len(msgs) == 1
    assert msgs[0].raw_data["commit_author"] == "Test"
    assert msgs[0].raw_data["commit_sha"]


def test_secret_in_commit_body_is_found(repo):
    """The body, not just the subject — the log format must capture both."""
    (repo / "c.py").write_text("y = 2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fix: rotate later",
         "-m", f"old token kept for reference: {FAKE_PAT}")

    msgs = _messages(scan_git_history(str(repo)))
    assert len(msgs) == 1


def test_message_findings_are_history_only(repo):
    """There is no file to edit, so deleting one can never resolve it.

    Downstream, `history_only` is what stops the deleted-file sweep from
    closing these.
    """
    (repo / "d.py").write_text("z = 3\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", f"wip {FAKE_PAT}")

    msg = _messages(scan_git_history(str(repo)))[0]
    assert msg.raw_data["history_only"] is True
    assert msg.raw_data["found_in_history"] is True


def test_same_secret_in_many_messages_is_one_finding(repo):
    """Quoting one key in ten commits is one leak, not ten findings."""
    for i in range(3):
        (repo / f"f{i}.py").write_text(f"v = {i}\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", f"wip {i}: key {FAKE_PAT}")

    assert len(_messages(scan_git_history(str(repo)))) == 1


def test_distinct_secrets_are_distinct_findings(repo):
    for i, tok in enumerate((FAKE_PAT, FAKE_PAT_2)):
        (repo / f"g{i}.py").write_text(f"v = {i}\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", f"wip: {tok}")

    assert len(_messages(scan_git_history(str(repo)))) == 2


def test_clean_messages_produce_no_findings(repo):
    (repo / "h.py").write_text("ok = True\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "chore: tidy up imports")

    assert _messages(scan_git_history(str(repo))) == []


def test_file_findings_still_work_alongside_messages(repo):
    """The message pass must not disturb the file pass."""
    (repo / "conf.py").write_text(f'GITHUB_TOKEN = "{FAKE_PAT}"\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add config")

    findings = scan_git_history(str(repo))
    files = [f for f in findings if not (f.raw_data or {}).get("in_commit_message")]
    assert any(f.file_path == "conf.py" for f in files)


def test_stats_report_a_truncated_walk(repo):
    """A partial walk must be reported, not left to look like a clean one."""
    for i in range(4):
        (repo / f"n{i}.py").write_text(f"v = {i}\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", f"commit {i}")

    stats: dict = {}
    scan_git_history(str(repo), max_commits=2, stats=stats)
    assert stats["truncated"] is True
    assert stats["commits_scanned"] == 2
    assert stats["total_commits"] == 5

    full: dict = {}
    scan_git_history(str(repo), max_commits=5000, stats=full)
    assert full["truncated"] is False
    assert full["commits_scanned"] == full["total_commits"] == 5


def test_message_of_a_deletion_only_commit_is_scanned(repo):
    """The commit that REMOVES a file is where people explain the key.

    Deletion-only commits carry no scannable diff, and the history walk
    used to skip them entirely — so "removing the old key, it was X"
    was invisible.
    """
    (repo / "secrets.py").write_text("PLACEHOLDER = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add config")
    _git(repo, "rm", "-q", "secrets.py")
    _git(repo, "commit", "-q", "-m", f"remove config; the old token was {FAKE_PAT}")

    msgs = _messages(scan_git_history(str(repo)))
    assert len(msgs) == 1


def test_message_on_a_side_branch_is_scanned(repo):
    """Parity with the diff walk, which scans every ref.

    Walking HEAD alone would scan the FILES a side branch added while
    ignoring what its commit messages said.
    """
    _git(repo, "checkout", "-q", "-b", "side")
    (repo / "side.py").write_text("s = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", f"side work; token {FAKE_PAT}")
    _git(repo, "checkout", "-q", "-")

    msgs = _messages(scan_git_history(str(repo)))
    assert len(msgs) == 1
