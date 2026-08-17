"""History-scan line relocation must be RENAME-aware (2026-06-14).

The HEAD-relocation pass fixes a history finding's line to where the secret lives
in HEAD. It originally did `git show HEAD:<recorded_path>`, which fails when the
file was RENAMED/MOVED between the introducing commit and HEAD — leaving the
finding stranded at the stale introducing-commit path+line and wrongly tagged
history_only (the UI then highlights the wrong line). The path-agnostic fallback
`git grep`s the raw value across HEAD and relocates BOTH path and line.

These pin all three branches: rename (relocate path+line), same-path line-shift
(relocate line in place), scrubbed (stay history_only).
"""
import os
import subprocess

from services.secret_scan.engine import SecretScanner, scan_git_history

_V = "wJ8fK2mNpQ4rS6tV9xZ1aB3cD5eF7gH0iK2lM4nO"          # detectable, not a dummy
_SEC = f'aws_secret_access_key = "{_V}"'
_scanner = SecretScanner()


def _git(repo, *args):
    subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True)


def _init(repo):
    os.makedirs(repo, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.co")
    _git(repo, "config", "user.name", "t")


def _write(repo, rel, content):
    p = os.path.join(repo, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(content)


def _commit(repo, msg):
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", msg)


def _finding(repo):
    fs = [f for f in scan_git_history(repo, scanner=_scanner)
          if _V in ((f.raw_data or {}).get("_raw_value_for_verification") or "")]
    assert fs, "the secret must be found in history"
    return fs[0]


def test_renamed_file_relocates_path_and_line(tmp_path):
    repo = str(tmp_path / "r")
    _init(repo)
    _write(repo, "tests/a.py", f"l1\nl2\n{_SEC}\n")            # introduced at line 3
    _commit(repo, "c1")
    os.remove(os.path.join(repo, "tests/a.py"))                # RENAME + shift down
    _write(repo, "src/a.py", f"h1\nh2\nh3\nh4\nh5\nh6\nh7\n{_SEC}\n")  # HEAD: line 8
    _commit(repo, "c2 rename")
    f = _finding(repo)
    assert f.file_path == "src/a.py", f.file_path
    assert f.line_start == 8, f.line_start
    assert (f.raw_data or {}).get("line_relocated_to_head")
    assert (f.raw_data or {}).get("head_path_resolved")
    assert not (f.raw_data or {}).get("history_only")


def test_same_path_line_shift_relocates_in_place(tmp_path):
    repo = str(tmp_path / "r")
    _init(repo)
    _write(repo, "t/b.py", f"x1\nx2\n{_SEC}\n")
    _commit(repo, "c1")
    _write(repo, "t/b.py", f"p1\np2\np3\np4\np5\n{_SEC}\n")     # same path, now line 6
    _commit(repo, "c2")
    f = _finding(repo)
    assert f.file_path == "t/b.py"
    assert f.line_start == 6
    assert (f.raw_data or {}).get("line_relocated_to_head")
    assert not (f.raw_data or {}).get("head_path_resolved")    # in-place, not a rename


def test_scrubbed_secret_stays_history_only(tmp_path):
    repo = str(tmp_path / "r")
    _init(repo)
    _write(repo, "t/c.py", f"x1\n{_SEC}\n")
    _commit(repo, "c1")
    _write(repo, "t/c.py", "x1\n# secret removed\n")            # value gone from HEAD
    _commit(repo, "c2")
    f = _finding(repo)
    assert (f.raw_data or {}).get("history_only")
    assert not (f.raw_data or {}).get("line_relocated_to_head")
