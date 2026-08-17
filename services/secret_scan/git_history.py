# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Git History Scanner — streams diffs from git log to find secrets
introduced in past commits (even if later deleted).

Streams commit-by-commit to avoid loading entire history into memory.
Only scans ADDED lines (lines starting with +) per commit.
"""

import os
import subprocess
import re
import structlog
from dataclasses import dataclass, field
from typing import Iterator, Optional

logger = structlog.get_logger()

MAX_COMMITS = 5000
MAX_DIFF_SIZE = 1024 * 1024


@dataclass
class CommitDiff:
    file_path: str
    added_lines: list[str] = field(default_factory=list)
    added_content: str = ""
    # Parallel to ``added_lines``: the REAL new-file line number of each added
    # line (from the ``@@ … +new_start @@`` hunk headers). Lets callers map a
    # finding's added-content line back to its true file line instead of a
    # number relative to the concatenated added-lines blob.
    added_line_nums: list[int] = field(default_factory=list)


@dataclass
class CommitInfo:
    sha: str
    author: str
    email: str
    date: str
    message: str
    diffs: list[CommitDiff] = field(default_factory=list)


# Wall-clock budget for the whole git-log stream.  Replaces the
# previous subprocess.run(timeout=...) since we no longer block on a
# single call; checked on every line so we abort gracefully without
# leaving git running in the background.
STREAM_TIMEOUT_SECONDS = 600


def _parse_commit_block(lines: list[str]) -> Optional[CommitInfo]:
    """Parse one buffered commit block (without delimiter) → CommitInfo.

    Extracted so the streaming reader can reuse the exact parsing
    logic the old buffered implementation had — no behavior diff,
    just a different data-flow shape around it.
    """
    if len(lines) < 5:
        return None

    sha = lines[0].strip()
    author = lines[1].strip()
    email = lines[2].strip()
    date = lines[3].strip()
    message = lines[4].strip()

    if not sha or len(sha) < 7:
        return None

    commit = CommitInfo(sha=sha, author=author, email=email, date=date, message=message[:200])

    current_diff: Optional[CommitDiff] = None
    in_header = False

    cur_new_line = 0  # running new-file line number within the active hunk
    for line in lines[5:]:
        if line.startswith("diff --git"):
            # Save previous diff
            if current_diff and current_diff.added_lines:
                current_diff.added_content = "\n".join(current_diff.added_lines)
                commit.diffs.append(current_diff)

            match = re.match(r"diff --git a/(.*) b/(.*)", line)
            file_path = match.group(2) if match else ""
            current_diff = CommitDiff(file_path=file_path)
            in_header = True
            continue

        # Hunk header — appears in the per-file header AND between hunks.
        # ``@@ -old_start,n +new_start,m @@`` carries new_start, the real file
        # line where this hunk's new content begins. Capture it so each added
        # line maps to its true file line.
        if line.startswith("@@"):
            _hm = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
            cur_new_line = int(_hm.group(1)) if _hm else cur_new_line
            in_header = False
            continue

        if in_header or not current_diff:
            continue

        # Collect added lines, tracking each one's real new-file line number.
        if line.startswith("+") and not line.startswith("+++"):
            added = line[1:]
            if added.strip():
                current_diff.added_lines.append(added)
                current_diff.added_line_nums.append(cur_new_line)
            cur_new_line += 1            # every added line occupies a new-file line
        elif line.startswith("-") and not line.startswith("---"):
            pass                         # removed line: absent from the new file
        else:
            cur_new_line += 1            # context/blank line is present in the new file

    # Save last diff
    if current_diff and current_diff.added_lines:
        current_diff.added_content = "\n".join(current_diff.added_lines)
        commit.diffs.append(current_diff)

    return commit


def stream_git_history(
    repo_path: str,
    max_commits: int = MAX_COMMITS,
    branch: Optional[str] = None,
) -> Iterator[CommitInfo]:
    """Stream git log with diffs, yielding one CommitInfo per commit.

    Streams commit-by-commit by spawning ``git log -p`` via
    ``subprocess.Popen`` and reading stdout line-by-line.  Peak memory
    is bounded by one commit's diff buffer (typically < 1 MB) rather
    than the full history (multi-GB on large repos).

    Why this matters
    ────────────────
    The previous implementation called ``subprocess.run(capture_output=
    True)`` which buffers the ENTIRE ``git log -p --all`` output into a
    bytes object, then ``.decode()`` materialised a second copy as a
    Python string, then ``.split(delim)`` materialised a third copy as
    a list of substrings.  On pulumi/pulumi this peaked around 15-30 GB
    of resident memory and the kernel OOM-killer reliably fired ~3 min
    into every history scan.  Streaming brings peak memory down to a
    few hundred KB regardless of repo size.

    Caller contract unchanged: same function signature, same return
    type, same ordering, same per-commit content, same ``max_commits``
    semantics, same yield-only-commits-with-diffs filter.
    """
    import time

    # Mark safe directory (no change from prior impl).
    try:
        subprocess.run(
            ["git", "config", "--global", "--add", "safe.directory", repo_path],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass

    delim = "---VOODA_COMMIT_DELIM---"
    cmd = [
        "git", "-C", repo_path, "log",
        "--all" if not branch else branch,
        "-p",
        # --root: GUARANTEE the initial commit's creation diff is emitted.
        # Modern git (verified 2.47) already includes the root commit's patch
        # in ``git log -p`` by default, so on current toolchains this is a
        # no-op — but that behaviour is NOT contractually guaranteed across
        # all git versions/configs (and path-limited / history-simplified
        # logs can drop it). Since this is a commercial scanner run against
        # unknown customer git versions under a recall=1.0 guarantee, we make
        # root-commit coverage explicit rather than version-dependent. --root
        # is idempotent where the root is already shown (scan_git_history's
        # secret_hash dedup collapses any duplicate), so it is pure
        # belt-and-suspenders with zero downside. The REAL root-commit bug
        # was in the diff-tree path (services/git_history/scanner.py); this
        # is the matching hardening for the git-log path. Generic.
        "--root",
        "--diff-filter=ACMR",
        "--no-merges",
        f"--max-count={max_commits}",
        f"--format={delim}%n%H%n%an%n%ae%n%aI%n%s",
    ]

    try:
        # stderr → DEVNULL so a chatty git (e.g. "warning: invalid
        # commit author") cannot fill the stderr pipe and deadlock the
        # subprocess.  We surface error context via the returncode
        # check at the bottom — losing the specific warning text is an
        # acceptable trade for liveness.
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=1,           # line-buffered (text mode)
            text=True,
            encoding="utf-8",
            errors="replace",    # preserve old behaviour on non-UTF8 commits
        )
    except Exception as e:
        logger.error("git_log_spawn_failed", error=str(e)[:200])
        return

    start_time = time.monotonic()
    commit_count = 0
    current_block: list[str] = []

    try:
        for line in proc.stdout:
            # Wall-clock timeout — replaces the prior subprocess.run(
            # timeout=600).  Checked per-line so we never hang past
            # the budget even if git is still producing data.
            if time.monotonic() - start_time > STREAM_TIMEOUT_SECONDS:
                logger.warning(
                    "git_history_stream_timeout",
                    seconds=STREAM_TIMEOUT_SECONDS,
                    commits_yielded=commit_count,
                    repo_path=repo_path,
                )
                break

            line = line.rstrip("\n")

            if line == delim:
                # Delimiter encountered — the buffer holds the PREVIOUS
                # commit's full content (or is empty on the very first
                # delimiter at start-of-output).
                if current_block:
                    commit = _parse_commit_block(current_block)
                    if commit and commit.diffs:
                        yield commit
                        commit_count += 1
                        if commit_count >= max_commits:
                            break
                current_block = []
            else:
                current_block.append(line)

        # Flush the final commit — it has no trailing delimiter since
        # the delimiter is in the --format prefix, not a suffix.
        if current_block and commit_count < max_commits:
            commit = _parse_commit_block(current_block)
            if commit and commit.diffs:
                yield commit
                commit_count += 1
    finally:
        # Always reap the subprocess so we don't leave a zombie git
        # process per scan.  terminate() sends SIGTERM (graceful);
        # kill() sends SIGKILL if it doesn't honor TERM within 5s.
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass
        except Exception:
            pass

        # Non-zero rc only matters for fully-failed runs; we don't
        # treat a TERM-on-early-break as failure.  rc==-15 (-SIGTERM)
        # and rc==-9 (-SIGKILL) mean we stopped it ourselves.
        rc = proc.returncode
        if rc is not None and rc != 0 and rc not in (-15, -9) and commit_count == 0:
            logger.error("git_log_failed", returncode=rc, repo_path=repo_path)

    logger.info("git_history_stream_complete", commits_processed=commit_count, repo_path=repo_path)


def get_diff_files(
    repo_path: str,
    base_sha: str,
    head_sha: str,
) -> list[tuple[str, str]]:
    """
    Get changed files between two commits.
    Returns list of (file_path, content_at_head) tuples.
    Only includes added/modified files, not deleted ones.
    """
    # Mark safe directory
    try:
        subprocess.run(
            ["git", "config", "--global", "--add", "safe.directory", repo_path],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass

    # Get list of changed files
    result = subprocess.run(
        ["git", "-C", repo_path, "diff", "--name-only", "--diff-filter=ACMR", f"{base_sha}..{head_sha}"],
        capture_output=True, text=True, timeout=30,
    )

    if result.returncode != 0:
        logger.warning("git_diff_failed", stderr=result.stderr[:200], base=base_sha[:8], head=head_sha[:8])
        return []

    files = []
    for file_path in result.stdout.strip().split("\n"):
        if not file_path.strip():
            continue

        # Get file content at head_sha
        content_result = subprocess.run(
            ["git", "-C", repo_path, "show", f"{head_sha}:{file_path}"],
            capture_output=True, text=True, timeout=10,
        )

        if content_result.returncode == 0:
            files.append((file_path, content_result.stdout))

    logger.info("diff_files_loaded", base=base_sha[:8], head=head_sha[:8], files=len(files))
    return files


def get_deleted_files(
    repo_path: str,
    base_sha: str,
    head_sha: str,
) -> list[str]:
    """Return paths of files that were DELETED between base and head.

    Companion to :func:`get_diff_files` (which returns A/C/M/R only,
    intentionally skipping deletions because there's nothing to scan).

    Used by the deleted-file tombstone pass in the worker: after an
    incremental scan, we resolve every existing finding whose
    ``file_path`` matches a deletion, so dashboards / SLA metrics
    don't keep counting a finding whose source file no longer exists.

    Returns an empty list on git-diff failure (force-pushed history,
    missing commit) — same defensive default as ``get_diff_files``.
    """
    try:
        subprocess.run(
            ["git", "config", "--global", "--add", "safe.directory", repo_path],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass

    result = subprocess.run(
        ["git", "-C", repo_path, "diff", "--name-only", "--diff-filter=D",
         f"{base_sha}..{head_sha}"],
        capture_output=True, text=True, timeout=30,
    )

    if result.returncode != 0:
        logger.warning(
            "git_deleted_diff_failed",
            stderr=result.stderr[:200],
            base=base_sha[:8],
            head=head_sha[:8],
        )
        return []

    deleted = [p.strip() for p in result.stdout.split("\n") if p.strip()]
    logger.info(
        "deleted_files_loaded",
        base=base_sha[:8],
        head=head_sha[:8],
        deleted=len(deleted),
    )
    return deleted


def count_commits(repo_path: str) -> int:
    try:
        subprocess.run(["git", "config", "--global", "--add", "safe.directory", repo_path], capture_output=True, timeout=5)
        result = subprocess.run(
            ["git", "-C", repo_path, "rev-list", "--all", "--count"],
            capture_output=True, text=True, timeout=10,
        )
        return int(result.stdout.strip()) if result.returncode == 0 else 0
    except Exception:
        return 0
