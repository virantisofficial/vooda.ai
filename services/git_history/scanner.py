# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Git History Scanner — traverses commit history to find secrets in diffs.

Scans every commit diff for secrets that may have been committed and later
deleted. Supports full history, branch scanning, incremental mode, and
blame attribution.
"""

import subprocess
import os
import re
import structlog
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

from packages.parsers.base import ParsedFinding
from services.secret_scan.engine import SecretScanner

logger = structlog.get_logger()


@dataclass
class CommitInfo:
    sha: str
    author_name: str
    author_email: str
    date: str
    message: str


@dataclass
class HistoryFinding(ParsedFinding):
    """Extended finding with git history metadata."""
    pass


@dataclass
class HistoryScanResult:
    findings: list[ParsedFinding] = field(default_factory=list)
    commits_scanned: int = 0
    branches_scanned: int = 0
    errors: list[str] = field(default_factory=list)


def _run_git(args: list[str], cwd: str, timeout: int = 60) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


class GitHistoryScanner:
    def __init__(self, scanner: Optional[SecretScanner] = None):
        self.scanner = scanner or SecretScanner(enable_entropy=True)

    def scan_history(
        self,
        repo_path: str,
        branch: Optional[str] = None,
        since_commit: Optional[str] = None,
        max_commits: int = 5000,
        scan_all_branches: bool = False,
    ) -> HistoryScanResult:
        """
        Scan git history for secrets in diffs.

        Args:
            repo_path: Path to git repository
            branch: Specific branch to scan (default: current)
            since_commit: Only scan commits after this SHA (incremental)
            max_commits: Maximum commits to scan
            scan_all_branches: Scan all branches, not just current/specified
        """
        result = HistoryScanResult()
        seen_secrets: set[str] = set()

        branches = self._get_branches(repo_path, branch, scan_all_branches)
        result.branches_scanned = len(branches)

        for br in branches:
            commits = self._get_commits(repo_path, br, since_commit, max_commits)
            for commit in commits:
                result.commits_scanned += 1
                try:
                    findings = self._scan_commit(repo_path, commit, seen_secrets)
                    result.findings.extend(findings)
                except Exception as e:
                    result.errors.append(f"Error scanning {commit.sha[:8]}: {str(e)[:100]}")

        logger.info(
            "git_history_scan_complete",
            commits=result.commits_scanned,
            branches=result.branches_scanned,
            findings=len(result.findings),
            errors=len(result.errors),
        )
        return result

    def scan_commit_range(
        self,
        repo_path: str,
        base_sha: str,
        head_sha: str,
    ) -> HistoryScanResult:
        """Scan only commits between two SHAs (e.g., for PR scanning)."""
        result = HistoryScanResult()
        seen_secrets: set[str] = set()

        stdout, stderr, rc = _run_git(
            ["log", "--format=%H|%an|%ae|%aI|%s", f"{base_sha}..{head_sha}", "--no-merges"],
            cwd=repo_path,
        )
        if rc != 0:
            result.errors.append(f"git log failed: {stderr[:200]}")
            return result

        commits = self._parse_log_output(stdout)
        result.commits_scanned = len(commits)

        for commit in commits:
            try:
                findings = self._scan_commit(repo_path, commit, seen_secrets)
                result.findings.extend(findings)
            except Exception as e:
                result.errors.append(f"Error scanning {commit.sha[:8]}: {str(e)[:100]}")

        return result

    def scan_staged(self, repo_path: str) -> list[ParsedFinding]:
        """Scan only staged (git add) changes — for pre-commit hooks."""
        stdout, _, rc = _run_git(["diff", "--cached", "--unified=0", "--no-color"], cwd=repo_path)
        if rc != 0 or not stdout:
            return []
        return self._scan_diff_content(stdout, "staged", CommitInfo(
            sha="staged", author_name="", author_email="", date="", message="staged changes",
        ))

    def scan_diff(self, repo_path: str, base: str, head: str) -> list[ParsedFinding]:
        """Scan diff between two refs."""
        stdout, _, rc = _run_git(["diff", "--unified=0", "--no-color", f"{base}..{head}"], cwd=repo_path)
        if rc != 0 or not stdout:
            return []
        return self._scan_diff_content(stdout, f"{base}..{head}", CommitInfo(
            sha=head, author_name="", author_email="", date="", message=f"diff {base}..{head}",
        ))

    def _get_branches(self, repo_path: str, branch: Optional[str], scan_all: bool) -> list[str]:
        if branch:
            return [branch]
        if scan_all:
            stdout, _, rc = _run_git(["branch", "--format=%(refname:short)"], cwd=repo_path)
            if rc == 0:
                return [b.strip() for b in stdout.strip().split("\n") if b.strip()]
        # Default: current branch
        stdout, _, rc = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_path)
        if rc == 0:
            return [stdout.strip()]
        return ["HEAD"]

    def _get_commits(
        self,
        repo_path: str,
        branch: str,
        since_commit: Optional[str],
        max_commits: int,
    ) -> list[CommitInfo]:
        args = ["log", "--format=%H|%an|%ae|%aI|%s", f"--max-count={max_commits}", "--no-merges", branch]
        if since_commit:
            args.insert(4, f"{since_commit}..{branch}")
            args.remove(branch)

        stdout, stderr, rc = _run_git(args, cwd=repo_path, timeout=120)
        if rc != 0:
            return []
        return self._parse_log_output(stdout)

    def _parse_log_output(self, output: str) -> list[CommitInfo]:
        commits = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("|", 4)
            if len(parts) < 5:
                continue
            commits.append(CommitInfo(
                sha=parts[0],
                author_name=parts[1],
                author_email=parts[2],
                date=parts[3],
                message=parts[4][:200],
            ))
        return commits

    def _scan_commit(
        self,
        repo_path: str,
        commit: CommitInfo,
        seen_secrets: set[str],
    ) -> list[ParsedFinding]:
        stdout, _, rc = _run_git(
            # --root: a parentless ROOT commit produces an EMPTY diff-tree
            # without this flag, so a secret introduced in the repo's first
            # commit is never scanned (a silent recall hole). ``--root``
            # renders the root commit as a full creation diff; it has no
            # effect on any non-root commit. Generic.
            ["diff-tree", "--root", "--no-commit-id", "-p", "--unified=0", "--no-color", "-r", commit.sha],
            cwd=repo_path,
            timeout=30,
        )
        if rc != 0 or not stdout:
            return []
        return self._scan_diff_content(stdout, commit.sha, commit, seen_secrets)

    def _scan_diff_content(
        self,
        diff_output: str,
        ref: str,
        commit: CommitInfo,
        seen_secrets: Optional[set[str]] = None,
    ) -> list[ParsedFinding]:
        if seen_secrets is None:
            seen_secrets = set()

        findings = []
        current_file = None
        added_lines: dict[str, list[tuple[int, str]]] = {}

        # Parse diff to extract added lines per file
        for line in diff_output.split("\n"):
            if line.startswith("diff --git"):
                match = re.search(r'b/(.+)$', line)
                if match:
                    current_file = match.group(1)
                    if current_file not in added_lines:
                        added_lines[current_file] = []
            elif line.startswith("@@"):
                m = re.search(r'\+(\d+)', line)
                self._current_line = int(m.group(1)) if m else 1
            elif line.startswith("+") and not line.startswith("+++"):
                if current_file:
                    added_lines.setdefault(current_file, []).append(
                        (getattr(self, '_current_line', 1), line[1:])
                    )
                    self._current_line = getattr(self, '_current_line', 1) + 1

        # Scan added content per file
        for file_path, lines in added_lines.items():
            if not lines:
                continue
            content = "\n".join(text for _, text in lines)
            file_findings = self.scanner.scan_file(file_path, content)

            for f in file_findings:
                secret_hash = f.raw_data.get("secret_hash", "")
                dedup_key = f"{secret_hash}:{file_path}"
                if dedup_key in seen_secrets:
                    continue
                seen_secrets.add(dedup_key)

                # Enrich with git metadata
                f.raw_data["commit_sha"] = commit.sha
                f.raw_data["commit_author"] = commit.author_name
                f.raw_data["commit_email"] = commit.author_email
                f.raw_data["commit_date"] = commit.date
                f.raw_data["commit_message"] = commit.message
                f.raw_data["is_in_history_only"] = True
                f.raw_data["branch"] = ref

                # Check if file still exists (deleted file = history only)
                findings.append(f)

        return findings

    def get_blame(self, repo_path: str, file_path: str, line_num: int) -> Optional[dict]:
        """Get blame info for a specific line."""
        stdout, _, rc = _run_git(
            ["blame", "-L", f"{line_num},{line_num}", "--porcelain", file_path],
            cwd=repo_path,
        )
        if rc != 0:
            return None

        info = {}
        for line in stdout.split("\n"):
            if line.startswith("author "):
                info["author"] = line[7:]
            elif line.startswith("author-mail "):
                info["author_email"] = line[12:].strip("<>")
            elif line.startswith("author-time "):
                info["author_time"] = line[12:]
            elif line.startswith("summary "):
                info["summary"] = line[8:]
        return info if info else None
