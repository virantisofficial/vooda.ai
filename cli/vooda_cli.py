#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""
Vooda AI CLI — Secret scanner for pre-commit hooks and local scanning.

Usage:
    vooda scan --staged          Scan staged git changes (pre-commit hook)
    vooda scan --all             Scan entire repository (HEAD)
    vooda scan --history         Scan full git history
    vooda scan <file>            Scan a single file
    vooda scan --dir <path>      Scan a directory

Exit codes:
    0 = No secrets found
    1 = Secrets found (blocks commit in pre-commit mode)
    2 = Error
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Optional, List, Tuple, Dict

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# Shared CLI↔platform sync (single source of truth — same masked-envelope
# import path the `vooda monitor` CI flow uses).
from cli import _sync  # noqa: E402


# ── API persistence helpers ───────────────────────────────

def _push_to_ui(findings, scan_path, scanner=None):
    """Sync findings to the Vooda platform via the SHARED native-envelope path
    (``cli/_sync``) — the SAME masked-import flow ``vooda monitor`` uses, so the
    pre-commit hook and the CI flow never diverge.

    WS-6: only ``masked_value`` + one-way ``secret_hash`` leave the machine;
    the snippet is redacted by the scanner first.  Silent no-op when
    unauthenticated (so the hook works offline / for contributors without a
    key).  ``scan_path``'s git toplevel maps to the Vooda repository; a default
    scanner is built when the caller (e.g. history scan) doesn't supply one.
    """
    if not findings:
        return
    if scanner is None:
        from services.secret_scan.engine import SecretScanner
        scanner = SecretScanner()
    # Pre-commit / local scans are "cli" provenance and non-idempotent.
    _sync._sync_findings(findings, scan_path, "cli", scanner)


# ── Terminal colors ───────────────────────────────────────

class Color:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @staticmethod
    def enabled():
        return sys.stdout.isatty()

    @classmethod
    def red(cls, s): return f"{cls.RED}{s}{cls.RESET}" if cls.enabled() else s
    @classmethod
    def yellow(cls, s): return f"{cls.YELLOW}{s}{cls.RESET}" if cls.enabled() else s
    @classmethod
    def green(cls, s): return f"{cls.GREEN}{s}{cls.RESET}" if cls.enabled() else s
    @classmethod
    def cyan(cls, s): return f"{cls.CYAN}{s}{cls.RESET}" if cls.enabled() else s
    @classmethod
    def gray(cls, s): return f"{cls.GRAY}{s}{cls.RESET}" if cls.enabled() else s
    @classmethod
    def bold(cls, s): return f"{cls.BOLD}{s}{cls.RESET}" if cls.enabled() else s


# ── Severity formatting ───────────────────────────────────

SEV_COLORS = {
    "critical": Color.red,
    "high": lambda s: f"\033[38;5;208m{s}\033[0m" if Color.enabled() else s,
    "medium": Color.yellow,
    "low": Color.cyan,
}

SEV_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
}


def format_severity(sev: str) -> str:
    color_fn = SEV_COLORS.get(sev, Color.gray)
    icon = SEV_ICONS.get(sev, "⚪")
    return f"{icon} {color_fn(sev.upper())}"


# ── Get staged diff content ───────────────────────────────

def get_staged_files() -> List[Tuple[str, str]]:
    """Get list of staged files with their content from git diff --cached.
    Returns list of (file_path, content) tuples.
    """
    # Get list of staged files
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return []

    files = []
    for file_path in result.stdout.strip().split("\n"):
        if not file_path.strip():
            continue

        # Get the staged content (not the working tree version)
        content_result = subprocess.run(
            ["git", "show", f":{file_path}"],
            capture_output=True, text=True,
        )
        if content_result.returncode == 0:
            files.append((file_path, content_result.stdout))

    return files


# ── Print findings ────────────────────────────────────────

def print_findings(findings, mode: str = "staged"):
    """Print findings in a terminal-friendly format."""
    if not findings:
        print(Color.green("✅ No secrets found."))
        return

    # Header
    count = len(findings)
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")

    print()
    print(Color.bold(f"🔍 Vooda AI — {count} secret{'s' if count != 1 else ''} detected"))
    print(Color.gray(f"   Mode: {mode}"))
    if critical:
        print(Color.red(f"   {critical} CRITICAL"))
    if high:
        print(f"   \033[38;5;208m{high} HIGH\033[0m" if Color.enabled() else f"   {high} HIGH")
    print()

    # Group by file
    by_file: Dict[str, list] = {}
    for f in findings:
        path = f.file_path or "unknown"
        by_file.setdefault(path, []).append(f)

    for file_path, file_findings in sorted(by_file.items()):
        print(Color.bold(f"  {file_path}"))
        for f in sorted(file_findings, key=lambda x: x.line_start or 0):
            sev = format_severity(f.severity)
            line = f":{f.line_start}" if f.line_start else ""
            title = f.title[:60]
            masked = (f.raw_data or {}).get("masked_value", "")
            method = (f.raw_data or {}).get("detection_method", "")

            print(f"    {sev:>20s}  {Color.gray(f'L{f.line_start:<4}' if f.line_start else '    ')} {title}")
            if masked:
                print(f"                        {Color.cyan(masked)}  {Color.gray(f'[{method}]')}")
        print()

    # Footer
    print(Color.gray("─" * 60))
    if mode == "staged":
        print(Color.red(f"❌ Commit blocked — {count} secret{'s' if count != 1 else ''} found in staged files."))
        print(Color.gray("   Fix: Remove secrets and use environment variables or a secret manager."))
        print(Color.gray("   Skip: git commit --no-verify (not recommended)"))
    else:
        print(Color.yellow(f"⚠️  {count} secret{'s' if count != 1 else ''} found."))
    print()


# ── Scan commands ─────────────────────────────────────────

def scan_staged() -> int:
    """Scan staged git changes. Returns exit code (0=clean, 1=secrets found)."""
    from services.secret_scan.engine import SecretScanner

    staged_files = get_staged_files()
    if not staged_files:
        print(Color.gray("No staged files to scan."))
        return 0

    scanner = SecretScanner()
    all_findings = []

    for file_path, content in staged_files:
        findings = scanner.scan_file(file_path, content)
        all_findings.extend(findings)

    print_findings(all_findings, mode="staged")
    _push_to_ui(all_findings, ".", scanner)
    return 1 if all_findings else 0


def scan_file(file_path: str) -> int:
    """Scan a single file. Returns exit code."""
    from services.secret_scan.engine import SecretScanner

    if not os.path.exists(file_path):
        print(Color.red(f"Error: File not found: {file_path}"))
        return 2

    with open(file_path, "r", errors="ignore") as f:
        content = f.read()

    scanner = SecretScanner()
    findings = scanner.scan_file(file_path, content)
    print_findings(findings, mode=f"file: {file_path}")
    _push_to_ui(findings, os.path.dirname(os.path.abspath(file_path)), scanner)
    return 1 if findings else 0


def scan_directory(dir_path: str) -> int:
    """Scan an entire directory. Returns exit code."""
    from services.secret_scan.engine import SecretScanner

    if not os.path.isdir(dir_path):
        print(Color.red(f"Error: Directory not found: {dir_path}"))
        return 2

    scanner = SecretScanner()
    findings = scanner.scan_directory(dir_path)
    print_findings(findings, mode=f"directory: {dir_path}")
    _push_to_ui(findings, dir_path, scanner)
    return 1 if findings else 0


def scan_history(repo_path: str = ".") -> int:
    """Scan full git history. Returns exit code."""
    from services.secret_scan.engine import scan_git_history

    findings = scan_git_history(repo_path)
    print_findings(findings, mode="git history (all commits)")
    _push_to_ui(findings, repo_path)  # no scanner in scope → default built
    return 1 if findings else 0


# ── Main ──────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="vooda",
        description="Vooda AI — Secret Scanner CLI",
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan for secrets")
    scan_group = scan_parser.add_mutually_exclusive_group()
    scan_group.add_argument("--staged", action="store_true", help="Scan staged git changes (pre-commit)")
    scan_group.add_argument("--all", action="store_true", help="Scan entire repository")
    scan_group.add_argument("--history", action="store_true", help="Scan full git history")
    scan_group.add_argument("--dir", type=str, help="Scan a directory")
    scan_group.add_argument("--file", type=str, help="Scan a single file")
    scan_parser.add_argument("path", nargs="?", help="File or directory to scan")

    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        return 0

    try:
        if args.staged:
            return scan_staged()
        elif args.history:
            return scan_history()
        elif args.all or args.dir:
            return scan_directory(args.dir or ".")
        elif args.file or args.path:
            target = args.file or args.path
            if os.path.isdir(target):
                return scan_directory(target)
            return scan_file(target)
        else:
            # Default: scan staged if in git repo, else scan current dir
            git_check = subprocess.run(["git", "rev-parse", "--git-dir"], capture_output=True)
            if git_check.returncode == 0:
                return scan_staged()
            return scan_directory(".")
    except KeyboardInterrupt:
        print(Color.gray("\nScan interrupted."))
        return 2
    except Exception as e:
        print(Color.red(f"Error: {e}"))
        return 2


if __name__ == "__main__":
    sys.exit(main())
