#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Vooda AI CLI — scan for secrets in code, manage findings, install hooks.

Usage:
    vooda scan <path>                   Scan local directory
    vooda scan --repo <url>             Scan remote git repo
    vooda scan --history                Include git history
    vooda scan --staged                 Scan staged changes (pre-commit)
    vooda scan --diff <base>..<head>    Scan diff between commits
    vooda monitor [--wait] [--fail-on]  CI/CD: scan, sync to platform, gate build
    vooda auth login                    Authenticate with Vooda API

Auth (CI-first, no disk write):
    VOODA_API_KEY=vooda_...  VOODA_SERVER=https://vooda.example.com  vooda monitor
    vooda findings list                 List findings
    vooda findings resolve <id>         Resolve a finding
    vooda hook install                  Install pre-commit hook
    vooda config                        Show configuration
"""

import argparse
import json
import os
import sys
import time

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── API persistence helpers ───────────────────────────────

# All CLI↔platform sync logic lives in the shared cli/_sync.py module so the
# `vooda monitor` CI flow and the pre-commit hook (cli/vooda_cli.py) build the
# SAME masked envelope and POST to the same endpoint — single source of truth,
# no divergence.  Imported into this namespace so existing call sites (and the
# unit tests that introspect cli.main) keep resolving.
from cli._sync import (  # noqa: E402
    _CLIENT_UA,
    _assert_safe_transport,
    _resolve_auth,
    _repo_root,
    _rel_path,
    _detect_provenance,
    _envelope_finding,
    _idem_key,
    _post_import,
    _wait_for_import,
    _sync_findings,
)


def _load_auth_optional():
    """Back-compat shim — env-var-first resolution; (None, None) if unset."""
    return _resolve_auth()


def _api_call(method: str, path: str, server: str, token: str, data=None, files=None):
    """Make an authenticated API call. Returns None on failure."""
    import urllib.request
    import urllib.error
    url = f"{server.rstrip('/')}{path}"
    try:
        if files:
            # multipart/form-data using urllib
            import urllib.parse
            boundary = "----VoodaCLIBoundary"
            body_parts = []
            for name, value in (data or {}).items():
                body_parts.append(
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
                )
            for name, (filename, content, content_type) in files.items():
                body_parts.append(
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
                    f"Content-Type: {content_type}\r\n\r\n"
                )
            body = "".join(body_parts).encode() + content + f"\r\n--{boundary}--\r\n".encode()
            req = urllib.request.Request(url, data=body, method=method)
            req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        else:
            body = json.dumps(data).encode() if data else None
            req = urllib.request.Request(url, data=body, method=method)
            req.add_header("Content-Type", "application/json")

        req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        print(f"  ⚠️  API error {e.code}: {err_body[:200]}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  ⚠️  API call failed: {e}", file=sys.stderr)
        return None


def _resolve_repo(server: str, token: str, name: str, url):
    """Find existing repo by name or create it. Returns repo_id or None."""
    import urllib.parse
    result = _api_call("GET", f"/api/v1/repositories?search={urllib.parse.quote(name)}&page_size=10", server, token)
    if result:
        repos = result.get("repositories") or result.get("items") or (result if isinstance(result, list) else [])
        for r in repos:
            if r.get("name") == name:
                return r["id"]

    # Create new repo
    payload = {
        "name": name,
        "url": url or "",
        "source_type": "git_url" if url else "local",
        "scan_mode": "vooda",
    }
    created = _api_call("POST", "/api/v1/repositories", server, token, data=payload)
    if created:
        return created.get("id")
    return None


def cmd_scan(args):
    from services.secret_scan.engine import SecretScanner
    from services.secret_scan.detectors.registry import get_rule_count

    scanner = SecretScanner(enable_entropy=not args.no_entropy)
    target = args.path or "."
    temp_clone_dir = None

    if getattr(args, "repo", None):
        import tempfile
        import subprocess
        temp_clone_dir = tempfile.mkdtemp(prefix="vooda_scan_")
        print(f"Cloning {args.repo}...", file=sys.stderr)
        result = subprocess.run(
            ["git", "clone", "--depth=1", args.repo, temp_clone_dir],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"Error cloning: {result.stderr[:200]}", file=sys.stderr)
            sys.exit(2)
        target = temp_clone_dir

    if args.staged:
        from services.git_history.scanner import GitHistoryScanner
        hist = GitHistoryScanner(scanner)
        findings = hist.scan_staged(target)
    elif args.diff:
        parts = args.diff.split("..")
        if len(parts) != 2:
            print("Error: --diff requires format base..head", file=sys.stderr)
            sys.exit(2)
        from services.git_history.scanner import GitHistoryScanner
        hist = GitHistoryScanner(scanner)
        findings = hist.scan_diff(target, parts[0], parts[1])
    elif args.history:
        from services.git_history.scanner import GitHistoryScanner
        hist = GitHistoryScanner(scanner)
        result = hist.scan_history(
            target,
            max_commits=args.max_commits or 1000,
            scan_all_branches=args.all_branches,
        )
        findings = result.findings
        # Status/meta lines go to STDERR so --format json/sarif keeps stdout
        # clean for `| jq` / SARIF upload.
        print(f"Scanned {result.commits_scanned} commits across {result.branches_scanned} branch(es)",
              file=sys.stderr)
    else:
        if not os.path.exists(target):
            print(f"Error: Path not found: {target}", file=sys.stderr)
            sys.exit(2)
        start = time.time()
        if os.path.isfile(target):
            # Single-file scan: scan_directory()'s os.walk yields NOTHING for a
            # file path, which would silently report a secret-laden file as
            # clean (false negative). Read + scan the file directly.
            try:
                with open(target, "r", errors="ignore") as _fh:
                    _content = _fh.read()
            except OSError as e:
                print(f"Error reading {target}: {e}", file=sys.stderr)
                sys.exit(2)
            findings = scanner.scan_file(os.path.abspath(target), _content)
        else:
            findings = scanner.scan_directory(os.path.abspath(target))
        elapsed = time.time() - start
        print(f"Scanned with {get_rule_count()} rules in {elapsed:.1f}s", file=sys.stderr)

    # Output
    if args.format == "json":
        output = [_finding_to_dict(f) for f in findings]
        print(json.dumps(output, indent=2))
    elif args.format == "sarif":
        print(json.dumps(_to_sarif(findings), indent=2))
    else:
        _print_table(findings)

    # ── Persist to Vooda platform ────────────────────────────
    # Attempt sync if authenticated (env VOODA_API_KEY or `vooda auth login`).
    # Silent no-op otherwise (pre-commit hook, CI without a key, offline).
    # Interactive `vooda scan` is NON-idempotent (each run is its own job);
    # `vooda monitor` is the idempotent CI path.
    if findings:
        _sync_findings(findings, target, "cli", scanner, wait=False, idempotent=False)

    # Cleanup temp clone
    if temp_clone_dir:
        import shutil
        shutil.rmtree(temp_clone_dir, ignore_errors=True)

    # Exit code. Summary → STDERR so json/sarif stdout stays document-only.
    if findings:
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        print(f"\nFound {len(findings)} secret(s): {critical} critical, {high} high", file=sys.stderr)
        sys.exit(1)
    else:
        print("\nNo secrets found.", file=sys.stderr)
        sys.exit(0)


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def cmd_monitor(args):
    """CI/CD mode — scan, sync to the platform as a 'ci' scan (provenance +
    repo auto-detected from the CI environment), and gate the build.

    The build gate is decided on the LOCAL scan results (the CLI has them in
    hand), so the gate is authoritative even if the platform is unreachable.
    Platform sync is for dashboard/history/incident visibility and is
    idempotent (a retried run of the same commit collapses to one job)."""
    from services.secret_scan.engine import SecretScanner
    from services.secret_scan.detectors.registry import get_rule_count

    scanner = SecretScanner(enable_entropy=not args.no_entropy)
    target = args.path or "."
    if not os.path.exists(target):
        print(f"Error: Path not found: {target}", file=sys.stderr)
        sys.exit(2)

    if args.history:
        from services.git_history.scanner import GitHistoryScanner
        hist = GitHistoryScanner(scanner)
        result = hist.scan_history(
            target, max_commits=args.max_commits or 1000, scan_all_branches=args.all_branches,
        )
        findings = result.findings
        print(f"Scanned {result.commits_scanned} commits across "
              f"{result.branches_scanned} branch(es)", file=sys.stderr)
    else:
        start = time.time()
        findings = scanner.scan_directory(os.path.abspath(target))
        print(f"Scanned with {get_rule_count()} rules in {time.time()-start:.1f}s",
              file=sys.stderr)

    # ── Sync to the platform (idempotent CI path) ──
    _sync_findings(findings, target, "ci", scanner, wait=args.wait, idempotent=True)

    # ── Build gate (decided on local findings) ──
    crit = sum(1 for f in findings if (f.severity or "").lower() == "critical")
    high = sum(1 for f in findings if (f.severity or "").lower() == "high")
    print(f"\nFound {len(findings)} secret(s): {crit} critical, {high} high", file=sys.stderr)

    fail_on = (args.fail_on or "high").lower()
    if fail_on == "none":
        print("Build gate disabled (--fail-on none).", file=sys.stderr)
        sys.exit(0)
    threshold = _SEV_ORDER.get(fail_on, 1)
    blocking = [f for f in findings if _SEV_ORDER.get((f.severity or "info").lower(), 4) <= threshold]
    if blocking:
        print(f"BUILD GATE FAILED — {len(blocking)} finding(s) at or above '{fail_on}'.",
              file=sys.stderr)
        sys.exit(1)
    print("BUILD GATE PASSED.", file=sys.stderr)
    sys.exit(0)


def cmd_hook_install(args):
    """Install pre-commit hook in the current git repository."""
    git_dir = os.path.join(args.path or ".", ".git")
    if not os.path.isdir(git_dir):
        print("Error: Not a git repository", file=sys.stderr)
        sys.exit(2)

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)

    hook_script = """#!/bin/sh
# Vooda AI Secret Scanner — pre-commit hook
# Scans staged files for secrets before allowing commit

echo "Vooda AI: Scanning staged changes for secrets..."
vooda scan --staged .

if [ $? -ne 0 ]; then
    echo ""
    echo "COMMIT BLOCKED: Secrets detected in staged files."
    echo "Fix the issues above or use 'git commit --no-verify' to bypass."
    exit 1
fi
"""

    hook_path = os.path.join(hooks_dir, "pre-commit")
    with open(hook_path, "w") as f:
        f.write(hook_script)
    os.chmod(hook_path, 0o755)
    print(f"Pre-commit hook installed at {hook_path}")

    # Also create pre-push hook
    push_script = """#!/bin/sh
# Vooda AI Secret Scanner — pre-push hook
echo "Vooda AI: Scanning for secrets before push..."
vooda scan --history --max-commits 50 .

if [ $? -ne 0 ]; then
    echo ""
    echo "PUSH BLOCKED: Secrets detected in commit history."
    exit 1
fi
"""
    push_path = os.path.join(hooks_dir, "pre-push")
    with open(push_path, "w") as f:
        f.write(push_script)
    os.chmod(push_path, 0o755)
    print(f"Pre-push hook installed at {push_path}")

    # commit-msg hook
    commitmsg_script = """#!/bin/sh
# Vooda AI Secret Scanner — commit-msg hook
# Scans commit message for accidentally pasted secrets

echo "Vooda AI: Checking commit message for secrets..."
MSG_FILE="$1"
MSG_CONTENT=$(cat "$MSG_FILE")

# Quick regex check for common secret patterns in commit message
if echo "$MSG_CONTENT" | grep -qiE '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{36}|sk_live_[A-Za-z0-9]{24}|xoxb-[0-9]{10}|-----BEGIN.*PRIVATE KEY)'; then
    echo ""
    echo "COMMIT BLOCKED: Possible secret detected in commit message."
    echo "Remove the secret from your commit message and try again."
    exit 1
fi
"""
    commitmsg_path = os.path.join(hooks_dir, "commit-msg")
    with open(commitmsg_path, "w") as f:
        f.write(commitmsg_script)
    os.chmod(commitmsg_path, 0o755)
    print(f"Commit-msg hook installed at {commitmsg_path}")

    # Create .pre-commit-config.yaml if it doesn't exist
    config_path = os.path.join(args.path or ".", ".pre-commit-config.yaml")
    if not os.path.exists(config_path):
        config = """# Vooda AI Secret Scanner
repos:
  - repo: local
    hooks:
      - id: vooda-secret-scan
        name: Vooda AI Secret Scan
        entry: vooda scan --staged .
        language: system
        pass_filenames: false
        always_run: true
"""
        with open(config_path, "w") as f:
            f.write(config)
        print(f"Created {config_path}")

    # Create husky config for JS projects
    package_json = os.path.join(args.path or ".", "package.json")
    husky_dir = os.path.join(args.path or ".", ".husky")
    if os.path.exists(package_json) and not os.path.exists(husky_dir):
        os.makedirs(husky_dir, exist_ok=True)
        husky_precommit = """#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

vooda scan --staged .
"""
        husky_path = os.path.join(husky_dir, "pre-commit")
        with open(husky_path, "w") as f:
            f.write(husky_precommit)
        os.chmod(husky_path, 0o755)
        print(f"Husky pre-commit hook created at {husky_path}")


def cmd_auth_login(args):
    """Authenticate with Vooda AI API."""
    import getpass
    config_dir = os.path.expanduser("~/.vooda")
    os.makedirs(config_dir, exist_ok=True)
    config_file = os.path.join(config_dir, "config.json")

    server = args.server.rstrip("/")
    token = args.token or getpass.getpass("API Token (vooda_...): ")

    if not token.startswith("vooda_"):
        print("Warning: Token should start with 'vooda_'", file=sys.stderr)

    # Verify token
    try:
        import urllib.request
        req = urllib.request.Request(
            f"{server}/api/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                print(f"Authenticated with {server}")
            else:
                print(f"Server returned {resp.status}", file=sys.stderr)
                sys.exit(1)
    except Exception as e:
        print(f"Warning: Could not verify token ({e}). Saving anyway.", file=sys.stderr)

    config = {"server": server, "token": token}
    with open(config_file, "w") as f:
        json.dump(config, f)
    os.chmod(config_file, 0o600)
    print(f"Credentials saved to {config_file}")


def _load_auth():
    server, token = _resolve_auth()
    if not server or not token:
        print(
            "Not authenticated. Set VOODA_API_KEY (and VOODA_SERVER) or run "
            "'vooda auth login' first.",
            file=sys.stderr,
        )
        sys.exit(1)
    return server, token


def _api_request(method: str, path: str, data=None):
    import urllib.request, urllib.error
    server, token = _load_auth()
    url = f"{server}{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:200]
        hint = " (this key may lack the read scope for findings)" if e.code in (401, 403) else ""
        print(f"Error: API returned {e.code}{hint}: {detail}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: could not reach Vooda at {server}: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_findings_list(args):
    """List findings from the API."""
    params = f"page=1&page_size={args.limit}"
    if args.severity:
        params += f"&severity={args.severity}"
    data = _api_request("GET", f"/api/v1/findings?{params}")
    findings = data.get("findings", [])

    if args.format == "json":
        print(json.dumps(findings, indent=2))
    else:
        if not findings:
            print("No findings found.")
            return
        sev_colors = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[33m", "low": "\033[37m"}
        reset = "\033[0m"
        print(f"\n{'ID':<12} {'SEVERITY':<10} {'TYPE':<25} {'FILE':<35} {'STATUS':<15}")
        print("-" * 100)
        for f in findings:
            sev = f.get("severity", "medium")
            color = sev_colors.get(sev, "")
            sm = f.get("source_metadata", {}) or {}
            print(f"{f['id'][:11]:<12} {color}{sev:<10}{reset} {(sm.get('secret_type') or '')[:24]:<25} {(f.get('file_path') or '')[:34]:<35} {f.get('classification', ''):<15}")
        print(f"\nShowing {len(findings)} finding(s)")


def cmd_findings_resolve(args):
    """Mark a finding as resolved."""
    try:
        data = _api_request("PATCH", f"/api/v1/findings/{args.finding_id}", {
            "classification": "confirmed_false_positive",
            "review_status": "reviewed",
        })
        print(f"Finding {args.finding_id} resolved.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_config(args):
    from services.secret_scan.detectors.registry import get_all_rules, get_rule_count
    from services.secret_scan.config import SCAN_EXTENSIONS, ENTROPY_THRESHOLDS

    print(f"Vooda AI Secret Scanner Configuration")
    print(f"  Rules loaded: {get_rule_count()}")
    print(f"  File extensions: {len(SCAN_EXTENSIONS)}")
    print(f"  Entropy thresholds: base64={ENTROPY_THRESHOLDS['base64']}, hex={ENTROPY_THRESHOLDS['hex']}")
    print(f"\nRules by provider:")
    from collections import Counter
    providers = Counter(r.secret_type.split("_")[0] for r in get_all_rules())
    for p, c in sorted(providers.items(), key=lambda x: -x[1]):
        print(f"  {p}: {c}")


def _finding_to_dict(f):
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity,
        "file": f.file_path,
        "line": f.line_start,
        "confidence": f.confidence,
        "secret_type": (f.raw_data or {}).get("secret_type"),
        "masked_value": (f.raw_data or {}).get("masked_value"),
        "detection_method": (f.raw_data or {}).get("detection_method"),
    }


def _print_table(findings):
    if not findings:
        return
    sev_colors = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[33m", "low": "\033[37m"}
    reset = "\033[0m"
    print(f"\n{'SEVERITY':<10} {'TYPE':<25} {'FILE':<40} {'LINE':<6} {'CONF':<5}")
    print("-" * 90)
    for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)):
        color = sev_colors.get(f.severity, "")
        secret_type = (f.raw_data or {}).get("secret_type", "")[:24]
        file_path = f.file_path[:39] if f.file_path else ""
        print(f"{color}{f.severity:<10}{reset} {secret_type:<25} {file_path:<40} {f.line_start or '':<6} {f.confidence:<5}")


def _to_sarif(findings):
    from packages.common.scanner_branding import get_sarif_tool_info
    tool = get_sarif_tool_info()
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(f.severity, "note"),
            "message": {"text": f.title},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file_path}, "region": {"startLine": f.line_start or 1}}}],
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": tool, "results": results}]}


def main():
    # CLI hygiene: the scan engine logs a structlog banner
    # ("secret_scanner_compiled"). structlog's default PrintLogger writes to
    # STDOUT, which would corrupt `vooda scan --format json|sarif | jq`. Pin
    # the logger to STDERR so stdout carries ONLY the requested document.
    try:
        import structlog
        structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))
    except Exception:
        pass

    parser = argparse.ArgumentParser(prog="vooda", description="Vooda AI Secret Scanner CLI")
    subparsers = parser.add_subparsers(dest="command")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan for secrets")
    scan_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    scan_parser.add_argument("--history", action="store_true", help="Scan git history")
    scan_parser.add_argument("--staged", action="store_true", help="Scan staged changes")
    scan_parser.add_argument("--diff", type=str, help="Scan diff (base..head)")
    scan_parser.add_argument("--all-branches", action="store_true", help="Scan all branches")
    scan_parser.add_argument("--max-commits", type=int, default=1000, help="Max commits to scan")
    scan_parser.add_argument("--repo", type=str, help="Remote git repo URL to clone and scan")
    scan_parser.add_argument("--no-entropy", action="store_true", help="Disable entropy detection")
    scan_parser.add_argument("--format", choices=["table", "json", "sarif"], default="table", help="Output format")

    # monitor (CI/CD: scan + sync + gate)
    monitor_parser = subparsers.add_parser(
        "monitor", help="CI/CD: scan, sync results to the Vooda platform, gate the build")
    monitor_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    monitor_parser.add_argument("--history", action="store_true", help="Scan git history")
    monitor_parser.add_argument("--all-branches", action="store_true", help="Scan all branches")
    monitor_parser.add_argument("--max-commits", type=int, default=1000, help="Max commits to scan")
    monitor_parser.add_argument("--no-entropy", action="store_true", help="Disable entropy detection")
    monitor_parser.add_argument("--wait", action="store_true",
                                help="Wait for the platform import to finish and report counts")
    monitor_parser.add_argument("--fail-on",
                                choices=["critical", "high", "medium", "low", "info", "none"],
                                default="high",
                                help="Minimum severity that fails the build (default: high)")

    # auth
    auth_parser = subparsers.add_parser("auth", help="Authentication")
    auth_sub = auth_parser.add_subparsers(dest="auth_action")
    login_parser = auth_sub.add_parser("login", help="Login to Vooda AI API")
    login_parser.add_argument("--server", type=str, default="http://localhost:8001", help="Vooda API server URL")
    login_parser.add_argument("--token", type=str, help="API token (or prompted)")

    # findings
    findings_parser = subparsers.add_parser("findings", help="Manage findings")
    findings_sub = findings_parser.add_subparsers(dest="findings_action")
    list_parser = findings_sub.add_parser("list", help="List findings")
    list_parser.add_argument("--severity", type=str, help="Filter by severity")
    list_parser.add_argument("--limit", type=int, default=50, help="Max results")
    list_parser.add_argument("--format", choices=["table", "json"], default="table")
    resolve_parser = findings_sub.add_parser("resolve", help="Resolve a finding")
    resolve_parser.add_argument("finding_id", help="Finding ID to resolve")

    # hook
    hook_parser = subparsers.add_parser("hook", help="Manage git hooks")
    hook_sub = hook_parser.add_subparsers(dest="hook_action")
    install_parser = hook_sub.add_parser("install", help="Install pre-commit hook")
    install_parser.add_argument("path", nargs="?", default=".", help="Repository path")

    # config
    subparsers.add_parser("config", help="Show configuration")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "monitor":
        cmd_monitor(args)
    elif args.command == "auth" and args.auth_action == "login":
        cmd_auth_login(args)
    elif args.command == "findings":
        if args.findings_action == "list":
            cmd_findings_list(args)
        elif args.findings_action == "resolve":
            cmd_findings_resolve(args)
        else:
            findings_parser.print_help()
    elif args.command == "hook" and args.hook_action == "install":
        cmd_hook_install(args)
    elif args.command == "config":
        cmd_config(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
