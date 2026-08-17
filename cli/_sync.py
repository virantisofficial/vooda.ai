#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Shared CLI ↔ platform sync — the SINGLE source of truth for both CLI
entrypoints (``cli/main.py`` and ``cli/vooda_cli.py``).

Both the ``vooda monitor`` CI flow and the pre-commit hook (``vooda_cli.py
scan --staged``) build the SAME native masked envelope and POST it to the
same ``/api/v1/imports/scan`` endpoint, so the import path can never diverge
between them.

Security invariants enforced here (WS-6 at the source):
  * the raw secret value never leaves the machine — snippets are run through
    the authoritative scanner redaction and only ``masked_value`` + one-way
    ``secret_hash`` are sent (``_raw_value_for_verification`` is never copied);
  * the API key is refused over plaintext http to a PUBLIC host;
  * file paths are made repo-RELATIVE so a CLI finding and a server-clone
    finding compute the IDENTICAL ``stability_id`` (cross-client dedup).
"""
from __future__ import annotations

import json
import os
import sys
import time

# Ensure project root is importable (engine, etc.) regardless of caller.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_CLIENT_UA = "vooda-cli/1.0.0"


def _assert_safe_transport(server: str, token: str):
    """Refuse to send a bearer API key over plaintext http:// to a NON-local
    host.  A CI secret travelling in clear text is exactly the kind of leak
    Vooda exists to prevent — so we hard-fail rather than silently expose it.
    Internal single-label names / *.local / RFC1918 + loopback IPs over http
    are allowed (an enterprise Vooda on a private network is legitimate)."""
    from urllib.parse import urlparse
    u = urlparse(server)
    host = (u.hostname or "").lower()
    # A single-label host (no dots, e.g. "api", "localhost", an internal
    # Docker/K8s service name) can ONLY resolve on a private/internal network
    # — it can never be a public FQDN — so plaintext http to it is not a
    # public-internet exposure.  A public host always has a dot.
    is_internal = (
        host in ("localhost", "127.0.0.1", "::1")
        or host.endswith(".local")
        or ("." not in host and ":" not in host)  # single-label internal name
    )
    if not is_internal:
        # Private/loopback IP (RFC1918, 127/8, ::1, fc00::/7) is internal too.
        try:
            import ipaddress
            ip = ipaddress.ip_address(host)
            is_internal = ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            pass
    if u.scheme != "https" and not is_internal:
        print(
            f"Refusing to send the Vooda API key over insecure http:// to "
            f"non-local host '{host or server}'. Use an https:// server URL.",
            file=sys.stderr,
        )
        sys.exit(2)


def _resolve_auth():
    """Resolve (server, token).

    Precedence (CI-first, no-disk):
      1. Environment: VOODA_API_KEY (+ optional VOODA_SERVER).  Nothing is
         written to disk — the ideal path for CI, where the key is injected
         as a masked secret and must never be persisted on the runner.
      2. ~/.vooda/config.json (written by `vooda auth login`) — dev machines.

    Returns (None, None) when not configured (callers treat as "skip sync").
    """
    env_token = os.environ.get("VOODA_API_KEY")
    if env_token:
        server = (os.environ.get("VOODA_SERVER") or "http://localhost:8001").rstrip("/")
        _assert_safe_transport(server, env_token)
        return server, env_token

    config_file = os.path.expanduser("~/.vooda/config.json")
    if not os.path.exists(config_file):
        return None, None
    try:
        with open(config_file) as f:
            config = json.load(f)
        server = (config.get("server") or "").rstrip("/") or None
        token = config.get("token")
        if server and token:
            _assert_safe_transport(server, token)
        return server, token
    except Exception:
        return None, None


def _repo_root(target: str) -> str:
    """Resolve the git toplevel of `target` (so paths match a server clone's
    repo-relative layout), falling back to the scan target's abspath."""
    try:
        import subprocess as sp
        r = sp.run(["git", "-C", target, "rev-parse", "--show-toplevel"],
                   capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return os.path.abspath(r.stdout.strip())
    except Exception:
        pass
    return os.path.abspath(target)


def _rel_path(file_path, repo_root: str) -> str:
    """Repo-RELATIVE path — the single most important field for cross-client
    dedup.  A CLI finding at /home/runner/work/app/src/x.py and a server clone
    finding at /app/storage/clones/abc/src/x.py must BOTH reduce to src/x.py
    so they compute the identical stability_id."""
    if not file_path:
        return "unknown"
    ap = os.path.abspath(file_path)
    if ap.startswith(repo_root):
        return ap[len(repo_root):].lstrip("/")
    return str(file_path).lstrip("/")


def _detect_provenance(repo_root: str):
    """Best-effort provenance autodetect.  Returns (provenance_dict, repo_ref).

    Recognises GitHub Actions and GitLab CI explicitly, then fills any gaps
    (commit/branch/remote) from local git.  `repo_ref` is the git remote URL
    the server resolves to a Vooda repository."""
    env = os.environ
    prov: dict = {}
    repo_ref = None

    if env.get("GITHUB_ACTIONS") == "true":
        prov["ci_provider"] = "github_actions"
        prov["commit_sha"] = env.get("GITHUB_SHA")
        prov["branch"] = env.get("GITHUB_REF_NAME") or env.get("GITHUB_HEAD_REF")
        prov["actor"] = env.get("GITHUB_ACTOR")
        srv = env.get("GITHUB_SERVER_URL", "https://github.com")
        repo = env.get("GITHUB_REPOSITORY")
        run = env.get("GITHUB_RUN_ID")
        if repo and run:
            prov["ci_pipeline_url"] = f"{srv}/{repo}/actions/runs/{run}"
        if repo:
            repo_ref = f"{srv}/{repo}"
    elif env.get("GITLAB_CI") == "true":
        prov["ci_provider"] = "gitlab_ci"
        prov["commit_sha"] = env.get("CI_COMMIT_SHA")
        prov["branch"] = env.get("CI_COMMIT_REF_NAME")
        prov["actor"] = env.get("GITLAB_USER_LOGIN") or env.get("GITLAB_USER_NAME")
        prov["ci_pipeline_url"] = env.get("CI_PIPELINE_URL")
        repo_ref = env.get("CI_PROJECT_URL")

    def _git(*a):
        try:
            import subprocess as sp
            r = sp.run(["git", "-C", repo_root, *a], capture_output=True, text=True, timeout=5)
            return r.stdout.strip() if r.returncode == 0 else None
        except Exception:
            return None

    if not prov.get("commit_sha"):
        prov["commit_sha"] = _git("rev-parse", "HEAD")
    if not prov.get("branch"):
        b = _git("rev-parse", "--abbrev-ref", "HEAD")
        prov["branch"] = None if b == "HEAD" else b  # detached HEAD → leave unset
    if not repo_ref:
        repo_ref = _git("remote", "get-url", "origin")

    prov = {k: v for k, v in prov.items() if v}  # drop empties
    return prov, repo_ref


def _envelope_finding(f, repo_root: str, scanner) -> dict:
    """Map one engine finding to the import schema — MASKED ONLY (WS-6).

    The raw secret value never leaves the machine: the snippet is run through
    the authoritative scanner redaction (the same pass the server uses), and
    only `masked_value` + one-way `secret_hash` are sent.  The raw
    `_raw_value_for_verification` is deliberately NOT included."""
    rd = getattr(f, "raw_data", None) or {}
    snippet = getattr(f, "code_snippet", None) or ""
    if snippet:
        try:
            from services.secret_scan.engine import redact_with_scanner
            snippet = redact_with_scanner(snippet, scanner)
        except Exception:
            snippet = None  # if we can't guarantee masking, send no snippet
    st = rd.get("secret_type")
    return {
        "rule_id": getattr(f, "rule_id", "") or "",
        "title": getattr(f, "title", None),
        "description": getattr(f, "description", None),
        "severity": getattr(f, "severity", None),
        "vulnerability_category": getattr(f, "category", None) or "secret",
        "cwe": getattr(f, "cwe", None),
        "file_path": _rel_path(getattr(f, "file_path", None), repo_root),
        "line_start": getattr(f, "line_start", None),
        "line_end": getattr(f, "line_end", None),
        "confidence": getattr(f, "confidence", None),
        "code_snippet": snippet or None,
        "secret_type": st,
        "masked_value": rd.get("masked_value"),
        "secret_hash": rd.get("secret_hash"),
        "detection_method": rd.get("detection_method"),
        "validation_status": rd.get("validation_status"),
        "provider": rd.get("provider") or (st.split("_")[0] if st else None),
        "entropy_score": rd.get("entropy_score"),
        "commit_sha": None,
    }


def _idem_key(repo_ref, provenance) -> str:
    """Deterministic key so CI retries of the SAME commit collapse to one
    import job (server enforces partial-unique tenant+key)."""
    import hashlib
    basis = f"{repo_ref}|{provenance.get('commit_sha','')}|{provenance.get('branch','')}"
    return hashlib.sha256(basis.encode()).hexdigest()[:64]


def _post_import(server: str, token: str, envelope: dict, idem):
    """POST the native envelope to /api/v1/imports/scan.  Returns the parsed
    response dict, or None on failure (printing a helpful message)."""
    import urllib.request, urllib.error
    url = f"{server.rstrip('/')}/api/v1/imports/scan"
    body = json.dumps(envelope).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    if idem:
        req.add_header("Idempotency-Key", idem)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        if e.code == 404:
            print("  ⚠️  Repository not onboarded in Vooda — add it in the dashboard "
                  "first, then re-run.", file=sys.stderr)
        elif e.code in (401, 403):
            print(f"  ⚠️  Auth/scope error ({e.code}). The key needs the "
                  f"'findings:import' scope. {err[:160]}", file=sys.stderr)
        else:
            print(f"  ⚠️  Sync failed ({e.code}): {err[:200]}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  ⚠️  Sync failed: {e}", file=sys.stderr)
        return None


def _wait_for_import(server: str, token: str, job_id: str, timeout_s: int = 120):
    """Poll the import-status endpoint (readable by the write-only key for its
    OWN job) until terminal, then print created/updated counts."""
    import urllib.request, urllib.error
    url = f"{server.rstrip('/')}/api/v1/imports/scan/{job_id}"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                d = json.loads(resp.read())
        except Exception as e:
            print(f"  ⚠️  Could not read import status: {e}", file=sys.stderr)
            return
        status = d.get("status")
        if status in ("completed", "failed", "cancelled"):
            stats = d.get("stats") or {}
            if status == "completed":
                print(f"  ✅ platform sync complete: "
                      f"{stats.get('imported_created', '?')} new + "
                      f"{stats.get('imported_updated', '?')} existing finding(s)",
                      file=sys.stderr)
            else:
                print(f"  ⚠️  platform sync {status}: {d.get('status_message', '')}",
                      file=sys.stderr)
            return
        time.sleep(2)
    print("  ⚠️  Timed out waiting for platform sync (it may still finish).", file=sys.stderr)


def _sync_findings(findings: list, target: str, scan_type: str, scanner, *, wait: bool = False, idempotent: bool = False):
    """Build the native masked envelope and POST it to the platform.

    Silent no-op when unauthenticated (pre-commit / offline use).  `scan_type`
    is "cli" (dev machine) or "ci" (pipeline).  When `idempotent`, a commit-
    derived Idempotency-Key collapses retries of the same commit.
    Returns the import response dict, or None."""
    server, token = _resolve_auth()
    if not server or not token:
        return None
    if not findings:
        return None

    repo_root = _repo_root(target)
    provenance, repo_ref = _detect_provenance(repo_root)
    if not repo_ref:
        print("  ⚠️  No git remote ('origin') found — can't map this scan to a "
              "Vooda repository, skipping platform sync.", file=sys.stderr)
        return None

    envelope = {
        "repository_ref": repo_ref,
        "provenance": {**provenance, "scan_type": scan_type},
        "findings": [_envelope_finding(f, repo_root, scanner) for f in findings],
        "client": _CLIENT_UA,
        "stats": {"findings_total": len(findings)},
    }
    idem = _idem_key(repo_ref, provenance) if (idempotent and provenance.get("commit_sha")) else None

    print(f"\n  📤 Syncing {len(findings)} finding(s) to Vooda ({server})…", file=sys.stderr)
    resp = _post_import(server, token, envelope, idem)
    if not resp:
        return None
    job_id = resp.get("scan_job_id")
    tag = "replay" if resp.get("idempotent_replay") else "new"
    print(f"  ✅ accepted {resp.get('findings_received', len(findings))} finding(s) "
          f"→ job {job_id} ({tag})", file=sys.stderr)
    if wait and job_id:
        _wait_for_import(server, token, job_id)
    return resp
