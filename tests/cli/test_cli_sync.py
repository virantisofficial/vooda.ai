"""Unit tests for the CLI two-way-sync helpers (``cli/main.py``, P0).

Guard the source-side guarantees that make CI sync safe and consistent:

  * the transport guard refuses to send the API key over plaintext http to a
    PUBLIC host (but allows internal / private / TLS),
  * env-var auth wins over the config file and never writes disk,
  * file paths are made repo-RELATIVE so a CLI finding and a server-clone
    finding compute the IDENTICAL stability_id (the dedup invariant),
  * the import envelope carries ``masked_value`` + one-way ``secret_hash``
    only — the raw value (incl. ``_raw_value_for_verification``) never leaves
    the machine,
  * provenance is auto-detected from CI env (GitHub Actions here).

Pure unit tests — the helpers are module-level and import lazily, so importing
``cli.main`` does not pull in the scan engine.
"""
from __future__ import annotations

import os
import sys

import pytest

# Project root on path so `import cli.main` resolves.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import cli.main as C  # noqa: E402


# ── transport guard ──────────────────────────────────────────────────
@pytest.mark.parametrize(
    "server,allowed",
    [
        ("http://api:8000", True),            # single-label internal name
        ("http://localhost:8001", True),
        ("http://10.0.0.5:8000", True),       # RFC1918
        ("http://192.168.1.10:8000", True),   # RFC1918
        ("http://172.20.0.3:8000", True),     # RFC1918
        ("https://vooda.example.com", True),  # TLS public is fine
        ("http://evil.example.com", False),   # plaintext to public FQDN
        ("http://8.8.8.8:8000", False),       # plaintext to public IP
    ],
)
def test_transport_guard(server, allowed):
    if allowed:
        C._assert_safe_transport(server, "vooda_x")  # must not raise
    else:
        with pytest.raises(SystemExit):
            C._assert_safe_transport(server, "vooda_x")


# ── env-var auth precedence (CI-first, no disk) ──────────────────────
def test_env_auth_wins_over_config(monkeypatch):
    monkeypatch.setenv("VOODA_API_KEY", "vooda_abc")
    monkeypatch.setenv("VOODA_SERVER", "https://srv.example.com")
    assert C._resolve_auth() == ("https://srv.example.com", "vooda_abc")


def test_env_auth_default_server(monkeypatch):
    monkeypatch.setenv("VOODA_API_KEY", "vooda_abc")
    monkeypatch.delenv("VOODA_SERVER", raising=False)
    server, token = C._resolve_auth()
    assert token == "vooda_abc"
    assert server == "http://localhost:8001"


# ── repo-relative path: the cross-client dedup invariant ─────────────
def test_rel_path_server_clone_and_ci_runner_match():
    server = C._rel_path("/app/storage/clones/abc/src/config.py", "/app/storage/clones/abc")
    runner = C._rel_path("/home/runner/work/app/src/config.py", "/home/runner/work/app")
    assert server == runner == "src/config.py"


# ── idempotency key ──────────────────────────────────────────────────
def test_idem_key_deterministic_and_64_hex():
    a = C._idem_key("https://github.com/o/r", {"commit_sha": "abc", "branch": "main"})
    b = C._idem_key("https://github.com/o/r", {"commit_sha": "abc", "branch": "main"})
    assert a == b and len(a) == 64


def test_idem_key_changes_with_commit():
    assert C._idem_key("r", {"commit_sha": "abc"}) != C._idem_key("r", {"commit_sha": "def"})


# ── envelope masking (WS-6): raw value never leaves the machine ──────
class _NoopScanner:
    """Stand-in scanner — redact_with_scanner over it is a no-op, so the
    masking we assert comes purely from the field mapping, not the engine."""

    def scan_file(self, name, content):
        return []


class _Finding:
    rule_id = "aws-access-key"
    title = "AWS access key"
    description = "hardcoded"
    severity = "critical"
    file_path = "/repo/src/x.py"
    line_start = 3
    line_end = 3
    confidence = 0.9
    category = "secret"
    cwe = "CWE-798"
    code_snippet = 'key = "AKIA****MPLE"'  # already masked
    raw_data = {
        "secret_type": "aws_access_key",
        "masked_value": "AKIA****MPLE",
        "secret_hash": "deadbeef",
        # The raw value lives in memory during a scan — it must NOT be copied
        # into the outgoing envelope.
        "_raw_value_for_verification": "AKIAIOSFODNN7EXAMPLE",
    }


def test_envelope_is_masked_only_and_repo_relative():
    item = C._envelope_finding(_Finding(), "/repo", _NoopScanner())
    assert item["masked_value"] == "AKIA****MPLE"
    assert item["secret_hash"] == "deadbeef"
    assert item["file_path"] == "src/x.py"  # repo-relative
    # The raw value must appear NOWHERE in the envelope.
    assert "AKIAIOSFODNN7EXAMPLE" not in repr(item)
    assert "_raw_value_for_verification" not in item


# ── provenance autodetect (GitHub Actions) ───────────────────────────
def test_detect_provenance_github_actions(monkeypatch, tmp_path):
    for k in list(os.environ):
        if k.startswith(("GITHUB_", "GITLAB_", "CI_")):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_SHA", "deadbeefcafe")
    monkeypatch.setenv("GITHUB_REF_NAME", "feature/x")
    monkeypatch.setenv("GITHUB_ACTOR", "octocat")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_RUN_ID", "99")
    # tmp_path is not a git repo, so the local-git fallback can't override the
    # GHA-provided commit/branch.
    prov, repo_ref = C._detect_provenance(str(tmp_path))
    assert prov["ci_provider"] == "github_actions"
    assert prov["commit_sha"] == "deadbeefcafe"
    assert prov["branch"] == "feature/x"
    assert prov["actor"] == "octocat"
    assert prov["ci_pipeline_url"] == "https://github.com/org/repo/actions/runs/99"
    assert repo_ref == "https://github.com/org/repo"
