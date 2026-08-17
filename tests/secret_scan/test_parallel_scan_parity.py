"""Intra-scan MULTIPROCESS parallelism parity tests.

scan_directory() can scan files across a PROCESS pool (max_workers) for true
multi-core speedup — threads don't help because google-re2 doesn't release the
GIL. That parallelism must NEVER change WHAT is found. These tests force the
process-pool path (VOODA_SCAN_PARALLEL_MIN_FILES=1) on a small fixture and
assert byte-identical, deterministic output vs the sequential walk, plus the
safety fallbacks (small repo, worker-count resolution).
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "a.py").write_text(
        'GITHUB_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"\nx = 1\n'
    )
    (tmp_path / "b.env").write_text(
        "STRIPE=sk_live_51H8xK2eZvKYlo2C9qVxYzAbCdEfGhIjKlMnOpQrStUvWx\n"
    )
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.txt").write_text("tok: ghp_ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJ012345\n")
    (sub / "clean.py").write_text("def f():\n    return 42\n")
    (tmp_path / "empty.py").write_text("")
    return str(tmp_path)


def _canon(findings):
    return sorted(
        (f.file_path, f.line_start or 0, f.rule_id or "", (f.raw_data or {}).get("secret_hash", ""))
        for f in findings
    )


def test_parallel_matches_sequential(repo, monkeypatch):
    monkeypatch.setenv("VOODA_SCAN_PARALLEL_MIN_FILES", "1")  # force the process pool
    sc = SecretScanner()
    seq = sc.scan_directory(repo, max_workers=1)   # forced sequential
    par = sc.scan_directory(repo, max_workers=4)   # process pool
    assert _canon(seq) == _canon(par), "parallel scan diverged from sequential"
    assert len(seq) >= 2, "fixture should plant at least 2 detectable secrets"


def test_parallel_deterministic(repo, monkeypatch):
    monkeypatch.setenv("VOODA_SCAN_PARALLEL_MIN_FILES", "1")
    sc = SecretScanner()
    runs = [_canon(sc.scan_directory(repo, max_workers=4)) for _ in range(3)]
    assert runs[0] == runs[1] == runs[2], "parallel scan is non-deterministic"


def test_small_repo_falls_back_to_sequential(repo, monkeypatch):
    # Default threshold (400): a tiny repo must NOT spin up a process pool, yet
    # must still find the planted secrets.
    monkeypatch.delenv("VOODA_SCAN_PARALLEL_MIN_FILES", raising=False)
    sc = SecretScanner()
    assert len(sc.scan_directory(repo, max_workers=8)) >= 2


def test_resolve_workers_arg_env_cap_default(monkeypatch):
    sc = SecretScanner()
    assert sc._resolve_scan_workers(1) == 1          # arg forces sequential
    assert sc._resolve_scan_workers(4) == 4
    monkeypatch.setenv("VOODA_SCAN_WORKERS", "3")
    assert sc._resolve_scan_workers(None) == 3        # env honoured
    monkeypatch.setenv("VOODA_SCAN_WORKERS", "99")
    assert sc._resolve_scan_workers(None) == 16       # capped at 16
    monkeypatch.setenv("VOODA_SCAN_WORKERS", "bogus")
    assert sc._resolve_scan_workers(None) >= 1        # bad env → safe default
