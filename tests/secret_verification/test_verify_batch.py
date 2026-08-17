"""Unit tests for S2 bounded-concurrent verification (`_verify_batch` in
apps/worker/tasks.py).

Proves: correct per-outcome counts + per-ParsedFinding mutations; that
concurrency is bounded by the semaphore yet genuinely overlapping; that a
finding's verdict is INDEPENDENT of concurrency (parity); and that the absolute
wall-clock backstop cancels stragglers so the phase can never hang.

`_verify_batch` calls the module-global `_verify_with_cache`, so we monkeypatch
`apps.worker.tasks._verify_with_cache`.
"""
from __future__ import annotations

import asyncio
import time

import pytest

import apps.worker.tasks as tasks
from services.secret_verification.verifier import VerificationResult


class FakePF:
    """Minimal stand-in for a ParsedFinding (only .raw_data + .severity used)."""
    def __init__(self, provider, severity="medium"):
        self.raw_data = {
            "_raw_value_for_verification": "x",
            "provider": provider,
            "detection_method": "regex",
            "secret_hash": "h_" + provider,
        }
        self.severity = severity


def _mk(provider, n):
    return [FakePF(provider) for _ in range(n)]


@pytest.fixture
def stub_verify(monkeypatch):
    """Replace _verify_with_cache with a verdict-by-provider stub that also
    records concurrency (in-flight / max-in-flight)."""
    state = {"inflight": 0, "max_inflight": 0, "calls": 0}

    async def fake(verify_sm, tenant_id, secret_hash):
        state["calls"] += 1
        state["inflight"] += 1
        state["max_inflight"] = max(state["max_inflight"], state["inflight"])
        try:
            await asyncio.sleep(0.02)
            p = verify_sm["provider"]
            if p == "active_p":
                return VerificationResult(status="active", details="live", provider=p)
            if p == "inactive_p":
                return VerificationResult(status="inactive", details="dead", provider=p)
            if p == "err_p":
                raise RuntimeError("boom")
            return None  # → skipped
        finally:
            state["inflight"] -= 1

    monkeypatch.setattr(tasks, "_verify_with_cache", fake)
    return state


@pytest.mark.asyncio
async def test_counts_and_mutations(stub_verify):
    pfs = _mk("active_p", 5) + _mk("inactive_p", 3) + _mk("err_p", 2) + _mk("skip_p", 4)
    stats = await tasks._verify_batch(pfs, "t1", concurrency=8, abs_budget_s=30, blast_fn=None)

    assert stats == {"active": 5, "inactive": 3, "verified": 8,
                     "error": 2, "skipped": 4, "total": 14}
    # active → stamped + escalated to critical
    for pf in pfs[:5]:
        assert pf.raw_data["validation_status"] == "active"
        assert pf.severity == "critical"
    # inactive → stamped, NOT escalated
    for pf in pfs[5:8]:
        assert pf.raw_data["validation_status"] == "inactive"
        assert pf.severity == "medium"
    # error + skip → untouched
    for pf in pfs[8:14]:
        assert "validation_status" not in pf.raw_data


@pytest.mark.asyncio
async def test_concurrency_is_bounded_but_real(stub_verify):
    await tasks._verify_batch(_mk("inactive_p", 16), "t1", concurrency=4, abs_budget_s=30)
    assert stub_verify["max_inflight"] <= 4      # never exceeds the cap
    assert stub_verify["max_inflight"] > 1       # genuinely concurrent


@pytest.mark.asyncio
async def test_concurrency_one_is_sequential(stub_verify):
    await tasks._verify_batch(_mk("inactive_p", 6), "t1", concurrency=1, abs_budget_s=30)
    assert stub_verify["max_inflight"] == 1


@pytest.mark.asyncio
async def test_verdict_parity_across_concurrency(monkeypatch):
    """Same inputs, different concurrency → identical verdicts + stats."""
    async def fake(sm, tid, h):
        await asyncio.sleep(0.005)
        p = sm["provider"]
        return VerificationResult(
            status="active" if p == "active_p" else "inactive", details="", provider=p)
    monkeypatch.setattr(tasks, "_verify_with_cache", fake)

    seq = _mk("active_p", 7) + _mk("inactive_p", 9)
    par = _mk("active_p", 7) + _mk("inactive_p", 9)
    s1 = await tasks._verify_batch(seq, "t", concurrency=1, abs_budget_s=30)
    s8 = await tasks._verify_batch(par, "t", concurrency=8, abs_budget_s=30)

    assert s1 == s8
    assert ([p.raw_data["validation_status"] for p in seq]
            == [p.raw_data["validation_status"] for p in par])


@pytest.mark.asyncio
async def test_absolute_backstop_cancels_stragglers(monkeypatch):
    async def hang(sm, tid, h):
        await asyncio.sleep(60)   # never completes within the budget
        return VerificationResult(status="active", details="", provider="x")
    monkeypatch.setattr(tasks, "_verify_with_cache", hang)

    pfs = _mk("active_p", 5)
    t0 = time.monotonic()
    stats = await tasks._verify_batch(pfs, "t", concurrency=8, abs_budget_s=1)
    elapsed = time.monotonic() - t0

    assert elapsed < 5            # backstop fired (~1s), not 60s
    assert stats["verified"] == 0
    assert stats["error"] == 5    # all stragglers → error, none stamped
    for pf in pfs:
        assert "validation_status" not in pf.raw_data


@pytest.mark.asyncio
async def test_empty_batch_is_noop(stub_verify):
    stats = await tasks._verify_batch([], "t", concurrency=8, abs_budget_s=30)
    assert stats == {"active": 0, "inactive": 0, "verified": 0,
                     "error": 0, "skipped": 0, "total": 0}
    assert stub_verify["calls"] == 0


# ── live-bar on_progress (k/N) — completion-ordered progress callback ──────────

@pytest.mark.asyncio
async def test_on_progress_fires_once_per_completion_monotonic(stub_verify):
    """on_progress is called exactly once per resolved credential, in strictly
    increasing `done` order ending at N/N — the contract the step-5 verify bar
    relies on to climb 55→60. `total` is constant = batch size."""
    pfs = _mk("inactive_p", 10)
    seen = []

    async def on_prog(done, total):
        seen.append((done, total))

    stats = await tasks._verify_batch(
        pfs, "t", concurrency=4, abs_budget_s=30, on_progress=on_prog)

    assert stats["verified"] == 10
    assert [d for d, _ in seen] == list(range(1, 11))   # 1..N, no gaps/dupes
    assert all(t == 10 for _, t in seen)                # total constant
    assert seen[-1] == (10, 10)                          # lands on N/N


@pytest.mark.asyncio
async def test_on_progress_exception_never_breaks_verification(stub_verify):
    """A throwing progress callback (UI/DB hiccup) must not corrupt counts —
    progress is best-effort."""
    pfs = _mk("active_p", 3) + _mk("inactive_p", 2)

    async def boom(done, total):
        raise RuntimeError("ui/db exploded mid-tick")

    stats = await tasks._verify_batch(
        pfs, "t", concurrency=2, abs_budget_s=30, on_progress=boom)

    assert stats == {"active": 3, "inactive": 2, "verified": 5,
                     "error": 0, "skipped": 0, "total": 5}


@pytest.mark.asyncio
async def test_timeout_actually_cancels_stragglers_no_leak(monkeypatch):
    """REGRESSION GUARD for the as_completed refactor: when the abs budget
    expires, every in-flight verification must be CANCELLED (not leaked), and
    NO k/N tick may fire for a credential that never completed.

    This catches the subtle bug where the inner ``except Exception`` around
    ``await fut`` swallows the ``asyncio.TimeoutError`` that ``as_completed``
    raises at the deadline (TimeoutError IS an Exception subclass): with the
    bug, stragglers are never cancelled (``cancelled == 0``) and bogus ticks
    fire for the swallowed timeouts (``progress == [1..5]``). With the fix,
    the timeout propagates to the cancel/drain handler."""
    state = {"started": 0, "cancelled": 0}

    async def hang(sm, tid, h):
        state["started"] += 1
        try:
            await asyncio.sleep(60)            # never completes within budget
        except asyncio.CancelledError:
            state["cancelled"] += 1
            raise
        return VerificationResult(status="active", details="", provider="x")

    monkeypatch.setattr(tasks, "_verify_with_cache", hang)

    progress = []

    async def on_prog(done, total):
        progress.append(done)

    pfs = _mk("active_p", 5)
    t0 = time.monotonic()
    stats = await tasks._verify_batch(
        pfs, "t", concurrency=8, abs_budget_s=1, on_progress=on_prog)
    elapsed = time.monotonic() - t0

    assert elapsed < 5                       # backstop fired ~1s, not 60s
    assert stats["error"] == 5 and stats["verified"] == 0
    assert state["started"] == 5             # all began
    assert state["cancelled"] == 5           # all CANCELLED — no leaked tasks
    assert progress == []                    # no completion → no k/N tick
    for pf in pfs:
        assert "validation_status" not in pf.raw_data


@pytest.mark.asyncio
async def test_partial_completion_before_timeout(monkeypatch):
    """Mixed batch where some resolve fast and some hang past the budget:
    the fast ones count + tick; the slow ones are cancelled → error. Proves
    on_progress only reflects genuinely-completed credentials."""
    async def mixed(sm, tid, h):
        p = sm["provider"]
        if p == "fast_p":
            await asyncio.sleep(0.01)
            return VerificationResult(status="inactive", details="", provider=p)
        await asyncio.sleep(60)              # slow → cancelled at budget
        return VerificationResult(status="active", details="", provider=p)

    monkeypatch.setattr(tasks, "_verify_with_cache", mixed)

    progress = []

    async def on_prog(done, total):
        progress.append((done, total))

    pfs = _mk("fast_p", 4) + _mk("slow_p", 3)
    stats = await tasks._verify_batch(
        pfs, "t", concurrency=8, abs_budget_s=1, on_progress=on_prog)

    assert stats["inactive"] == 4           # the fast ones resolved
    assert stats["error"] == 3              # the slow ones cancelled
    assert stats["total"] == 7
    # exactly 4 ticks (one per fast completion), monotonic, total constant = 7
    assert [d for d, _ in progress] == [1, 2, 3, 4]
    assert all(t == 7 for _, t in progress)
