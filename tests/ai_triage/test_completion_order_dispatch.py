# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Triage dispatches in completion order, not fixed batches.

Slicing findings into fixed chunks and awaiting ``gather`` on each means
the next chunk cannot start until the SLOWEST call in the current one
returns, which idles fast calls behind slow ones and caps effective
parallelism at the chunk size rather than at ``max_concurrent``.

These tests pin the behaviour that replaces it: everything is scheduled
at once, the semaphore and the rpm bucket are the only limits, and
progress fires on real completions.
"""
import asyncio
import time

import pytest

from services.ai_triage.batch import BatchTriageProcessor, BatchTriageConfig, TriageResult


class _FakeEngine:
    """Engine stub with controllable per-finding latency."""

    def __init__(self, latencies):
        self.latencies = latencies
        self.started_at = {}
        self.concurrent = 0
        self.peak_concurrent = 0

    async def triage_finding(self, finding, code_context, repo_context):
        fid = finding["id"]
        self.concurrent += 1
        self.peak_concurrent = max(self.peak_concurrent, self.concurrent)
        self.started_at[fid] = time.monotonic()
        try:
            await asyncio.sleep(self.latencies.get(fid, 0.01))
            return {"classification": "likely_false_positive", "confidence_score": 0.9}
        finally:
            self.concurrent -= 1


def _findings(n):
    return [{"id": f"f{i}", "title": "t", "file_path": "a.py"} for i in range(n)]


def _proc(engine, **cfg):
    base = dict(batch_size=5, max_concurrent=10, rate_limit_rpm=100000,
                max_retries=0, request_timeout=30)
    base.update(cfg)
    return BatchTriageProcessor(engine, BatchTriageConfig(**base))


def _run(coro):
    return asyncio.run(coro)


def test_every_finding_is_processed():
    eng = _FakeEngine({})
    res = _run(_proc(eng).process_batch(_findings(23), {}, {}))
    assert len(res) == 23
    assert all(r.success for r in res)


def test_concurrency_reaches_max_concurrent_not_batch_size():
    """The core regression: with batch_size=5 the old code could never
    exceed 5 in flight even with max_concurrent=10."""
    eng = _FakeEngine({f"f{i}": 0.25 for i in range(20)})
    _run(_proc(eng, batch_size=5, max_concurrent=10).process_batch(_findings(20), {}, {}))
    assert eng.peak_concurrent > 5, (
        f"peak concurrency {eng.peak_concurrent} — still capped by batch_size, "
        f"so max_concurrent remains unreachable"
    )
    assert eng.peak_concurrent <= 10, "must still respect max_concurrent"


def test_a_slow_call_does_not_block_later_findings():
    """One 1.5s straggler must not gate the fast calls behind it."""
    lat = {f"f{i}": 0.02 for i in range(12)}
    lat["f0"] = 1.5
    eng = _FakeEngine(lat)
    _run(_proc(eng, batch_size=5, max_concurrent=10).process_batch(_findings(12), {}, {}))
    # Under the old barrier, f5+ could not START until f0's chunk finished.
    assert eng.started_at["f11"] - eng.started_at["f0"] < 1.0, (
        "later findings waited on the slow call — barrier still present"
    )


def test_progress_fires_once_per_finding():
    eng = _FakeEngine({})
    seen = []

    async def on_progress(done, total):
        seen.append((done, total))

    _run(_proc(eng).process_batch(_findings(9), {}, {}, on_progress=on_progress))
    assert [d for d, _ in seen] == list(range(1, 10))
    assert all(t == 9 for _, t in seen)


def test_one_failure_does_not_abort_the_run():
    class _Flaky(_FakeEngine):
        async def triage_finding(self, finding, code_context, repo_context):
            if finding["id"] == "f3":
                raise RuntimeError("provider exploded")
            return await super().triage_finding(finding, code_context, repo_context)

    res = _run(_proc(_Flaky({}), max_retries=0).process_batch(_findings(8), {}, {}))
    assert len(res) == 8
    assert sum(1 for r in res if not r.success) == 1
    assert sum(1 for r in res if r.success) == 7


def test_rate_limit_is_still_enforced():
    """Removing the barrier must not remove the rpm ceiling."""
    eng = _FakeEngine({})
    t0 = time.monotonic()
    _run(_proc(eng, rate_limit_rpm=120, max_concurrent=10).process_batch(_findings(6), {}, {}))
    elapsed = time.monotonic() - t0
    # 120/min = one every 0.5s; 6 calls cannot complete in under ~2s.
    assert elapsed > 1.5, f"rate limit not enforced (finished in {elapsed:.2f}s)"


def test_empty_input_is_safe():
    assert _run(_proc(_FakeEngine({})).process_batch([], {}, {})) == []
