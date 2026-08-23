# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""A cancel raised from a progress callback must stop batch triage.

The cooperative-cancellation checkpoint runs inside the heartbeat, which
the AI phase reaches through ``on_progress``. Every handler between that
callback and the task entry point therefore has to let ScanCancelled
through — a ``try/except Exception`` around a progress call absorbs it
and the scan runs to completion with its row already marked CANCELLED.

Asserting on the checkpoint alone cannot catch that: the function raises
correctly and the run continues anyway. These tests drive the real
dispatch loop and assert the exception escapes it, plus that no work is
left running behind it.
"""
import asyncio

import pytest

from packages.common.cancellation import ScanCancelled
from services.ai_triage.batch import BatchTriageProcessor, BatchTriageConfig


class _Engine:
    """Triage engine stub; records how many calls actually ran."""

    def __init__(self, delay=0.01):
        self.delay = delay
        self.started = 0
        self.finished = 0

    async def triage_finding(self, finding, code_context, repo_context):
        self.started += 1
        await asyncio.sleep(self.delay)
        self.finished += 1
        return {
            "classification": "likely_true_positive",
            "confidence_score": 0.9,
            "reasoning": "stub",
        }


def _processor(engine, **kw):
    cfg = BatchTriageConfig(max_concurrent=4, rate_limit_rpm=100000, **kw)
    return BatchTriageProcessor(engine=engine, config=cfg)


def _findings(n):
    return [{"id": f"f{i}", "secret_type": "aws", "file_path": f"a{i}.py"} for i in range(n)]


@pytest.mark.asyncio
async def test_cancel_from_progress_callback_escapes_the_loop():
    engine = _Engine()
    proc = _processor(engine)

    async def on_progress(done, total):
        if done >= 3:
            raise ScanCancelled("job-1")

    with pytest.raises(ScanCancelled):
        await proc.process_batch(
            findings=_findings(40),
            code_contexts={},
            repo_context={},
            on_progress=on_progress,
        )


@pytest.mark.asyncio
async def test_cancel_does_not_leave_pending_calls_running():
    """A cancelled scan must stop spending AI budget immediately."""
    engine = _Engine(delay=0.05)
    proc = _processor(engine)

    async def on_progress(done, total):
        if done >= 2:
            raise ScanCancelled("job-1")

    with pytest.raises(ScanCancelled):
        await proc.process_batch(
            findings=_findings(60),
            code_contexts={},
            repo_context={},
            on_progress=on_progress,
        )

    started_at_cancel = engine.started
    await asyncio.sleep(0.3)
    assert engine.started == started_at_cancel, (
        "calls were still being dispatched after the cancel — pending "
        "tasks must be cancelled on the way out"
    )
    assert engine.finished < 60, "the whole batch ran despite the cancel"


@pytest.mark.asyncio
async def test_ordinary_progress_errors_are_still_swallowed():
    """Only cancellation aborts; a broken progress bar must not."""
    engine = _Engine()
    proc = _processor(engine)

    async def on_progress(done, total):
        raise RuntimeError("progress bar exploded")

    result = await proc.process_batch(
        findings=_findings(5),
        code_contexts={},
        repo_context={},
        on_progress=on_progress,
    )
    assert engine.finished == 5
    assert result is not None


@pytest.mark.asyncio
async def test_ordinary_triage_errors_are_still_per_finding():
    """One failing finding must not abort the others."""

    class _Flaky(_Engine):
        async def triage_finding(self, finding, code_context, repo_context):
            if finding["id"] == "f2":
                raise ValueError("model refused")
            return await super().triage_finding(finding, code_context, repo_context)

    engine = _Flaky()
    proc = _processor(engine)
    result = await proc.process_batch(
        findings=_findings(6), code_contexts={}, repo_context={},
    )
    assert result is not None
