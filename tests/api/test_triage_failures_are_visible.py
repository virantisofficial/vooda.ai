# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""A failed AI triage must never be counted as a successful one.

A wrongsecrets scan attempted 28 findings, produced 24 verdicts, and
reported `ai_triaged: 28`. The four that failed — three empty responses
and one truncated mid-JSON — were presented as triaged. One of them was
a committed RSA private key.

The count came from `max(triaged, ai_classified_count)`, where `triaged`
counts ATTEMPTS. The max() existed for a real reason (a clean re-scan
inherits verdicts via dedup, so `triaged` is 0 and the card must not
read "AI triage pending") — but it also meant failures could only ever
inflate the number.
"""
import pathlib
import re

WORKER = pathlib.Path("apps/worker/tasks.py")
CARD = pathlib.Path("apps/web/src/app/repositories/[id]/page.tsx")


def test_ai_triaged_counts_verdicts_not_attempts():
    src = WORKER.read_text(encoding="utf-8")
    assert '"ai_triaged": max(' not in src, (
        "ai_triaged must count findings carrying a verdict, never the "
        "larger of attempts and verdicts"
    )
    assert '"ai_triaged": ai_classified_count,' in src


def test_both_triage_paths_record_failures():
    """The live scan path and the retro path both write stats; a fix to
    one would leave the other silently lying."""
    src = WORKER.read_text(encoding="utf-8")
    assert src.count("ai_triage_failed") >= 2, (
        "both _run_ai_triage callers that write stats must record failures"
    )
    assert src.count("ai_triage_failures") >= 2


def test_failures_are_attributed_to_a_model():
    """Vooda can be pointed at any provider, so a bare failure count is
    not comparable across them: "returned empty on 11%" and "truncated
    on 2%" are different problems with different fixes."""
    src = WORKER.read_text(encoding="utf-8")
    assert "ai_triage_model" in src
    assert 'f"{mc.provider}:{mc.model_id}"' in src


def test_a_total_failure_is_not_reported_as_a_config_problem():
    """With ai_triaged now counting verdicts, a run where EVERY call
    failed reads 0 — which previously meant "no model configured". That
    would send the reader to Settings for a problem that is not
    configuration: the model is configured and answering, just not
    usefully.
    """
    if not CARD.exists():
        return
    src = CARD.read_text(encoding="utf-8")
    # the "configure" branch must be guarded by a failure check
    idx = src.index("AI triage pending — configure AI model")
    preceding = src[:idx]
    assert "ai_triage_failed" in preceding, (
        "the configure-AI-model prompt must not fire when triage ran "
        "and failed"
    )
    assert "untriaged, not low-risk" in src, (
        "a failed finding must be described as untriaged, not as safe"
    )


def test_the_card_surfaces_the_failure_count():
    if not CARD.exists():
        return
    src = CARD.read_text(encoding="utf-8")
    assert "triage failed" in src
    assert "ai_triage_failures" in src, "per-type breakdown should be surfaced"


def test_failure_count_comes_from_the_engine_not_from_subtraction():
    """(attempted - classified) goes NEGATIVE on a re-scan.

    Dedup inherits verdicts from earlier scans, so `attempted` can be 5
    while `classified` is 24. The subtraction clamps to 0 and reports
    "0 failed" directly beside a breakdown listing 3 — observed on a
    real wrongsecrets re-scan. The engine already counts each failure;
    use that.
    """
    src = WORKER.read_text(encoding="utf-8")
    assert "sum((failure_summary or {}).values())" in src, (
        "derive the failure count from the engine's own tally"
    )


def test_triage_stats_locals_are_bound_even_when_triage_never_runs():
    """Regression: the scan failed at "[6/8] Storing findings".

    The stats block reads `failure_summary` and `_triage_model_label`
    unconditionally, but both are only assigned inside the branch that
    actually calls _run_ai_triage. A scan with no model configured, with
    skip_ai, or that raised early therefore hit UnboundLocalError and
    the WHOLE SCAN failed — findings already detected were never stored.

    Adding a stat that reads a conditionally-bound local is an easy
    mistake to repeat, so pin the initialisation.
    """
    src = WORKER.read_text(encoding="utf-8")
    init = src.index("            triaged = 0\n            dedup_saved = 0")
    stats = src.index('"ai_triage_failures": dict(failure_summary or {})')
    assert init < stats, "initialisation must precede the stats block"
    window = src[init:stats]
    assert "failure_summary: dict[str, int] = {}" in window
    assert '_triage_model_label = ""' in window


def test_a_deliberate_abstention_counts_as_triaged():
    """NEEDS_REVIEW carrying a real confidence means the model read the
    finding and declined to commit. That is triage working, and
    excluding it understated the work done.

    The confidence is what separates it from the default: NEEDS_REVIEW
    with confidence 0 or NULL means nothing ever ran, and counting THAT
    puts us straight back to reporting failures as successes.
    """
    src = WORKER.read_text(encoding="utf-8")
    block = src[src.index("ai_classified_result = await db.execute"):]
    block = block[: block.index(")\n\n")]
    assert "NEEDS_REVIEW" in block, "abstentions must be counted"
    assert "ai_confidence > 0" in block, (
        "…but only when the model actually answered"
    )
    assert "isnot(None)" in block


def test_the_count_query_does_not_depend_on_a_conditional_import():
    """A statement bound to a name imported inside an unrelated branch
    has already cost one debugging round today — the unsupported-validity
    sweep looked correct and updated nothing."""
    src = WORKER.read_text(encoding="utf-8")
    block = src[src.index("# Imported locally on purpose"):]
    block = block[: block.index("ai_classified_result")]
    assert "from sqlalchemy import or_" in block
    assert "import Classification as _ClsCount" in block
