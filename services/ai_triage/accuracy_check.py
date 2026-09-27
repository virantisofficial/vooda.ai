"""How often is this model right?

model_probe answers whether a model produces a usable verdict. That is
a formatting question, and a model can pass it while being wrong about
every finding. Measured live: two models both reporting Ready
contradicted each other on two of three real findings, one of them
dismissing a hardcoded encryption key at 0.75 confidence.

So this runs the same request against findings whose answer is already
known and counts the mistakes — separating the two kinds, because they
are not equally bad. Raising a harmless finding costs a reviewer a few
minutes. Dismissing a live credential is the failure that ends up in an
incident report, and it is invisible: a scan that hides real secrets
looks tidier than one that surfaces them.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, asdict

from services.ai_triage.accuracy_corpus import (
    AccuracyCase, load_cases, TRUE_POSITIVE, FALSE_POSITIVE,
)
from services.ai_triage.model_probe import grade_reply, PROBE_SYSTEM

#: Verdict vocabulary mapped onto the two answers the corpus knows.
_SAYS_REAL = {"true_positive", "likely_true_positive"}
_SAYS_NOISE = {"false_positive", "likely_false_positive"}

#: Between requests. The probe found free tiers rate-limit well below
#: what a tight loop asks for, and a 429 scored as a wrong answer would
#: make a good model look bad.
_GAP_SECONDS = 0.4


@dataclass
class CaseResult:
    case_id: str
    expected: str
    answered: str | None
    correct: bool
    #: A real secret the model waved through. The mistake that matters.
    missed_secret: bool = False
    critical: bool = False
    note: str = ""
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AccuracyResult:
    model_id: str
    total: int = 0
    correct: int = 0
    #: Real secrets called noise — counted apart from the total, because
    #: "17 of 20" hides whether the three misses were harmless.
    missed_secrets: int = 0
    #: Noise called a real secret. Wastes review time, hides nothing.
    false_alarms: int = 0
    unanswered: int = 0
    cases: list = field(default_factory=list)
    latency_ms: float = 0.0

    @property
    def scored(self) -> int:
        """Cases the model actually answered."""
        return self.total - self.unanswered

    @property
    def headline(self) -> str:
        if self.total == 0:
            return "No cases to score."

        # Nothing answered is not a clean sheet.
        #
        # This read "0 of 20 correct — missed no real secrets" when
        # every request had failed with a 401, which states the
        # safest-sounding half of a result that does not exist. An
        # unfinished check has to look unfinished.
        if self.scored == 0:
            return "Couldn't score this model — no answers came back."

        base = f"{self.correct} of {self.total} correct"
        if self.unanswered:
            base += f" ({self.unanswered} unanswered)"
        if self.missed_secrets:
            s = "" if self.missed_secrets == 1 else "s"
            return f"{base} — missed {self.missed_secrets} real secret{s}"
        if self.unanswered:
            # Silence about the cases that never ran would read as
            # "none missed" across the whole corpus.
            return f"{base} — none missed among those answered"
        return f"{base} — missed no real secrets"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cases"] = [c.to_dict() if hasattr(c, "to_dict") else c for c in self.cases]
        d["headline"] = self.headline
        d["scored"] = self.scored
        return d


def case_prompt(case: AccuracyCase) -> str:
    """The same shape the probe sends, with the case's details.

    Deliberately carries no hint of the expected answer — not the note,
    not whether it is marked critical. A model scored on a prompt that
    contains the answer is not being scored.
    """
    return (
        'Classify this finding and reply with a single JSON object:\n'
        '{"classification": "TRUE_POSITIVE" or "FALSE_POSITIVE", '
        '"confidence": 0.0-1.0, "reasoning": "one sentence"}\n\n'
        f"File: {case.file_path}\n"
        f"Line: {case.line}\n"
        f"Rule: {case.rule_id}\n"
        f"Match:\n{case.snippet}"
    )


def score_answer(case: AccuracyCase, verdict: str | None) -> CaseResult:
    """Compare one answer to the known truth."""
    if not verdict:
        return CaseResult(case.case_id, case.expected, None, False,
                          critical=case.critical, note=case.note,
                          error="no verdict returned")

    v = verdict.strip().lower()
    said_real = v in _SAYS_REAL
    said_noise = v in _SAYS_NOISE
    if not (said_real or said_noise):
        # needs_review is not an answer here. The corpus cases are
        # deliberately unambiguous, so declining to decide is a miss —
        # though not a dangerous one, and it is not counted as such.
        return CaseResult(case.case_id, case.expected, v, False,
                          critical=case.critical, note=case.note)

    correct = (said_real and case.expected == TRUE_POSITIVE) or \
              (said_noise and case.expected == FALSE_POSITIVE)
    missed = said_noise and case.expected == TRUE_POSITIVE
    return CaseResult(case.case_id, case.expected, v, correct,
                      missed_secret=missed, critical=case.critical,
                      note=case.note)


async def run_accuracy_check(
    provider_name: str, api_key: str, model_id: str,
    endpoint_url: str | None = None, max_tokens: int = 4096,
    supports_json_mode: bool = True, extra_payload: dict | None = None,
    cases: tuple[AccuracyCase, ...] | None = None,
) -> AccuracyResult:
    """Score one model against the corpus. One request per case."""
    import time
    from services.ai_triage.provider import create_provider

    cases = cases or load_cases()
    result = AccuracyResult(model_id=model_id, total=len(cases))
    t0 = time.monotonic()

    provider = create_provider(provider_name, api_key, model_id, endpoint_url,
                               supports_json_mode=supports_json_mode,
                               extra_payload=extra_payload)

    for i, case in enumerate(cases):
        try:
            r = await provider.complete(
                PROBE_SYSTEM, case_prompt(case),
                max_tokens=max_tokens, temperature=0.0,
                json_mode=supports_json_mode,
            )
            _, parsed, _ = grade_reply(r.content, r.stop_reason,
                                       r.output_tokens, r.latency_ms)
            verdict = (parsed or {}).get("classification")
            scored = score_answer(case, verdict)
        except Exception as e:
            scored = CaseResult(case.case_id, case.expected, None, False,
                                critical=case.critical, note=case.note,
                                error=str(e)[:160])

        result.cases.append(scored)
        if scored.correct:
            result.correct += 1
        elif scored.missed_secret:
            result.missed_secrets += 1
        elif scored.answered is None:
            result.unanswered += 1
        elif case.expected == FALSE_POSITIVE:
            result.false_alarms += 1

        if i + 1 < len(cases):
            await asyncio.sleep(_GAP_SECONDS)

    result.latency_ms = (time.monotonic() - t0) * 1000
    return result
