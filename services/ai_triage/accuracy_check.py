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
import collections
from dataclasses import dataclass, field, asdict

from services.ai_triage.accuracy_corpus import (
    AccuracyCase, load_cases, TRUE_POSITIVE, FALSE_POSITIVE,
)
from services.ai_triage.account_errors import REMEDY, SHORT, refusal_reason
from services.ai_triage.model_probe import grade_reply, PROBE_SYSTEM

#: Verdict vocabulary mapped onto the two answers the corpus knows.
_SAYS_REAL = {"true_positive", "likely_true_positive"}
_SAYS_NOISE = {"false_positive", "likely_false_positive"}

#: How many cases to run at once.
#:
#: Sequential with a gap took about seventy seconds against a slower
#: model — long enough that a proxy closed the connection first, so a
#: score that had completed and been stored server-side was reported to
#: the customer as "Couldn't score this model". The cure for a request
#: that outlives its connection is to make it shorter, not to wait
#: longer for it.
#:
#: Bounded for the same reason the probe is: a 429 scored as a wrong
#: answer makes a good model look bad.
_CONCURRENCY = 8

#: A refusal for going too fast is worth waiting out, twice, growing
#: the wait each time. Twenty cases spread over three windows still
#: finishes inside a minute, and a metered free tier scores honestly
#: instead of reporting twenty unanswered cases.
_RATE_LIMIT_RETRIES = 2
_RATE_LIMIT_BACKOFF = 8.0


#: Below this share of cases answered, there is no grade to give.
#:
#: A run where the model itself fluffed a case is still data about the
#: model. A run where most cases never completed is not a low score, it
#: is an unfinished measurement, and publishing it as a grade invites a
#: decision the evidence cannot support.
_MIN_COVERAGE = 0.75


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
    #: Set when the provider refused the account rather than the model —
    #: no credit, a rejected key, a rate limit that outlasted the
    #: retries. A refusal like this reaches every model equally, so
    #: nothing measured under it describes the one being scored.
    refused: str | None = None
    cases: list = field(default_factory=list)
    latency_ms: float = 0.0

    @property
    def scored(self) -> int:
        """Cases the model actually answered."""
        return self.total - self.unanswered

    @property
    def headline(self) -> str:
        """A verdict, and the kind of mistakes behind it.

        This used to read "15 of 20 correct - missed 1 real secret",
        which had two faults.

        The counts published the size of the corpus, and a corpus a
        reader can enumerate is one a model can be tuned against. The
        number was never the point anyway - nobody chooses differently
        on 15 rather than 16.

        Worse, it accounted for one mistake and left four unexplained.
        A reader could not tell whether the rest were harmless findings
        raised as real, or real secrets let through, and those have
        opposite consequences: a false alarm costs a reviewer minutes,
        a missed secret ends in an incident report. So the two kinds of
        error are named rather than summed, and any miss caps the
        verdict however good the overall rate.
        """
        if self.total == 0:
            return "No cases to score."

        # A refusal aimed at the account is not a result about the
        # model. Nine cases answered out of twenty once produced
        # "Good - missed no real secrets", a confident grade describing
        # a billing state: the other eleven were 402 Payment Required.
        if self.refused:
            return f"Couldn't score — {REMEDY[self.refused]}"

        # Nothing answered is not a clean sheet.
        #
        # This read as a pass when every request had failed with a 401,
        # stating the safest-sounding half of a result that does not
        # exist. An unfinished check has to look unfinished.
        if self.scored == 0:
            return "Couldn't score this model — no answers came back."

        # Too little of the corpus completed to grade on.
        if self.scored / self.total < _MIN_COVERAGE:
            return ("Couldn't score reliably — too many cases failed to "
                    "complete. Try again.")

        if self.missed_secrets == 1:
            parts = ["missed a real secret"]
        elif self.missed_secrets > 1:
            parts = ["missed several real secrets"]
        else:
            parts = ["missed no real secrets"]

        if self.false_alarms:
            parts.append("flagged harmless findings often"
                         if self.false_alarms / self.scored >= 0.25
                         else "flagged some harmless findings")
        if self.unanswered:
            parts.append("some cases went unanswered")

        rate = self.correct / self.scored
        if self.missed_secrets:
            verdict = "Not safe for triage"
        elif rate >= 0.9:
            verdict = "Strong"
        elif rate >= 0.75:
            verdict = "Good"
        else:
            verdict = "Weak"

        return f"{verdict} — " + ", ".join(parts) + "."

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

    gate = asyncio.Semaphore(_CONCURRENCY)

    async def score_one(case: AccuracyCase) -> CaseResult:
        async with gate:
            last = ""
            # A free tier that meters by the minute will refuse some of
            # a burst this size. Being refused is not being wrong, and
            # it is not a fact about the model either — so wait out the
            # window rather than record an answer the model never got
            # the chance to give.
            for attempt in range(_RATE_LIMIT_RETRIES + 1):
                try:
                    r = await provider.complete(
                        PROBE_SYSTEM, case_prompt(case),
                        max_tokens=max_tokens, temperature=0.0,
                        json_mode=supports_json_mode,
                    )
                    _, parsed, _ = grade_reply(r.content, r.stop_reason,
                                               r.output_tokens, r.latency_ms)
                    return score_answer(case, (parsed or {}).get("classification"))
                except Exception as e:
                    last = str(e)[:160]
                    if attempt >= _RATE_LIMIT_RETRIES or refusal_reason(e) != "rate_limited":
                        break
                    await asyncio.sleep(_RATE_LIMIT_BACKOFF * (attempt + 1))
            return CaseResult(case.case_id, case.expected, None, False,
                              critical=case.critical, note=case.note,
                              error=last)

    # Ordered with the corpus, so the breakdown reads in a stable order
    # however the answers arrive.
    scored_all = await asyncio.gather(*(score_one(c) for c in cases))

    for case, scored in zip(cases, scored_all):
        result.cases.append(scored)
        if scored.correct:
            result.correct += 1
        elif scored.missed_secret:
            result.missed_secrets += 1
        elif scored.answered is None:
            result.unanswered += 1
        elif case.expected == FALSE_POSITIVE:
            result.false_alarms += 1

    # Why the cases that failed, failed. One refused case is enough to
    # void the run: the account is refused as a whole, so the cases that
    # did answer were the lucky ones rather than a fair sample.
    refusals = collections.Counter(
        r for r in (refusal_reason(c.error) for c in result.cases) if r)
    if refusals:
        result.refused = refusals.most_common(1)[0][0]

    result.latency_ms = (time.monotonic() - t0) * 1000
    return result
