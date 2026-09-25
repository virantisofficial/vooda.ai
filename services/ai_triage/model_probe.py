"""Ask a model to do the job before telling a customer it is ready.

The old /test asked for the literal string CONNECTION_OK with a 20-token
budget and reported success on whatever came back — including nothing at
all. Measured live: gemini-3.5-flash and gemma-4-31b-it both returned an
EMPTY reply, stop_reason=truncated, and both were reported as
"Connected successfully". Neither can produce a single triage verdict.
That green tick is where "why are these findings not Checked?" starts.

So this probe runs a miniature version of the real thing — a real
finding, the real output budget, the real parser — and grades what comes
back. Reachability is not fitness.

Nothing here knows any model's name. Vooda connects to whatever the
customer configured, including models that did not exist when this was
written, so every verdict comes from the reply itself: the stop signal,
the visible token count, whether the text parses, and whether the
verdict is one we can store. A name-based allowlist would be stale
within a month — three new Gemini models appeared during the week this
was written.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# States, in the order a customer cares about them.
READY = "ready"            # returned a usable verdict, first try
NEEDS_SETUP = "needs_setup"  # reachable and fixable — we verified the fix
UNVERIFIED = "unverified"  # transient: overload/timeout. NOT a judgment.
UNUSABLE = "unusable"      # cannot triage at any budget we tried

#: Verdicts the triage pipeline can actually store. A model that answers
#: "maybe" is not answering.
_ACCEPTED_VERDICTS = {
    "true_positive", "false_positive", "needs_review",
    "likely_true_positive", "likely_false_positive",
}

#: Floor for the second attempt when the first is starved. Reasoning
#: models spend the budget thinking before any visible text: measured,
#: gemini-3.5-flash returned 0 visible tokens at 300 and clean JSON in
#: 64 at 2000.
_RETRY_FLOOR = 2000
#: Never escalate past this. A model needing more than this to answer a
#: one-line verdict is not a model to run over thousands of findings.
_RETRY_CEILING = 8000


def retry_budget(current: int) -> int:
    """How much room to offer on the second attempt.

    Scaled from what was actually tried rather than fixed, because the
    probe now runs at the budget the tenant has configured — and triage
    calls with that same number. A flat 2000 would have been a
    REDUCTION for anyone on the 4096 default, which would have made the
    retry look like a failure and condemned a working model.
    """
    if current >= _RETRY_CEILING:
        # Already more room than any one-line verdict needs. Offering
        # less would be a reduction dressed up as a fix, and the caller
        # skips the retry when this is not an increase.
        return current
    return min(_RETRY_CEILING, max(_RETRY_FLOOR, current * 4))

#: Above this, a per-finding cost makes a large scan impractical. A
#: 2,000-finding scan at 10s/finding is over five hours.
_SLOW_MS = 10_000

PROBE_SYSTEM = "You are a secret-scanning triage assistant. Reply with JSON only."
PROBE_USER = """Classify this finding and reply with a single JSON object:
{"classification": "TRUE_POSITIVE" or "FALSE_POSITIVE", "confidence": 0.0-1.0, "reasoning": "one sentence"}

File: config/database.yml
Line: 12
Match: password: "hunter2"
Rule: generic-password"""


@dataclass
class ProbeResult:
    model_id: str
    state: str
    #: One plain sentence for the customer. Never token counts — the
    #: settings screen is not a debugger. Evidence lives in `detail`.
    headline: str = ""
    #: What to change, when there is something to change.
    remedy: str = ""
    #: Applied by the Fix button. Empty when nothing is auto-fixable.
    suggested_config: dict = field(default_factory=dict)
    #: Raw signals, shown only behind "Details".
    detail: dict = field(default_factory=dict)
    latency_ms: float = 0.0
    calls_used: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def _looks_transient(err: str) -> bool:
    """Overloaded is not broken.

    Four healthy models returned 503 during one sweep. Folding that into
    "unusable" would hide working models behind a filter the customer
    cannot see past — the filter failing in the direction that costs a
    sale rather than the one that annoys.
    """
    e = err.lower()
    return any(s in e for s in (
        "503", "429", "overload", "rate limit", "timeout", "timed out",
        "unavailable", "connection reset", "temporarily",
    ))


def grade_reply(content: str, stop_reason: str, output_tokens: int,
                latency_ms: float) -> tuple[str, Optional[dict], dict]:
    """Grade one reply. Returns (outcome, parsed_verdict, evidence).

    Split out from the network call so every branch is testable without
    an API key — the provider-contract suite found three real bugs that
    way.
    """
    ev = {
        "stop_reason": stop_reason,
        "output_tokens": output_tokens,
        "latency_ms": round(latency_ms),
        "reply_preview": (content or "").strip()[:200],
    }
    text = (content or "").strip()

    if not text:
        # The signature of a reasoning model: budget spent before it
        # said anything visible.
        return ("empty_truncated" if stop_reason == "truncated" else "empty"), None, ev

    parsed = None
    salvaged = False
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        from services.ai_triage.engine import _extract_json_object
        recovered = _extract_json_object(text)
        if recovered is not None:
            parsed = json.loads(recovered)
            salvaged = True
    ev["salvaged"] = salvaged

    if parsed is None:
        return ("truncated_partial" if stop_reason == "truncated" else "unparseable"), None, ev
    if not isinstance(parsed, dict):
        return "unparseable", None, ev

    verdict = str(parsed.get("classification", "")).strip().lower()
    ev["verdict"] = verdict or None
    if verdict not in _ACCEPTED_VERDICTS:
        return "bad_vocabulary", parsed, ev

    ev["has_confidence"] = "confidence" in parsed
    ev["has_reasoning"] = bool(str(parsed.get("reasoning", "")).strip())

    if salvaged:
        return "ok_salvaged", parsed, ev
    if latency_ms > _SLOW_MS:
        return "ok_slow", parsed, ev
    return "ok", parsed, ev


def _verdict_for(outcome: str, ev: dict, retried_ok: bool,
                 retry_at: int = _RETRY_FLOOR) -> ProbeResult:
    """Translate an outcome into something a customer can act on."""
    if outcome == "ok":
        return ProbeResult("", READY, "Ready to triage.", "", {}, ev)

    if outcome == "ok_slow":
        secs = ev.get("latency_ms", 0) / 1000
        return ProbeResult(
            "", NEEDS_SETUP,
            f"Works, but takes about {secs:.0f}s per finding.",
            "A large scan will be slow. Consider a faster model for bulk triage.",
            {}, ev)

    if outcome == "ok_salvaged":
        return ProbeResult(
            "", NEEDS_SETUP,
            "Works, but wraps its answer in extra text.",
            "Vooda reads it correctly. Turning on JSON mode makes it faster and cheaper.",
            {"supports_json_mode": True}, ev)

    if outcome in ("empty_truncated", "truncated_partial", "empty"):
        if retried_ok:
            return ProbeResult(
                "", NEEDS_SETUP,
                "This model thinks before answering and used its whole reply budget.",
                f"Raise the output limit to {retry_at}. Verified working at that setting.",
                {"max_tokens": retry_at}, ev)
        return ProbeResult(
            "", UNUSABLE,
            "Returned no usable answer, even with a larger reply budget.",
            "Pick a different model for triage.", {}, ev)

    if outcome == "bad_vocabulary":
        return ProbeResult(
            "", NEEDS_SETUP,
            "Answered, but not with a verdict Vooda recognises.",
            "Try the Strict analysis strategy, which states the allowed answers more firmly.",
            {"prompt_strategy": "strict"}, ev)

    # unparseable
    if retried_ok:
        return ProbeResult(
            "", NEEDS_SETUP,
            "Needed a larger reply budget to answer completely.",
            f"Raise the output limit to {retry_at}. Verified working at that setting.",
            {"max_tokens": retry_at}, ev)
    return ProbeResult(
        "", UNUSABLE,
        "Did not return an answer Vooda can read.",
        "Pick a different model for triage.", {}, ev)


async def probe_model(provider_name: str, api_key: str, model_id: str,
                      endpoint_url: str | None = None,
                      max_tokens: int = 4096,
                      supports_json_mode: bool = True,
                      extra_payload: dict | None = None) -> ProbeResult:
    """One real triage request. A second only when the first is starved.

    A good model costs one call. A model we are about to tell the
    customer to fix costs two — because we confirm the fix works before
    putting a Fix button in front of them.
    """
    from services.ai_triage.provider import create_provider

    calls = 0
    t0 = time.monotonic()

    async def attempt(budget: int):
        nonlocal calls
        p = create_provider(provider_name, api_key, model_id, endpoint_url,
                            supports_json_mode=supports_json_mode,
                            extra_payload=extra_payload)
        calls += 1
        return await p.complete(PROBE_SYSTEM, PROBE_USER, max_tokens=budget,
                                temperature=0.0, json_mode=supports_json_mode)

    try:
        r = await attempt(max_tokens)
    except Exception as e:
        msg = str(e)
        total = (time.monotonic() - t0) * 1000
        if _looks_transient(msg):
            return ProbeResult(model_id, UNVERIFIED,
                               "Couldn't check right now — the provider was busy.",
                               "Try again in a moment.", {}, {"error": msg[:300]}, total, calls)

        definitive = _definitive_failure(msg)
        if definitive:
            return ProbeResult(model_id, UNUSABLE, definitive[0], definitive[1],
                               {}, {"error": msg[:300]}, total, calls)

        # An error we do not recognise is not evidence the model is
        # broken. gemma-4-31b-it failed one call this way and was marked
        # unusable; the very next probe graded it needs_setup. Calling
        # an unknown failure "unusable" hides a working model behind the
        # filter with no way for the customer to see past it, which is
        # the expensive direction to be wrong in. "I don't know" is an
        # honest answer and it keeps the model visible.
        return ProbeResult(model_id, UNVERIFIED,
                           "Couldn't check this model.",
                           "Try again, or check the model name and endpoint.",
                           {}, {"error": msg[:300]}, total, calls)

    outcome, _parsed, ev = grade_reply(r.content, r.stop_reason, r.output_tokens, r.latency_ms)

    # Starved on the first pass — find out whether more room fixes it,
    # rather than guessing on the customer's behalf.
    retried_ok = False
    escalated = retry_budget(max_tokens)
    if outcome in ("empty_truncated", "truncated_partial", "empty", "unparseable") \
            and escalated > max_tokens:
        try:
            r2 = await attempt(escalated)
            outcome2, _p2, ev2 = grade_reply(r2.content, r2.stop_reason,
                                             r2.output_tokens, r2.latency_ms)
            retried_ok = outcome2 in ("ok", "ok_slow", "ok_salvaged")
            ev["retry"] = {"max_tokens": escalated, "outcome": outcome2, **ev2}
        except Exception as e:
            if _looks_transient(str(e)):
                total = (time.monotonic() - t0) * 1000
                return ProbeResult(model_id, UNVERIFIED,
                                   "Couldn't finish checking — the provider was busy.",
                                   "Try again in a moment.", {}, ev, total, calls)
            ev["retry_error"] = str(e)[:300]

    res = _verdict_for(outcome, ev, retried_ok, escalated)
    res.model_id = model_id
    res.latency_ms = (time.monotonic() - t0) * 1000
    res.calls_used = calls
    res.detail["outcome"] = outcome
    return res


def _definitive_failure(err: str) -> Optional[tuple[str, str]]:
    """Only a failure that cannot be a blip earns "unusable".

    Positive evidence the model will never work — it does not exist, or
    this key may not use it. Everything else stays UNVERIFIED, because
    guessing "broken" removes the model from the customer's list.
    """
    e = err.lower()
    if "404" in e or "not found" in e:
        return ("Vooda could not find this model.",
                "It isn't available on your plan, or the name has changed.")
    if any(k in e for k in ("401", "403", "unauthor", "permission denied", "invalid api key")):
        return ("This key cannot use this model.",
                "Check the API key has access to it.")
    return None
