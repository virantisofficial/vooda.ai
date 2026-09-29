"""Refusals that are about the account, not about the model.

A provider answers "no" for several different reasons and they are not
interchangeable. A model that does not exist will never work. A model
your plan excludes may work tomorrow. A key with no credit behind it
fails for *every* model, so nothing it touches says anything about any
model at all.

Folding these together produced two real faults:

  - The Accuracy Check scored a model 9 cases out of 20 and published a
    grade, when the other 11 had come back 402 Payment Required. The
    number described a billing state, not a model.
  - A scan that died on an exhausted account notified the operator with
    "consider switching the model_id to a different provider/route, or
    retry once the upstream recovers". Switching cannot help when every
    model is refused, and nothing recovers on its own.

One definition, used by the probe, the accuracy check and the triage
engine, so the three cannot drift apart.
"""
from __future__ import annotations

#: Reason keys. Narrow on purpose: each one has a distinct remedy, and
#: a reason nobody can act on differently is not worth separating.
PAYMENT_REQUIRED = "payment_required"
UNAUTHORIZED = "unauthorized"
RATE_LIMITED = "rate_limited"

_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (PAYMENT_REQUIRED, ("402", "payment required", "insufficient credit",
                        "insufficient_quota", "insufficient funds",
                        "billing", "quota exceeded")),
    (UNAUTHORIZED, ("401", "403", "unauthor", "permission denied",
                    "invalid api key", "invalid_api_key", "authentication")),
    (RATE_LIMITED, ("429", "rate limit", "too many requests",
                    "resource_exhausted")),
)

#: What to tell the operator. One sentence, naming the remedy that
#: actually works — never a model change, because the account refused
#: the request before any model was reached.
REMEDY = {
    PAYMENT_REQUIRED: ("The provider refused these requests for payment. "
                       "Add credit to the account, then run this again — "
                       "no model can answer until it is funded."),
    UNAUTHORIZED: ("The provider rejected the credential. Check the API "
                   "key on this provider, then run this again."),
    RATE_LIMITED: ("The provider is rate-limiting this account. Wait for "
                   "the limit to reset, then run this again."),
}

SHORT = {
    PAYMENT_REQUIRED: "payment required",
    UNAUTHORIZED: "credential rejected",
    RATE_LIMITED: "rate limited",
}


def refusal_reason(err: object) -> str | None:
    """Why the account was refused, or None if this is about the model.

    Payment is tested first. A provider out of credit often says so
    alongside a status that reads like a permissions problem, and
    sending someone to check a key that is perfectly valid wastes the
    one piece of information the error did carry.
    """
    text = str(err or "").lower()
    if not text:
        return None
    for reason, markers in _MARKERS:
        if any(m in text for m in markers):
            return reason
    return None
