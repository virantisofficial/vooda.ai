# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Secret redaction for the ``raw`` field of IntegrationError.

The raw provider response can legitimately contain echoes of the
credential the request was made with (e.g. an Authorization header
appearing in an error envelope, or a token reflected back in a 4xx
body).  We never want those values reaching disk in worker logs or
SIEM, even though we DO want everything else (status, error code,
trace IDs, request URL) for forensics.

This redactor is intentionally conservative — false-positives are
fine (a non-secret string redacted is just less helpful in logs);
false-negatives are not (a real secret leaking).  When in doubt,
err toward redaction.
"""

from __future__ import annotations

import re
from typing import Any


# Common credential prefixes the redactor recognises by structure.
# Each pattern matches the FULL token shape, not just the prefix —
# we don't redact the literal string "ghp_" if it appears alone, only
# the full ghp_<32-char-suffix> form.
_CREDENTIAL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Atlassian classic API token: ATATT3xFf<long base64-ish>=<8 hex>
    (re.compile(r"ATATT3xFf[A-Za-z0-9_=\-]{32,}=[A-F0-9]{8}"), "<atlassian-token>"),
    # GitHub PAT (classic + fine-grained)
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"), "<github-pat>"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"), "<github-pat-fg>"),
    # Slack tokens (xoxb / xoxp / xapp / xoxe.xoxp)
    (re.compile(r"\bxox[bpars]-[A-Za-z0-9-]{10,}\b"), "<slack-token>"),
    (re.compile(r"\bxoxe\.xoxp-[A-Za-z0-9-]{20,}\b"), "<slack-rotated-token>"),
    # AWS access key (AKIA prefix is canonical for IAM users; ASIA for STS)
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "<aws-access-key>"),
    # Generic Bearer: don't try to validate, just hide everything
    # after "Bearer " up to the next whitespace.
    (re.compile(r"(?i)(Bearer\s+)[^\s\"']{12,}"), r"\1<redacted>"),
    # Stripe live keys
    (re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"), "<stripe-live-key>"),
    (re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b"), "<stripe-test-key>"),
    # Generic API-key-like header value: anything 32+ chars of
    # high-entropy base64ish that's the entire value of a header
    # called Authorization / X-Api-Key / token / api_token.
    # (Only applied to header *values*, not free text — see
    # _redact_headers below.)
]


# Header names whose VALUE we redact wholesale.  Treated case-insensitively.
_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "cookie",
    "set-cookie",
    "x-vooda-signature",
    "atlassian-token",
}


# Body-key names whose VALUE we redact wholesale.  Same case-insensitive
# rule.  Catches ``{"api_token": "..."}`` patterns in error bodies.
_SENSITIVE_BODY_KEYS = {
    "api_token",
    "apitoken",
    "token",
    "access_token",
    "refresh_token",
    "client_secret",
    "password",
    "secret",
    "private_key",
}


def _redact_string(s: str) -> str:
    """Apply every credential pattern to a free-form string."""
    if not s:
        return s
    out = s
    for pattern, replacement in _CREDENTIAL_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def _redact_headers(headers: dict[str, Any]) -> dict[str, Any]:
    """Wholesale-redact known sensitive header values.

    Header keys are case-insensitive per RFC 7230, so we lower the
    incoming key for the membership check but preserve the original
    casing in the output (operators want to recognise the header by
    its usual capitalisation).
    """
    out: dict[str, Any] = {}
    for k, v in headers.items():
        if k.lower() in _SENSITIVE_HEADER_NAMES:
            out[k] = "<redacted>"
        else:
            out[k] = _redact_string(str(v)) if isinstance(v, str) else v
    return out


def _redact_obj(obj: Any) -> Any:
    """Recursively redact a JSON-like structure.

    Lists, dicts, and strings are walked; any other primitive is
    returned unchanged.  Dict keys named in ``_SENSITIVE_BODY_KEYS``
    have their values replaced wholesale.
    """
    if isinstance(obj, dict):
        return {
            k: ("<redacted>" if k.lower() in _SENSITIVE_BODY_KEYS else _redact_obj(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact_obj(x) for x in obj]
    if isinstance(obj, str):
        return _redact_string(obj)
    return obj


def redact_secrets(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    """Public entry-point: redact a raw-response dict in place-safe fashion.

    Expected shape::

        {
            "headers": { ... },          # optional
            "body":    "<str>" | { ... }, # optional
            ... other forensic fields
        }

    Non-string / non-dict / non-list values are passed through verbatim.
    Returns a new dict — the input is not mutated, so callers can safely
    re-use it in logs that need the un-redacted variant (none should,
    but the contract is non-mutating either way).
    """
    if payload is None:
        return None
    out: dict[str, Any] = {}
    for k, v in payload.items():
        if k == "headers" and isinstance(v, dict):
            out[k] = _redact_headers(v)
        elif k == "body":
            out[k] = _redact_obj(v)
        else:
            out[k] = _redact_obj(v)
    return out
