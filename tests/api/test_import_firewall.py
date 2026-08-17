"""Unit tests for the CLI/CI findings-import redaction firewall (P0 two-way sync).

These guard the trust-boundary guarantees of ``routers/imports.py`` — the
exact things that, if they silently regressed, would let a raw secret reach
storage or break repository resolution:

  * a forbidden raw-value key anywhere in the body is rejected (422),
  * a ``masked_value`` that is actually a raw secret is rejected (422),
  * high-entropy unmasked snippet tokens are scrubbed (non-fatal),
  * a git remote ref normalises to a comparable slug so ssh / https / .git
    forms all resolve to the same onboarded repository.

Pure unit tests — no DB, no FastAPI test client.  The firewall helpers are
module-level pure functions, so we import and call them directly.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from apps.api.app.routers import imports as I


# ── forbidden-key tripwire ───────────────────────────────────────────
def test_forbidden_key_rejected_top_level():
    with pytest.raises(HTTPException) as e:
        I._assert_no_forbidden_keys({"findings": [{"raw_value": "AKIAEXAMPLE"}]})
    assert e.value.status_code == 422


def test_forbidden_key_rejected_when_nested_in_free_form_stats():
    # `stats` is the one free-form surface extra="forbid" can't cover.
    with pytest.raises(HTTPException):
        I._assert_no_forbidden_keys({"stats": {"debug": {"cleartext": "x"}}})


@pytest.mark.parametrize(
    "key",
    ["raw_value", "raw_secret", "plaintext", "cleartext", "unmasked",
     "_raw_value_for_verification", "paired_raw"],
)
def test_each_forbidden_key_variant_rejected(key):
    with pytest.raises(HTTPException):
        I._assert_no_forbidden_keys({key: "secret"})


def test_benign_keys_pass_no_substring_false_positive():
    # secret_type / secret_hash / masked_value LOOK secret-ish but are legit;
    # the tripwire matches whole keys, not substrings.
    I._assert_no_forbidden_keys(
        {"findings": [{"secret_type": "aws", "secret_hash": "h", "masked_value": "AKIA****"}]}
    )


def test_forbidden_key_recursion_is_bounded():
    # Deeply nested input must not blow the stack (depth guard).
    root: dict = {}
    cur = root
    for _ in range(50):
        cur["k"] = {}
        cur = cur["k"]
    I._assert_no_forbidden_keys(root)  # returns without raising


# ── masked_value fatal check ─────────────────────────────────────────
@pytest.mark.parametrize(
    "mv,is_raw",
    [
        ("AKIAIOSFODNN7EXAMPLE", True),                 # raw AWS key id, no mask marker
        ("sk_live_4eC39HqLyjWDarjtT1zdp7dc", True),     # raw stripe secret
        ("AKIA************MPLE", False),                # properly masked
        ("ghp_••••", False),                            # short masked (bullet)
        ("Q7QF", False),                                # short tail reveal
        ("AKIA…MPLE", False),                           # ellipsis mask
        ("", False),                                    # empty
    ],
)
def test_masked_value_unmasked_detection(mv, is_raw):
    assert I._masked_value_is_unmasked(mv) is is_raw


def test_x_in_text_is_not_a_mask_marker():
    # The 'X' in "EXAMPLE" must NOT count as masking (strict marker set
    # excludes x/X), else a raw AWS key would slip through.
    assert I._masked_value_is_unmasked("AKIAIOSFODNN7EXAMPLE") is True


# ── snippet entropy scrub (non-fatal) ────────────────────────────────
def test_scrub_replaces_high_entropy_unmasked_token():
    # Token deliberately avoids x/X/*/•/… — those are treated as mask markers
    # by the conservative (non-fatal) snippet scrub, which intentionally
    # skips anything that looks already-masked.
    token = "Zq9Kp2Lm7Pw4Rt6Yb1Nc8Vd3Fg5Hj0Wm6Tn4Rs2Qp8"
    out, n = I._scrub_snippet(f'token = "{token}"')
    assert n >= 1
    assert "REDACTED-HIGH-ENTROPY" in out
    assert token not in out


def test_scrub_catches_high_entropy_base64_with_xX():
    # Regression for F1 (QA): a base64 secret body (PEM/JWT/token) routinely
    # contains x/X. The scrub must NOT treat x/X as a mask marker, or such a
    # token slips past this defense-in-depth backstop. (entropy 5.2, has x+X)
    token = "inRa5kdtNTyM7yyQTSR2xXCS0fUItNuq8pUktsH8VUggpMeew8hJv7rFA7tnIg3UXCl6iF"
    assert ("x" in token) and ("X" in token)
    out, n = I._scrub_snippet(f'priv = "{token}"')
    assert n >= 1 and token not in out and "REDACTED-HIGH-ENTROPY" in out


def test_scrub_keeps_prose_and_already_masked():
    s = 'api_key = "AKIA****MPLE"  # the masked aws key in config'
    out, n = I._scrub_snippet(s)
    assert n == 0
    assert out == s


def test_scrub_handles_none_and_empty():
    assert I._scrub_snippet(None) == (None, 0)
    assert I._scrub_snippet("") == ("", 0)


# ── git remote slug normalisation ────────────────────────────────────
def test_remote_slug_ssh_equals_https_equals_dotgit():
    a = I._remote_slug("git@github.com:org/repo.git")
    b = I._remote_slug("https://github.com/org/repo")
    c = I._remote_slug("https://github.com/org/repo.git/")
    assert a == b == c == "github.com/org/repo"


def test_remote_slug_empty():
    assert I._remote_slug("") == ""


# ── entropy helper sanity ────────────────────────────────────────────
def test_entropy_prose_low_random_high():
    assert I._shannon_entropy("the quick brown fox") < I._shannon_entropy(
        "Zx9Kq2Lm7Pw4Rt6Yb1Nc8Vd3Fg5Hj0Aa"
    )
