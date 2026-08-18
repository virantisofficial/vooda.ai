"""Entropy threshold tuning regression tests (Track-A P1.3).

Three coordinated changes shipped 2026-05-20:

  1. ENTROPY_THRESHOLDS["base64"]  5.3 → 5.0  (config.py)
  2. _is_known_hash_format         require PURE-LOWERCASE hex for the
                                   exact-length exclusion (entropy.py)
  3. _looks_like_word              vowel range tightened 0.25-0.55
                                   AND require ≥1 contiguous lowercase
                                   span of length ≥4 (entropy.py)

These tests pin the new behaviour by exercising the 8 boundary
samples we measured by hand earlier in the audit.  Each test
documents BOTH the input and the rationale so a future refactor
can see why the threshold sits where it does.
"""
from __future__ import annotations

import pytest

from services.secret_scan.config import ENTROPY_THRESHOLDS, MIN_SECRET_LENGTH
from services.secret_scan.entropy import (
    shannon_entropy,
    find_high_entropy_strings,
    _is_known_hash_format,
    _looks_like_word,
)


# ── Threshold constants ────────────────────────────────────────


def test_base64_threshold_lowered_to_five():
    """The headline change.  If a future refactor walks the threshold
    back up, this test fails loudly so we don't silently regress."""
    assert ENTROPY_THRESHOLDS["base64"] == 5.0, (
        "base64 threshold reverted from 5.0 — boundary tokens "
        "(GitHub PAT 5.27, Stripe 5.28) will be missed again"
    )


# ── Scenario A + B: real-world boundary tokens now flagged ─────


@pytest.mark.parametrize("token,label", [
    ("ghp_aB3xT9KmN2vPq8RsLwE7yJhFdGuVcXzY1nM4", "GitHub PAT shape (entropy ~5.27)"),
    ("k_live_rsa_3iC4xPdwLqV9rTuYzN8oM1aZbE7H6gKjFsXvJ", "Stripe-shape (entropy ~5.28)"),
])
def test_boundary_tokens_now_flagged(token: str, label: str):
    """Scenario A + B: tokens that hovered just below 5.3 must now
    cross the 5.0 bar and end up in the matches list."""
    ent = shannon_entropy(token)
    # Sanity-check our threshold logic — these should land between
    # the old (5.3) and new (5.0) thresholds so the test actually
    # exercises the tuning.
    assert 5.0 <= ent < 5.3, f"{label} entropy={ent:.2f} — sample no longer in the boundary band"
    matches = find_high_entropy_strings(token)
    assert matches, f"{label} entropy={ent:.2f} should now be flagged at threshold 5.0"


# ── Scenario C: AKIA-shape no longer mis-classified as word ────


def test_aws_akia_example_not_classified_as_word():
    """Scenario C: AWS access-key IDs like AKIAIOSFODNN7EXAMPLE have
    vowel ratio 0.30 (in the OLD 0.15-0.55 word range) but are pure
    uppercase — no lowercase run, so they should NOT pass the word
    filter under the tightened rule."""
    assert not _looks_like_word("AKIAIOSFODNN7EXAMPLE")
    # Also confirm a stripped-letters AWS shape doesn't trip the filter
    assert not _looks_like_word("AKIAQYLPMN5HEXAMPLE")


def test_pure_uppercase_strings_not_words():
    """Generalisation: any pure-uppercase token regardless of vowel
    ratio must fall out of the word filter (no lowercase span)."""
    for s in ["AKIAEXAMPLE", "GHCTOKENFAKEABC", "AAAAAAAAAA", "EUROPEANUNION"]:
        assert not _looks_like_word(s), f"{s!r} should not be classified as a word"


# ── Scenario D + E: hash-length exclusion now requires lowercase ─


def test_lowercase_sha256_hex_still_excluded_as_hash():
    """Scenario D: a real SHA-256 hex digest is pure lowercase and 64
    chars — must still be excluded so we don't flag every integrity
    hash on the planet."""
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert len(sha256) == 64
    assert _is_known_hash_format(sha256)


def test_lowercase_md5_hex_still_excluded():
    """MD5: 32 lowercase hex chars."""
    md5 = "098f6bcd4621d373cade4e832627b4f6"
    assert len(md5) == 32
    assert _is_known_hash_format(md5)


def test_lowercase_sha1_hex_still_excluded():
    """SHA1: 40 lowercase hex chars."""
    sha1 = "a94a8fef8c1c4e9d8b3a2e2a8b8a8b8a8b8a8b8a"
    assert len(sha1) == 40
    assert _is_known_hash_format(sha1)


@pytest.mark.parametrize("api_key,length", [
    ("aB3xT9KmN2vPq8RsLwE7yJhFdGuVcXzY", 32),       # Mailgun-shape
    ("Ab3xT9KmN2vPq8RsLwE7yJhFdGuVcXzY1nM4LpQwEr", 42),  # Datadog-ish
    ("AAAAbbbbCCCCddddEEEEffff0000111122223333", 40),    # mixed-case 40-char
])
def test_mixed_case_strings_at_hash_lengths_not_excluded(api_key: str, length: int):
    """Scenario E: strings of exactly 32/40/64/128 chars that contain
    UPPERCASE letters should NOT be excluded as hashes — real API
    keys often live at these lengths.  Pre-fix, ALL exact-length hex
    strings were dropped regardless of case."""
    assert len(api_key) == length
    assert not _is_known_hash_format(api_key), (
        f"{length}-char mixed-case key should not be classified as a hash"
    )


# ── Scenario F: bcrypt et al still excluded ────────────────────


@pytest.mark.parametrize("hash_value", [
    "$2b$12$LJ4uXyB.D6gI1y1Z3MqOpO9c2fI/yKuFvQHj/U4xL2g6KZN9p2eN.",  # bcrypt
    "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",  # bcrypt
    "$argon2id$v=19$m=65536,t=3,p=4$kjf$kdfksdjfksjdf",  # argon2
    "$pbkdf2-sha256$29000$N2YzdEZ4UTRmRGl6$abcd",  # pbkdf2
    "sha256-MlPzthQNGNdr+9ULSP+UO9MS6QY4hO5cYE+m4Vo+9hY=",  # SRI
    "h1:abcdef1234567890",  # Terraform provider hash
])
def test_known_hash_formats_still_excluded(hash_value: str):
    assert _is_known_hash_format(hash_value)


# ── Scenario G: English words still excluded ───────────────────


@pytest.mark.parametrize("word", [
    "password", "secrets", "examples", "validation",
    "configuration", "documentation",
])
def test_english_words_still_excluded(word: str):
    assert _looks_like_word(word), f"{word!r} should still be classified as a word"


# ── Scenario H: UUID handling unchanged ────────────────────────


def test_uuid_v4_with_hyphens_still_excluded_via_find_path():
    """Sanity check that UUID exclusion still wins — _looks_like_word
    isn't the relevant filter here, _is_uuid is.  Confirm the end-to-
    end find path still drops UUIDs (no entropy match generated)."""
    uuid_val = "550e8400-e29b-41d4-a716-446655440000"
    matches = find_high_entropy_strings(uuid_val)
    assert not matches, "UUID v4 must not produce an entropy match"


# ── Word-filter edge cases ─────────────────────────────────────


def test_word_filter_handles_empty_string():
    assert not _looks_like_word("")


def test_word_filter_vowel_ratio_below_floor_rejected():
    """A string with vowel ratio under 0.25 (e.g. random consonants)
    should NOT be classified as a word — tightening to 0.25 closes
    the lower edge that was admitting noise."""
    # 'tprstr' — 0 vowels, ratio 0, lowercase span 6
    assert not _looks_like_word("tprstr")


def test_word_filter_lowercase_run_under_four_rejected():
    """Strings with a lowercase letter scattered among uppercase
    (no run ≥4) shouldn't pass the word filter."""
    # Vowel-rich but only ASOLO-like — lowercase runs of 1
    # 'AeIoUaEiOu' — vowel ratio 1.0 (will fail upper bound)
    # Better: a real boundary case with mixed runs
    assert not _looks_like_word("aBcDeFgHiJkL")  # alternating, max lowercase run = 1


# ── End-to-end on a synthetic content block ────────────────────


def test_full_find_path_catches_github_pat_post_tuning():
    """Belt-and-braces: drop a GitHub-PAT-shape token into a synthetic
    file body and confirm the public ``find_high_entropy_strings``
    surfaces it post-tuning.  Pre-tuning, this would have returned []."""
    content = (
        "# Sample config — should NOT contain real secrets, but tests our detector\n"
        "GITHUB_TOKEN = 'ghp_aB3xT9KmN2vPq8RsLwE7yJhFdGuVcXzY1nM4'\n"
        "OTHER_VAR = 'short'\n"
    )
    matches = find_high_entropy_strings(content, min_length=MIN_SECRET_LENGTH)
    # At least one match must be near the GitHub token line
    assert any("ghp_" in m.value or m.value.endswith("nM4") for m in matches), (
        "Tuned detector failed to surface the GitHub PAT shape"
    )
