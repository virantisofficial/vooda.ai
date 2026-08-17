"""Tier A — tighten near-zero-TP rules to canonical shapes (recall-safe).

Derived from the 100-repo Opus-vs-Vooda benchmark. Three independent
tightenings, each pinned here so it can't silently regress:

1. Base64 self-anchor gate (engine ``_pattern_is_b64_self_anchored``).
   The Phase-2.5 base64 pass decodes every base64 run and re-runs EVERY rule on
   the decoded bytes, bypassing keyword/post_filter context. That is only sound
   for self-anchored rules (``ghp_``/``AKIA``/``xox``/slack-URL). Bare-shape
   rules (Segment {32}, Plausible {43}, Vercel {24}, ConvertKit {22}) collide
   with arbitrary decoded base64 → ~430 benchmark FPs / ~0 real. The gate emits
   ``-B64`` only for anchored rules. Recall-safe: a base64-wrapped real secret
   carries its own signature, which only anchored rules can identify.

2. SEGMENT-WRITE-001 — the bare word "segment" within 500 chars matched any
   32-char hash near "segment tree"/"network segment" (211 FP / 0 TP). Now
   requires the canonical write-key assignment anchor in a tight window.

3. ETSY-002 — the unbounded bridge `(?:etsy)[...]*` let an "etsy" substring
   span a whole codegen JSON to any 24-char token (90 FP / 0 TP). Now bounded
   to an adjacent assignment.

Every tightening ships with a TP fixture (recall=1.0 hard gate) AND an FP-trap
fixture (the exact shape that used to false-fire).
"""
from __future__ import annotations

import base64

import pytest

from services.secret_scan.engine import SecretScanner, _pattern_is_b64_self_anchored


def _rule_ids(findings):
    return {(f.rule_id or "") for f in findings}


def _fires(scanner, path, content, rule_substr):
    return any(rule_substr in (f.rule_id or "")
               for f in scanner.scan_file(path, content))


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


# ── 1. Base64 self-anchor predicate (the recall guarantee for the gate) ──
@pytest.mark.parametrize("pattern", [
    r'ghp_[A-Za-z0-9]{36}',                                  # GitHub PAT
    r'AKIA[0-9A-Z]{16}',                                     # AWS access key id
    r'xox[baprs]-[0-9A-Za-z-]{10,48}',                       # Slack token
    r'glpat-[0-9A-Za-z_-]{20}',                              # GitLab PAT
    r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+',     # Slack webhook URL
    r'(?:^|[^A-Za-z0-9])(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})',  # SendGrid
])
def test_anchored_patterns_are_b64_eligible(pattern):
    assert _pattern_is_b64_self_anchored(pattern) is True, (
        f"RECALL REGRESSION: anchored pattern wrongly excluded from -B64: {pattern}"
    )


@pytest.mark.parametrize("pattern", [
    r'\b([A-Za-z0-9]{32})\b',               # SEGMENT-WRITE-001
    r'\b([A-Za-z0-9_-]{43})\b',             # PLAUSIBLE-001
    r'(?:^|[^A-Za-z0-9])([a-zA-Z0-9]{24})',  # VERCEL-002
    r'\b([A-Za-z0-9_-]{22})\b',             # CONVERTKIT-001
])
def test_bare_shape_patterns_are_not_b64_eligible(pattern):
    assert _pattern_is_b64_self_anchored(pattern) is False, (
        f"bare-shape pattern wrongly allowed into -B64 (shape-collision FP source): {pattern}"
    )


# ── 1b. End-to-end: bare-shape -B64 FP gone, anchored -B64 recall kept ──
def test_base64_of_bare_32char_does_not_emit_segment_b64(scanner):
    # A base64 blob whose plaintext is 32 alnum chars (Segment shape) but with
    # NO segment/writeKey context. Pre-fix this emitted SEGMENT-WRITE-001-B64.
    blob = base64.b64encode(b"abcdABCD1234abcdABCD1234abcdABCD").decode()
    findings = scanner.scan_file("config/app.json", f'{{"opaque_blob": "{blob}"}}\n')
    assert not any("SEGMENT-WRITE-001-B64" in (f.rule_id or "") for f in findings), (
        f"bare-shape Segment rule still emits -B64 on contextless base64: {_rule_ids(findings)}"
    )


def test_base64_of_anchored_token_still_emits_b64(scanner):
    # A base64 blob whose plaintext carries a self-anchored signature (AWS AKIA)
    # MUST still surface via the -B64 path — the gate preserves anchored recall.
    blob = base64.b64encode(b"AKIAQWERTYUIOPASDFGH is the key").decode()
    findings = scanner.scan_file("config/data.txt", f'value = "{blob}"\n')
    assert any((f.rule_id or "").endswith("-B64") for f in findings), (
        f"anchored secret no longer recalled through -B64 path: {_rule_ids(findings)}"
    )


# ── 2. SEGMENT-WRITE-001: canonical write-key anchor ──
def test_segment_writekey_assignment_fires(scanner):
    # TP fixture — recall=1.0 hard gate. A real Segment write key assigned to
    # writeKey must still be caught.
    content = 'analytics.config = { writeKey: "aB3dEf9hIjKlMnOpQrStUvWxYz012345" }\n'
    assert _fires(scanner, "src/analytics.js", content, "SEGMENT-WRITE-001"), (
        "RECALL REGRESSION: canonical Segment writeKey assignment not detected"
    )


def test_segment_word_near_random_hash_does_not_fire(scanner):
    # FP trap — the exact shape that produced 211 FP: the word "segment" near a
    # 32-char hash, with no write-key assignment.
    content = (
        "// rebalance the segment tree after each insert\n"
        'const nodeHash = "aB3dEf9hIjKlMnOpQrStUvWxYz012345";\n'
    )
    assert not _fires(scanner, "src/segment_tree.ts", content, "SEGMENT-WRITE-001"), (
        "SEGMENT-WRITE-001 still fires on a 32-char hash merely near the word 'segment'"
    )


# ── 3. ETSY-002: bounded bridge ──
def test_etsy_keystring_assignment_fires(scanner):
    # TP fixture — recall=1.0 hard gate. An adjacent Etsy keystring assignment
    # must still be DETECTED. (The more-specific ETSY-001 rule overlaps and wins
    # dedup here; ETSY-002 also matches. Either attribution satisfies recall —
    # what matters is that the credential is not missed.)
    content = 'etsy_keystring = "abcdef0123456789abcdef01"\n'
    assert _fires(scanner, "config/etsy.py", content, "ETSY"), (
        "RECALL REGRESSION: adjacent Etsy keystring assignment not detected by any Etsy rule"
    )


def test_etsy_word_far_from_token_does_not_fire(scanner):
    # FP trap — "etsy" mentioned, then a 24-char token far away (>16 chars), the
    # long-distance collision the unbounded bridge used to match.
    content = (
        'description = "etsy is an online marketplace for handmade goods";\n'
        'opaque_id = "abcdef0123456789abcdef01";\n'
    )
    assert not _fires(scanner, "data/catalog.json", content, "ETSY-002"), (
        "ETSY-002 still spans a long gap from the word 'etsy' to an unrelated token"
    )
