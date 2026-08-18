"""CI guard: every rule must compile with google-re2 OR be in the
allowlist.

Why this test exists
====================
Vooda's secret-scanner uses a hybrid regex engine.  ~97.8% of the
rule pack lands on google-re2 (ReDoS-immune by design) and the
remaining ~2.2% falls back to the third-party `regex` library with
a 2-second per-match timeout safety net.

The fallback path is the LEGACY path — every rule on it represents
ongoing ReDoS exposure (bounded by timeout, but still capable of
burning CPU for 2 seconds per pathological input).  The goal is to
drive that count to zero (Track-A Option B-4).

This test pins the current fallback set as a baseline in
``services/secret_scan/detectors/re2_fallback_baseline.json``.  It
fails when:

  * a PR introduces a brand-new fallback rule (rule_id not in
    baseline).  Author must either rewrite the pattern to be re2-
    compatible (see scripts/rewrite_lookaheads.py for the 2-pass
    codemod) OR explicitly add to the baseline with a justification
    comment in the same commit.

  * a PR changes WHY an existing baseline rule is on the fallback
    path (e.g. went from "lookahead" to "large_repetition").  Forces
    an explicit update so historical context is preserved.

It does NOT fail when:

  * a PR removes a rule from the fallback (i.e. rewrites it to be
    re2-compatible).  Instead it prints the rule_ids that became
    compatible so the developer can update the baseline in the same
    commit — leaving the baseline stale would dilute the test's
    signal over time.

Failure messages quote the offending rule_id + the re2 compile error
so the developer can act without running the survey script manually.

To regenerate the baseline after intentional changes:

    docker compose exec worker python -c "
    import json, re2
    from services.secret_scan.detectors.registry import get_all_rules
    opts = re2.Options(); opts.log_errors = False
    rules = get_all_rules()
    fallback = []
    for r in rules:
        try: re2.compile(r.pattern, options=opts)
        except Exception as e:
            reason = (
                'lookahead' if '(?=' in r.pattern else
                'negative_lookahead' if '(?!' in r.pattern else
                'lookbehind' if '(?<' in r.pattern else
                'large_repetition' if 'repetition' in str(e).lower() else 'other'
            )
            fallback.append({'rule_id': r.rule_id, 'reason': reason})
    fallback.sort(key=lambda x: x['rule_id'])
    data = {'_baseline_version': '2', '_total_count': len(fallback),
            'fallback_rules': fallback}
    json.dump(data, open('services/secret_scan/detectors/re2_fallback_baseline.json', 'w'), indent=2)
    "
"""
from __future__ import annotations

import json
import os
import pathlib

import pytest

try:
    import re2 as _re2  # type: ignore
    _RE2_AVAILABLE = True
except ImportError:
    _re2 = None
    _RE2_AVAILABLE = False

from services.secret_scan.detectors.registry import get_all_rules


BASELINE_PATH = (
    pathlib.Path(__file__).resolve().parents[2]
    / "services" / "secret_scan" / "detectors" / "re2_fallback_baseline.json"
)


def _load_baseline() -> dict[str, str]:
    """Return ``{rule_id: reason}`` from the JSON baseline."""
    with open(BASELINE_PATH) as f:
        data = json.load(f)
    return {entry["rule_id"]: entry["reason"] for entry in data["fallback_rules"]}


def _classify_re2_error(pattern: str, err_msg: str) -> str:
    """Map a re2 compile failure to one of the documented reason codes.

    Match the canonical reasons used in the baseline JSON so the
    baseline-comparison errors stay consistent over time.
    """
    if "(?=" in pattern:
        return "lookahead"
    if "(?!" in pattern:
        return "negative_lookahead"
    if "(?<" in pattern:
        return "lookbehind"
    if "repetition" in err_msg.lower():
        return "large_repetition"
    return "other"


@pytest.mark.skipif(not _RE2_AVAILABLE, reason="google-re2 not installed in this env")
def test_no_new_regex_fallback_rules() -> None:
    """Every rule must compile with re2 OR be in the baseline allowlist.

    A new rule that uses lookahead / lookbehind / large-repetition
    (>1000) WILL fail this test.  The fix is one of:

    1. Rewrite the pattern to be re2-compatible (preferred).  For
       lookahead patterns specifically, ``scripts/rewrite_lookaheads.py``
       can auto-convert single-stage lookaheads to the post_filter_*
       2-pass form.

    2. Shrink the repetition upper bound to <=1000.

    3. If the pattern semantically cannot be expressed in re2 (rare),
       add the rule_id to the baseline JSON with a comment in the PR
       explaining why.  This is an explicit, reviewable opt-in to the
       legacy regex+timeout fallback path.
    """
    opts = _re2.Options()
    opts.log_errors = False  # silence per-pattern stderr noise

    baseline = _load_baseline()
    actual_fallback: dict[str, tuple[str, str]] = {}  # rule_id -> (reason, err_msg)

    for r in get_all_rules():
        try:
            _re2.compile(r.pattern, options=opts)
        except Exception as exc:
            msg = str(exc)
            actual_fallback[r.rule_id] = (
                _classify_re2_error(r.pattern, msg),
                msg[:200],
            )

    new_fallback = sorted(set(actual_fallback) - set(baseline))
    resolved = sorted(set(baseline) - set(actual_fallback))
    reason_changed = sorted(
        rid for rid in (set(actual_fallback) & set(baseline))
        if actual_fallback[rid][0] != baseline[rid]
    )

    problems: list[str] = []

    if new_fallback:
        problems.append(
            f"❌ {len(new_fallback)} new rule(s) cannot compile with re2 and were not "
            f"in the baseline allowlist.  Either rewrite the pattern to be re2-compatible "
            f"(see scripts/rewrite_lookaheads.py for the lookahead codemod) OR add the "
            f"rule_id to {BASELINE_PATH.name} with a justification.  New entries:"
        )
        for rid in new_fallback:
            reason, msg = actual_fallback[rid]
            problems.append(f"  - {rid}  ({reason}): {msg[:120]}")

    if reason_changed:
        problems.append(
            f"❌ {len(reason_changed)} baseline rule(s) changed reason.  Update the "
            f"baseline to match the new classification:"
        )
        for rid in reason_changed:
            new_reason = actual_fallback[rid][0]
            old_reason = baseline[rid]
            problems.append(f"  - {rid}: {old_reason} → {new_reason}")

    # Resolved rules are SUCCESS — but stale baseline entries dilute
    # the test's signal over time, so flag them as a warning the
    # author must address (by removing them from the baseline) in
    # the same PR.  We fail the test for this case too: the baseline
    # is part of the rule pack's invariants, not an optional artifact.
    if resolved:
        problems.append(
            f"⚠️  {len(resolved)} baseline rule(s) are now re2-compatible — remove "
            f"them from {BASELINE_PATH.name}:"
        )
        for rid in resolved:
            problems.append(f"  - {rid}")

    assert not problems, "\n" + "\n".join(problems)


def test_baseline_file_is_well_formed() -> None:
    """The JSON baseline itself is parseable + every entry has a known reason."""
    valid_reasons = {"lookahead", "negative_lookahead", "lookbehind", "large_repetition", "other"}
    assert BASELINE_PATH.exists(), f"Baseline JSON missing: {BASELINE_PATH}"
    with open(BASELINE_PATH) as f:
        data = json.load(f)
    assert "fallback_rules" in data, "Baseline JSON missing fallback_rules key"
    assert isinstance(data["fallback_rules"], list), "fallback_rules must be a list"

    seen_ids: set[str] = set()
    for entry in data["fallback_rules"]:
        assert "rule_id" in entry, f"Entry missing rule_id: {entry}"
        assert "reason" in entry, f"Entry missing reason: {entry}"
        assert entry["reason"] in valid_reasons, (
            f"{entry['rule_id']}: unknown reason {entry['reason']!r}; "
            f"valid reasons are {sorted(valid_reasons)}"
        )
        assert entry["rule_id"] not in seen_ids, f"Duplicate rule_id in baseline: {entry['rule_id']}"
        seen_ids.add(entry["rule_id"])

    # Entries should be sorted alphabetically — keeps git diffs clean
    rule_ids = [e["rule_id"] for e in data["fallback_rules"]]
    assert rule_ids == sorted(rule_ids), (
        "fallback_rules must be sorted alphabetically by rule_id for clean diffs"
    )
