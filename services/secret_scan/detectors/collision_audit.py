# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Same-id collision audit for detector modules.

Why this module exists
======================
Vooda's detector registry uses **last-wins dedup** — when two detector
modules define a ``SecretRule`` with the same ``rule_id``, only the
LAST-loaded one ends up in the live rule set; the earlier one is
silently shadowed dead code.

Discovered 2026-05-22 during the Track-A detection audit: **72 such
collisions existed** on master at the time of discovery, silently
shadowing **51 rules**.  Some shadows were strictly-worse versions
(safe to delete), some were complementary detectors that should have
their own id (real lost coverage), and one (`VOODA-SEC-NEON-001`)
actually had the higher-severity version silently shadowed by a
lower-severity one — a real misclassification.

This module exposes the parser + the baseline-aware diff so a CI test
can catch any **new** collision introduced by a PR while tolerating
the documented baseline.  When Phase 1+ work removes baseline
collisions, the baseline file is updated in the same PR — making the
cleanup visible in the diff.

Public API
----------
* ``walk_secret_rule_definitions()`` — yields one ``RuleDefinition``
  per ``SecretRule(...)`` call found in the detector source.
* ``find_collisions()`` — returns {rule_id: [source_files]} for every
  rule_id appearing in 2+ files.
* ``load_baseline()`` / ``BASELINE_PATH`` — the frozen snapshot of
  collisions that existed when this module shipped.
* ``diff_against_baseline()`` — returns (new_collisions, grown_collisions,
  resolved_collisions) — the three things a CI test cares about.

ZERO behavior change to runtime detection.  Pure audit infrastructure.
"""
from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


# Anchor on this file's location so the walker works whether you call
# it from repo root, from tests/, or from inside the API container.
_DETECTORS_DIR = Path(__file__).resolve().parent
BASELINE_PATH = _DETECTORS_DIR / "collision_baseline.json"


@dataclass(frozen=True)
class RuleDefinition:
    """One `SecretRule(...)` call located in the detector source.

    `file` is the module name (without `.py`), matching the strings in
    ``registry._DETECTOR_MODULES`` so callers can correlate against
    the load order.
    """
    file: str
    line: int
    rule_id: str


def walk_secret_rule_definitions(detectors_dir: Path = _DETECTORS_DIR) -> Iterable[RuleDefinition]:
    """Parse every ``SecretRule(...)`` call out of the detector source.

    AST-light approach: we use a paren-balanced scan rather than the
    `ast` module because we only need the rule_id string out of each
    call — full AST would be slower and require importing every module
    (which has import-time side effects like compiling regexes).
    """
    for fname in sorted(os.listdir(detectors_dir)):
        if not fname.endswith(".py") or fname.startswith("__"):
            continue
        # Skip ourselves and the registry — they don't define SecretRules
        if fname in ("collision_audit.py", "registry.py", "base.py"):
            continue
        src = (detectors_dir / fname).read_text()
        mod = fname.replace(".py", "")
        for m in re.finditer(r'SecretRule\s*\(', src):
            # Walk balanced parens to find the end of this SecretRule(...)
            depth = 1
            i = m.end()
            in_str = False
            str_char = ''
            while i < len(src) and depth > 0:
                c = src[i]
                if in_str:
                    if c == '\\':
                        i += 2
                        continue
                    if c == str_char:
                        in_str = False
                elif c in '"\'':
                    in_str = True
                    str_char = c
                elif c == '(':
                    depth += 1
                elif c == ')':
                    depth -= 1
                i += 1
            block = src[m.start():i]
            rid_match = re.search(r'rule_id\s*=\s*[\'"]([^\'"]+)[\'"]', block)
            if rid_match:
                line_no = src[:m.start()].count('\n') + 1
                yield RuleDefinition(file=mod, line=line_no, rule_id=rid_match.group(1))


def find_collisions(detectors_dir: Path = _DETECTORS_DIR) -> dict[str, list[str]]:
    """Return ``{rule_id: sorted_unique_source_files}`` for every rule_id
    that appears in more than one detector module.

    Files are sorted + deduplicated so the output is stable across runs
    and serializes cleanly into the baseline JSON.
    """
    by_rid: dict[str, set[str]] = defaultdict(set)
    for d in walk_secret_rule_definitions(detectors_dir):
        by_rid[d.rule_id].add(d.file)
    return {
        rid: sorted(files)
        for rid, files in sorted(by_rid.items())
        if len(files) > 1
    }


def load_baseline(path: Path = BASELINE_PATH) -> dict[str, list[str]]:
    """Load the frozen baseline of known-tolerated collisions.

    The baseline file is JSON in one of two shapes:

    1. Documented form (what we ship):
       ``{"_doc": "...narrative...", "collisions": {rule_id: [files]}}``
       The ``_doc`` field makes the file self-documenting when a
       developer opens it cold.

    2. Bare form (returned by older tooling):
       ``{rule_id: [files], ...}``
       Treated as the raw collision map.

    Returns an empty dict if the file doesn't exist yet — useful for
    bootstrapping in a fresh repo.
    """
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    if isinstance(data, dict) and "collisions" in data and isinstance(data["collisions"], dict):
        return data["collisions"]
    return data


def diff_against_baseline(
    current: dict[str, list[str]] | None = None,
    baseline: dict[str, list[str]] | None = None,
) -> tuple[dict[str, list[str]], dict[str, tuple[list[str], list[str]]], list[str]]:
    """Compare the current collision state to the baseline.

    Returns three buckets a CI test cares about:

    1. ``new_collisions`` — rule_ids that collide today but weren't in
       baseline.  PR introduced a brand-new collision.  **FAIL**.
    2. ``grown_collisions`` — rule_ids that collided in baseline AND
       still collide, but the set of source files changed (e.g. went
       from 2 → 3 files, or a new file replaced an old one).  **FAIL**
       because it indicates the shadow set grew or shifted unexpectedly.
    3. ``resolved_collisions`` — rule_ids that were in baseline but
       no longer collide today.  Not a failure — this is Phase 1+
       cleanup work.  The test should INSTRUCT the developer to update
       the baseline in the same PR.
    """
    if current is None:
        current = find_collisions()
    if baseline is None:
        baseline = load_baseline()

    new_collisions = {
        rid: files for rid, files in current.items() if rid not in baseline
    }
    grown_collisions = {
        rid: (baseline[rid], files)
        for rid, files in current.items()
        if rid in baseline and set(baseline[rid]) != set(files)
    }
    resolved_collisions = sorted(rid for rid in baseline if rid not in current)

    return new_collisions, grown_collisions, resolved_collisions
