"""CI guard: no NEW same-rule_id collisions across detector modules.

Why this test exists
====================
Vooda's detector registry uses last-wins dedup — when two detector
modules define a ``SecretRule`` with the same ``rule_id``, the
earlier one is silently shadowed dead code.  Discovered 2026-05-22
during the Track-A detection audit: 72 such collisions existed on
master, silently shadowing 51 rules.

This test pins the current collision set as a baseline (frozen in
``services/secret_scan/detectors/collision_baseline.json``).  It
fails when:

  * a PR introduces a brand-new collision (rule_id not in baseline)
  * a PR changes WHICH files a baseline collision spans
    (e.g. went from 2 files to 3, or replaced a file)

It does NOT fail when:

  * a PR resolves a baseline collision (Phase 1+ cleanup work).
    Instead it prints the rule_ids that were resolved so the
    developer can update the baseline in the same commit.

Failure message includes the offending rule_id + the file pair so
the developer can act without re-running the audit script.
"""
from __future__ import annotations

import pytest

from services.secret_scan.detectors.collision_audit import (
    diff_against_baseline,
    find_collisions,
    load_baseline,
    BASELINE_PATH,
)


def test_no_new_same_id_collisions():
    """Hard fail on new collisions; soft message on resolved ones."""
    current = find_collisions()
    baseline = load_baseline()

    new_collisions, grown_collisions, resolved_collisions = diff_against_baseline(
        current=current, baseline=baseline,
    )

    failures: list[str] = []

    if new_collisions:
        lines = ["NEW same-rule_id collisions introduced (this PR added them):"]
        for rid, files in sorted(new_collisions.items()):
            lines.append(f"  - {rid}: defined in {files}")
        lines.append("")
        lines.append(
            "Each new collision means one of the rules is dead code "
            "(silently shadowed by the registry's last-wins dedup). "
            "Pick a distinct rule_id for the new rule or remove the "
            "duplicate definition."
        )
        failures.append("\n".join(lines))

    if grown_collisions:
        lines = ["EXISTING collisions changed shape (new file added or replaced):"]
        for rid, (was, now) in sorted(grown_collisions.items()):
            lines.append(f"  - {rid}: was {was} → now {now}")
        lines.append("")
        lines.append(
            "Either intentional (then update collision_baseline.json) "
            "or accidental (then revert the new file's rule_id)."
        )
        failures.append("\n".join(lines))

    # Resolved collisions are NOT a failure — they're the goal of
    # Phase 1+ cleanup.  But the developer must update the baseline
    # in the same commit so the snapshot stays in sync.
    if resolved_collisions and not failures:
        # Print as a notice, not a failure, so cleanup PRs see a clear
        # call to action.
        msg = (
            f"\n[NOTICE] {len(resolved_collisions)} baseline collision(s) "
            "appear to have been resolved by this change:\n"
            + "\n".join(f"  - {rid}" for rid in resolved_collisions)
            + f"\n\nUpdate the baseline in this PR so the snapshot stays in "
              f"sync.  From repo root:\n\n"
            f"  python3 -m services.secret_scan.detectors.collision_audit_refresh\n"
            f"\n(or hand-edit {BASELINE_PATH.relative_to(BASELINE_PATH.parents[3])})"
        )
        print(msg)

    if failures:
        pytest.fail("\n\n".join(failures))


def test_baseline_file_is_well_formed():
    """The baseline file must exist, be valid JSON, and contain only
    known rule_ids — guards against the baseline drifting into
    something the rest of the suite can't load."""
    baseline = load_baseline()
    assert isinstance(baseline, dict), "baseline must deserialize to a dict"
    for rid, files in baseline.items():
        assert isinstance(rid, str) and rid.startswith("VOODA-SEC-"), (
            f"baseline contains invalid rule_id {rid!r}"
        )
        assert isinstance(files, list) and all(isinstance(f, str) for f in files), (
            f"baseline entry for {rid} must be a list of file names"
        )
        assert len(files) >= 2, (
            f"baseline entry for {rid} must list at least 2 files "
            "(otherwise it's not a collision); got {files}"
        )


def test_baseline_count_matches_audit_findings():
    """Sanity guard: pin the baseline collision count to catch drift
    from direct DB / manual edits.  Updated as Phase 1+ cleanup work
    resolves collisions.

    History:
      2026-05-22  initial baseline (Phase 0)        — 72 collisions
      2026-05-22  Phase 1 (7 safe drops)            → 65 collisions
      2026-05-22  Phase 2 (NEON unhide via rename)  → 64 collisions
      2026-05-22  Phase 3 (25 context_vs_shape)     → 39 collisions
      2026-05-22  Phase 4 (39 genuine_conflict)     →  0 collisions
    """
    baseline = load_baseline()
    EXPECTED_BASELINE_COUNT = 0
    assert len(baseline) == EXPECTED_BASELINE_COUNT, (
        f"Baseline drifted: expected {EXPECTED_BASELINE_COUNT} collisions, "
        f"found {len(baseline)}. If this is intentional (cleanup work), "
        "update EXPECTED_BASELINE_COUNT in this test."
    )
