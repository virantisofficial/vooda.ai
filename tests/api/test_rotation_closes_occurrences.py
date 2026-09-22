# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Rotation is the way a finding closes, so the pieces it relies on must hold.

Scans no longer close a finding because its file was deleted — the value
survives in git history — which leaves rotation and human triage as the
exits. Marking an incident rotated therefore closes its open occurrences.
These are the invariants that makes rest on; the propagation itself is
covered end to end against a live scan.
"""
from apps.api.app.core.classification_provenance import ESTABLISHED_CLASSIFICATIONS
from apps.api.app.models.finding import Classification
from apps.api.app.core.finding_state import CLOSED as _CLOSED_CLASSIFICATIONS


def test_rotated_counts_as_closed():
    """If this ever drops out, rotating stops draining the open list."""
    assert Classification.ROTATED in _CLOSED_CLASSIFICATIONS


def test_a_deleted_file_no_longer_counts_as_a_fix_route():
    """The classification stays for legacy rows, but scans must not write it.

    Nothing in the worker may set it; a deleted file marks
    `removed_from_code` in source_metadata and leaves the finding open.
    """
    import io
    src = io.open("apps/worker/tasks.py", encoding="utf-8").read()
    assert "RESOLVED_FILE_DELETED" not in src


def test_rotation_is_not_provenance_gated():
    """Closure states are workflow output, so a bulk UPDATE is legitimate.

    Were ROTATED ever added to the provenance-gated set, the propagation
    would have to write through the ORM with an actor attached instead.
    """
    assert Classification.ROTATED.value not in ESTABLISHED_CLASSIFICATIONS
    assert Classification.CONFIRMED_TRUE_POSITIVE.value in ESTABLISHED_CLASSIFICATIONS


def test_only_undecided_occurrences_are_touched():
    """A human verdict must survive someone else's decision on the incident.

    Asserted against the propagation contract rather than the SQL text,
    so a refactor cannot quietly widen it.
    """
    from apps.api.app.core.occurrences import UNDECIDED

    # NOT_ENOUGH_EVIDENCE joined this set when the vocabulary moved to
    # finding_state: it means the model could not decide, so no human
    # verdict is at stake and a later decision must be free to land on
    # it. Leaving it out stranded such occurrences permanently.
    assert set(UNDECIDED) == {
        Classification.NEEDS_REVIEW,
        Classification.NOT_ENOUGH_EVIDENCE,
        Classification.LIKELY_TRUE_POSITIVE,
        Classification.LIKELY_FALSE_POSITIVE,
    }
    for human_verdict in (
        Classification.ACCEPTED_RISK,
        Classification.CONFIRMED_FALSE_POSITIVE,
        Classification.CONFIRMED_TRUE_POSITIVE,
        Classification.TEST_CREDENTIAL,
        Classification.ROTATED,
    ):
        assert human_verdict not in UNDECIDED


def test_every_propagation_site_uses_the_shared_helper():
    """One rule, one implementation.

    Each site that used to hand-roll this disagreed with the others, and
    each disagreement was a bug: no propagation at all, overwritten human
    verdicts, or confirmations written without provenance.
    """
    import io as _io

    for path in (
        "apps/api/app/routers/incidents.py",
        "apps/api/app/routers/findings.py",
    ):
        src = _io.open(path, encoding="utf-8").read()
        assert "propagate_to_occurrences" in src, path
        # No site may write a finding classification across an incident
        # by hand again.
        assert "update(NormalizedFinding)" not in src, path
        assert "sa_update(NormalizedFinding)" not in src, path


def test_every_fan_out_write_to_findings_is_tenant_scoped():
    """A write that touches rows it did not fetch must name the tenant.

    Enumerated mechanically rather than by memory: the audit that found
    the propagation bugs missed three mutation sites the first time,
    because the list was written from recollection.
    """
    import io as _io
    import re

    sources = [
        "apps/worker/tasks.py",
        "apps/api/app/routers/incidents.py",
        "apps/api/app/routers/findings.py",
        "apps/api/app/core/occurrences.py",
        "services/suppressions/engine.py",
    ]
    pattern = re.compile(r"(?:sa_update|sa_update_rs|update)\(NormalizedFinding\)")
    checked = 0
    for path in sources:
        src = _io.open(path, encoding="utf-8").read()
        for m in pattern.finditer(src):
            # The predicate list sits within the statement that follows.
            window = src[m.end(): m.end() + 700]
            assert "tenant_id" in window, f"{path}: fan-out write without tenant scoping"
            checked += 1
    assert checked >= 4, f"expected to audit several sites, saw {checked}"
