# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""The finding-state vocabulary has exactly one owner.

Five modules used to hand-roll their own tuples of classifications and
they disagreed. The worst pair: the metrics router counted
LIKELY_FALSE_POSITIVE as CLOSED while the occurrence propagator counted
it as UNDECIDED — ~90% of all findings, reported as settled on the
dashboard and as open work by the engine that fans verdicts out.
"""

import io
import pathlib
import re

from apps.api.app.core import finding_state as fs
from apps.api.app.models.finding import Classification


def test_every_classification_is_open_or_closed():
    """A new enum value cannot silently default to 'open' or vanish."""
    assert set(fs.CLOSED) | set(fs.OPEN) == set(Classification)
    assert not (set(fs.CLOSED) & set(fs.OPEN))


def test_an_ai_verdict_alone_never_closes_a_finding():
    """The rule the whole module exists to enforce.

    LIKELY_* is the model's opinion. Opinions are carried by
    ai_confidence; only a decision, or a provably dead credential,
    closes. GitHub, GitGuardian and GitLab all require an explicit
    resolution to leave the open state for the same reason.
    """
    for advisory in fs.AI_ADVISORY:
        assert advisory in fs.OPEN, advisory
        assert advisory not in fs.CLOSED, advisory
    assert Classification.LIKELY_FALSE_POSITIVE in fs.OPEN


def test_undecided_never_contradicts_the_open_predicate():
    """The exact contradiction this change removes."""
    for c in fs.UNDECIDED:
        assert c in fs.OPEN, f"{c} is undecided but counted closed"


def test_a_confirmed_real_secret_is_open_until_it_is_rotated():
    assert Classification.CONFIRMED_TRUE_POSITIVE in fs.OPEN


def test_mttr_cannot_count_losing_visibility_as_a_fix():
    """Deleting a repo must not read as an instant remediation."""
    assert Classification.RESOLVED_REPO_REMOVED not in fs.REMEDIATED
    assert Classification.RESOLVED_SOURCE_REMOVED not in fs.REMEDIATED
    assert Classification.ROTATED in fs.REMEDIATED


def test_no_module_hand_rolls_its_own_classification_set():
    """Structural guard: inline literal sets are how this drifted.

    Walks the whole tree rather than a list of files chosen by hand.
    The first pass at this guard *did* use a hand-picked list of five
    modules and consequently missed nine more sites in reports.py and
    the worker — the identical failure mode it exists to prevent.
    """
    inline = re.compile(r"classification\.(not)?in_\(\s*\[")
    offenders = []
    for root in ("apps", "services"):
        for path in pathlib.Path(root).rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            src = path.read_text(encoding="utf-8", errors="replace")
            if inline.search(src):
                offenders.append(str(path))
            assert "_CLOSED_CLASSIFICATIONS" not in src, path
    assert not offenders, (
        "these modules define a classification set inline instead of "
        "importing a named set from apps/api/app/core/finding_state.py: "
        f"{sorted(offenders)}"
    )


def test_sla_reports_exclude_findings_that_were_actually_fixed():
    """A rotated critical secret must not breach SLA forever.

    reports.py used to exclude only the two false-positive verdicts, so
    rotated / accepted-risk / resolved findings still counted as overdue
    in a customer-facing compliance report.
    """
    src = pathlib.Path("apps/api/app/routers/reports.py").read_text(encoding="utf-8")
    assert "is_open(NormalizedFinding)" in src
    assert "confirmed_false_positive" not in src


def test_the_frontend_does_not_hand_roll_the_vocabulary_either():
    """The Python sweep could not see TypeScript, and three components
    had drifted: the dashboard carried its own SETTLED array, and the
    finding panel and incident drawer both told the operator "No action
    needed" on the strength of an unreviewed AI verdict.

    Everything client-side now goes through src/lib/findingState.ts.
    """
    web = pathlib.Path("apps/web/src")
    if not web.exists():            # api-only checkout
        return
    offenders = []
    for path in list(web.rglob("*.tsx")) + list(web.rglob("*.ts")):
        if any(p in path.parts for p in ("node_modules", ".next")):
            continue
        if path.name == "findingState.ts":
            continue
        src = path.read_text(encoding="utf-8", errors="replace")
        # A component listing classification values in an array literal
        # is re-deriving the vocabulary.
        if '"likely_false_positive"' in src and "[" in src:
            for line in src.splitlines():
                if '"likely_false_positive"' in line and "," in line and "[" in line:
                    offenders.append(f"{path}: {line.strip()[:80]}")
    assert not offenders, (
        "client code deriving its own classification set instead of "
        f"importing from src/lib/findingState.ts:\n" + "\n".join(offenders)
    )


def test_an_ai_verdict_is_labelled_as_one_in_the_ui():
    """"False Positive" and "Confirmed FP" must not read identically.

    The label asserted a conclusion the system had not reached.
    """
    lib = pathlib.Path("apps/web/src/lib/findingState.ts")
    if not lib.exists():
        return
    src = lib.read_text(encoding="utf-8")
    assert '"AI: likely not a secret"' in src
    assert '"AI: likely real"' in src


def test_compliance_report_counts_every_classification():
    """by_classification must sum to total_findings.

    The old hand-picked list of six omitted rotated, test_credential and
    the four resolved_* states, so a customer-facing compliance report
    silently dropped findings from its own breakdown.
    """
    src = io.open("services/reporting/generator.py", encoding="utf-8").read()
    assert "for cls in [c.value for c in Classification]" in src
