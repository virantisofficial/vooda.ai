# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Suppression rules must actually suppress.

The rules were storable, listable, editable and deletable, and the UI
rendered a "Matches" column for them — but nothing ever read them. They
appeared in their own model, their own router, and nowhere else: not in
the scan pipeline, not in the findings query. An operator could write a
rule to silence a known false positive, watch it save, and see the same
finding on every subsequent scan.

These tests pin the behaviour that makes the feature real, and the
properties that keep it safe:

- Every criterion a rule sets must match (AND, not OR). The looser
  reading lets a narrow-looking rule silence a whole codebase.
- A rule with no criteria matches nothing rather than everything.
- A suppression is reversible, and reversal is scoped by a machine
  reason so it can never revert a human's decision or a
  verified-inactive suppression.
- Findings are hidden, never deleted — the evidence survives.
"""
import uuid

import pytest

from apps.api.app.models.suppression import SuppressionRule
from services.suppressions.engine import (
    REASON_PREFIX,
    apply_suppression_rules,
    compute_pattern_hash,
    reason_for,
    rule_has_criteria,
    rule_matches,
)


def _rule(**criteria) -> SuppressionRule:
    r = SuppressionRule(name="t", suppression_type="manual", **criteria)
    r.id = uuid.uuid4()
    r.times_applied = 0
    r.is_active = True
    return r


class _Finding:
    """Stands in for NormalizedFinding — the matcher reads these fields."""

    def __init__(self, rule=None, cat=None, cwe=None, path="", code="",
                 suppressed=False, reason=None):
        self.scanner_rule_id = rule
        self.vulnerability_category = cat
        self.cwe = cwe
        self.file_path = path
        self.code_snippet = code
        self.is_suppressed = suppressed
        self.suppression_reason = reason


FINDING = dict(rule="VOODA-SEC-AWS-001", cat="secret", cwe="CWE-798", path="src/app.py")


# ── matching ─────────────────────────────────────────────────────────

def test_a_rule_with_no_criteria_matches_nothing():
    """Treating "no criteria" as a wildcard would silence the tenant."""
    assert rule_has_criteria(_rule()) is False
    assert rule_matches(_rule(), _Finding(**FINDING)) is False


@pytest.mark.parametrize("criteria", [
    {"scanner_rule_id": "VOODA-SEC-AWS-001"},
    {"vulnerability_category": "secret"},
    {"cwe": "CWE-798"},
    {"file_path_pattern": "src/*"},
])
def test_each_criterion_matches_on_its_own(criteria):
    assert rule_matches(_rule(**criteria), _Finding(**FINDING)) is True


@pytest.mark.parametrize("criteria", [
    {"scanner_rule_id": "VOODA-SEC-GCP-001"},
    {"vulnerability_category": "sql_injection"},
    {"cwe": "CWE-89"},
    {"file_path_pattern": "tests/*"},
])
def test_a_wrong_criterion_blocks_the_match(criteria):
    assert rule_matches(_rule(**criteria), _Finding(**FINDING)) is False


def test_criteria_combine_with_and_not_or():
    """A rule naming a scanner rule AND a path means "this rule, in these
    files". Read as OR, it would silence every finding in the codebase."""
    rule = _rule(scanner_rule_id="VOODA-SEC-AWS-001", file_path_pattern="tests/*")
    assert rule_matches(rule, _Finding(**FINDING)) is False, (
        "the rule id matched but the path did not — this must not suppress"
    )
    in_tests = dict(FINDING, path="tests/unit/x.py")
    assert rule_matches(rule, _Finding(**in_tests)) is True


def test_glob_crosses_directory_separators():
    """Someone writing `tests/*` means everything under tests."""
    rule = _rule(file_path_pattern="tests/*")
    assert rule_matches(rule, _Finding(path="tests/deep/nested/x.py")) is True


def test_pattern_hash_ignores_reindentation():
    a = _Finding(code='key = "AKIA..."')
    b = _Finding(code='    key   =   "AKIA..."  ')
    assert compute_pattern_hash(a.code_snippet) == compute_pattern_hash(b.code_snippet)
    rule = _rule(pattern_hash=compute_pattern_hash(a.code_snippet))
    assert rule_matches(rule, b) is True


# ── applying ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_apply_suppresses_and_stamps_a_reversible_reason():
    rule = _rule(scanner_rule_id="VOODA-SEC-AWS-001")
    f = _Finding(**FINDING)
    n = await apply_suppression_rules(None, uuid.uuid4(), [f], only_rule=rule)
    assert n == 1
    assert f.is_suppressed is True
    assert f.suppression_reason == reason_for(rule.id)
    assert f.suppression_reason.startswith(REASON_PREFIX), (
        "without a machine-readable back-reference the suppression is a "
        "one-way door — nothing can find what this rule hid"
    )


@pytest.mark.asyncio
async def test_times_applied_reflects_what_happened():
    """The UI renders this as the "Matches" column; it was never
    incremented, so it always read zero."""
    rule = _rule(scanner_rule_id="VOODA-SEC-AWS-001")
    findings = [_Finding(**FINDING) for _ in range(3)]
    await apply_suppression_rules(None, uuid.uuid4(), findings, only_rule=rule)
    assert rule.times_applied == 3


@pytest.mark.asyncio
async def test_an_already_suppressed_finding_is_left_alone():
    """A human's decision, or a verified-inactive suppression, must not
    be overwritten by a rule that happens to match."""
    rule = _rule(scanner_rule_id="VOODA-SEC-AWS-001")
    f = _Finding(**FINDING, suppressed=True, reason="analyst reviewed")
    n = await apply_suppression_rules(None, uuid.uuid4(), [f], only_rule=rule)
    assert n == 0
    assert f.suppression_reason == "analyst reviewed"


@pytest.mark.asyncio
async def test_findings_are_hidden_not_deleted():
    rule = _rule(scanner_rule_id="VOODA-SEC-AWS-001")
    findings = [_Finding(**FINDING), _Finding(rule="OTHER")]
    await apply_suppression_rules(None, uuid.uuid4(), findings, only_rule=rule)
    assert len(findings) == 2, "suppression hides evidence, it does not destroy it"
    assert findings[1].is_suppressed is False


@pytest.mark.asyncio
async def test_one_rule_owns_a_finding():
    """Two matching rules must not double-count; the reason names one."""
    r1 = _rule(scanner_rule_id="VOODA-SEC-AWS-001")
    r2 = _rule(vulnerability_category="secret")
    f = _Finding(**FINDING)
    n = 0
    n += await apply_suppression_rules(None, uuid.uuid4(), [f], only_rule=r1)
    n += await apply_suppression_rules(None, uuid.uuid4(), [f], only_rule=r2)
    assert n == 1
    assert f.suppression_reason == reason_for(r1.id)


# ── wiring ───────────────────────────────────────────────────────────

def test_the_scan_pipeline_applies_rules():
    """The whole defect: rules existed but nothing consulted them."""
    import inspect
    from apps.worker import tasks
    src = inspect.getsource(tasks)
    assert "apply_suppression_rules" in src, (
        "suppression rules are not applied during a scan, so a rule an "
        "operator writes has no effect on the next scan"
    )


@pytest.mark.parametrize("path", ["source_scan", "webhook_scan"])
def test_every_scan_path_applies_rules(path):
    """Rule overrides run in all three scan paths; suppressions ran in
    one. A rule that silences a finding from Git while missing the same
    secret arriving via Jira or a pull request is worse than no rule —
    the operator believes it is handled."""
    import inspect
    from apps.worker import tasks
    src = inspect.getsource(tasks)
    assert f'path="{path}"' in src, (
        f"the {path} path does not apply suppression rules"
    )


def test_suppression_coverage_matches_rule_overrides():
    """Both are noise control. If one covers a scan path the other does
    not, findings leak through whichever is behind."""
    import inspect
    from apps.worker import tasks
    src = inspect.getsource(tasks)
    assert src.count("apply_suppression_rules") >= src.count("load_active_rule_ids") - 1, (
        "suppressions cover fewer scan paths than rule overrides do"
    )


@pytest.mark.parametrize("hook", ["apply_rule_to_existing", "unapply_rule"])
def test_the_router_applies_and_reverts(hook):
    """Creating a rule must silence findings already on screen, and
    removing or deactivating it must bring them back."""
    import inspect
    from apps.api.app.routers import suppressions
    assert hook in inspect.getsource(suppressions)
