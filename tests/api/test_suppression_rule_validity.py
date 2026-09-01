# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""A saved suppression rule must be capable of matching something.

Three ways a rule could be stored looking healthy and never fire:

1. No criteria at all. The matcher refuses to read an empty criteria set
   as a wildcard — correctly, since that would silence the tenant — so
   the rule sat Active with zero matches forever. The form let you save
   one with just a name and a reason.
2. An unknown `suppression_type`. The column took any string, so a typo
   produced a rule the type filter could never surface.
3. A `learned` rule, whose `pattern_hash` came from the learning engine
   while the matcher recomputed it with a *different* function — a
   different normaliser and a different digest length. The two could
   never be equal, so auto-learned rules were structurally inert.

The third is the reason the hash lives in one place now.
"""
import uuid

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from apps.api.app.models.suppression import SuppressionType
from apps.api.app.routers.suppressions import SuppressionRuleCreate
from services.learning.pattern_learner import (
    compute_pattern_hash as learner_hash,
)
from services.suppressions.engine import (
    compute_pattern_hash as engine_hash,
    rule_has_criteria,
    rule_matches,
)


# ── 1. a rule must be able to match ──────────────────────────────────

def test_a_rule_with_only_a_name_is_refused():
    with pytest.raises(ValidationError) as exc:
        SuppressionRuleCreate(name="Silence test noise", description="known FP")
    assert "at least one match criterion" in str(exc.value)


@pytest.mark.parametrize("criterion", [
    {"scanner_rule_id": "AWS-001"},
    {"vulnerability_category": "Hardcoded Secret"},
    {"cwe": "CWE-798"},
    {"file_path_pattern": "tests/**"},
])
def test_any_single_criterion_is_enough(criterion):
    assert SuppressionRuleCreate(name="x", **criterion)


def test_the_refusal_names_the_fields_that_would_fix_it():
    """An error that does not say what to fill in just moves the dead
    end from the list view to the form."""
    with pytest.raises(ValidationError) as exc:
        SuppressionRuleCreate(name="x")
    msg = str(exc.value)
    for field in ("scanner_rule_id", "vulnerability_category",
                  "cwe", "file_path_pattern"):
        assert field in msg


# ── 2. the type must be one we can filter by ─────────────────────────

@pytest.mark.parametrize("value", ["manual", "scanner_rule", "learned"])
def test_known_types_are_accepted(value):
    assert SuppressionRuleCreate(
        name="x", suppression_type=value, scanner_rule_id="AWS-001",
    ).suppression_type == value


@pytest.mark.parametrize("value", ["banana", "auto_learned", "MANUAL", ""])
def test_unknown_types_are_refused(value):
    """`auto_learned` is in here on purpose: it was the example in this
    model's own schema, and it is not a value SuppressionType defines."""
    with pytest.raises(ValidationError):
        SuppressionRuleCreate(
            name="x", suppression_type=value, scanner_rule_id="AWS-001",
        )


def test_the_schema_example_is_a_value_the_schema_accepts():
    """The example is what a client copies. It must validate."""
    for ex in SuppressionRuleCreate.model_fields["suppression_type"].examples:
        assert ex in {t.value for t in SuppressionType}


# ── 3. one hash, or learned rules never fire ─────────────────────────

@pytest.mark.parametrize("code", [
    'aws_key = "AKIAIOSFODNN7EXAMPLE"',
    "token: str = 'ghp_xxxxxxxxxxxx'  # demo",
    "",
])
def test_the_matcher_and_the_learner_agree_on_the_hash(code):
    """The learner writes `pattern_hash`; the matcher reads it. Two
    implementations meant a learned rule could never match its own
    evidence."""
    assert engine_hash(code) == learner_hash(code)


def test_a_learned_rule_matches_the_code_it_was_learned_from():
    """End to end for the case that was broken: a rule carrying the
    hash the learner computed must suppress that same snippet."""
    code = 'password = "hunter2"'

    class _LearnedRule:
        id = uuid.uuid4()
        scanner_rule_id = "GEN-001"
        pattern_hash = learner_hash(code)   # written by the learner
        vulnerability_category = None
        cwe = None
        file_path_pattern = None

    class _Finding:
        scanner_rule_id = "GEN-001"
        vulnerability_category = None
        cwe = None
        file_path_pattern = None
        file_path = "src/app.py"
        code_snippet = code
        is_suppressed = False

    assert rule_has_criteria(_LearnedRule) is True
    assert rule_matches(_LearnedRule, _Finding) is True, (
        "the rule stores the learner's hash and the matcher recomputes "
        "it; if these disagree every auto-learned rule is inert"
    )


def test_reindentation_still_does_not_defeat_a_rule():
    """The shared normaliser must keep the property the matcher relied
    on before: same code, different whitespace, same hash."""
    assert engine_hash('k = "v"') == engine_hash('   k   =   "v"   ')


# ── the update path ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_an_edit_may_not_clear_the_last_criterion():
    from unittest.mock import AsyncMock, MagicMock
    from apps.api.app.routers.suppressions import (
        SuppressionRuleUpdate, update_suppression_rule,
    )

    class _Rule:
        id = uuid.uuid4()
        name = "r"
        description = None
        is_active = True
        review_status = None
        scanner_rule_id = "AWS-001"
        vulnerability_category = None
        cwe = None
        file_path_pattern = None

    db = MagicMock()
    res = MagicMock()
    res.scalar_one_or_none = MagicMock(return_value=_Rule)
    db.execute = AsyncMock(return_value=res)

    user = MagicMock()
    user.tenant_id = uuid.uuid4()

    with pytest.raises(HTTPException) as exc:
        await update_suppression_rule(
            rule_id=_Rule.id,
            body=SuppressionRuleUpdate(scanner_rule_id=None),
            db=db, user=user,
        )
    assert exc.value.status_code == 422
    assert _Rule.scanner_rule_id == "AWS-001", (
        "a refused edit must not have mutated the row"
    )
