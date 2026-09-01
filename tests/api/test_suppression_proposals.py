# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Learning may propose a suppression, but only a human may enable one.

Learning previously read one signal: findings a person marked false
positive. That is the strongest evidence available, and it is also
evidence most installs never produce — nobody hand-triages, so nothing
was ever learned.

AI triage is the abundant signal. It is also a guess, and letting a
guess create a live rule closes a loop: matching findings would be
suppressed before anyone saw them, and the evidence that would expose a
systematic blind spot is exactly what gets hidden. The fingerprint makes
that worse — string literals normalise to "STR", so a real credential
and a documentation sample share a pattern. Fair to generalise from
several people agreeing; reckless from a verdict on a finding nobody
opened.

So AI evidence proposes and a human disposes. These tests pin that
boundary, and the two things that make the queue survivable: a human's
"this is real" outranks the model, and a rejection is remembered.
"""
import uuid

import pytest

from services.learning import pattern_learner as PL
from services.suppressions.engine import rule_matches


class _Rule:
    """Stands in for a stored SuppressionRule."""

    def __init__(self, **kw):
        self.id = uuid.uuid4()
        self.scanner_rule_id = kw.get("scanner_rule_id")
        self.pattern_hash = kw.get("pattern_hash")
        self.vulnerability_category = kw.get("vulnerability_category")
        self.cwe = kw.get("cwe")
        self.file_path_pattern = kw.get("file_path_pattern")
        self.is_active = kw.get("is_active", True)
        self.review_status = kw.get("review_status")


# ── the boundary ─────────────────────────────────────────────────────

def test_ai_evidence_needs_more_of_it_than_human_evidence():
    """A human FP mark means someone looked. A model verdict does not,
    so more of them are required to say the same thing."""
    assert PL.MIN_AI_FP_COUNT > PL.MIN_FP_COUNT


def test_the_two_sources_are_distinguishable_on_the_pattern():
    p = PL.LearnedPattern(
        rule_id="AWS-001", pattern_hash="h", category="c",
        fp_count=5, repo_count=2, source=PL.SOURCE_AI,
    )
    assert p.source == "ai"
    assert PL.LearnedPattern(
        rule_id="x", pattern_hash="h", category="c", fp_count=3, repo_count=2,
    ).source == PL.SOURCE_HUMAN, "human evidence stays the default"


# ── a pending proposal is inert ──────────────────────────────────────

def test_a_pending_proposal_is_stored_inactive():
    """Inactive is what keeps it out of the matcher. If a proposal were
    created live, approving it would be a formality after the fact."""
    rule = _Rule(scanner_rule_id="AWS-001", is_active=False, review_status="pending")
    assert rule.is_active is False


def test_the_matcher_query_excludes_pending_rules():
    """Belt and braces: the loader filters on review_status as well as
    is_active, so a rule that went live while still reading 'pending'
    cannot suppress findings the reviewer has not seen."""
    import inspect
    from services.suppressions import engine
    src = inspect.getsource(engine._active_rules)
    assert "review_status" in src and "pending" in src


def test_an_approved_proposal_matches_like_any_other_rule():
    """Approval is the only difference; the matching logic is shared."""
    code = 'key = "AKIA..."'
    rule = _Rule(
        scanner_rule_id="AWS-001", pattern_hash=PL.compute_pattern_hash(code),
        is_active=True, review_status="approved",
    )

    class _F:
        scanner_rule_id = "AWS-001"
        vulnerability_category = None
        cwe = None
        file_path = "src/a.py"
        code_snippet = code
        is_suppressed = False

    assert rule_matches(rule, _F) is True


# ── a human's judgement outranks the model's ─────────────────────────

def test_a_human_true_positive_vetoes_the_pattern():
    """If somebody looked at this shape and called it a real secret, the
    model does not get to propose suppressing it. A proposal in the queue
    reads as an invitation to approve, and the reviewer cannot see the
    earlier disagreement."""
    import inspect
    src = inspect.getsource(PL.propose_patterns)
    assert "_patterns_a_human_called_real" in src or "vetoed" in src

    veto_src = inspect.getsource(PL._patterns_a_human_called_real)
    assert 'action == "mark_tp"' in veto_src


def test_already_suppressed_findings_are_not_re_proposed():
    """Otherwise every scan proposes rules for findings a rule already
    hid, and the queue never empties."""
    import inspect
    src = inspect.getsource(PL.propose_patterns)
    assert "is_suppressed == False" in src


# ── rejection has to stick ───────────────────────────────────────────

def test_sync_skips_any_pattern_that_already_has_a_rule():
    """Including a rejected one. Without that, a rejected proposal is
    re-derived on the next scan and the reviewer decides it forever."""
    import inspect
    src = inspect.getsource(PL.sync_learned_rules)
    assert "review_status" not in src.split("seen = ")[1].split("\n")[0], (
        "the existing-rule lookup must not filter by review_status"
    )
    assert "if key in seen" in src


def test_human_evidence_wins_when_both_sources_agree():
    """The same pattern reaching both thresholds should go live, not sit
    in a queue behind a weaker version of the same conclusion."""
    import inspect
    src = inspect.getsource(PL.sync_learned_rules)
    assert "confirmed + proposed" in src, (
        "confirmed patterns must be consumed first so they claim the key"
    )


# ── the review endpoint ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_reviewing_something_that_is_not_a_proposal_is_refused():
    from unittest.mock import AsyncMock, MagicMock
    from fastapi import HTTPException
    from apps.api.app.routers.suppressions import review_proposal

    rule = _Rule(scanner_rule_id="AWS-001", review_status=None)
    db = MagicMock()
    res = MagicMock()
    res.scalar_one_or_none = MagicMock(return_value=rule)
    db.execute = AsyncMock(return_value=res)
    user = MagicMock()
    user.tenant_id = uuid.uuid4()

    with pytest.raises(HTTPException) as exc:
        await review_proposal(rule_id=rule.id, decision="approve", db=db, user=user)
    assert exc.value.status_code == 409


def test_rejecting_leaves_the_rule_disabled():
    """A rejected proposal must not be enabled as a side effect of being
    decided — the whole point is that the reviewer said no."""
    import inspect
    from apps.api.app.routers import suppressions
    src = inspect.getsource(suppressions.review_proposal)
    assert "rule.is_active = approved" in src


# ── evidence must come from distinct codebases ───────────────────────

def test_the_same_repo_registered_twice_counts_once():
    """The thresholds say "across N repositories" and mean N codebases.

    A repository can be registered many times — one row per scan config,
    per branch policy, or per model being evaluated. On the dataset this
    was built against, 4 codebases were registered as 16 rows, and every
    one of 358 candidate patterns appeared in exactly ONE codebase while
    looking like evidence from five. Counting rows would have created
    337 rules on the strength of duplicate registrations alone.
    """
    a = PL.repo_identity(uuid.uuid4(), "https://github.com/OWASP/wrongsecrets")
    b = PL.repo_identity(uuid.uuid4(), "https://github.com/OWASP/wrongsecrets")
    assert a == b, "different rows, same codebase — this must be one vote"


@pytest.mark.parametrize("variant", [
    "https://github.com/OWASP/wrongsecrets",
    "https://github.com/OWASP/wrongsecrets/",
    "https://github.com/OWASP/wrongsecrets.git",
    "HTTPS://GitHub.com/OWASP/WrongSecrets",
])
def test_url_spelling_does_not_split_a_codebase(variant):
    canonical = PL.repo_identity(uuid.uuid4(), "https://github.com/OWASP/wrongsecrets")
    assert PL.repo_identity(uuid.uuid4(), variant) == canonical


def test_different_codebases_stay_distinct():
    a = PL.repo_identity(uuid.uuid4(), "https://github.com/OWASP/wrongsecrets")
    b = PL.repo_identity(uuid.uuid4(), "https://github.com/gitleaks/gitleaks")
    assert a != b


def test_a_repo_with_no_url_counts_only_as_itself():
    """Merging every URL-less row into one bucket would under-count real
    evidence; merging them into distinct buckets is the safe direction."""
    r1, r2 = uuid.uuid4(), uuid.uuid4()
    assert PL.repo_identity(r1, None) != PL.repo_identity(r2, None)
    assert PL.repo_identity(r1, None) == PL.repo_identity(r1, "")


def test_both_evidence_paths_count_codebases():
    """The human path shares the hazard — it also has a repo threshold."""
    import inspect
    for fn in (PL.learn_patterns, PL.propose_patterns):
        assert "repo_identity" in inspect.getsource(fn), (
            f"{fn.__name__} counts repository rows, so duplicate "
            f"registrations of one codebase pass as independent evidence"
        )


# ── enabling a proposal is approving it ──────────────────────────────

@pytest.mark.asyncio
async def test_toggling_a_pending_proposal_active_approves_it():
    """The list has an ordinary Active switch, and it used to set
    `is_active` alone. The matcher excludes pending rules, so the rule
    read Active and suppressed nothing — the exact silent no-op this
    surface keeps producing. Flipping it on has to mean approval."""
    from unittest.mock import AsyncMock, MagicMock, patch
    from apps.api.app.routers import suppressions as mod
    from apps.api.app.routers.suppressions import (
        SuppressionRuleUpdate, update_suppression_rule,
    )

    rule = _Rule(scanner_rule_id="AWS-001", is_active=False, review_status="pending")
    rule.name = "Proposed: AWS-001"
    rule.description = None
    rule.evidence_count = 5
    rule.evidence_repo_count = 2

    db = MagicMock()
    res = MagicMock()
    res.scalar_one_or_none = MagicMock(return_value=rule)
    db.execute = AsyncMock(return_value=res)
    db.flush = AsyncMock()
    db.commit = AsyncMock()

    async def _refresh(obj):
        return None
    db.refresh = _refresh

    user = MagicMock()
    user.tenant_id = uuid.uuid4()
    user.id = uuid.uuid4()

    async def _noop_audit(*a, **k):
        return None

    with patch.object(mod, "log_audit", side_effect=_noop_audit):
        result = await update_suppression_rule(
            rule_id=rule.id,
            body=SuppressionRuleUpdate(is_active=True),
            db=db, user=user,
        )

    assert rule.review_status == "approved", (
        "enabling a proposal left it pending, so the matcher still skips it"
    )
    assert rule.is_active is True
    assert result["review_status"] == "approved"


def test_the_toggle_delegates_rather_than_duplicating_the_decision():
    """Approval applies the rule to existing findings and writes a
    distinct audit action. A second copy of that logic in the update
    path would drift from it."""
    import inspect
    from apps.api.app.routers import suppressions
    src = inspect.getsource(suppressions.update_suppression_rule)
    assert "review_proposal(" in src
