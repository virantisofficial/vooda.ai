"""Scoring, without spending a request.

The two kinds of mistake are not equal and the arithmetic has to keep
them apart: raising a harmless finding costs a reviewer minutes, while
dismissing a live credential is the failure that reaches an incident
report — and it is the quiet one, because a scan that hides real
secrets looks tidier than one that surfaces them.
"""
import pytest

from services.ai_triage.accuracy_corpus import (
    load_cases, BASE_CASES, TRUE_POSITIVE, FALSE_POSITIVE, AccuracyCase,
)
from services.ai_triage.accuracy_check import (
    score_answer, case_prompt, AccuracyResult, CaseResult,
)

REAL = next(c for c in BASE_CASES if c.expected == TRUE_POSITIVE)
NOISE = next(c for c in BASE_CASES if c.expected == FALSE_POSITIVE)


# ── the corpus itself ───────────────────────────────────────────

def test_case_ids_are_unique():
    ids = [c.case_id for c in load_cases()]
    assert len(ids) == len(set(ids))


def test_both_answers_are_represented():
    cases = load_cases()
    assert sum(1 for c in cases if c.expected == TRUE_POSITIVE) >= 5
    assert sum(1 for c in cases if c.expected == FALSE_POSITIVE) >= 5


def test_noise_outnumbers_secrets():
    """Real scan output is mostly noise. A corpus weighted the other way
    would reward a model that shouts "real secret" at everything."""
    cases = load_cases()
    real = sum(1 for c in cases if c.expected == TRUE_POSITIVE)
    noise = sum(1 for c in cases if c.expected == FALSE_POSITIVE)
    assert noise > real


def test_every_real_secret_is_marked_critical():
    for c in load_cases():
        if c.expected == TRUE_POSITIVE:
            assert c.critical, f"{c.case_id} hides a credential when answered wrongly"


def test_the_prompt_never_leaks_the_answer():
    """A model scored on a prompt containing the answer is not scored.

    Both verdicts appear, because the prompt offers them as the choice
    — that is the question, not a hint. What must not appear is
    anything that distinguishes THIS case: the note explaining why it
    is in the corpus, or the fact that it is marked critical.
    """
    for c in load_cases():
        p = case_prompt(c)
        assert TRUE_POSITIVE in p and FALSE_POSITIVE in p, (
            f"{c.case_id}: both options must be offered, unweighted")
        assert "critical" not in p.lower(), c.case_id
        if c.note:
            assert c.note not in p, c.case_id


def test_the_two_options_are_offered_symmetrically():
    """Naming one verdict twice, or first in a way that suggests a
    default, would tilt every answer in the corpus the same way."""
    p = case_prompt(REAL)
    assert p.count(TRUE_POSITIVE) == p.count(FALSE_POSITIVE) == 1


# ── scoring ─────────────────────────────────────────────────────

@pytest.mark.parametrize("verdict", ["TRUE_POSITIVE", "likely_true_positive"])
def test_catching_a_real_secret_is_correct(verdict):
    r = score_answer(REAL, verdict)
    assert r.correct and not r.missed_secret


@pytest.mark.parametrize("verdict", ["FALSE_POSITIVE", "likely_false_positive"])
def test_dismissing_a_real_secret_is_the_dangerous_miss(verdict):
    r = score_answer(REAL, verdict)
    assert not r.correct
    assert r.missed_secret, "a waved-through credential must be counted apart"


def test_dismissing_noise_is_correct():
    assert score_answer(NOISE, "FALSE_POSITIVE").correct


def test_flagging_noise_is_wrong_but_not_dangerous():
    r = score_answer(NOISE, "TRUE_POSITIVE")
    assert not r.correct
    assert not r.missed_secret, "a false alarm hides nothing"


def test_declining_to_answer_is_not_a_dangerous_miss():
    """needs_review on an unambiguous case is a miss, but it leaves the
    finding in front of a human — which is the safe direction."""
    r = score_answer(REAL, "needs_review")
    assert not r.correct
    assert not r.missed_secret


def test_no_answer_at_all_is_recorded_as_such():
    r = score_answer(REAL, None)
    assert not r.correct and r.error


# ── the headline ────────────────────────────────────────────────

def test_the_headline_leads_with_missed_secrets():
    res = AccuracyResult("m", total=20, correct=17, missed_secrets=2)
    assert "17 of 20 correct" in res.headline
    assert "missed 2 real secrets" in res.headline


def test_a_clean_run_says_so_explicitly():
    """Silence on this point reads as absence of data rather than
    absence of misses."""
    res = AccuracyResult("m", total=20, correct=18, missed_secrets=0)
    assert "missed no real secrets" in res.headline


def test_one_miss_is_singular():
    assert "1 real secret" in AccuracyResult("m", total=20, correct=19,
                                             missed_secrets=1).headline


def test_a_check_that_answered_nothing_is_not_a_clean_sheet():
    """Seen live: every request returned 401 and the headline read
    "0 of 20 correct — missed no real secrets", stating the
    safest-sounding half of a result that did not exist."""
    res = AccuracyResult("m", total=20, correct=0, missed_secrets=0, unanswered=20)
    assert "missed no real secrets" not in res.headline
    assert "Couldn't score" in res.headline


def test_a_partial_run_says_how_much_it_covered():
    """Silence about the cases that never ran reads as "none missed"
    across the whole corpus."""
    res = AccuracyResult("m", total=20, correct=12, missed_secrets=0, unanswered=8)
    assert "8 unanswered" in res.headline
    assert "among those answered" in res.headline


def test_a_complete_clean_run_still_says_so_plainly():
    res = AccuracyResult("m", total=20, correct=20, missed_secrets=0, unanswered=0)
    assert res.headline == "20 of 20 correct — missed no real secrets"
