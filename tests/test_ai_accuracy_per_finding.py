"""AI-triage accuracy is a PER-FINDING measure: the AI makes one prediction per
finding, the human reaches one final verdict per finding — regardless of how many
times they change their mind.

These pin the pure aggregation helpers against every scenario that produced a
wrong panel number this session:
  * agree / disagree
  * mind-change (FP then back to TP) → the FINDING counts once, final verdict wins
  * the exact session sequence (50% then 100%)
  * non-AI-triaged decisions excluded
  * by-severity subset
"""
from apps.api.app.routers.metrics import _per_finding_verdicts, _accuracy_of

# row = (finding_id, action, previous_classification, severity, category),
# ORDERED by (finding_id, created_at ASC) — earliest decision first.


def _acc(rows):
    pf = _per_finding_verdicts(rows)
    conf, corr = _accuracy_of(pf.values())
    return pf, conf, corr


def test_agree_ai_tp_human_tp():
    _, conf, corr = _acc([("f1", "mark_tp", "confirmed_true_positive", "critical", "secret")])
    assert (conf, corr) == (1, 1)  # 100%


def test_disagree_ai_tp_human_fp():
    _, conf, corr = _acc([("f1", "mark_fp", "confirmed_true_positive", "critical", "secret")])
    assert (conf, corr) == (1, 0)  # AI said TP, human said FP → 0%


def test_mind_change_counts_finding_once_final_wins():
    # AI predicted TP; human marked FP, then flipped back to TP. The 2nd decision's
    # previous_classification is the human FP state and must NOT be read as the AI
    # verdict. Final human verdict = TP → correct, and it's ONE finding.
    rows = [
        ("f1", "mark_fp", "confirmed_true_positive", "critical", "secret"),    # AI verdict = TP
        ("f1", "mark_tp", "confirmed_false_positive", "critical", "secret"),   # flip back
    ]
    pf, conf, corr = _acc(rows)
    assert len(pf) == 1
    assert pf["f1"]["ai_pred"] == "tp" and pf["f1"]["human"] == "tp"
    assert (conf, corr) == (1, 1)  # 100% — not 50% / 33%


def test_exact_session_sequence_50_then_100():
    # Two AWS findings, AI predicted TP on both.
    phase1 = [
        ("akia", "mark_fp", "confirmed_true_positive", "critical", "secret"),
        ("secret", "mark_tp", "confirmed_true_positive", "critical", "secret"),
    ]
    assert _acc(phase1)[1:] == (2, 1)  # accept one + reject one → 50%
    phase2 = [
        ("akia", "mark_fp", "confirmed_true_positive", "critical", "secret"),
        ("akia", "mark_tp", "confirmed_false_positive", "critical", "secret"),  # flip back to TP
        ("secret", "mark_tp", "confirmed_true_positive", "critical", "secret"),
    ]
    assert _acc(phase2)[1:] == (2, 2)  # both agree → 100%, denominator = 2 findings (not 3 decisions)


def test_non_ai_triaged_decision_excluded():
    rows = [
        ("f1", "mark_tp", "needs_review", "low", "secret"),               # AI made no prediction
        ("f2", "mark_tp", "confirmed_true_positive", "low", "secret"),
    ]
    _, conf, corr = _acc(rows)
    assert (conf, corr) == (1, 1)  # only f2 counts


def test_by_severity_subset():
    rows = [
        ("f1", "mark_tp", "confirmed_true_positive", "critical", "secret"),
        ("f2", "mark_fp", "confirmed_true_positive", "high", "secret"),
    ]
    pf = _per_finding_verdicts(rows)
    assert _accuracy_of([r for r in pf.values() if r["sev"] == "critical"]) == (1, 1)
    assert _accuracy_of([r for r in pf.values() if r["sev"] == "high"]) == (1, 0)
