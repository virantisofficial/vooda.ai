"""Never asked and asked-without-answer are different facts.

They shared the "Not checked" label while never-checked models carried
no badge at all, so on screen the only cards reading "Not checked" were
the ones Vooda had checked and failed to reach — the badge said the
opposite of what had happened.

This is the Python-side guard on the vocabulary the UI renders; the
labels themselves live in apps/web/src/lib/modelReadiness.ts.
"""
from services.ai_triage.model_probe import READY, NEEDS_SETUP, UNVERIFIED, UNUSABLE


def test_unverified_is_its_own_state():
    assert len({READY, NEEDS_SETUP, UNVERIFIED, UNUSABLE}) == 4


def test_unverified_reports_an_attempt_that_returned_nothing():
    """The headline has to describe a failed attempt, not an absence —
    a model nobody asked about has no headline at all."""
    from services.ai_triage.model_probe import probe_model, _looks_transient
    assert _looks_transient("Google API error 503: overloaded")
    # A never-probed model has no record, so there is nothing to render
    # from; the UI supplies "Not checked" for that case instead.


def test_the_four_stored_states_are_the_only_ones():
    """A fifth state would need a label, and an unlabelled state
    renders as whatever the default happens to be."""
    import services.ai_triage.model_probe as mp
    stored = {v for k, v in vars(mp).items()
              if k.isupper() and isinstance(v, str)
              and v in {"ready", "needs_setup", "unverified", "unusable"}}
    assert stored == {"ready", "needs_setup", "unverified", "unusable"}
