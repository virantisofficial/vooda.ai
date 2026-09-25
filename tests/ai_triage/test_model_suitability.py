"""The classifier must work on models nobody has heard of.

Vooda connects to whatever a customer configured, including models that
did not exist when this was written and self-hosted ones nobody outside
their company has ever seen. Every case here is therefore stated in
terms of METADATA, and the names used are invented on purpose.
"""
import pytest

from services.ai_triage.model_suitability import (
    classify, CANDIDATE, OTHER_MODALITY, CANNOT_SERVE,
    DECLARED, CONTRACT, SUGGESTED, NONE,
)

GEN = "generateContent"


# ── The genericity guarantee ────────────────────────────

def test_identical_metadata_classifies_identically_whatever_it_is_called():
    """The claim "it does not look at names" is the kind that quietly
    stops being true, so it is asserted rather than trusted."""
    meta = dict(methods=[GEN], required_method=GEN,
                description="Music Generation model")
    verdicts = {classify(**meta).tier for _ in range(3)}
    assert verdicts == {OTHER_MODALITY}
    # classify() takes no id at all — nothing to differ on.
    assert "model_id" not in classify.__annotations__


def test_an_invented_future_model_is_classified_on_its_metadata():
    """Nothing is looked up, so a model from next year works today."""
    assert classify(methods=[GEN], required_method=GEN,
                    description="Symphony Engine — music generation").tier == OTHER_MODALITY
    assert classify(methods=[GEN], required_method=GEN,
                    description="general purpose instruct model").tier == CANDIDATE


# ── Declared beats everything ───────────────────────────

def test_declared_non_text_output_may_exclude():
    s = classify(output_modalities=["image"], methods=[GEN], required_method=GEN)
    assert (s.tier, s.confidence) == (OTHER_MODALITY, DECLARED)
    assert s.may_exclude is True


def test_a_model_that_also_emits_text_stays_a_candidate():
    """Emitting images too does not stop it answering in text."""
    s = classify(output_modalities=["text", "image"], methods=[GEN], required_method=GEN)
    assert s.tier == CANDIDATE


def test_declared_structured_output_settles_json_mode():
    s = classify(output_modalities=["text"], supported_parameters=["structured_outputs", "tools"],
                 methods=[GEN], required_method=GEN)
    assert s.declared_config == {"supports_json_mode": True}


# ── Contract ────────────────────────────────────────────

def test_a_model_that_cannot_serve_our_call_is_excluded():
    s = classify(methods=["bidiGenerateContent", "countTokens"], required_method=GEN)
    assert (s.tier, s.confidence) == (CANNOT_SERVE, CONTRACT)
    assert s.may_exclude is True


def test_method_matching_is_exact_not_substring():
    """bidiGenerateContent contains GenerateContent. Substring matching
    a stringified list is correct only by accident of capitalisation."""
    assert classify(methods=["bidiGenerateContent"], required_method=GEN).tier == CANNOT_SERVE
    assert classify(methods=["batchGenerateContent"], required_method=GEN).tier == CANNOT_SERVE
    assert classify(methods=["batchGenerateContent", GEN], required_method=GEN).tier == CANDIDATE


def test_no_declared_methods_means_no_contract_judgment():
    """OpenAI and Ollama declare nothing. Absence is not evidence."""
    assert classify(methods=None, required_method=GEN).tier == CANDIDATE


# ── Prose may group, never hide ─────────────────────────

def test_prose_can_never_exclude_a_model():
    """The whole safety property. If a description is misleading the
    model sorts into a group the user can open, never disappears."""
    s = classify(methods=[GEN], required_method=GEN, display_name="Flash Image")
    assert s.tier == OTHER_MODALITY
    assert s.confidence == SUGGESTED
    assert s.may_exclude is False, "prose must only group"


@pytest.mark.parametrize("desc", [
    "a multimodal model that understands text, images and audio",
    "reads images and answers questions about them",
    "supports vision input for document analysis",
])
def test_a_text_model_that_reads_images_is_not_demoted(desc):
    """The failure this module exists to avoid: hiding a working
    triager because its description mentions what it can look at."""
    assert classify(methods=[GEN], required_method=GEN, description=desc).tier == CANDIDATE


@pytest.mark.parametrize("desc", [
    "Music Generation model", "Text-to-Speech preview",
    "image generation and editing", "Transcribe",
])
def test_output_claims_are_recognised(desc):
    assert classify(methods=[GEN], required_method=GEN, description=desc).tier == OTHER_MODALITY


def test_an_explicit_generation_claim_wins_over_input_talk():
    """'Understands prompts and performs image generation' produces
    pictures, whatever else the sentence says."""
    s = classify(methods=[GEN], required_method=GEN,
                 description="understands text prompts and performs image generation")
    assert s.tier == OTHER_MODALITY


def test_missing_metadata_is_never_held_against_a_model():
    for meta in ({}, {"description": ""}, {"description": "   ", "display_name": ""}):
        assert classify(**meta).tier == CANDIDATE, meta


# ── Declared protects against prose ─────────────────────

def test_a_declared_text_emitter_is_never_demoted_by_prose():
    """Found on live data: a vision-language model declaring
    output_modalities=['text'] was demoted on the word "images" in a
    sentence about what it can RECOGNISE. Structured fields outrank
    prose; that was the stated hierarchy and now it is enforced."""
    s = classify(
        output_modalities=["text"], methods=[GEN], required_method=GEN,
        description="proficient in recognizing common objects: flowers, birds, fish and insects",
    )
    assert s.tier == CANDIDATE


def test_declared_mixed_output_stays_a_candidate_for_the_probe_to_judge():
    """Emitting images AND text means it can still answer in text.
    Whether it answers WELL is measured, not guessed from a keyword."""
    s = classify(output_modalities=["image", "text"], methods=[GEN], required_method=GEN,
                 description="state of the art image generation model")
    assert s.tier == CANDIDATE


def test_prose_still_applies_when_the_provider_declares_no_modalities():
    """Most providers declare nothing, so the weak signal still earns
    its place — it just cannot override a strong one."""
    s = classify(methods=[GEN], required_method=GEN, description="Music Generation model")
    assert (s.tier, s.confidence) == (OTHER_MODALITY, SUGGESTED)
