"""The classifier must work on models nobody has heard of.

Vooda connects to whatever a customer configured, including models that
did not exist when this was written and self-hosted ones nobody outside
their company has seen. Every case is stated in terms of METADATA, and
the names are invented on purpose.
"""
import pytest

from services.ai_triage.model_suitability import (
    classify, CANDIDATE, OTHER_MODALITY, CANNOT_SERVE,
)

GEN = "generateContent"


# ── No names, ever ──────────────────────────────────────

def test_a_name_with_no_modality_word_changes_nothing():
    """Names are read as text, never looked up in a list."""
    base = dict(methods=[GEN], required_method=GEN, description="general purpose instruct model")
    for name in ("gpt-4o", "claude-x", "llama-9", "acme-internal-7b", ""):
        assert classify(identifier=name, **base).tier == CANDIDATE, name


def test_an_invented_future_model_classifies_on_its_metadata():
    assert classify(identifier="zzz-9", methods=[GEN], required_method=GEN,
                    description="Symphony Engine — music generation").tier == OTHER_MODALITY
    assert classify(identifier="zzz-9", methods=[GEN], required_method=GEN,
                    description="general purpose instruct model").tier == CANDIDATE


# ── What may hide a model, and what may not ─────────────

def test_only_the_provider_stating_it_can_hide_a_model():
    declared = classify(output_modalities=["image"], methods=[GEN], required_method=GEN)
    assert (declared.tier, declared.may_exclude) == (OTHER_MODALITY, True)

    contract = classify(methods=["bidiGenerateContent", "countTokens"], required_method=GEN)
    assert (contract.tier, contract.may_exclude) == (CANNOT_SERVE, True)


def test_a_guess_from_text_may_group_but_never_hide():
    """The safety property. If a description or a name is misleading,
    the model lands in a group the user can open, never nowhere."""
    for kw in (dict(display_name="Flash Image"), dict(identifier="tts-1-hd"),
               dict(description="Music Generation model")):
        s = classify(methods=[GEN], required_method=GEN, **kw)
        assert s.tier == OTHER_MODALITY, kw
        assert s.may_exclude is False, kw


# ── Declared beats guessed ──────────────────────────────

def test_a_declared_text_emitter_is_never_demoted_by_text():
    """Found on live data: a vision model declaring text-only output was
    demoted on the word "images" in a sentence about what it RECOGNISES."""
    s = classify(output_modalities=["text"], methods=[GEN], required_method=GEN,
                 description="recognizes common objects: flowers, birds, fish and insects")
    assert s.tier == CANDIDATE


def test_declared_mixed_output_stays_for_the_probe_to_judge():
    """Emitting images AND text means it can still answer in text."""
    s = classify(output_modalities=["image", "text"], methods=[GEN], required_method=GEN,
                 description="state of the art image generation model")
    assert s.tier == CANDIDATE


# ── The contract check ──────────────────────────────────

def test_method_matching_is_exact_not_substring():
    """bidiGenerateContent contains GenerateContent — a substring test
    against a stringified list only worked by accident of capitalisation."""
    assert classify(methods=["bidiGenerateContent"], required_method=GEN).tier == CANNOT_SERVE
    assert classify(methods=["batchGenerateContent"], required_method=GEN).tier == CANNOT_SERVE
    assert classify(methods=["batchGenerateContent", GEN], required_method=GEN).tier == CANDIDATE


def test_no_declared_methods_means_no_judgment():
    """Some providers declare nothing. Absence is not evidence."""
    assert classify(methods=None, required_method=GEN).tier == CANDIDATE


# ── Settings the provider stated ────────────────────────

def test_declared_structured_output_settles_json_mode():
    s = classify(output_modalities=["text"], supported_parameters=["structured_outputs", "tools"],
                 methods=[GEN], required_method=GEN)
    assert s.declared_config == {"supports_json_mode": True}


def test_missing_metadata_is_never_held_against_a_model():
    for meta in ({}, {"description": ""}, {"description": "   ", "display_name": ""}):
        assert classify(**meta).tier == CANDIDATE, meta


# ── Declared modality settles modality, and nothing else ──────

def test_a_declared_text_emitter_is_still_checked_for_non_output_words():
    """Every asynchronous batch endpoint declares text output, so the
    declared-output rule waved all of them through as candidates.
    Measured across 458 live models: 72 of the 89 that failed a real
    check were batch variants."""
    s = classify(identifier="openai/o3:batch", output_modalities=["text"],
                 display_name="OpenAI: o3 (batch)")
    assert s.tier == OTHER_MODALITY
    assert s.may_exclude is False, "a name is still only a guess"


def test_the_plain_model_beside_it_is_untouched():
    """The pair differ by a suffix and a price, nothing else."""
    assert classify(identifier="openai/o3", output_modalities=["text"],
                    display_name="OpenAI: o3").tier == CANDIDATE


def test_declared_modality_still_protects_a_vision_model():
    """The rule this sits beside must keep working — that was the
    original reason for it."""
    s = classify(output_modalities=["text"], identifier="qwen/qwen2.5-vl-72b-instruct",
                 description="recognizes common objects: flowers, birds, fish and insects")
    assert s.tier == CANDIDATE


def test_an_encoder_is_caught_even_when_text_output_is_declared():
    s = classify(identifier="baai/bge-reranker-v2-m3", output_modalities=["text"])
    assert s.tier == OTHER_MODALITY
