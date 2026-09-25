"""Rogue models must not reach the picker, whoever lists them.

Vooda connects to any provider, and each one publishes a different
amount about its models — OpenRouter declares output modalities,
Google declares generation methods, OpenAI and Ollama publish an id and
little else. A filter proven against one catalogue proves nothing about
the others, so each shape is exercised here with the models that
provider actually lists beside its chat models.

Entries are realistic catalogue rows, not invented ones. Where a model
slips through it is recorded as such rather than quietly omitted: the
probe is the backstop for those, and a test that hides them would make
this file worse than useless.
"""
import pytest

from services.ai_triage.model_suitability import (
    classify, CANDIDATE, OTHER_MODALITY, CANNOT_SERVE,
)

# (id, extra metadata) — triage models a customer would legitimately pick
USABLE = [
    ("gpt-4o", {}), ("gpt-4.1-mini", {}), ("o3", {}),
    ("claude-opus-4-20250514", {"display_name": "Claude Opus 4"}),
    ("claude-3-5-haiku-20241022", {"display_name": "Claude 3.5 Haiku"}),
    ("llama3.3:70b", {}), ("qwen2.5-coder:7b", {}), ("phi4:latest", {}),
    ("meta-llama/Llama-3.3-70B-Instruct", {}),
    ("mistralai/mistral-large", {}), ("deepseek/deepseek-r1", {}),
    # A vision-language model still answers in text.
    ("llava:13b", {}),
    ("qwen/qwen2.5-vl-72b-instruct", {"output_modalities": ["text"],
     "description": "recognizes common objects: flowers, birds, fish and insects"}),
]

# Models that are not for triage and must not be offered as though they were
ROGUE = [
    ("text-embedding-3-large", {}), ("tts-1-hd", {}), ("gpt-image-1", {}),
    ("omni-moderation-latest", {}),
    ("nomic-embed-text:latest", {}), ("mxbai-embed-large:latest", {}),
    ("stable-diffusion:latest", {}),
    ("BAAI/bge-reranker-v2-m3", {}),
    ("lyria-3.5", {"description": "Music Generation model"}),
    ("gemini-3.5-transcribe", {"display_name": "Gemini 3.5 Transcribe"}),
    ("veo-3.1-generate-preview", {"methods": ["predictLongRunning"],
                                  "required_method": "generateContent"}),
    ("gemini-embedding-001", {"methods": ["embedContent"],
                              "required_method": "generateContent"}),
]

#: Named, not hidden. These carry no word describing what they do — only
#: a product name — and catching them would mean maintaining a list of
#: one vendor's brands, which goes stale and does nothing for the next
#: provider. They reach the probe, which rejects them in one call.
SLIPS_THROUGH_TO_THE_PROBE = ["dall-e-3", "whisper-1", "sora-2",
                              "bge-m3:latest", "all-minilm:latest"]


def _classify(mid, extra):
    return classify(
        identifier=mid,
        methods=extra.get("methods"),
        required_method=extra.get("required_method"),
        output_modalities=extra.get("output_modalities"),
        description=extra.get("description", ""),
        display_name=extra.get("display_name", ""),
    )


@pytest.mark.parametrize("mid,extra", USABLE, ids=[m for m, _ in USABLE])
def test_a_usable_model_is_offered(mid, extra):
    """The expensive direction to be wrong in. A customer whose
    organisation standardised on this model must find it here."""
    assert _classify(mid, extra).tier == CANDIDATE


@pytest.mark.parametrize("mid,extra", ROGUE, ids=[m for m, _ in ROGUE])
def test_a_rogue_model_is_kept_out_of_the_picker(mid, extra):
    assert _classify(mid, extra).tier in (OTHER_MODALITY, CANNOT_SERVE)


@pytest.mark.parametrize("mid", SLIPS_THROUGH_TO_THE_PROBE)
def test_the_known_gap_is_recorded_not_hidden(mid):
    """Documents what the metadata cannot catch. If a future change
    starts catching one of these, this fails and the list gets shorter
    — which is the point."""
    assert classify(identifier=mid).tier == CANDIDATE


def test_every_provider_shape_is_represented():
    """Guards against the file drifting into one provider's catalogue."""
    ids = [m for m, _ in USABLE + ROGUE]
    assert any("gpt-" in m or "o3" == m for m in ids), "OpenAI"
    assert any("claude-" in m for m in ids), "Anthropic"
    assert any(":" in m for m in ids), "Ollama tag form"
    assert any("/" in m for m in ids), "OpenRouter / vLLM path form"
    assert any("gemini-" in m or "veo-" in m for m in ids), "Google"
