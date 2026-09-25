"""Is this model worth offering as a triage option?

Three checks, in order of how much the provider actually told us. It
answers the cheap question — is this the right KIND of model — and
leaves "does it work" to model_probe.py, which asks the model itself.

    Metadata decides ORDER. Measurement decides VERDICT.

No model names anywhere. A name list is stale the week it is written,
and the codebase carried proof: OpenAI discovery filtered on a hardcoded
prefix tuple whose own comment recorded that it returned an empty list
for every model on some endpoints.

`may_exclude` is the only thing that can hide a model, and it is set
only when the PROVIDER stated the fact. A guess read out of prose can
sort a model into a group the user can open, never remove it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

CANDIDATE = "candidate"
OTHER_MODALITY = "other_modality"
CANNOT_SERVE = "cannot_serve"

#: Words naming a purpose that is not text triage — either a non-text
#: output, or a job that is not generation at all. Checked against the
#: description, the display name and the id, because some providers
#: state nothing but an id: "tts-1" and "nomic-embed-text" carry their
#: only description in the name itself.
#:
#: These are function words, never product names. "embed" and "rerank"
#: describe what a model does and hold for a vendor nobody has heard
#: of; "whisper" and "dall-e" identify one company's products and would
#: be a maintenance list. Models named only that way reach the probe,
#: which is the backstop for exactly this.
#:
#: One list, because two were measured against 521 live models and made
#: no difference: a phrase list ("image generation", "text-to-speech")
#: caught nothing these words missed, and an input-side list meant to
#: stop "understands images" demoting a vision model prevented zero
#: false positives — the declared-modality check below already does it.
_NON_TRIAGE_WORDS = {
    # non-text output
    "tts", "transcribe", "transcription", "speech", "music",
    "image", "images", "audio", "video", "diffusion",
    # not generation at all — encoders and scorers, which self-hosted
    # catalogues list right beside the chat models
    "embed", "embedding", "embeddings", "rerank", "reranker",
    "reranking", "moderation",
}


#: Architecture markers for encoder-only models. An encoder produces
#: vectors, not text, so it cannot answer a triage prompt at all —
#: structural, the same kind of fact as a missing generation method,
#: not an inference from a name.
#:
#: Substring-matched, so this one marker covers bert, nomic-bert,
#: distilbert and roberta. Architectures are named once and outlive
#: model releases by years, which is what makes this safe to act on
#: where a product name is not.
#:
#: Deliberately just this. A multimodal model reports several families
#: — llava reports llama alongside clip — and disqualifying on any
#: encoder in the list would hide a model that generates text perfectly
#: well. A test holds that case.
_ENCODER_ARCHITECTURES = ("bert",)


@dataclass
class Suitability:
    tier: str
    #: One short phrase for the UI. Never a model name.
    reason: str = ""
    #: True only when the provider DECLARED it, so hiding is safe.
    may_exclude: bool = False
    #: Settings the provider stated outright, safe to apply.
    declared_config: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"tier": self.tier, "reason": self.reason,
                "may_exclude": self.may_exclude}


def classify(
    *,
    identifier: str = "",
    methods: list[str] | None = None,
    required_method: str | None = None,
    output_modalities: list[str] | None = None,
    architecture_families: list[str] | None = None,
    supported_parameters: list[str] | None = None,
    description: str = "",
    display_name: str = "",
) -> Suitability:
    declared_config: dict = {}

    # The provider stated which parameters it honours, so JSON mode is a
    # fact rather than a checkbox the user has to reason about.
    if supported_parameters:
        params = {str(p).lower() for p in supported_parameters}
        if {"structured_outputs", "response_format"} & params:
            declared_config["supports_json_mode"] = True

    # 1. Did the provider say what comes out?
    if output_modalities:
        outs = {str(m).lower() for m in output_modalities}
        if "text" not in outs:
            return Suitability(OTHER_MODALITY,
                               f"Produces {', '.join(sorted(outs))}, not text",
                               may_exclude=True)
        # It emits text, which is all triage needs — and that is a
        # stated fact, so the guess below does not get to argue with it.
        # Measured: a vision model declaring text-only output was being
        # demoted on the word "images" in a sentence about what it can
        # RECOGNISE. Whether it triages WELL is the probe's call.
        return Suitability(CANDIDATE, declared_config=declared_config)

    # 2. Is it an encoder? Self-hosted catalogues list embedding models
    #    beside the chat models, and their ids do not always say so —
    #    "bge-m3" and "all-minilm" name a model, not a job. The runtime
    #    reports the architecture, and an encoder cannot generate.
    if architecture_families:
        fams = " ".join(str(f).lower() for f in architecture_families)
        if any(marker in fams for marker in _ENCODER_ARCHITECTURES):
            return Suitability(CANNOT_SERVE, "Produces embeddings, not text",
                               may_exclude=True, declared_config=declared_config)

    # 3. Can it serve the call Vooda makes? Exact membership: a
    #    substring test also matches bidiGenerateContent.
    if required_method and methods is not None and required_method not in set(methods):
        return Suitability(CANNOT_SERVE, "Does not support the request Vooda makes",
                           may_exclude=True, declared_config=declared_config)

    # 4. Nothing structured to go on — fall back to what it is called.
    words = set(re.split(r"[^a-z0-9]+", f"{description} {display_name} {identifier}".lower()))
    hit = words & _NON_TRIAGE_WORDS
    if hit:
        return Suitability(OTHER_MODALITY, f"Described as {sorted(hit)[0]}",
                           declared_config=declared_config)

    return Suitability(CANDIDATE, declared_config=declared_config)
