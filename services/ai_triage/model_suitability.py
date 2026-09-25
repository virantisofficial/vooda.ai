"""Is this model the kind of thing that can triage at all?

Not whether it triages WELL, and not whether it triages at all — that is
model_probe.py's job, and it is the only authority here. This module
answers the cheaper, earlier question: given what the provider told us
when it listed its models, should this one be offered as a candidate?

The rule that survives every provider:

    Metadata decides ORDER. Measurement decides VERDICT.

Measured across four providers, what they declare is wildly uneven:

  OpenRouter  output_modalities, structured_outputs, reasoning   (rich)
  Google      generation methods, a bare `thinking` flag         (partial)
  OpenAI      id and owner                                       (nothing)
  Ollama      size and parameter count                           (nothing)

So the classifier is built to degrade: it uses the strongest signal a
provider offers and says how confident that makes it. Nothing here
knows a model's name. A name list is stale the week it is written —
three new models appeared at one provider during the week this was
built — and the codebase already carries proof: OpenAI discovery
filters on a hardcoded prefix tuple whose own comment records that it
returned an empty list for every model on some endpoints.

Confidence decides POWER, which is the whole design:

  DECLARED   the provider stated it in a structured field  -> may exclude
  CONTRACT   the call we make is not in its method list    -> may exclude
  SUGGESTED  only the provider's prose hints at it         -> may GROUP
  NONE       nothing known                                 -> candidate

Prose may never hide a model. If a description is misleading, the worst
outcome is a model sorted into a collapsed group the user can open —
never one that silently vanishes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Tiers
CANDIDATE = "candidate"
OTHER_MODALITY = "other_modality"
CANNOT_SERVE = "cannot_serve"

# Confidence
DECLARED = "declared"
CONTRACT = "contract"
SUGGESTED = "suggested"
NONE = "none"

#: Confidence levels that may remove a model from the default list.
#: SUGGESTED is deliberately absent.
EXCLUDABLE = (DECLARED, CONTRACT)

#: Unambiguous claims about what a model PRODUCES. Present in a
#: description, these settle it even alongside input talk.
_GENERATION_PHRASES = (
    "image generation", "music generation", "video generation",
    "speech generation", "audio generation", "speech synthesis",
    "text-to-speech", "text to speech", "image editing",
)

#: Single words naming a non-text output. Weaker: these also appear when
#: a text model describes what it can READ, so they only count when no
#: input-side word is present.
_MODALITY_WORDS = {
    "tts", "transcribe", "transcription", "speech", "music",
    "image", "images", "audio", "video", "embedding", "embeddings",
}

#: Input-side vocabulary. A model that "understands images" is a text
#: model with vision, and demoting it would hide a perfectly good
#: triager — the failure this whole module exists to avoid.
_INPUT_CONTEXT = {
    "understands", "understand", "understanding", "input", "inputs",
    "accepts", "accept", "vision", "multimodal", "reads", "read",
    "analyze", "analyse", "analysis", "reasoning", "supports",
}


@dataclass
class Suitability:
    tier: str
    confidence: str
    #: One short phrase for the UI. Never a model name.
    reason: str = ""
    #: Settings the provider stated outright, safe to apply.
    declared_config: dict = field(default_factory=dict)

    @property
    def may_exclude(self) -> bool:
        """Whether this verdict is strong enough to hide the model."""
        return self.tier != CANDIDATE and self.confidence in EXCLUDABLE

    def to_dict(self) -> dict:
        return {
            "tier": self.tier, "confidence": self.confidence,
            "reason": self.reason, "may_exclude": self.may_exclude,
        }


def _tokens(text: str) -> set[str]:
    return set(re.split(r"[^a-z0-9]+", (text or "").lower())) - {""}


def _prose_suggests_other_modality(description: str, display_name: str) -> str | None:
    blob = f"{description or ''} {display_name or ''}".lower()
    if not blob.strip():
        return None

    for phrase in _GENERATION_PHRASES:
        if phrase in blob:
            return phrase

    toks = _tokens(blob)
    if toks & _INPUT_CONTEXT:
        # Talking about what it takes in, not what it puts out.
        return None
    hit = toks & _MODALITY_WORDS
    return sorted(hit)[0] if hit else None


def classify(
    *,
    identifier: str = "",
    methods: list[str] | None = None,
    required_method: str | None = None,
    output_modalities: list[str] | None = None,
    supported_parameters: list[str] | None = None,
    description: str = "",
    display_name: str = "",
) -> Suitability:
    """Classify one discovered model from provider metadata alone.

    `identifier` is the model id, and it is read as TEXT — one more
    place a provider might name a modality — never as a lookup key.
    Some providers state nothing else: OpenAI's /v1/models returns an id
    and an owner, so "tts-1" and "text-embedding-3-small" carry their
    only description in the id itself.

    That keeps it generic. The vocabulary is about modalities, not
    vendors, so an id nobody has seen before still classifies, and an
    unrecognised one stays a candidate. And because an id is only text,
    it lands in the SUGGESTED tier: it can sort a model into a group the
    user can open, never hide it, and never overrule a declared field.
    Tests assert both limits.
    """
    declared_config: dict = {}

    # Strongest signal: the provider stated what comes out.
    emits_text_by_declaration = False
    if output_modalities:
        outs = {str(m).lower() for m in output_modalities}
        if "text" not in outs:
            return Suitability(
                OTHER_MODALITY, DECLARED,
                f"produces {', '.join(sorted(outs))}, not text",
            )
        # It emits text, which is all triage needs. Remember that, so
        # the prose pass below cannot talk us out of a fact.
        emits_text_by_declaration = True

    # The provider stated which parameters it honours, so JSON mode is
    # a fact rather than a checkbox the user has to reason about.
    if supported_parameters:
        params = {str(p).lower() for p in supported_parameters}
        if {"structured_outputs", "response_format"} & params:
            declared_config["supports_json_mode"] = True

    # Contract: Vooda makes one specific call. A model that does not
    # list it cannot serve that request, whatever else it can do.
    if required_method and methods is not None:
        if required_method not in set(methods):
            return Suitability(
                CANNOT_SERVE, CONTRACT,
                "does not support the request Vooda makes",
                declared_config,
            )

    # Declared beats suggested. Stated as a hierarchy from the start,
    # but not implemented until live data showed the gap: a
    # vision-language model declaring text-only output was demoted on
    # the word "images" in a sentence about what it can RECOGNISE. It
    # is a fine triager. Prose does not get to overrule a structured
    # field, and whether a text-emitting model triages WELL is the
    # probe's call, not a keyword's.
    hint = None if emits_text_by_declaration else _prose_suggests_other_modality(
        description, f"{display_name} {identifier}")
    if hint:
        return Suitability(
            OTHER_MODALITY, SUGGESTED,
            f"described as {hint}", declared_config,
        )

    return Suitability(CANDIDATE, NONE if not declared_config else DECLARED,
                       "", declared_config)
