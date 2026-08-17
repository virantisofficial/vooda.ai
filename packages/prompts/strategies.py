# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Prompt strategy presets for AI triage.

Each strategy is a named configuration that auto-sets:
- system_prompt, stop_sequences, temperature, JSON mode, compact prompt
- Optimized for different goals (low FP, low FN, balanced)

Users select a strategy from the UI instead of manually tuning raw parameters.
"""

import re

# ── Model Size Thresholds ────────────────────────────────────
# Used for auto-detection from Ollama/provider model info

MODEL_SIZE_THRESHOLDS = {
    "small": 7_000_000_000,      # < 7B parameters
    "medium": 30_000_000_000,    # 7B - 30B
    # "large" = anything above 30B
}

# Matches parameter count in a model name: 3b, 3.8b, 7B, 14b, 32B, 72b, etc.
# Word boundaries prevent matching inside unrelated tokens (e.g., "bert").
_PARAM_COUNT_RE = re.compile(r"(?:^|[-:_/\s.])(\d+(?:\.\d+)?)\s*[bB]\b")

# Known "large" cloud/hosted models that don't carry a numeric size in their ID.
_LARGE_NAMED_MODELS = (
    "gpt-4", "gpt-5", "o1", "o3",
    "claude", "sonnet", "opus", "haiku",
    "gemini-pro", "gemini-1.5", "gemini-2",
)
# Known "small" model families.
_SMALL_NAMED_MODELS = ("mini", "tiny", "nano", "phi-3", "phi3")


def classify_model_size(param_count: int | None, model_id: str = "") -> str:
    """Classify model as small/medium/large from parameter count or model name.

    Priority:
    1. Explicit param_count (from discovery API metadata).
    2. Regex-extracted Nb suffix in model_id (covers 3b/7b/14b/32b/72b/etc.).
    3. Named cloud-model hints (GPT-4, Claude, Gemini → large; Mini/Nano → small).
    4. Fall back to "medium" (safest default for unknown cloud endpoints).
    """
    if param_count:
        if param_count < MODEL_SIZE_THRESHOLDS["small"]:
            return "small"
        elif param_count < MODEL_SIZE_THRESHOLDS["medium"]:
            return "medium"
        return "large"

    mid = (model_id or "").lower()

    # Regex: extract explicit Nb suffix (e.g. "qwen-2.5-coder-32b" → 32.0)
    m = _PARAM_COUNT_RE.search(mid)
    if m:
        try:
            params_b = float(m.group(1))
            if params_b < 7:
                return "small"
            if params_b < 30:
                return "medium"
            return "large"
        except ValueError:
            pass

    # Named-model fallback for cloud models without a size suffix.
    # Small-name wins over family-name so e.g. gpt-4o-mini → small, not large.
    if any(n in mid for n in _SMALL_NAMED_MODELS):
        return "small"
    if any(n in mid for n in _LARGE_NAMED_MODELS):
        return "large"

    # Safe default for unknown model IDs.
    return "medium"


# ── Provider Auto-Config ─────────────────────────────────────

# Default temperature is 0 across the board. Secret-triage classification is
# a discriminative task, not a generative one — non-determinism (even at
# temp=0.1) was observed to cause reasoning-model response collapse in
# session testing. Any customer who wants probabilistic output for
# summarization can raise this manually per-model.
PROVIDER_DEFAULTS = {
    "anthropic": {
        "supports_json_mode": False,  # Claude uses structured output differently
        "stop_sequences": [],
        "default_temperature": 0,
        "default_max_tokens": 4096,
        "default_context_window": 200000,
    },
    "openai": {
        "supports_json_mode": True,
        "stop_sequences": [],
        "default_temperature": 0,
        "default_max_tokens": 4096,
        "default_context_window": 128000,
    },
    "google": {
        "supports_json_mode": True,
        "stop_sequences": [],
        "default_temperature": 0,
        "default_max_tokens": 4096,
        "default_context_window": 1000000,
    },
    "ollama": {
        "supports_json_mode": True,
        # stop_sequences intentionally empty: `"}\n"` was a legacy default for
        # tiny-model compact JSON output, but it truncates modern larger models
        # mid-response (the first closing brace of a nested object fires it).
        # Rely on max_tokens as the natural terminator.
        "stop_sequences": [],
        "default_temperature": 0,
        "default_max_tokens": 512,
        "default_context_window": 4096,
    },
    "azure_openai": {
        "supports_json_mode": True,
        "stop_sequences": [],
        "default_temperature": 0,
        "default_max_tokens": 4096,
        "default_context_window": 128000,
    },
    "custom": {
        # JSON mode defaults to False for custom providers (OpenRouter, vLLM,
        # LM Studio, etc.) because upstream routes don't consistently honor the
        # `response_format` field — we saw this cause mid-JSON truncation via
        # OpenRouter. Prompt itself asks for JSON; most models comply without
        # the flag. Users enable it explicitly when they know their route
        # supports it natively.
        "supports_json_mode": False,
        "stop_sequences": [],
        "default_temperature": 0,
        "default_max_tokens": 4096,
        "default_context_window": 8192,
    },
}


# ── Prompt Strategies ────────────────────────────────────────

PROMPT_STRATEGIES = {
    "recommended": {
        "label": "Recommended",
        "description": "Balanced accuracy — good for most use cases. Auto-adapts to model size.",
        "system_prompt": None,  # Uses default from triage.py or triage_compact.py
        "temperature_override": None,  # Uses provider default
        "notes": "Full prompt for large models, compact for small. JSON mode when supported.",
    },
    "strict": {
        "label": "Strict (Low False Positives)",
        "description": "Conservative — only marks clear FPs. Higher precision, may miss some FPs.",
        "system_prompt": """You are a senior application security engineer. Your job is to identify FALSE POSITIVES with HIGH CONFIDENCE only.

CRITICAL RULES:
1. Default to "likely_true_positive" unless you are VERY confident it is a false positive.
2. A finding is only a false positive if: the value is a known placeholder, test fixture, or documentation example — AND the code context clearly confirms this.
3. When in doubt, classify as "needs_review" — never guess.
4. Return ONLY valid JSON. No text before or after.""",
        "temperature_override": 0,
        "notes": "Best for: production pipelines where FPs must be near-zero.",
    },
    "sensitive": {
        "label": "Sensitive (Low False Negatives)",
        "description": "Aggressive FP detection — flags more false positives. Higher recall, some real secrets may be marked FP.",
        "system_prompt": """You are a security triage analyst. Your goal is to reduce alert fatigue by identifying as many false positives as possible.

RULES:
1. Be aggressive in identifying false positives — test values, examples, documentation, disabled code, and placeholder strings are all FPs.
2. Consider the file path: test files, example directories, documentation, and CI fixtures are likely FPs.
3. Low-entropy values assigned to sensitive-sounding keys are often configuration, not real secrets.
4. When the value matches common patterns (localhost, 127.0.0.1, example.com, changeme, password123), mark as FP.
5. Return ONLY valid JSON. No text before or after.""",
        "temperature_override": 0.1,
        "notes": "Best for: initial triage of large backlogs where reducing noise is the priority.",
    },
    "custom": {
        "label": "Custom",
        "description": "Write your own system prompt for full control over AI behavior.",
        "system_prompt": None,  # User provides via system_prompt_override field
        "temperature_override": None,
        "notes": "For advanced users who need specific behavior.",
    },
}


def get_auto_config(provider: str, model_id: str, model_size: str | None = None,
                    prompt_strategy: str = "recommended") -> dict:
    """
    Generate recommended configuration for a model based on provider, model ID, and strategy.

    Returns dict with all fields needed for AIModelConfig:
    - temperature, max_tokens, context_window, stop_sequences
    - supports_json_mode, use_compact_prompt, system_prompt_override
    """
    provider_cfg = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["custom"])
    size = model_size or classify_model_size(None, model_id)
    strategy = PROMPT_STRATEGIES.get(prompt_strategy, PROMPT_STRATEGIES["recommended"])

    # Base config from provider defaults
    config = {
        "temperature": strategy.get("temperature_override") if strategy.get("temperature_override") is not None else provider_cfg["default_temperature"],
        "max_tokens": provider_cfg["default_max_tokens"],
        "context_window": provider_cfg["default_context_window"],
        "stop_sequences": provider_cfg["stop_sequences"],
        "supports_json_mode": provider_cfg["supports_json_mode"],
        "use_compact_prompt": False,
        "system_prompt_override": strategy.get("system_prompt") or "",
        "prompt_strategy": prompt_strategy,
    }

    # Adjust for model size. Stop sequences are intentionally NOT set per size —
    # the old `["}\n"]` default truncated non-compact schemas mid-response. If
    # a user explicitly needs a stop sequence they can set it via the UI.
    if size == "small":
        config["use_compact_prompt"] = True
        config["max_tokens"] = 512
        config["context_window"] = min(config["context_window"], 4096)
        config["supports_json_mode"] = True  # Always force for small models
    elif size == "medium":
        config["use_compact_prompt"] = False
        # 4096 not 2048 — the full triage schema (classification + confidence +
        # explanation + reasons[] + evidence[] + controls[]) can overflow 2048
        # on richer findings, leading to the same mid-JSON truncation symptom
        # we saw on qwen models. Medium-class models can handle 4096 fine.
        config["max_tokens"] = 4096
        config["context_window"] = min(config["context_window"], 32768)
    else:  # large
        config["use_compact_prompt"] = False
        # Keep provider defaults for max_tokens and context_window

    return config
