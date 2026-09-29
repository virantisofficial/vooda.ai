"""Vooda must never substitute a model name the customer did not choose.

create_provider used to fall back to a literal per provider when no
model was given — claude-sonnet-4-20250514, gpt-4o, gemini-2.0-flash,
phi3.5. That is a maintenance list, and it ages without anyone
noticing: the live Anthropic catalogue now lists Sonnet 5 and Opus 5.5,
and Gemini 2.x returns 404 on a current key. A missing model is a
configuration error, and inventing one turns it into an API failure far
from its cause.
"""
import re
from pathlib import Path

import pytest

from services.ai_triage.provider import create_provider

_SRC = Path(__file__).resolve().parents[2] / "services" / "ai_triage"

#: Vendor model identifiers, in any shape a provider publishes them.
_MODEL_ID = re.compile(
    r"\b(claude-[a-z0-9.-]+|gpt-[0-9o][a-z0-9.-]*|gemini-[a-z0-9.-]+|gemma-[a-z0-9.-]+|"
    r"phi[0-9.]+|llama[0-9.-]+|mistral-[a-z0-9.-]+|o[13]-[a-z0-9-]+)\b", re.I)


def _code(name: str) -> str:
    src = (_SRC / name).read_text()
    src = re.sub(r'"""[\s\S]*?"""', "", src)   # docstrings
    return re.sub(r"#.*", "", src)              # comments


@pytest.mark.parametrize("name", ["provider.py", "engine.py", "model_probe.py",
                                  "model_suitability.py"])
def test_no_model_identifier_appears_in_executable_code(name):
    found = sorted(set(_MODEL_ID.findall(_code(name))))
    assert not found, f"{name} hardcodes model names: {found}"


@pytest.mark.parametrize("provider", ["anthropic", "openai", "google", "ollama", "custom"])
def test_a_missing_model_is_an_error_not_a_substitution(provider):
    with pytest.raises(ValueError) as e:
        create_provider(provider, "key", model=None, endpoint_url="http://localhost:11434")
    assert "No model configured" in str(e.value)


def test_the_error_says_where_to_fix_it():
    with pytest.raises(ValueError) as e:
        create_provider("anthropic", "key", model="")
    assert "AI Provider" in str(e.value)


def test_a_configured_model_is_passed_through_untouched():
    p = create_provider("anthropic", "key", model="some-model-from-next-year")
    assert p.model == "some-model-from-next-year"
