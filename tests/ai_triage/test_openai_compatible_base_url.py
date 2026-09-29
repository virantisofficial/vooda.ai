"""An operator pastes the base URL their provider documents.

Every OpenAI-compatible provider documents it WITH the version segment
— OpenRouter, vLLM, LM Studio and LiteLLM all say ".../v1". Discovery
appended "/v1/models" to whatever was given, so the documented URL
became ".../v1/v1/models" and returned 404 while looking like a bad
endpoint or a bad key.

Worse, the completion path allowed for the trailing /v1 and discovery
did not, so the same endpoint listed nothing and then answered requests
perfectly. Both use one rule now.
"""
import pytest

from services.ai_triage.provider import openai_compatible_root, OpenAIProvider


@pytest.mark.parametrize("given", [
    "https://openrouter.ai/api/v1",
    "https://openrouter.ai/api/v1/",
    "https://openrouter.ai/api",
    "https://openrouter.ai/api/",
])
def test_every_way_of_writing_it_reaches_the_same_place(given):
    assert openai_compatible_root(given) == "https://openrouter.ai/api"


@pytest.mark.parametrize("given,expected", [
    ("http://localhost:8000/v1", "http://localhost:8000"),
    ("http://localhost:1234/v1/", "http://localhost:1234"),
    ("http://localhost:11434", "http://localhost:11434"),
    ("https://litellm.internal:4000/v1", "https://litellm.internal:4000"),
])
def test_self_hosted_endpoints_normalise_too(given, expected):
    assert openai_compatible_root(given) == expected


def test_no_endpoint_falls_back_to_openai():
    assert openai_compatible_root(None) == "https://api.openai.com"
    assert openai_compatible_root("") == "https://api.openai.com"


def test_a_v1_inside_the_path_is_not_stripped():
    """Only a trailing segment is the version marker. A host or path
    that merely contains v1 must survive."""
    assert openai_compatible_root("https://api.test/v1beta") == "https://api.test/v1beta"
    assert openai_compatible_root("https://v1.example.com") == "https://v1.example.com"


@pytest.mark.parametrize("given", ["https://openrouter.ai/api/v1", "https://openrouter.ai/api"])
def test_discovery_and_completion_agree(given):
    """The bug was not the 404 alone — it was that one half of the flow
    accepted the URL and the other did not."""
    p = OpenAIProvider(api_key="k", model="m", base_url=given)
    assert p._chat_url() == "https://openrouter.ai/api/v1/chat/completions"
    assert openai_compatible_root(given) + "/v1/models" == "https://openrouter.ai/api/v1/models"
