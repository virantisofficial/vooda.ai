"""Discovery must not report success for a request the provider refused.

Measured against a real organisation-level Anthropic key: the models
endpoint returned 400 — "not scoped to a workspace" — and Vooda
answered "API key validated. Showing known models", then offered four
Claude ids written into the source. The key had NOT been validated, and
every one of those models would have failed at triage, because the
messages endpoint refuses the same request for the same reason.

That is the pattern this whole area was built to remove: a green result
standing in for a check that did not happen.
"""
import inspect
import re

from apps.api.app.routers import ai_models


def _src() -> str:
    """Executable code only.

    A comment explaining what was removed contains the very string
    these tests look for, so an uncommented check passes on prose. That
    has caught me three times in this codebase; strip it at the source.
    """
    src = inspect.getsource(ai_models._discover_anthropic)
    src = re.sub(r'"""[\s\S]*?"""', "", src)
    return re.sub(r"#.*", "", src)


def test_no_model_names_are_written_into_discovery():
    """The fallback list went stale on the vendor's next release and
    was wrong here anyway."""
    src = _src()
    for name in ("claude-3-5-haiku", "claude-3-5-sonnet", "claude-opus-4", "claude-sonnet-4"):
        assert name not in src, f"{name} is hardcoded in discovery"


def test_an_unlistable_key_is_not_called_validated():
    src = _src()
    assert "API key validated" not in src
    assert 'status="error"' in src


def test_the_workspace_header_is_sent_when_configured():
    """An org-level key is refused on every request without it. The
    provider sent this header; discovery did not, so a good key failed
    at the first step."""
    src = _src()
    assert "anthropic-workspace-id" in src
    assert "workspace_id" in inspect.signature(ai_models._discover_anthropic).parameters


def test_the_workspace_error_says_where_the_id_goes():
    """The provider's own message is accurate but does not mention
    Provider Config, which is where Vooda reads it from."""
    src = _src()
    assert "workspace_id" in src and "Provider Config" in src


def test_discovery_accepts_provider_config():
    """Needed before a configuration exists to load it from."""
    assert "provider_config" in ai_models.DiscoverModelsRequest.model_fields
