"""Naming a config means asking about that config.

The UI read the provider from form state one render before setForm had
applied it, so opening a Google configuration sent provider="anthropic"
with that config's id. The body's value won, Vooda queried Anthropic
with a Google key, and the screen reported "Invalid API key" about a
key that was perfectly good — on every single edit.

Fixed at both ends: the caller passes the provider explicitly, and the
stored provider wins here regardless, because a caller's copy of it can
always be stale while the stored row cannot.
"""
import inspect

from apps.api.app.routers import ai_models


def _discover_source() -> str:
    return inspect.getsource(ai_models.discover_available_models)


def test_the_stored_provider_is_read_before_the_caller_s():
    src = _discover_source()
    assert 'provider = (stored.provider or provider or "").lower()' in src, (
        "the caller's provider must not take precedence over the stored one"
    )
    assert 'provider = (provider or stored.provider or "").lower()' not in src


def test_a_config_id_still_supplies_the_credentials():
    """The stored key must keep flowing, or the fix trades one broken
    edit flow for another."""
    src = _discover_source()
    assert "stored.api_key_encrypted" in src or "api_key = stored" in src


def test_probe_resolves_the_provider_from_the_config_too():
    """The probe takes the same model_config_id and must not be
    vulnerable to the same stale value."""
    src = inspect.getsource(ai_models.probe_models)
    assert "cfg.provider" in src, "probe must read the provider from the stored config"
