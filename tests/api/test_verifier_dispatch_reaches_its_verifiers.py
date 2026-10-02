# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""A verifier nothing can reach is a verifier that does not exist.

Dispatch was a single dict lookup on the finding's provider. That is
wrong in both directions, and 45 of the 250 registered verifiers could
never be invoked by a scan:

  * The provider name is sometimes COARSER than the API. `google`
    covers Gemini keys, OAuth client secrets and Chat webhooks; there
    is no verifier for all three, so Gemini keys were detected and
    never checked while a working Gemini verifier sat unused. `dropbox`
    covers Dropbox and Dropbox Sign, and routing a Dropbox Sign key to
    the Dropbox API gets it rejected — reporting a live credential as
    inactive, the worst answer this product can give.

  * The provider name is sometimes spelled differently from the
    verifier's registration — crates/cratesio, tomorrow/tomorrow_io,
    openexchange/openexchangerates.

Same shape as the paired-credential gap: the verifier key space is
finer-grained than the provider name, so dispatch has to resolve rather
than look up.
"""
import pytest


def _sm(**kw):
    base = {"detection_method": "regex", "provider": "", "secret_type": ""}
    base.update(kw)
    return base


# ── The coarse-provider misroutes ───────────────────────────────────

def test_a_gemini_key_reaches_the_gemini_verifier():
    from services.secret_verification.verifier import resolve_verifier_key
    for st in ("google_gemini_key", "google_ai_studio_key"):
        assert resolve_verifier_key(_sm(provider="google", secret_type=st)) == "gemini", st


@pytest.mark.parametrize("secret_type", [
    "google_oauth_client_secret",
    "google_chat_webhook_url",
    "google_oauth_client_id",
])
def test_other_google_credentials_are_not_sent_to_gemini(secret_type):
    """The reason this is a secret_type map and not a provider alias.
    An OAuth client secret posted to the Gemini models endpoint would
    come back rejected, and be reported as a dead credential."""
    from services.secret_verification.verifier import resolve_verifier_key
    assert resolve_verifier_key(
        _sm(provider="google", secret_type=secret_type)) != "gemini"


def test_a_dropbox_sign_key_does_not_go_to_dropbox():
    from services.secret_verification.verifier import resolve_verifier_key
    assert resolve_verifier_key(
        _sm(provider="dropbox", secret_type="dropbox_sign_key")) == "dropbox_sign"
    assert resolve_verifier_key(
        _sm(provider="dropbox", secret_type="dropbox_long_token")) == "dropbox"


# ── The spelling mismatches ─────────────────────────────────────────

@pytest.mark.parametrize("provider,expected", [
    ("crates", "cratesio"),
    ("openexchange", "openexchangerates"),
    ("tomorrow", "tomorrow_io"),
])
def test_a_renamed_provider_still_finds_its_verifier(provider, expected):
    from services.secret_verification.verifier import resolve_verifier_key
    assert resolve_verifier_key(_sm(provider=provider)) == expected


def test_every_alias_points_at_a_registered_verifier():
    """An alias naming a verifier that does not exist would silently
    make the credential unverifiable again."""
    from services.secret_verification.verifier import (
        VERIFIERS, _PROVIDER_ALIASES, _VERIFIER_BY_SECRET_TYPE,
    )
    for src, dst in {**_PROVIDER_ALIASES, **_VERIFIER_BY_SECRET_TYPE}.items():
        assert dst in VERIFIERS, f"{src} -> {dst} is not a registered verifier"


def test_every_alias_source_is_something_a_scan_can_produce():
    """An alias for a provider or secret type no rule emits is dead
    weight, and usually a sign the mapping was guessed."""
    from services.secret_verification.verifier import (
        _PROVIDER_ALIASES, _VERIFIER_BY_SECRET_TYPE,
    )
    from services.secret_scan.detectors.registry import get_all_rules
    providers, secret_types = set(), set()
    for r in get_all_rules():
        st = (r.secret_type or "").lower()
        secret_types.add(st)
        providers.add(
            (getattr(r, "provider_override", None) or st.split("_")[0]).lower())
    for src in _PROVIDER_ALIASES:
        assert src in providers, f"no rule emits provider {src!r}"
    for src in _VERIFIER_BY_SECRET_TYPE:
        assert src in secret_types, f"no rule emits secret_type {src!r}"


# ── An unknown credential is still refused ──────────────────────────

def test_resolution_does_not_invent_a_verifier():
    from services.secret_verification.verifier import resolve_verifier_key
    assert resolve_verifier_key(_sm(provider="rsa", secret_type="rsa_private_key")) is None
    assert resolve_verifier_key(_sm(provider="", secret_type="")) is None
    assert resolve_verifier_key({}) is None


def test_the_button_follows_the_same_resolution():
    """can_verify and the endpoint must agree, or the UI offers an
    action the API refuses."""
    from services.secret_verification.verifier import can_verify
    assert can_verify(_sm(provider="google", secret_type="google_gemini_key")) is True
    assert can_verify(_sm(provider="crates", secret_type="crates_io_token")) is True
    assert can_verify(_sm(provider="rsa", secret_type="rsa_private_key")) is False
