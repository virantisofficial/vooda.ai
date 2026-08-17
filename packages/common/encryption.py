# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Encryption utilities for sensitive data at rest.

Uses Fernet symmetric encryption (AES-128-CBC with HMAC-SHA256).
The encryption key is derived from the app SECRET_KEY.
"""

import base64
import hashlib
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken


def _derive_key(secret_key: str) -> bytes:
    """Derive a 32-byte Fernet key from the app secret key."""
    key_bytes = hashlib.sha256(secret_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(key_bytes)


_fernet: Optional[Fernet] = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        from apps.api.app.core.config import settings
        _fernet = Fernet(_derive_key(settings.SECRET_KEY))
    return _fernet


def encrypt_value(plaintext: str) -> str:
    """Encrypt a string value. Returns base64-encoded ciphertext with 'enc:' prefix."""
    if not plaintext:
        return plaintext
    f = _get_fernet()
    encrypted = f.encrypt(plaintext.encode("utf-8"))
    return "enc:" + encrypted.decode("utf-8")


def decrypt_value(ciphertext: str) -> str:
    """Decrypt an encrypted value. Handles both encrypted (enc: prefix) and plaintext."""
    if not ciphertext:
        return ciphertext
    if not ciphertext.startswith("enc:"):
        return ciphertext  # Not encrypted — return as-is for backward compatibility
    f = _get_fernet()
    try:
        decrypted = f.decrypt(ciphertext[4:].encode("utf-8"))
        return decrypted.decode("utf-8")
    except InvalidToken:
        return ciphertext  # If decryption fails, return as-is


# Suffix patterns that indicate a sensitive field — used in addition
# to the explicit ``_EXPLICIT_SENSITIVE_KEYS`` set below.  Pattern-
# matching catches new provider integrations whose credential fields
# follow common naming conventions (e.g. ``bot_token``,
# ``signing_secret``, ``access_key_id``) without requiring this set
# to be updated.  Without this, fields like Slack's ``bot_token``
# silently bypassed encryption — discovered E2E on 2026-05-19.
_SENSITIVE_SUFFIXES = (
    "_token", "_key", "_secret", "_password", "_pwd",
    "_credential", "_credentials", "_pass",
)
# Substrings that signal sensitive material when not caught by suffix
# (e.g. ``webhook_url`` is sensitive even though it ends in ``_url``).
_SENSITIVE_SUBSTRINGS = ("webhook_url", "private_key", "signing_secret")
# Explicit keys that don't match the suffix/substring rules but ARE
# sensitive (kept for backwards compatibility — old configs).
_EXPLICIT_SENSITIVE_KEYS = {
    "password", "secret", "token", "credential",
}


def is_sensitive_key(key: str) -> bool:
    """True if a config-dict key should be treated as sensitive.

    Matches on (a) explicit known names, (b) common suffixes
    (``_token`` / ``_key`` / ``_secret`` / ``_password``), and
    (c) specific substrings (``webhook_url``, ``private_key``,
    ``signing_secret``).  Centralised so encryption + masking +
    test-connection filtering all agree on what counts as a secret.
    """
    if not key:
        return False
    k = key.lower()
    if k in _EXPLICIT_SENSITIVE_KEYS:
        return True
    if any(s in k for s in _SENSITIVE_SUBSTRINGS):
        return True
    if any(k.endswith(suf) for suf in _SENSITIVE_SUFFIXES):
        return True
    return False


def encrypt_config_dict(config: dict, sensitive_keys: set[str] = None) -> dict:
    """Encrypt sensitive fields in a configuration dictionary.

    The optional ``sensitive_keys`` arg is now redundant with the
    pattern matcher (kept for backwards compat).  When provided it
    UNIONs with the pattern match — callers passing it in get
    additive behaviour, not override.
    """
    encrypted = {}
    for key, value in config.items():
        is_sensitive = is_sensitive_key(key) or (sensitive_keys and key in sensitive_keys)
        if isinstance(value, str) and is_sensitive and not value.startswith("enc:"):
            encrypted[key] = encrypt_value(value)
        else:
            encrypted[key] = value
    return encrypted


def decrypt_config_dict(config: dict, sensitive_keys: set[str] = None) -> dict:
    """Decrypt sensitive fields in a configuration dictionary."""
    decrypted = {}
    for key, value in config.items():
        is_sensitive = is_sensitive_key(key) or (sensitive_keys and key in sensitive_keys)
        if isinstance(value, str) and is_sensitive:
            decrypted[key] = decrypt_value(value)
        else:
            decrypted[key] = value
    return decrypted
