"""A provider API key must not sit in the database in the clear.

The column was named ``api_key_encrypted`` from the start and stored
the key verbatim — the router said so itself, twice, in a comment. Any
copy of the database carried the customer's provider credential.

These tests pin three things:

  1. Every write encrypts, and every read decrypts, so no route hands
     back or stores a bare key.
  2. A key that cannot be decrypted is refused rather than returned.
     ``decrypt_value`` hands the ciphertext back on failure, which is
     fine for a plaintext column and a trap once the column is real:
     the caller would send "enc:gAAAAA..." to a provider as a bearer
     token, every model would answer 401, and it would read as a
     revoked key. An operator would then rotate a credential that was
     never the problem.
  3. Rows written before encryption keep working.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from packages.common.encryption import (
    CredentialUnreadable, decrypt_credential, decrypt_value, encrypt_value,
)

_ROUTER = pathlib.Path("apps/api/app/routers/ai_models.py")
_PROVIDER = pathlib.Path("services/ai_triage/provider.py")


def _code_only(path: pathlib.Path) -> str:
    """Source with comments and docstrings stripped.

    A prose mention of the thing a test forbids has passed for the
    thing itself here before, so the check reads executable code only.
    """
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Module)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def test_round_trip_does_not_leave_the_key_recoverable_from_the_column():
    key = "sk-test-0123456789abcdefghij"
    stored = encrypt_value(key)
    assert stored != key
    assert stored.startswith("enc:")
    assert key not in stored, "the key survives inside the stored value"
    assert decrypt_credential(stored) == key


def test_an_unreadable_credential_is_refused_not_returned():
    """The difference between "cannot read this" and "provider said no"."""
    forged = "enc:" + "gAAAAABmFAKE_not_a_real_token_at_all=="
    with pytest.raises(CredentialUnreadable):
        decrypt_credential(forged)

    # The lenient helper is what makes this necessary — it hands the
    # ciphertext straight back, which would then be sent as a bearer
    # token. Pinned so a future tidy-up does not quietly unify them.
    assert decrypt_value(forged) == forged


def test_plaintext_written_before_encryption_still_works():
    assert decrypt_credential("sk-legacy-plaintext-key") == "sk-legacy-plaintext-key"
    assert decrypt_credential("") == ""


def test_no_route_stores_or_reads_the_column_raw():
    src = _code_only(_ROUTER)

    for line in src.splitlines():
        if "api_key_encrypted" not in line:
            continue
        # bool(...) and any(...) only ask whether a key is set.
        if "bool(" in line or "any(" in line or "_AUDITED" in line:
            continue
        assert ("encrypt_value(" in line or "_stored_key(" in line), line


def test_the_triage_path_decrypts_too():
    """The path that matters: a scan running with an unusable key.

    Triage that fails leaves findings untriaged while they look
    reviewed, which is the failure the health signal exists to catch.
    """
    src = _code_only(_PROVIDER)
    for line in src.splitlines():
        if "api_key_encrypted" in line:
            assert "decrypt_credential(" in line, line
