"""Tier B — GEN-003-WEAK gated to password-family keys (recall-safe).

GEN-003-WEAK is the default/weak-credential detector. Its key alternation used
to include `user(?:name)?|login`, so it fired on default USERNAMES
(`username="kafkaadmin"`, `user: root`) — which are not credential leaks. Value-
level ground truth over the 100-repo benchmark showed the user/login branch was
the #1 FP source (1,610 of 2,041 FP), and its "TP" labels were usernames / doc
comments / variable refs, not secrets. The rule is now gated to the password
family. A real default PASSWORD still fires — that is the actual security risk
the rule exists to catch.
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner

WEAK = "VOODA-SEC-GEN-003-WEAK"


def _weak_fires(scanner, content):
    return any((f.rule_id or "") == WEAK for f in scanner.scan_file("config/app.conf", content))


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


# ── TP kept: a default PASSWORD is the real default-credential risk ──
@pytest.mark.parametrize("content", [
    'password = "admin"',
    'passwd: "qwerty"',
    'pwd="letmein"',
    'PASSWORD = "welcome"',
    'db_password: "secret"',
])
def test_default_password_still_fires(scanner, content):
    assert _weak_fires(scanner, content), (
        f"RECALL REGRESSION: default password not detected by GEN-003-WEAK: {content!r}"
    )


# ── FP dropped: a default USERNAME (user/login key + weak value) is not a leak.
# (Each is a user/login key with a value that IS in the weak allowlist, so it
# fired before the gate and must not after. A password-family key on the same
# line would still fire — that is correct; the gate is key-family, not
# comment-stripping.)
@pytest.mark.parametrize("content", [
    'username = "admin"',
    'user: administrator',
    'login = "qwerty"',
    'username: welcome',
    'user = "default"',
])
def test_default_username_does_not_fire(scanner, content):
    assert not _weak_fires(scanner, content), (
        f"GEN-003-WEAK still fires on a default USERNAME (not a secret): {content!r}"
    )


# ── FP dropped: code idioms where the "value" after the password key is an
# identifier / trait-call / field access, NOT a literal weak credential. These
# were the #1 FP on Rust repos (`config.password = Default::default()` resets
# the field to its type default; `password = password.clone()` copies a var).
# The value must now terminate in a real literal boundary (quote / whitespace /
# ; , ) ] } / EOL), so a value immediately followed by `::`, `.`, `(`, or a word
# char no longer matches — while `password = "admin"` still fires (above).
@pytest.mark.parametrize("content", [
    "config.password = Default::default();",
    "config.password = password.clone();",
    "password: password.into(),",
    "config.password = secret_store.get();",
])
def test_code_idiom_value_does_not_fire(scanner, content):
    assert not _weak_fires(scanner, content), (
        f"GEN-003-WEAK fires on a code idiom, not a literal weak cred: {content!r}"
    )
