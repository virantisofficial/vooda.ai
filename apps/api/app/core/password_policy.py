# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Password strength policy — length, complexity, and a common-password blocklist.

Enforces the parts of the documented policy that can be checked offline, so it
works with egress disabled in air-gapped deployments. "Breached password"
detection uses a bundled blocklist of the most common / most-credential-stuffed
passwords rather than a live HaveIBeenPwned lookup.

`no reuse of the last N passwords` is enforced separately, at the call site,
because it needs the account's password history.
"""
from __future__ import annotations

import re

MIN_LENGTH = 12

#: How many previous passwords a self-service change may not reuse.
PASSWORD_HISTORY_DEPTH = 5

_UPPER = re.compile(r"[A-Z]")
_LOWER = re.compile(r"[a-z]")
_DIGIT = re.compile(r"[0-9]")
_SYMBOL = re.compile(r"[^A-Za-z0-9]")

#: Curated blocklist of the passwords that dominate real credential-stuffing
#: lists. This is a pragmatic offline subset, not the full HIBP corpus — it
#: catches the values that actually show up, at zero egress and zero latency.
#: Compared case-insensitively; a handful of common l33t/suffix variants are
#: listed explicitly because they slip past the complexity rules.
COMMON_PASSWORDS = frozenset(
    p.lower()
    for p in {
        "password", "password1", "password12", "password123", "password1234",
        "passw0rd", "passw0rd1", "p@ssw0rd", "p@ssword", "p@ssw0rd1", "pa$$w0rd",
        "123456", "1234567", "12345678", "123456789", "1234567890", "12345",
        "111111", "000000", "123123", "654321", "121212", "112233", "123321",
        "qwerty", "qwerty1", "qwerty123", "qwertyuiop", "1qaz2wsx", "qazwsx",
        "asdfghjkl", "zxcvbnm", "qweasdzxc", "1q2w3e4r", "1q2w3e4r5t",
        "letmein", "letmein1", "welcome", "welcome1", "welcome123",
        "admin", "admin1", "admin123", "administrator", "root", "toor",
        "changeme", "changeme1", "changeit", "default", "secret", "secret1",
        "iloveyou", "monkey", "dragon", "sunshine", "princess", "shadow",
        "football", "baseball", "superman", "batman", "master", "hello",
        "hello123", "abc123", "abcd1234", "abcdefgh", "test", "test123",
        "testtest", "guest", "guest123", "login", "trustno1", "whatever",
        "starwars", "michael", "jordan23", "access", "flower", "hottie",
        "loveme", "zaq12wsx", "password!", "p@ssw0rd!", "welcome!", "admin!",
        "vooda", "vooda123", "voodaai", "vooda2026", "vooda@123",
    }
)


def check_password_strength(password: str) -> list[str]:
    """Return a list of unmet-requirement phrases (empty list = passes).

    Each phrase completes the sentence "Password must ...".
    """
    pw = password or ""
    errors: list[str] = []
    if len(pw) < MIN_LENGTH:
        errors.append(f"be at least {MIN_LENGTH} characters")
    if not _UPPER.search(pw):
        errors.append("include an uppercase letter")
    if not _LOWER.search(pw):
        errors.append("include a lowercase letter")
    if not _DIGIT.search(pw):
        errors.append("include a number")
    if not _SYMBOL.search(pw):
        errors.append("include a symbol")
    if pw.lower() in COMMON_PASSWORDS:
        errors.append("not be a commonly used or breached password")
    return errors


def password_policy_error(password: str) -> str | None:
    """Return a single human-readable message if `password` fails policy, else None."""
    errors = check_password_strength(password)
    if not errors:
        return None
    return "Password must " + "; ".join(errors) + "."
