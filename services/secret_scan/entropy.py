# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Shannon entropy detection for high-randomness strings."""

import math
import re
from dataclasses import dataclass
from typing import Optional

from services.secret_scan.config import ENTROPY_THRESHOLDS, MIN_SECRET_LENGTH


@dataclass
class EntropyMatch:
    value: str
    entropy: float
    charset: str  # base64, hex, generic
    line_num: int
    start_col: int


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


_BASE64_RE = re.compile(r'[A-Za-z0-9+/=_\-]{20,}')
_HEX_RE = re.compile(r'[0-9a-fA-F]{32,}')

_BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
_HEX_CHARS = set("0123456789abcdefABCDEF")


def _classify_charset(s: str) -> Optional[str]:
    chars = set(s)
    if chars <= _HEX_CHARS and len(s) >= 32:
        return "hex"
    if chars <= _BASE64_CHARS and len(s) >= 20:
        return "base64"
    return None


def _is_sequential_or_repeated(s: str) -> bool:
    if len(set(s)) <= 3:
        return True
    # Check for repeating cycle (e.g., "1234567890" repeated)
    unique_chars = len(set(s))
    if unique_chars <= 10 and len(s) >= 20:
        # Likely a repeating short pattern
        for cycle_len in range(1, min(unique_chars + 2, 12)):
            cycle = s[:cycle_len]
            if cycle * (len(s) // cycle_len + 1) and all(s[i] == cycle[i % cycle_len] for i in range(len(s))):
                return True
    # Check for sequential patterns like "abcdefgh"
    diffs = [ord(s[i + 1]) - ord(s[i]) for i in range(min(len(s) - 1, 20))]
    if len(set(diffs)) <= 1:
        return True
    return False


def _is_known_hash_format(s: str) -> bool:
    """Exclude known password hash and checksum formats — these are hashes, not secrets.

    Hash-length exclusion tightened 2026-05-20 (Track-A P1.3): the
    exact-length hex rule (32/40/64/128) previously excluded ANY
    string of those lengths in [0-9a-fA-F].  Real hashes from
    ``hashlib`` always emit pure lowercase, while many real API keys
    that happen to land at those lengths (Mailgun 32, Twilio 32,
    some Datadog tokens 40) are mixed-case — and were being silently
    dropped as "must be a hash".  Now we require pure lowercase hex
    AND no uppercase characters; mixed-case strings fall through to
    the regular entropy path.
    """
    # bcrypt, argon2, scrypt prefixes
    if s.startswith(("$2a$", "$2b$", "$2y$", "$argon2", "$scrypt$", "$pbkdf2", "$5$", "$6$", "$1$")):
        return True
    # Exact-length hex hashes (MD5=32, SHA1=40, SHA256=64, SHA512=128).
    # Pure-lowercase guard added 2026-05-20 — see docstring.
    if len(s) in (32, 40, 64, 128) and re.match(r'^[0-9a-f]+$', s):
        return True
    # Subresource integrity hashes (sha256-..., sha384-..., sha512-...)
    if re.match(r'^sha(?:256|384|512)-', s):
        return True
    # h1: prefixed hashes (terraform provider hashes)
    if s.startswith(("h1:", "zh:")):
        return True
    return False


def _is_uuid(s: str) -> bool:
    """Exclude standard UUIDs/GUIDs — high entropy but never secrets."""
    s_clean = s.strip("{}")
    # Standard UUID with hyphens: 8-4-4-4-12
    if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', s_clean):
        return True
    # Compact UUID without hyphens: exactly 32 hex chars with version digit at position 12
    if len(s_clean) == 32 and re.match(r'^[0-9a-fA-F]{32}$', s_clean):
        # Check version digit (position 12) is 1-5
        if s_clean[12] in '12345':
            return True
    return False


def _is_allowlisted_pattern(candidate: str, line: str) -> bool:
    """Skip high-entropy strings that are clearly not secrets based on context."""
    # 1. URL path segments — candidate is embedded inside a URL
    if '://' in line:
        # Find URL in line and check if candidate is part of path/query
        url_match = re.search(r'https?://[^\s\'"]+', line)
        if url_match and candidate in url_match.group():
            return True

    # 2. Image digests — preceded by sha256:/sha384:/sha512:
    idx = line.find(candidate)
    if idx > 0:
        prefix = line[max(0, idx - 8):idx].lower()
        if any(h in prefix for h in ('sha256:', 'sha384:', 'sha512:')):
            return True

    # 3. File paths — contains internal path separators
    stripped = candidate[1:-1] if len(candidate) > 2 else candidate
    if '/' in stripped or '\\' in stripped:
        return True

    # 4. Low uniqueness ratio — repeated bigrams look high-entropy but aren't random
    unique_ratio = len(set(candidate)) / len(candidate) if candidate else 0
    if unique_ratio < 0.3:
        return True

    # 5. Version/build context — surrounded by build-related keywords
    line_lower = line.lower()
    build_ctx = ('version', 'build', 'commit', 'tag=', 'ref=', 'release',
                 'download/', 'releases/', 'artifacts/', 'dist/')
    if any(kw in line_lower for kw in build_ctx):
        # Only skip if candidate looks like a version/hash, not an actual key
        if not any(secret_kw in line_lower for secret_kw in
                   ('key', 'token', 'secret', 'password', 'credential', 'auth')):
            return True

    # 6. Import/require/include statements — code references, not secrets
    trimmed = line.strip()
    if trimmed.startswith(('import ', 'from ', 'require(', '#include', 'using ',
                           'use ', 'include ', 'load ', 'source ')):
        return True

    return False


def _looks_like_word(s: str) -> bool:
    """Heuristic: is this string shaped like an English word?

    Tightened 2026-05-20 (Track-A P1.3): the prior vowel range
    ``0.15-0.55`` was catching legitimate keys whose alphabet
    happened to contain a few vowels — most painfully AWS access-key
    IDs like ``AKIAIOSFODNN7EXAMPLE`` (vowel ratio 0.30, all
    uppercase) which fell in the range and were silently dropped
    from entropy detection.  Real English words almost always carry
    at least one contiguous lowercase span of length ≥4 ("pass" in
    "password", "secret" in "secrets") — require that AND a tighter
    vowel range so all-uppercase keys with incidental vowels stop
    misfiring.
    """
    if not s:
        return False
    lower = s.lower()
    vowels = sum(1 for c in lower if c in "aeiou")
    ratio = vowels / len(lower)
    if not (0.25 <= ratio <= 0.55):
        return False
    if len(s) >= 30:
        return False
    # Require a real contiguous lowercase run — pure-uppercase strings
    # (AKIA…, GHTOKEN…, AWS access-key shapes) no longer pass the word
    # filter even if their vowel ratio happens to fall in range.
    longest_lowercase_run = 0
    current = 0
    for ch in s:
        if ch.islower():
            current += 1
            if current > longest_lowercase_run:
                longest_lowercase_run = current
        else:
            current = 0
    return longest_lowercase_run >= 4


def find_high_entropy_strings(
    content: str,
    min_length: int = MIN_SECRET_LENGTH,
    file_path: str = "",
) -> list[EntropyMatch]:
    """Find high-entropy strings in content.

    2026-04-19 generic-accuracy pass: added an optional ``file_path``
    arg so the entropy threshold can adapt to context. In test / doc
    / example directories we require **0.5 bits more entropy** before
    flagging — those files are noisy for entropy detection (random
    test UUIDs, base64 fixtures, mock tokens) and the tighter bar
    cuts through that without changing any rule regex.
    """
    matches = []
    lines = content.split("\n")

    # Context-aware threshold boost. Keep the main ENTROPY_THRESHOLDS
    # table untouched so production-code defaults don't regress.
    # 0.3 bits is enough to cut through test-noise (mock tokens, random
    # fixtures) without dropping borderline real secrets — tuned down
    # from initial 0.5 after the real-world WebGoat scan lost JWT hits
    # in test-file context.
    threshold_boost = 0.0
    if file_path:
        fp = file_path.lower()
        if any(seg in fp for seg in (
            "/test/", "/tests/", "/spec/", "/specs/", "__tests__",
            "/fixture", "/example", "/sample", "/demo", "/mock",
            "/docs/", "/doc/", "/documentation/",
        )):
            threshold_boost = 0.3

    for line_idx, line in enumerate(lines):
        if len(line) > 2000:
            continue

        # Find potential base64 strings
        for m in _BASE64_RE.finditer(line):
            candidate = m.group()
            if len(candidate) < min_length:
                continue
            if _is_sequential_or_repeated(candidate):
                continue
            if _looks_like_word(candidate):
                continue
            if _is_known_hash_format(candidate):
                continue
            if _is_uuid(candidate):
                continue
            if _is_allowlisted_pattern(candidate, line):
                continue

            charset = _classify_charset(candidate)
            if not charset:
                continue

            threshold = ENTROPY_THRESHOLDS.get(charset, ENTROPY_THRESHOLDS["generic"]) + threshold_boost
            ent = shannon_entropy(candidate)

            if ent >= threshold:
                matches.append(EntropyMatch(
                    value=candidate,
                    entropy=ent,
                    charset=charset,
                    line_num=line_idx + 1,
                    start_col=m.start(),
                ))

        # Find potential hex strings (only if not already caught by base64)
        for m in _HEX_RE.finditer(line):
            candidate = m.group()
            if len(candidate) < 32:
                continue
            if _is_sequential_or_repeated(candidate):
                continue
            if _is_known_hash_format(candidate):
                continue
            if _is_uuid(candidate):
                continue
            if any(em.line_num == line_idx + 1 and em.start_col == m.start() for em in matches):
                continue

            ent = shannon_entropy(candidate)
            if ent >= ENTROPY_THRESHOLDS["hex"]:
                matches.append(EntropyMatch(
                    value=candidate,
                    entropy=ent,
                    charset="hex",
                    line_num=line_idx + 1,
                    start_col=m.start(),
                ))

    return matches
