# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Branch-pattern matching for per-repo monitoring config.

Used by the webhook receiver to decide whether a push / PR event on
branch X should trigger a scan.  Customers configure
``Repository.branch_patterns`` to opt out of scanning every branch
(default behaviour) and instead scan only branches that match at
least one fnmatch glob.

Pattern syntax is plain fnmatch, not regex.  Customer-friendly:

  ``*``           — match any sequence of characters
  ``?``           — match exactly one character
  ``[abc]``       — match any character in the set
  ``[!abc]``      — match any character NOT in the set

Examples:

  ``["main"]``                 → only main
  ``["main", "release/*"]``    → main + any branch under release/
  ``["*"]``                    → every branch (same as NULL but explicit)
  ``["feature-*", "develop"]`` → develop + any feature-X branch
"""
import fnmatch
from typing import Iterable, Optional


def branch_matches(branch: str, patterns: Optional[Iterable[str]]) -> bool:
    """Check whether ``branch`` should be scanned per the repo's pattern list.

    NULL / empty patterns → True (scan everything, preserves the
    pre-w0x1y2z3a4b5 behaviour).  This is the conservative choice so
    the migration doesn't silently throttle every existing repo.

    Non-empty patterns → True only if at least one non-empty pattern
    matches the branch via :func:`fnmatch.fnmatch`.  Empty / whitespace
    strings inside the list are ignored so a stray ``""`` left in the
    UI doesn't accidentally match everything (fnmatch("", "") is True
    in Python — caller filtering avoids that footgun).
    """
    if patterns is None:
        return True
    cleaned = [p for p in patterns if isinstance(p, str) and p.strip()]
    if not cleaned:
        return True
    return any(fnmatch.fnmatch(branch, p) for p in cleaned)
