# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Stability ID — identifies the "same finding" across scans.

Unlike Checkmarx's Similarity ID which uses line numbers (fragile),
our Stability ID hashes the code pattern itself so it survives:
- Line number changes (code added/removed above)
- Whitespace/formatting changes
- Comment changes near the vulnerable code

BUT it correctly invalidates when:
- The actual vulnerable code changes (developer fixed it)
- The function was refactored
- The vulnerability moved to a different function
"""

import hashlib
import re
from typing import Optional


def normalize_code(code: str) -> str:
    """
    Normalize code for stable hashing.
    Strips noise that doesn't affect vulnerability semantics.
    """
    if not code:
        return ""

    lines = code.split("\n")
    normalized = []

    for line in lines:
        # Strip leading/trailing whitespace
        stripped = line.strip()

        # Skip empty lines
        if not stripped:
            continue

        # Skip single-line comments
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("--"):
            continue

        # Skip block comment markers
        if stripped.startswith("/*") or stripped.startswith("*/") or stripped.startswith("*"):
            if stripped in ("/*", "*/", "*") or (stripped.startswith("*") and not stripped.startswith("**")):
                continue

        # Collapse multiple spaces to single
        stripped = re.sub(r"\s+", " ", stripped)

        # Remove trailing semicolons (style difference)
        stripped = stripped.rstrip(";")

        # Lowercase for case-insensitive matching
        stripped = stripped.lower()

        normalized.append(stripped)

    return "\n".join(normalized)


def compute_code_hash(code: str) -> str:
    """Hash the normalized code to detect changes."""
    normalized = normalize_code(code)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def compute_stability_id(
    rule_id: str,
    file_path: str,
    code_snippet: str = "",
    function_name: Optional[str] = None,
    cwe: Optional[str] = None,
    line_start: Optional[int] = None,
) -> str:
    """
    Generate a Stability ID for a finding.

    Uses rule_id + file_path + cwe + line_start as the primary identity.
    Code snippet is NOT used because it varies between enrichment levels
    across scan runs. Line numbers are stable enough for same-commit scans.

    The code_hash is tracked separately to detect code changes and invalidate
    the decision cache when the actual code at the finding location changes.
    """
    parts = [
        rule_id or "",
        file_path or "",
        function_name or "",
        cwe or "",
        str(line_start or ""),
    ]

    stability_id = hashlib.sha256("|".join(parts).encode()).hexdigest()[:20]
    return stability_id


def compute_secret_stability_id(
    *,
    secret_hash: str = "",
    rule_id: str = "",
    file_path: str = "",
    line_start: Optional[int] = None,
) -> str:
    """Canonical dedup key for SECRET findings.

    This is the SINGLE source of truth for "is this the same secret finding"
    and MUST be used identically by:
      * the worker storing loop (``_run_scan_job`` via ``_stability_id_for_pf``),
      * the CLI/CI SARIF-import path (so an imported finding dedupes against a
        server scan of the same secret instead of double-creating), and
      * the policy-DOWN sync (so the CLI can match a server-side suppression).

    Divergence here = silent double-creation or failed suppression matches,
    so all three call THIS function rather than re-deriving the formula.

      * with secret_hash (verified secret): ``sha256(secret_hash | path)``
      * without secret_hash:                ``sha256(rule_id | path | line_start)``

    ``file_path`` MUST already be repo-relative (the caller strips any
    absolute repo_path prefix) so the same secret hashes identically whether
    it was found by a server clone at /app/storage/... or by the CLI on a CI
    runner at /home/runner/work/...
    """
    if secret_hash:
        return hashlib.sha256(f"{secret_hash}|{file_path}".encode()).hexdigest()[:20]
    return hashlib.sha256(
        f"{rule_id or ''}|{file_path}|{line_start or ''}".encode()
    ).hexdigest()[:20]


def compute_pattern_hash(
    rule_id: str,
    code_snippet: str,
    cwe: Optional[str] = None,
) -> str:
    """
    Compute a pattern hash — identifies the same CODE PATTERN regardless of file.
    Used for cross-repo learning: "this pattern was FP in repo A → likely FP in repo B"

    Less specific than stability_id (no file_path, no function_name).
    """
    code_hash = compute_code_hash(code_snippet or "")
    parts = [rule_id or "", cwe or "", code_hash]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
