# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Fix Validator — verifies that a generated patch actually resolves the finding.

Applies the patch, then re-runs the secret scanner
to verify the finding no longer triggers.
"""

import os
import re
import structlog
from dataclasses import dataclass
from typing import Optional

logger = structlog.get_logger()


@dataclass
class ValidationResult:
    """Result from validating a fix."""
    valid: bool                     # True if the fix resolves the finding
    original_findings: int = 0     # findings in the original file
    patched_findings: int = 0      # findings in the patched file
    new_findings: int = 0          # new findings introduced by the patch
    error: Optional[str] = None


def apply_diff_to_content(original: str, diff: str) -> Optional[str]:
    """Apply a unified diff to file content in memory."""
    if not diff or not original:
        return None

    lines = original.split("\n")
    result = list(lines)
    offset = 0

    for diff_line in diff.split("\n"):
        if diff_line.startswith("@@"):
            m = re.match(r"@@ -(\d+)", diff_line)
            if m:
                current = int(m.group(1)) - 1 + offset
        elif diff_line.startswith("-") and not diff_line.startswith("---"):
            if 0 <= current < len(result):
                result.pop(current)
                offset -= 1
        elif diff_line.startswith("+") and not diff_line.startswith("+++"):
            result.insert(current, diff_line[1:])
            current += 1
            offset += 1
        elif diff_line.startswith(" "):
            current += 1

    return "\n".join(result)


async def validate_fix(
    original_content: str,
    patch_diff: str,
    file_path: str,
    rule_id: Optional[str] = None,
) -> ValidationResult:
    """
    Validate that a patch fixes the vulnerability.

    1. Scan original content with standalone scanner
    2. Apply patch, scan patched content
    3. Compare: patched should have fewer findings for the target rule

    Args:
        original_content: Original file content
        patch_diff: Unified diff to apply
        file_path: Original file path (for language detection)
        rule_id: Specific rule to check (optional)

    Returns:
        ValidationResult
    """
    patched_content = apply_diff_to_content(original_content, patch_diff)
    if patched_content is None:
        return ValidationResult(valid=False, error="Could not apply patch")

    if patched_content == original_content:
        return ValidationResult(valid=False, error="Patch produced no changes")

    try:
        from services.secret_scan.engine import SecretScanner

        scanner = SecretScanner()

        # Scan original
        orig_findings = scanner.scan_file(file_path, original_content)
        if rule_id:
            orig_findings = [f for f in orig_findings if f.rule_id == rule_id]
        original_count = len(orig_findings)

        # Scan patched
        patched_findings = scanner.scan_file(file_path, patched_content)
        if rule_id:
            patched_findings = [f for f in patched_findings if f.rule_id == rule_id]
        patched_count = len(patched_findings)

        # Check for new findings (regressions)
        orig_rules = set(f.rule_id for f in orig_findings)
        new_count = sum(1 for f in patched_findings if f.rule_id not in orig_rules)

        is_valid = patched_count < original_count and new_count == 0

        logger.info(
            "fix_validation_complete",
            file=file_path,
            original=original_count,
            patched=patched_count,
            new=new_count,
            valid=is_valid,
        )

        return ValidationResult(
            valid=is_valid,
            original_findings=original_count,
            patched_findings=patched_count,
            new_findings=new_count,
        )

    except Exception as e:
        logger.error("fix_validation_error", error=str(e)[:200])
        return ValidationResult(valid=False, error=str(e)[:200])
