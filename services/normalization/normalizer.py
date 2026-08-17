# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Finding normalization and deduplication service.
Converts ImportedFindings into NormalizedFindings with canonical schema.
"""

import hashlib
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from apps.api.app.models.finding import (
    ImportedFinding,
    NormalizedFinding,
    Severity,
    Classification,
)

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def compute_fingerprint(finding: ImportedFinding) -> str:
    """
    Generate a dedup fingerprint based on file, line, category, and rule.
    Two findings with the same fingerprint are considered duplicates.
    """
    parts = [
        finding.scanner_rule_id or "",
        finding.file_path or "",
        str(finding.line_start or ""),
        finding.category or "",
        finding.cwe or "",
    ]
    key = "|".join(parts)
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def normalize_severity(raw) -> Severity:
    # None / "" / non-str (e.g. an omitted-but-optional severity on the
    # CLI/CI import surface) must NEVER crash a caller — this is the single
    # shared normalizer used by both the server storing loop and the
    # findings-import worker. A missing severity defaults to MEDIUM rather
    # than throwing AttributeError on `None.lower()` (which previously failed
    # an entire import batch AFTER a 202, silently losing the findings).
    if not raw or not isinstance(raw, str):
        return Severity.MEDIUM
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
    }
    return mapping.get(raw.lower().strip(), Severity.MEDIUM)


async def normalize_imported_findings(
    db: AsyncSession,
    scan_job_id: UUID,
    tenant_id: UUID,
    repository_id: UUID,
) -> int:
    """
    Convert all ImportedFindings for a scan job into NormalizedFindings.
    Deduplicates against existing findings for the same repo.
    Returns count of new normalized findings created.
    """
    result = await db.execute(
        select(ImportedFinding).where(ImportedFinding.scan_job_id == scan_job_id)
    )
    imported = result.scalars().all()

    # Load existing fingerprints for this repo
    existing = await db.execute(
        select(NormalizedFinding.fingerprint).where(
            NormalizedFinding.repository_id == repository_id,
            NormalizedFinding.fingerprint.isnot(None),
        )
    )
    existing_fps = {row[0] for row in existing.all()}

    created = 0
    for imp in imported:
        fp = compute_fingerprint(imp)
        if fp in existing_fps:
            continue  # deduplicated
        existing_fps.add(fp)

        normalized = NormalizedFinding(
            scan_job_id=scan_job_id,
            imported_finding_id=imp.id,
            repository_id=repository_id,
            tenant_id=tenant_id,
            scanner_name=imp.scanner_name,
            scanner_rule_id=imp.scanner_rule_id,
            external_finding_id=imp.external_id,
            title=imp.title or "Untitled Finding",
            description=imp.raw_data.get("description", ""),
            vulnerability_category=imp.category or "uncategorized",
            cwe=imp.cwe,
            severity=normalize_severity(imp.severity or "medium"),
            file_path=imp.file_path or "unknown",
            line_start=imp.line_start,
            code_snippet=imp.raw_data.get("code_snippet"),
            classification=Classification.NEEDS_REVIEW,
            fingerprint=fp,
        )
        db.add(normalized)
        created += 1

    await db.flush()
    return created
