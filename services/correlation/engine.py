# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Multi-Scanner Correlation Engine — deduplicates and correlates findings
from different scanners that point to the same vulnerability.

When Checkmarx and SonarQube both flag SQL injection at app.py:45,
they should appear as ONE finding with 2 scanner attributions and
boosted confidence.

Correlation algorithm:
1. Group by (file_path, line_range ±5 lines)
2. Within groups, match by CWE or vulnerability category
3. Select primary finding (highest confidence scanner)
4. Link others as correlated
5. Compute aggregate confidence (multiple scanners = higher confidence)
"""

import uuid
import structlog
from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

logger = structlog.get_logger()

LINE_PROXIMITY = 5  # findings within ±5 lines are candidates for correlation

# CWE category grouping — different CWEs that represent the same vulnerability class
CWE_EQUIVALENCE = {
    "sqli": {"CWE-89", "CWE-564", "CWE-943"},
    "xss": {"CWE-79", "CWE-80", "CWE-87"},
    "ssrf": {"CWE-918"},
    "cmd_injection": {"CWE-78", "CWE-77"},
    "path_traversal": {"CWE-22", "CWE-23", "CWE-36"},
    "deserialization": {"CWE-502"},
    "weak_crypto": {"CWE-327", "CWE-328", "CWE-326"},
    "hardcoded_secret": {"CWE-798", "CWE-259", "CWE-321"},
    "open_redirect": {"CWE-601"},
    "xxe": {"CWE-611"},
    "csrf": {"CWE-352"},
}

# Build reverse mapping: CWE -> group
_CWE_TO_GROUP = {}
for group, cwes in CWE_EQUIVALENCE.items():
    for cwe in cwes:
        _CWE_TO_GROUP[cwe] = group

# Category keyword mapping for when CWEs aren't available
CATEGORY_KEYWORDS = {
    "sqli": ["sql injection", "sql", "sqli", "query injection"],
    "xss": ["cross-site scripting", "xss", "script injection", "html injection"],
    "ssrf": ["ssrf", "server-side request", "request forgery"],
    "cmd_injection": ["command injection", "os command", "shell injection", "code injection"],
    "path_traversal": ["path traversal", "directory traversal", "file inclusion"],
    "deserialization": ["deserialization", "deserialize", "pickle", "marshal"],
    "weak_crypto": ["weak crypto", "md5", "sha1", "weak hash", "insecure hash"],
    "hardcoded_secret": ["hardcoded", "secret", "credential", "api key", "password"],
}


@dataclass
class CorrelationGroup:
    """A group of correlated findings."""
    group_id: str
    file_path: str
    line_center: int
    category_group: str
    finding_ids: list[str] = field(default_factory=list)
    scanners: list[str] = field(default_factory=list)
    primary_finding_id: str | None = None
    aggregate_confidence: float = 0.0


def _get_cwe_group(cwe: str | None) -> str | None:
    """Map a CWE to its equivalence group."""
    if not cwe:
        return None
    clean = cwe.upper().strip()
    return _CWE_TO_GROUP.get(clean)


def _get_category_group(category: str) -> str | None:
    """Map a vulnerability category string to a group key."""
    if not category:
        return None
    cat_lower = category.lower()
    for group_key, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in cat_lower for kw in keywords):
            return group_key
    return None


async def correlate_findings(
    db: AsyncSession,
    repository_id: UUID,
    scan_job_id: UUID | None = None,
) -> int:
    """
    Correlate findings across scanners for a repository.

    Finds groups of related findings and links them via correlation_group_id.
    Returns the number of correlation groups created.

    Args:
        db: Database session
        repository_id: Repository to correlate findings for
        scan_job_id: If provided, only correlate findings from this scan against existing ones
    """
    from apps.api.app.models.finding import NormalizedFinding

    # Load all active findings for this repo
    query = select(NormalizedFinding).where(
        NormalizedFinding.repository_id == repository_id,
        NormalizedFinding.is_suppressed == False,
    )
    result = await db.execute(query)
    all_findings = result.scalars().all()

    if len(all_findings) < 2:
        return 0

    # Build candidate groups by (file, approximate line)
    file_groups: dict[str, list] = {}
    for f in all_findings:
        key = f.file_path or "unknown"
        if key not in file_groups:
            file_groups[key] = []
        file_groups[key].append(f)

    groups_created = 0

    for file_path, findings in file_groups.items():
        if len(findings) < 2:
            continue

        # Sort by line number
        findings.sort(key=lambda f: f.line_start or 0)

        # Find clusters of findings within LINE_PROXIMITY
        clusters: list[list] = []
        current_cluster = [findings[0]]

        for i in range(1, len(findings)):
            prev_line = current_cluster[-1].line_start or 0
            curr_line = findings[i].line_start or 0

            if abs(curr_line - prev_line) <= LINE_PROXIMITY:
                current_cluster.append(findings[i])
            else:
                if len(current_cluster) >= 2:
                    clusters.append(current_cluster)
                current_cluster = [findings[i]]

        if len(current_cluster) >= 2:
            clusters.append(current_cluster)

        # Within each cluster, group by vulnerability category
        for cluster in clusters:
            category_subgroups: dict[str, list] = {}

            for f in cluster:
                # Determine category group
                group_key = _get_cwe_group(f.cwe) or _get_category_group(f.vulnerability_category) or "unknown"
                if group_key not in category_subgroups:
                    category_subgroups[group_key] = []
                category_subgroups[group_key].append(f)

            for cat_group, group_findings in category_subgroups.items():
                if len(group_findings) < 2:
                    continue

                # Check if they're from different scanners (true correlation)
                unique_scanners = set(f.scanner_name for f in group_findings)

                if len(unique_scanners) >= 2:
                    # Multi-scanner correlation — high value
                    group_id = uuid.uuid4()

                    # Select primary finding (highest confidence)
                    primary = max(group_findings, key=lambda f: f.confidence or 0)

                    # Compute aggregate confidence
                    base_conf = max(f.confidence or 0.5 for f in group_findings)
                    scanner_bonus = min(0.2, 0.1 * (len(unique_scanners) - 1))
                    aggregate_conf = min(1.0, base_conf + scanner_bonus)

                    correlated_ids = [str(f.id) for f in group_findings]

                    for f in group_findings:
                        # Use proper DB columns
                        f.correlation_group_id = group_id
                        f.correlated_finding_ids = correlated_ids
                        f.aggregate_confidence = aggregate_conf
                        f.is_correlation_primary = (str(f.id) == str(primary.id))

                        # Also store scanner list in metadata for UI
                        f.source_metadata = {
                            **(f.source_metadata or {}),
                            "correlated_scanners": list(unique_scanners),
                        }
                        # Boost confidence
                        if f.confidence and f.confidence < aggregate_conf:
                            f.confidence = aggregate_conf

                    groups_created += 1
                    logger.info(
                        "correlation_group_created",
                        group_id=str(group_id)[:8],
                        file=file_path,
                        scanners=list(unique_scanners),
                        findings=len(group_findings),
                        category=cat_group,
                    )

                elif len(group_findings) >= 2 and len(unique_scanners) == 1:
                    # Same scanner, same location, same category. Partition by the
                    # secret VALUE before deciding — this is the generic guard that
                    # stops a credential PAIR being collapsed (2026-06-13):
                    #   • findings sharing the SAME value are TRUE duplicates (e.g.
                    #     two rules both matching one AKIA) → keep the best one,
                    #     suppress the rest.
                    #   • findings with DIFFERENT values are DISTINCT secrets that
                    #     merely sit in the same region — e.g. an AWS access-key id
                    #     + its secret access key. These must NOT be suppressed;
                    #     correlate them (group + keep visible) like the
                    #     multi-scanner branch above.
                    by_value: dict = {}
                    for f in group_findings:
                        vk = ((f.source_metadata or {}).get("secret_hash")
                              or f.fingerprint or f.stability_id or str(f.id))
                        by_value.setdefault(vk, []).append(f)

                    survivors = []
                    for _dupes in by_value.values():
                        d_primary = max(_dupes, key=lambda f: len(f.description or ""))
                        survivors.append(d_primary)
                        for f in _dupes:
                            if str(f.id) != str(d_primary.id):
                                f.is_suppressed = True
                                f.suppression_reason = "duplicate_same_scanner"
                                f.correlation_group_id = d_primary.correlation_group_id
                                f.source_metadata = {
                                    **(f.source_metadata or {}),
                                    "primary_finding_id": str(d_primary.id),
                                }

                    # ≥2 DISTINCT secrets remain in this region → correlate them
                    # (group + keep all visible) so a credential pair surfaces as
                    # one incident instead of one half being silently suppressed.
                    if len(survivors) >= 2:
                        group_id = uuid.uuid4()
                        primary = max(survivors, key=lambda f: f.confidence or 0)
                        correlated_ids = [str(f.id) for f in survivors]
                        for f in survivors:
                            f.correlation_group_id = group_id
                            f.correlated_finding_ids = correlated_ids
                            f.is_correlation_primary = (str(f.id) == str(primary.id))
                        groups_created += 1

    await db.flush()
    return groups_created
