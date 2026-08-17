# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Pre-AI Deduplication — groups similar findings to reduce AI API calls.

When 5 findings are the same CWE in the same file, we only need to triage ONE.
The AI's classification for that one finding applies to all in the group.

Grouping criteria:
- Same CWE
- Same file
- Same scanner rule (e.g., all "eval injection" in the same file)
- Similar code pattern (same function calls, same anti-pattern)

This typically reduces AI calls by 20-40% on real codebases.
"""

import structlog
from dataclasses import dataclass, field

logger = structlog.get_logger()


@dataclass
class FindingGroup:
    """A group of similar findings that only needs one AI triage call."""
    representative_id: str  # The finding we'll send to AI
    member_ids: list[str] = field(default_factory=list)  # All findings in this group (including representative)
    group_key: str = ""  # What makes them similar
    cwe: str = ""
    file_path: str = ""
    rule_id: str = ""


def _snippet_fingerprint(code_snippet: str) -> str:
    """Short stable fingerprint of a code snippet used as part of the dedup
    group key. Two findings with different snippet content (even in the
    same file + rule) must live in different groups — otherwise one
    representative's classification gets broadcast across structurally
    different sibling findings.

    Gold-label evidence (2026-04-24): moby's api/docs/v1.X.yaml files
    each contained both a JoinToken example (TP-looking schema with
    'Secret token for joining this swarm.' description) AND an
    IdentityToken example (ellipsis placeholder, clearly FP). With a
    snippet-free group key both fell into one group, and Mistral's TP
    verdict on the JoinToken representative was broadcast onto the
    IdentityToken sibling — producing ~90% wrong classifications on
    the whole moby HELM-001 set.
    """
    import hashlib
    # Normalize whitespace so trivial formatting differences don't break grouping
    normalized = " ".join((code_snippet or "").split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]


def group_findings_for_triage(findings_data: list[dict]) -> tuple[list[dict], dict[str, FindingGroup]]:
    """
    Group similar findings and return:
    1. Deduplicated list (one per group) to send to AI
    2. Mapping of groups for applying results back

    Returns:
        (deduped_list, groups_map)
        - deduped_list: findings to actually send to AI (one per group)
        - groups_map: keyed by representative finding ID, value is the FindingGroup

    Usage:
        deduped, groups = group_findings_for_triage(finding_data_list)
        # Send only `deduped` to AI (fewer calls)
        # After AI responds, apply results to all members in each group
    """
    # Group by (cwe + file + rule_id + snippet_fingerprint). The snippet
    # fingerprint is essential: without it the group-wide verdict broadcast
    # silently misclassifies structurally-different findings that happen
    # to share the same rule in the same file. See _snippet_fingerprint
    # docstring for the gold-label evidence that motivated this change.
    groups: dict[str, list[dict]] = {}

    for f in findings_data:
        snippet_fp = _snippet_fingerprint(f.get("code_snippet", "") or "")
        key = (
            f"{f.get('cwe', '')}|{f.get('file_path', '')}|"
            f"{f.get('scanner_rule_id', '')}|{snippet_fp}"
        )
        if key not in groups:
            groups[key] = []
        groups[key].append(f)

    deduped_list = []
    groups_map: dict[str, FindingGroup] = {}

    for key, members in groups.items():
        # Pick the representative — prefer the one with the most context (longest code snippet)
        representative = max(members, key=lambda m: len(m.get("code_snippet", "") or ""))
        rep_id = representative["id"]

        group = FindingGroup(
            representative_id=rep_id,
            member_ids=[m["id"] for m in members],
            group_key=key,
            cwe=representative.get("cwe", ""),
            file_path=representative.get("file_path", ""),
            rule_id=representative.get("scanner_rule_id", ""),
        )
        groups_map[rep_id] = group
        deduped_list.append(representative)

    saved = len(findings_data) - len(deduped_list)
    if saved > 0:
        logger.info("pre_ai_dedup",
            original=len(findings_data),
            deduped=len(deduped_list),
            saved=saved,
            groups=len(groups_map),
        )

    return deduped_list, groups_map


def apply_group_results(
    groups_map: dict[str, FindingGroup],
    triage_results: dict[str, dict],
) -> dict[str, dict]:
    """
    Expand triage results from representatives to all group members.

    Args:
        groups_map: From group_findings_for_triage
        triage_results: AI results keyed by finding ID

    Returns:
        Expanded results keyed by finding ID (includes all group members)
    """
    expanded = {}

    for rep_id, group in groups_map.items():
        result = triage_results.get(rep_id)
        if not result:
            continue

        # Apply the representative's result to ALL members in the group
        for member_id in group.member_ids:
            expanded[member_id] = result

    # Also include any results that weren't in groups (single findings)
    for fid, result in triage_results.items():
        if fid not in expanded:
            expanded[fid] = result

    return expanded
