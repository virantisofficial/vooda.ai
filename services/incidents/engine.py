# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Incident Grouping Engine — groups findings by secret_hash into incidents.

Same secret leaked in 5 repos = 1 incident with 5 occurrences.
Incidents track the lifecycle: Open → Investigating → Rotating → Resolved.
"""

import structlog
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
from datetime import datetime

logger = structlog.get_logger()


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    ROTATING = "rotating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SecretIncident:
    """A group of findings that share the same leaked secret."""
    secret_hash: str
    secret_type: str
    masked_value: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.OPEN
    occurrence_count: int = 0
    affected_repos: list[str] = field(default_factory=list)
    affected_files: list[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    validation_status: str = "not_validated"
    finding_ids: list[str] = field(default_factory=list)
    provider: str = "unknown"


def group_findings_into_incidents(findings: list[dict]) -> list[SecretIncident]:
    """
    Group findings by secret_hash into incidents.
    Each unique secret_hash = one incident, regardless of how many repos/files it appears in.
    """
    incidents_map: dict[str, SecretIncident] = {}

    for f in findings:
        sm = f.get("source_metadata") or {}
        secret_hash = sm.get("secret_hash")
        if not secret_hash:
            continue

        if secret_hash not in incidents_map:
            # Determine severity from highest-severity finding
            severity = _map_severity(f.get("severity", "medium"))
            incidents_map[secret_hash] = SecretIncident(
                secret_hash=secret_hash,
                secret_type=sm.get("secret_type", "unknown"),
                masked_value=sm.get("masked_value", "****"),
                severity=severity,
                validation_status=sm.get("validation_status", "not_validated"),
                provider=sm.get("provider", "unknown"),
                first_seen=f.get("first_seen_at") or f.get("created_at"),
            )

        incident = incidents_map[secret_hash]
        incident.occurrence_count += 1
        incident.finding_ids.append(str(f.get("id", "")))
        incident.last_seen = f.get("last_seen_at") or f.get("created_at")

        # Track affected repos
        repo_id = str(f.get("repository_id", ""))
        if repo_id and repo_id not in incident.affected_repos:
            incident.affected_repos.append(repo_id)

        # Track affected files
        file_path = f.get("file_path", "")
        if file_path and file_path not in incident.affected_files:
            incident.affected_files.append(file_path)

        # Escalate severity if higher-severity occurrence found
        finding_severity = _map_severity(f.get("severity", "medium"))
        if _severity_rank(finding_severity) > _severity_rank(incident.severity):
            incident.severity = finding_severity

        # Escalate to active if any occurrence is validated active
        if sm.get("validation_status") == "active":
            incident.validation_status = "active"

    incidents = sorted(
        incidents_map.values(),
        key=lambda i: (_severity_rank(i.severity), i.occurrence_count),
        reverse=True,
    )

    logger.info(
        "incidents_grouped",
        total_findings=len(findings),
        total_incidents=len(incidents),
        multi_repo=sum(1 for i in incidents if len(i.affected_repos) > 1),
    )

    return incidents


def _map_severity(sev: str) -> IncidentSeverity:
    sev_lower = sev.lower()
    if sev_lower == "critical":
        return IncidentSeverity.CRITICAL
    elif sev_lower == "high":
        return IncidentSeverity.HIGH
    elif sev_lower == "medium":
        return IncidentSeverity.MEDIUM
    return IncidentSeverity.LOW


def _severity_rank(sev: IncidentSeverity) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev.value, 0)
