# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Canonical severity vocabulary, and the case problem it solves.

Severity had three representations for the same five values:

    normalized_findings.severity   PG enum, stores the NAME  -> 'CRITICAL'
    secret_incidents.severity_max  varchar, stores the value -> 'critical'
    imported_findings.severity     varchar, unconstrained    -> anything

Comparing the first two directly is silently wrong, and lexical
ordering is wrong in a different way ('high' > 'critical'
alphabetically) — which is why ``severity_rank`` exists as a numeric
mirror. The canonical form is the lowercase value; ``normalize`` maps
any casing, any incumbent's spelling, onto it.
"""

import enum
from typing import Optional


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


#: Comparable ordering. Never sort severity lexically.
RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_ALIASES: dict[str, Severity] = {
    "critical": Severity.CRITICAL, "crit": Severity.CRITICAL,
    "blocker": Severity.CRITICAL, "very_high": Severity.CRITICAL,
    "high": Severity.HIGH, "major": Severity.HIGH, "error": Severity.HIGH,
    "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM, "med": Severity.MEDIUM,
    "low": Severity.LOW, "minor": Severity.LOW,
    "info": Severity.INFO, "informational": Severity.INFO,
    "note": Severity.INFO, "none": Severity.INFO, "unknown": Severity.INFO,
}


def normalize(value: Optional[str]) -> Severity:
    """Any casing or incumbent spelling -> the canonical value.

    Unrecognised input becomes INFO rather than raising: an
    uninterpretable severity must not be allowed to masquerade as
    CRITICAL and drown the queue, and it must not crash ingestion of an
    otherwise valid finding.
    """
    if value is None:
        return Severity.INFO
    if isinstance(value, Severity):
        return value
    # Accepts both the PG enum NAME ('CRITICAL') and the value.
    return _ALIASES.get(str(value).strip().lower(), Severity.INFO)


def rank(value: Optional[str]) -> int:
    return RANK[normalize(value)]


def _assert_total() -> None:
    missing = set(Severity) - set(RANK)
    if missing:
        raise RuntimeError(
            f"severity: unranked value(s): {sorted(m.value for m in missing)}"
        )
    for name, sev in _ALIASES.items():
        if not isinstance(sev, Severity):
            raise RuntimeError(f"severity: bad alias {name!r}")
    # Every enum member must be reachable by its own value.
    for sev in Severity:
        if _ALIASES.get(sev.value) is not sev:
            raise RuntimeError(f"severity: {sev.value!r} does not map to itself")


_assert_total()
