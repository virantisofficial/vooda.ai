"""SARIF 2.1.0 export contract tests.

Track-A P1.1 (2026-05-22): the export endpoint had ZERO test coverage.
This file is the regression net — it pins the SARIF document shape so
a future refactor cannot silently break the contract that GitHub
Advanced Security / Defender for Cloud / any SARIF consumer relies on.

Tests target the pure ``_build_sarif()`` function extracted from the
router so they don't need a DB session.  Fake findings are simple
namespaces matching ``NormalizedFinding`` duck typing.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Optional

import pytest

from apps.api.app.routers.reports import (
    _build_sarif,
    _SARIF_SEVERITY_MAP,
    SARIF_RESULT_HARD_LIMIT,
)


# ── Fixture helpers ─────────────────────────────────────────────


def _fake_finding(
    *,
    rule_id: str = "VOODA-SEC-AWS-001",
    title: str = "AWS access key in code",
    category: str = "Hardcoded Secret",
    cwe: str = "CWE-798",
    severity: str = "critical",
    file_path: str = "src/config.py",
    line_start: int = 42,
    classification: str = "needs_review",
    ai_confidence: Optional[float] = 0.85,
):
    """Build a minimal SimpleNamespace that quacks like a NormalizedFinding
    for ``_build_sarif()``'s purposes.  Only the attributes the builder
    reads are populated — keeps the fixture small and the test obvious."""
    return SimpleNamespace(
        scanner_rule_id=rule_id,
        title=title,
        vulnerability_category=category,
        cwe=cwe,
        severity=severity,
        file_path=file_path,
        line_start=line_start,
        classification=classification,
        ai_confidence=ai_confidence,
    )


# ── Schema-level invariants ─────────────────────────────────────


def test_empty_findings_still_produces_valid_sarif():
    """An export with no findings must still be a valid SARIF document
    — GHAS rejects malformed SARIF, so we must produce schema-valid
    output even on empty result sets."""
    sarif = _build_sarif([])
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].startswith("https://")
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    assert isinstance(sarif["runs"], list)
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Vooda AI Security Engine"


def test_top_level_required_fields_present():
    """SARIF 2.1.0 §3 requires version + $schema + runs."""
    sarif = _build_sarif([_fake_finding()])
    assert "version" in sarif
    assert "$schema" in sarif
    assert "runs" in sarif
    # runs is non-empty exactly when we add one (we always add one)
    assert len(sarif["runs"]) == 1
    assert "tool" in sarif["runs"][0]
    assert "results" in sarif["runs"][0]


def test_tool_driver_required_fields():
    """SARIF 2.1.0 §3.18.1 — toolComponent.name is required."""
    sarif = _build_sarif([_fake_finding()])
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"]
    assert driver["organization"] == "Vooda AI"
    assert "informationUri" in driver
    assert "rules" in driver  # populated from findings


# ── Result construction ─────────────────────────────────────────


def test_single_finding_produces_one_result():
    sarif = _build_sarif([_fake_finding()])
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "VOODA-SEC-AWS-001"
    assert r["message"]["text"] == "AWS access key in code"
    assert r["level"] == "error"  # critical → error
    assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/config.py"
    assert r["locations"][0]["physicalLocation"]["region"]["startLine"] == 42


def test_multiple_findings_dedupe_rules():
    """Two findings with the same rule_id must produce one rule
    definition (in tool.driver.rules) but two result entries."""
    f1 = _fake_finding(rule_id="VOODA-SEC-AWS-001", file_path="a.py")
    f2 = _fake_finding(rule_id="VOODA-SEC-AWS-001", file_path="b.py")
    f3 = _fake_finding(rule_id="VOODA-SEC-GITHUB-001", file_path="c.py")
    sarif = _build_sarif([f1, f2, f3])
    assert len(sarif["runs"][0]["results"]) == 3
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"VOODA-SEC-AWS-001", "VOODA-SEC-GITHUB-001"}


def test_missing_rule_id_falls_back_to_unknown():
    """Findings from custom detectors or legacy imports may have
    scanner_rule_id=None.  Must not crash — fall back to 'unknown'."""
    f = _fake_finding(rule_id=None)
    sarif = _build_sarif([f])
    assert sarif["runs"][0]["results"][0]["ruleId"] == "unknown"
    assert any(r["id"] == "unknown" for r in sarif["runs"][0]["tool"]["driver"]["rules"])


def test_missing_line_start_falls_back_to_one():
    """SARIF region.startLine must be ≥ 1.  Findings without a line
    number (e.g. binary-blob detections) must coerce to 1 rather than
    emit 0 / None."""
    f = _fake_finding(line_start=None)
    sarif = _build_sarif([f])
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


# ── Severity mapping ────────────────────────────────────────────


@pytest.mark.parametrize("vooda_sev,sarif_level", [
    ("critical", "error"),
    ("high",     "error"),
    ("medium",   "warning"),
    ("low",      "note"),
    ("info",     "none"),
])
def test_severity_maps_correctly(vooda_sev, sarif_level):
    """The Vooda → SARIF severity mapping is part of the public
    contract — GHAS uses level= to colour findings.  Locked here."""
    f = _fake_finding(severity=vooda_sev)
    sarif = _build_sarif([f])
    assert sarif["runs"][0]["results"][0]["level"] == sarif_level


def test_unknown_severity_falls_back_to_warning():
    """Defensive: an unrecognised severity (DB drift, custom detector,
    typo) must not produce invalid SARIF.  Warning is the safe default."""
    f = _fake_finding(severity="nonsense")
    sarif = _build_sarif([f])
    assert sarif["runs"][0]["results"][0]["level"] == "warning"


def test_severity_map_constant_is_complete():
    """Guard against the map drifting out of sync with the
    Severity enum.  Every value the schema accepts MUST appear."""
    expected = {"critical", "high", "medium", "low", "info"}
    assert set(_SARIF_SEVERITY_MAP.keys()) == expected
    assert set(_SARIF_SEVERITY_MAP.values()) <= {"error", "warning", "note", "none"}


# ── Vooda custom properties ─────────────────────────────────────


def test_vooda_properties_carry_classification_and_confidence():
    """We attach our own metadata under result.properties for any
    downstream tool that respects vendor extensions.  Locked because
    customers' own triage tooling may parse these."""
    f = _fake_finding(classification="confirmed_true_positive", ai_confidence=0.92)
    sarif = _build_sarif([f])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["vooda_classification"] == "confirmed_true_positive"
    assert props["vooda_confidence"] == 0.92


def test_cwe_appears_in_rule_tags():
    """The rule.properties.tags array carries the CWE so SARIF
    consumers that surface tags (GHAS Security Alerts UI) display the
    weakness category."""
    f = _fake_finding(cwe="CWE-798")
    sarif = _build_sarif([f])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "CWE-798" in rule["properties"]["tags"]


def test_missing_cwe_omits_tags():
    """When a finding has no CWE, the rule entry should NOT have an
    empty tags array — keeps the SARIF clean."""
    f = _fake_finding(cwe=None)
    sarif = _build_sarif([f])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "properties" not in rule  # absent rather than {"tags": []}


# ── Truncation behaviour ────────────────────────────────────────


def test_no_truncation_marker_when_under_limit():
    """A small export must NOT include the truncation marker — it
    would mislead consumers into thinking they have partial data."""
    sarif = _build_sarif([_fake_finding()], truncated_at=None)
    assert "invocations" not in sarif["runs"][0]


def test_truncation_marker_present_when_hit():
    """When the caller signals truncation, the SARIF doc must carry
    an explicit marker so consumers can detect partial exports.
    Critical for GitHub Advanced Security workflows where a silent
    truncation looks like a successful clean scan."""
    sarif = _build_sarif([_fake_finding()], truncated_at=25_000)
    invocations = sarif["runs"][0]["invocations"]
    assert len(invocations) == 1
    props = invocations[0]["properties"]
    assert props["vooda_truncated_at"] == 25_000
    assert "GitHub Advanced Security" in props["vooda_truncation_notice"]
    assert "filter by" in props["vooda_truncation_notice"].lower()


def test_hard_limit_constant_matches_ghas_ceiling():
    """SARIF_RESULT_HARD_LIMIT = 25_000 — matches GHAS upload ceiling.
    Pinned to catch accidental drift."""
    assert SARIF_RESULT_HARD_LIMIT == 25_000


# ── Schema regression ─────────────────────────────────────────


def test_schema_url_is_oasis_sarif_210():
    """The schema URL must reference the actual SARIF 2.1.0 spec —
    GHAS validates this string."""
    sarif = _build_sarif([])
    assert sarif["$schema"] == (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
        "Schemata/sarif-schema-2.1.0.json"
    )


def test_version_is_exactly_210_string():
    sarif = _build_sarif([])
    assert sarif["version"] == "2.1.0"


def test_full_sarif_is_json_serialisable():
    """End-to-end: the produced dict must round-trip through json.dumps
    without raising — catches any non-JSON-serialisable type sneaking
    into the document."""
    import json
    f = _fake_finding(ai_confidence=None)  # None handling
    sarif = _build_sarif([f], truncated_at=25_000)
    encoded = json.dumps(sarif)
    assert "vooda-findings" not in encoded or "VOODA-SEC" in encoded  # sanity
    # Round-trip
    assert json.loads(encoded) == sarif


def test_locations_array_always_non_empty():
    """SARIF §3.27.12 — locations should be present and non-empty
    for any result we emit (we always have file_path + line)."""
    sarif = _build_sarif([_fake_finding()])
    locs = sarif["runs"][0]["results"][0]["locations"]
    assert len(locs) >= 1
    assert "physicalLocation" in locs[0]
    assert locs[0]["physicalLocation"]["artifactLocation"]["uri"]
