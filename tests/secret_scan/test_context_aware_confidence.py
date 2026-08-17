"""Per-surface detector targeting + per-context confidence.

Two related mechanisms tested here:

  1. SecretRule.confidence_by_context — per-context confidence
     override on a single rule. Still works as a feature; the
     library doesn't currently use it (we use separate code-vs-
     collab rules instead — cleaner architecture), but the field
     stays for future use cases.

  2. SecretRule.surface_targeting + surface_excluded — let a rule
     opt in or out of specific content_type surfaces. THIS is what
     the GEN-* rules now use to split CODE vs COLLAB cleanly.

  3. End-to-end: hardcoded password in Jira description content
     fires VOODA-SEC-GEN-003-COLLAB at the right confidence; same
     content in source code (no content_type) fires the strict
     code-side rule instead.
"""
from __future__ import annotations

import pytest

from services.secret_scan.detectors.base import SecretRule
from services.secret_scan.engine import SecretScanner


# ── Unit: SecretRule.confidence_for ────────────────────────────────


def test_confidence_for_returns_default_when_no_override():
    rule = SecretRule(
        rule_id="TEST-1", title="t", secret_type="t",
        severity="high", pattern="x", confidence=0.4,
    )
    assert rule.confidence_for(None) == 0.4
    assert rule.confidence_for("message") == 0.4
    assert rule.confidence_for("anything") == 0.4


def test_confidence_for_returns_override_when_matched():
    rule = SecretRule(
        rule_id="TEST-2", title="t", secret_type="t",
        severity="high", pattern="x", confidence=0.3,
        confidence_by_context={"message": 0.7, "page": 0.65},
    )
    assert rule.confidence_for("message") == 0.7
    assert rule.confidence_for("page") == 0.65
    # Unknown content_type falls through to default
    assert rule.confidence_for("env_var") == 0.3
    assert rule.confidence_for(None) == 0.3


# ── Unit: SecretRule.applies_to_surface ────────────────────────────


def test_applies_to_surface_no_targeting_runs_everywhere():
    rule = SecretRule(rule_id="t", title="t", secret_type="t",
                      severity="high", pattern="x")
    assert rule.applies_to_surface(None) is True
    assert rule.applies_to_surface("message") is True
    assert rule.applies_to_surface("file") is True


def test_applies_to_surface_targeting_only_runs_on_listed():
    rule = SecretRule(rule_id="t", title="t", secret_type="t",
                      severity="high", pattern="x",
                      surface_targeting=["message", "page"])
    assert rule.applies_to_surface("message") is True
    assert rule.applies_to_surface("page") is True
    assert rule.applies_to_surface("file") is False
    assert rule.applies_to_surface(None) is False, (
        "surface_targeting without None in the list MUST exclude the "
        "git-scan path — otherwise a collab-only rule would also "
        "fire on every code scan."
    )


def test_applies_to_surface_excluded_skips_listed():
    rule = SecretRule(rule_id="t", title="t", secret_type="t",
                      severity="high", pattern="x",
                      surface_excluded=["message", "page"])
    assert rule.applies_to_surface("message") is False
    assert rule.applies_to_surface("page") is False
    assert rule.applies_to_surface("file") is True
    assert rule.applies_to_surface(None) is True, (
        "surface_excluded must NOT block the git-scan path — code "
        "rules still need to run there."
    )


# ── Engine: scan_file routes to the right rule per surface ────────


def test_scan_file_default_signature_unchanged():
    """Backward compat — every existing call site that doesn't pass
    content_type keeps behaving identically. GEN-003 (the strict
    code rule) still fires on .py file scans."""
    scanner = SecretScanner()
    findings = scanner.scan_file("test.py", 'PASSWORD = "longerpassword123"')
    pw_finding = next((f for f in findings if f.rule_id == "VOODA-SEC-GEN-003"), None)
    assert pw_finding is not None, "GEN-003 should still match in source-code mode"
    assert pw_finding.confidence <= 0.4, (
        f"Expected GEN-003 confidence near default 0.30 in source-code mode, got {pw_finding.confidence}"
    )


def test_scan_file_collab_routes_to_collab_rule():
    """The TRUF-5 motivation case: hardcoded password in a Jira
    description fires the COLLAB variant (relaxed quoting + collab-
    tuned confidence), not the strict code variant."""
    scanner = SecretScanner()
    findings = scanner.scan_file(
        "jira://TRUF-99/description",
        'the prod DB password = "hunter2-real-leak"',
        content_type="page",
    )
    rule_ids = {f.rule_id for f in findings}
    # Strict code-side rule must NOT fire (excluded from collab)
    assert "VOODA-SEC-GEN-003" not in rule_ids
    # Collab rule must fire
    assert "VOODA-SEC-GEN-003-COLLAB" in rule_ids
    collab = next(f for f in findings if f.rule_id == "VOODA-SEC-GEN-003-COLLAB")
    assert collab.confidence >= 0.55


def test_scan_file_collab_handles_unquoted_password():
    """The original Slack defect: `password=hdgshui@sn12` in chat,
    no quotes, must fire the COLLAB rule."""
    scanner = SecretScanner()
    findings = scanner.scan_file(
        "slack://C04ABC/1234.5",
        "the prod password=hdgshui@sn12 fyi",
        content_type="message",
    )
    rule_ids = {f.rule_id for f in findings}
    assert "VOODA-SEC-GEN-003-COLLAB" in rule_ids


def test_scan_file_message_context_routes_api_key_to_collab():
    """API key in a Slack message: COLLAB rule, not the code rule."""
    scanner = SecretScanner()
    findings = scanner.scan_file(
        "slack://C04ABC/123",
        'api_key = "abcdefghijklmnopqrst123456"',
        content_type="message",
    )
    rule_ids = {f.rule_id for f in findings}
    assert "VOODA-SEC-GEN-001" not in rule_ids, (
        "Code-side GEN-001 should be excluded on collab content."
    )
    assert "VOODA-SEC-GEN-001-COLLAB" in rule_ids


# ── Cross-cutting smoke: existing rules still register / fire ──────


def test_no_existing_rules_broken_by_field_addition():
    """Adding the new optional fields must not break any existing
    detector module loading or rule construction."""
    from services.secret_scan.detectors.registry import get_all_rules
    rules = get_all_rules()
    assert len(rules) > 800, "Sanity: detector library still loads ~880 rules"
    # Spot-check a few canonical rules still resolve confidence sanely.
    for rid in ("VOODA-SEC-AWS-001", "VOODA-SEC-GEN-003", "VOODA-SEC-ARTIFACTORY-001"):
        rule = next(r for r in rules if r.rule_id == rid)
        assert 0.0 <= rule.confidence_for(None) <= 1.0
        # Each rule should still have a sensible applies_to_surface
        # answer for every common content_type — non-targeted rules
        # default to True for None (git scan) which is the contract
        # the git path relies on.
        assert rule.applies_to_surface(None) is True
