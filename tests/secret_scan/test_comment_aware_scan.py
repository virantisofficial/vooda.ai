"""Comment-aware code scanning.

Code comments are free-form prose: developers leave the same
`# the prod password is hunter2` shape they'd put in Slack.
The strict CODE rules miss this (no quotes, no `=`-style assignment).

The engine's Phase 4 extracts comments per language, pads them back
to original line numbers, and re-scans with content_type="comment"
so the COLLAB rules fire.
"""
from __future__ import annotations

import pytest

from services.secret_scan.comment_extractor import (
    extract_comments,
    build_virtual_comment_content,
)
from services.secret_scan.engine import SecretScanner


# ── Unit: extract_comments per language ───────────────────────────


def test_extract_python_hash_comments():
    src = (
        "import os\n"
        "# the prod db password is hunter2-realdeal\n"
        "x = 1  # inline comment with secret_key=abc1234567890\n"
        "y = 2\n"
    )
    out = extract_comments(src, "/repo/app.py")
    bodies = {body for _, body in out}
    assert any("hunter2-realdeal" in b for b in bodies)
    assert any("secret_key=abc1234567890" in b for b in bodies)


def test_extract_c_family_line_and_block_comments():
    src = (
        "// the prod admin_password=adminP@ss-2026\n"
        "int main() {\n"
        "  /* legacy api_key=ZmFrZUtleVZhbHVlV2l0aDAxMjM0NTY3ODk=\n"
        "     do not delete */\n"
        "  return 0;\n"
        "}\n"
    )
    out = extract_comments(src, "/repo/main.c")
    bodies = " ".join(b for _, b in out)
    assert "admin_password=adminP@ss-2026" in bodies
    assert "ZmFrZUtleVZhbHVlV2l0aDAxMjM0NTY3ODk=" in bodies


def test_extract_sql_double_dash_comments():
    src = (
        "-- DBA note: the read replica password=ReplicaPwd2026!\n"
        "SELECT * FROM users;\n"
    )
    out = extract_comments(src, "/repo/migration.sql")
    bodies = {body for _, body in out}
    assert any("ReplicaPwd2026" in b for b in bodies)


def test_extract_html_comments():
    src = (
        "<html>\n"
        "  <!-- staging admin_password=StagingP@ss2026 -->\n"
        "  <body></body>\n"
        "</html>\n"
    )
    out = extract_comments(src, "/repo/index.html")
    bodies = {body for _, body in out}
    assert any("StagingP@ss2026" in b for b in bodies)


def test_extract_yaml_hash_comments():
    src = (
        "version: 1\n"
        "# the prod redis password=RedisLeaked2026!\n"
        "redis:\n"
        "  host: localhost\n"
    )
    out = extract_comments(src, "/repo/k8s.yaml")
    bodies = {body for _, body in out}
    assert any("RedisLeaked2026" in b for b in bodies)


def test_extract_unknown_extension_returns_empty():
    src = "anything goes here # password=hunter2\n"
    out = extract_comments(src, "/repo/file.unknown_ext_xyz")
    assert out == []


def test_extract_preserves_line_numbers():
    src = (
        "import os\n"      # line 1
        "x = 1\n"           # line 2
        "# a comment\n"     # line 3
        "y = 2\n"           # line 4
        "# another\n"       # line 5
    )
    out = extract_comments(src, "/repo/app.py")
    line_nums = sorted(ln for ln, _ in out)
    assert line_nums == [3, 5]


# ── Unit: build_virtual_comment_content padding ───────────────────


def test_virtual_content_pads_to_original_line_numbers():
    comments = [(3, "# comment at line 3"), (7, "# comment at line 7")]
    content = build_virtual_comment_content(comments)
    lines = content.split("\n")
    assert lines[2] == "# comment at line 3"   # 0-indexed → line 3
    assert lines[6] == "# comment at line 7"
    # Other lines are empty padding
    assert lines[0] == ""
    assert lines[5] == ""


def test_virtual_content_respects_total_lines_hint():
    comments = [(3, "# c3")]
    content = build_virtual_comment_content(comments, total_lines_hint=10)
    assert len(content.split("\n")) == 10


def test_virtual_content_empty_for_no_comments():
    assert build_virtual_comment_content([]) == ""


# ── End-to-end: engine fires COLLAB rules on comment text ─────────


@pytest.fixture(scope="module")
def scanner() -> SecretScanner:
    return SecretScanner()


def test_engine_detects_password_in_python_comment(scanner):
    """The motivating case: `# the team passphrase=...` in a .py
    file should fire GEN-003-COLLAB via the comment-aware scan even
    though strict GEN-003 misses it (no quotes) and CONFIG_KEY misses
    it (`passphrase` isn't in CONFIG_KEY's allowlist).
    """
    src = (
        "from db import connect\n"
        "# DBA: the team passphrase=correct-horse-battery-staple-prod fyi\n"
        "conn = connect()\n"
    )
    findings = scanner.scan_file("/repo/db_setup.py", src)
    rule_ids = {f.rule_id for f in findings}
    assert "VOODA-SEC-GEN-003-COLLAB" in rule_ids, (
        f"Expected GEN-003-COLLAB to fire on comment text, got {rule_ids}"
    )
    # Verify the finding is tagged with found_in_comment marker
    collab = next(f for f in findings if f.rule_id == "VOODA-SEC-GEN-003-COLLAB")
    assert collab.raw_data.get("found_in_comment") is True


def test_engine_detects_api_key_in_javascript_block_comment(scanner):
    src = (
        "function foo() {\n"
        "  /* the integration_key=int_live_abc123def456ghi789jkl */\n"
        "  return 1;\n"
        "}\n"
    )
    findings = scanner.scan_file("/repo/foo.js", src)
    rule_ids = {f.rule_id for f in findings}
    assert "VOODA-SEC-GEN-001-COLLAB" in rule_ids, (
        f"Expected GEN-001-COLLAB to fire on JS block comment, got {rule_ids}"
    )


def test_engine_does_not_double_fire_provider_rule_on_comment(scanner):
    """An AWS key that lives in a .py comment fires the provider AWS
    rule on the regular pass (provider rules are surface-agnostic). The
    comment re-scan must NOT also report it — the dedup on
    (line, secret_hash) suppresses the duplicate.

    Uses a non-example AWS key on purpose: the documented placeholder
    ``AKIAIOSFODNN7EXAMPLE`` is now correctly suppressed by the example-key
    denylist, so it would no longer exercise the dedup path this test pins."""
    src = (
        "# stash this for the migration: AKIAZX9QWMR7KP2DLY4N\n"
    )
    findings = scanner.scan_file("/repo/notes.py", src)
    aws_findings = [f for f in findings if "AWS" in f.rule_id]
    # Exactly one AWS finding — not double-counted
    assert len(aws_findings) == 1, (
        f"AWS rule double-fired on comment text: {[f.rule_id for f in aws_findings]}"
    )


def test_engine_skips_comment_scan_for_collab_content(scanner):
    """Recursion guard: a Slack message (content_type='message')
    must NOT trigger the comment-aware scan — that would double-fire
    every COLLAB rule."""
    text = "the prod admin_password=hdgshui@sn12 fyi"
    findings = scanner.scan_file(
        "slack://probe", text, content_type="message",
    )
    collab_hits = [f for f in findings if f.rule_id == "VOODA-SEC-GEN-003-COLLAB"]
    assert len(collab_hits) == 1, (
        f"GEN-003-COLLAB double-fired via comment recursion: {[f.line_start for f in collab_hits]}"
    )


def test_engine_reports_comment_finding_at_source_line(scanner):
    """Finding line number should be the line in the original source,
    not a synthetic offset from the comment-only virtual content."""
    src = (
        "import os\n"                                              # 1
        "import sys\n"                                             # 2
        "x = 1\n"                                                  # 3
        "y = 2\n"                                                  # 4
        "# the team passphrase=correct-horse-battery-2026 fyi\n"   # 5  ← here
        "z = 3\n"                                                  # 6
    )
    findings = scanner.scan_file("/repo/app.py", src)
    collab = [f for f in findings if f.rule_id == "VOODA-SEC-GEN-003-COLLAB"]
    assert collab, "GEN-003-COLLAB should fire on line 5"
    assert collab[0].line_start == 5, (
        f"Expected line 5, got line {collab[0].line_start}"
    )


def test_engine_does_not_fire_collab_on_code_lines(scanner):
    """Code lines (not inside comments) should still get the strict
    CODE rules — the comment-aware scan must not leak COLLAB rules
    onto regular code. We use `api_key` (matches GEN-001) rather than
    `api_token` (matches the broader GEN-009 variable-assignment rule)
    so the assertion is unambiguous about which CODE rule fires."""
    src = (
        "def f():\n"
        "    api_key = 'abcdefghijklmnopqrst123456'\n"
        "    return api_key\n"
    )
    findings = scanner.scan_file("/repo/api.py", src)
    rule_ids = {f.rule_id for f in findings}
    # Code-side GEN-001 should fire
    assert "VOODA-SEC-GEN-001" in rule_ids
    # COLLAB variant must NOT fire on code lines
    assert "VOODA-SEC-GEN-001-COLLAB" not in rule_ids


def test_engine_handles_empty_comments_gracefully(scanner):
    """Files with no comments should not crash the comment-scan pass."""
    src = "x = 1\ny = 2\nz = 3\n"
    findings = scanner.scan_file("/repo/no_comments.py", src)
    # No assertion on findings count — just verifying no crash
    assert isinstance(findings, list)
