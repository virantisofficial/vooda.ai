"""Per-extension content_type routing for cloud-storage adapters.

The contract:
  - Prose extensions (.md, .txt, .rst, .csv, .log, ...) → "page"
    so the COLLAB rules fire on free-form content like
    `the prod password is hunter2-realdeal`.
  - Everything else stays at the caller-provided default (almost
    always "file") so the strict CODE rules handle structured content
    like `secrets.env` / `config.yaml`.

End-to-end tests verify that an actual scan via the engine routes
the right rule cohort per extension.
"""
from __future__ import annotations

import pytest

from services.secret_scan.engine import SecretScanner
from services.source_scanners.file_routing import content_type_for_path


# ── Unit: helper returns the right content_type per extension ─────


@pytest.mark.parametrize("path", [
    "notes.md",
    "deep/nested/runbook.txt",
    "incident_report.rst",
    "data_export.csv",
    "app.log",
    "PRODUCTION.MD",            # case-insensitive
    "/abs/path/to/notes.MARKDOWN",
    "team_handbook.adoc",
    "spec.org",
])
def test_prose_extensions_route_to_page(path):
    assert content_type_for_path(path) == "page"


@pytest.mark.parametrize("path", [
    "secrets.env",
    "config.yaml",
    "config.yml",
    "settings.json",
    "main.py",
    "app.js",
    "Dockerfile",
    "no_extension_file",
    "main.tf",
    "app.toml",
    ".env.production",
])
def test_structured_extensions_keep_default(path):
    assert content_type_for_path(path, default="file") == "file"


def test_default_is_overridable():
    """Caller can pass a non-'file' default when scanning logs etc."""
    assert content_type_for_path("settings.yaml", default="env_var") == "env_var"


# ── End-to-end via SecretScanner.scan_file ─────────────────────────


@pytest.fixture(scope="module")
def scanner() -> SecretScanner:
    return SecretScanner()


def _ids(scanner, path, content, content_type):
    return {f.rule_id for f in scanner.scan_file(path, content, content_type=content_type)}


def test_prose_routing_makes_collab_fire_on_text_file():
    """`notes.txt` in S3 with a free-form password disclosure should
    trigger COLLAB rules under the new routing."""
    scanner = SecretScanner()
    path = "s3://acme/runbooks/oncall_notes.txt"
    content = "during the may incident the prod admin_password=hunter2-leaked-real fyi"
    ct = content_type_for_path(path, default="file")
    assert ct == "page"
    findings = scanner.scan_file(path, content, content_type=ct)
    rule_ids = {f.rule_id for f in findings}
    assert "VOODA-SEC-GEN-003-COLLAB" in rule_ids


def test_structured_routing_keeps_code_rules_firing_on_yaml():
    """`config.yaml` in S3 should stay on content_type='file' so
    structured CODE rules handle it. The COLLAB rules must NOT fire."""
    scanner = SecretScanner()
    path = "s3://acme/configs/app.yaml"
    content = 'database:\n  password: "really-long-yaml-secret-2026"\n'
    ct = content_type_for_path(path, default="file")
    assert ct == "file"
    findings = scanner.scan_file(path, content, content_type=ct)
    rule_ids = {f.rule_id for f in findings}
    # At least one of: structured parser / code-side GEN-003 should fire
    assert any(rid.startswith("VOODA-SEC-STRUCT-") or rid == "VOODA-SEC-GEN-003"
               for rid in rule_ids), (
        f"Structured-file CODE rules should still fire on .yaml; got {rule_ids}"
    )
    # COLLAB rules MUST NOT fire on file content_type
    assert "VOODA-SEC-GEN-003-COLLAB" not in rule_ids


def test_provider_rules_fire_on_either_routing():
    """AWS / GitHub / etc. provider rules are surface-agnostic — they
    fire regardless of whether the file is routed as 'page' or 'file'.
    Verifies the routing change didn't accidentally break provider
    detection on prose files.

    Uses a non-example AWS key: the documented placeholder
    ``AKIAIOSFODNN7EXAMPLE`` is now correctly suppressed by the example-key
    denylist, so it can no longer stand in for a real key in a routing test."""
    scanner = SecretScanner()
    aws_secret = "the prod AWS key is AKIAZX9QWMR7KP2DLY4N — please rotate"
    # Same content as both file (CODE path) and page (COLLAB path)
    file_findings = scanner.scan_file("creds.env", aws_secret, content_type="file")
    page_findings = scanner.scan_file("notes.md", aws_secret, content_type="page")
    file_aws = {f.rule_id for f in file_findings if "AWS" in f.rule_id}
    page_aws = {f.rule_id for f in page_findings if "AWS" in f.rule_id}
    assert file_aws, f"AWS rule should fire on file content_type, got {file_findings}"
    assert page_aws, f"AWS rule should fire on page content_type, got {page_findings}"
    # Same provider rule fires on both — they're surface-agnostic
    assert file_aws == page_aws


# ── Adapter wiring smoke test ─────────────────────────────────────


def test_s3_adapter_imports_routing():
    """Guard against the import being dropped. A missing import would
    NameError at scan time, not pytest-collection time, so a smoke
    import test is the cheap insurance."""
    from services.source_scanners.adapters import s3
    assert hasattr(s3, "content_type_for_path")


def test_box_adapter_imports_routing():
    from services.source_scanners.adapters import box
    assert hasattr(box, "content_type_for_path")


def test_onedrive_adapter_imports_routing():
    from services.source_scanners.adapters import onedrive_sharepoint
    assert hasattr(onedrive_sharepoint, "content_type_for_path")


def test_azure_blob_adapter_imports_routing():
    from services.source_scanners.adapters import azure_blob
    assert hasattr(azure_blob, "content_type_for_path")
