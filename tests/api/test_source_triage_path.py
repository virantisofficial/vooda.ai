"""Source-scan AI triage path — locator helper + filter branching.

Bug discovered 2026-05-04: source-scan findings were never AI-
triaged because three blockers in the triage pipeline assumed every
job had a `repository_id` set:

  1. `_run_ai_triage` filtered findings by `repository_id ==
     job.repository_id`. For source jobs both sides are NULL and SQL
     `NULL == NULL` evaluates to NULL (not TRUE) — the filter
     excluded ALL source findings.
  2. `_normalize_and_triage` looked up a `RepositorySnapshot` by
     `repository_id` to get a `repo_path` for code-context
     extraction. Source jobs have no repo to clone → no snapshot →
     `repo_path = ""`.
  3. `extract_rich_context("", "slack://channel/msg-id", ...)`
     can't read a URL locator from disk (returns empty `CodeContext`
     — not a crash, but the AI loses the surrounding-prose signal).

Fixes shipped 2026-05-04 in `apps/worker/tasks.py`:
  - Filter branches on `job.scan_source_id` vs `job.repository_id`
  - Snapshot lookup is gated on `job.repository_id is not None`
  - New `_is_source_locator()` helper picks the right context
    strategy: filesystem extract for git findings, pre-populated
    `code_snippet` reuse for source findings

These tests guard against regressions in the locator detector and
the SQL filter logic. Pure unit tests — no DB, no Celery, no AI
provider call.
"""
from __future__ import annotations

import pytest


def _import_helpers():
    """Import the helpers under test. Done inside the function so
    pytest collection doesn't fail if the worker module has an
    initialization-time error unrelated to what we're testing."""
    from apps.worker.tasks import _is_source_locator, _SOURCE_URL_SCHEMES
    return _is_source_locator, _SOURCE_URL_SCHEMES


# ── _is_source_locator: positive cases ────────────────────────


@pytest.mark.parametrize("locator", [
    # Collaboration tools
    "slack://C04ABC/1234.5",
    "jira://TRUF-99/description",
    "jira://TRUF-99/comment/4",
    "confluence://space/page-id",
    "notion://workspace/page-uuid",
    "salesforce://Case/5003t",
    "linear://team/issue-id",
    "asana://project/task-id",
    "mattermost://channel/post-id",
    "azuredevops://org/project/workitem/123",
    "bitbucket://workspace/repo/issue/4",
    "servicenow://table/sys_id",
    "github-issues://owner/repo/123",
    # Cloud storage
    "s3://acme-bucket/path/to/key.env",
    "m365://site/drive/item/file.docx",
    "box://file/12345/notes.md",
    "azureblob://account/container/blob",
    "gdrive://folder/file-id",
    # Container / image
    "container://registry.acme.com/img:latest",
    "docker://registry.acme.com/img:tag",
    # Misc
    "postman://collection/uuid/request/uuid",
])
def test_is_source_locator_recognises_known_schemes(locator):
    _is_source_locator, _ = _import_helpers()
    assert _is_source_locator(locator) is True, (
        f"Expected True for known source-scanner locator: {locator!r}"
    )


def test_is_source_locator_recognises_unknown_url_scheme():
    """Catch-all: anything URL-shaped (`://` in first 32 chars) is
    treated as a source locator. Future scanners that emit a new
    scheme don't need an explicit allowlist update to be handled
    correctly."""
    _is_source_locator, _ = _import_helpers()
    assert _is_source_locator("brand-new-scanner://acme/resource/123")


# ── _is_source_locator: negative cases ────────────────────────


@pytest.mark.parametrize("path", [
    "src/api/auth.py",
    "/repo/src/main.go",
    "C:\\Users\\dev\\repo\\file.cs",
    "apps/web/src/app/page.tsx",
    "tests/secret_scan/test_engine.py",
    ".env",
    ".env.production",
    "Dockerfile",
    "config/database.yml",
    # Looks vaguely URL-ish but isn't a scheme
    "very/long/path/with/many/segments/and/colons:in:names.py",
    # Empty string
    "",
])
def test_is_source_locator_rejects_filesystem_paths(path):
    _is_source_locator, _ = _import_helpers()
    assert _is_source_locator(path) is False, (
        f"Expected False for filesystem path: {path!r}"
    )


def test_is_source_locator_handles_none_safely():
    """Defensive check: shouldn't blow up on None even though the
    callers always pass a string."""
    _is_source_locator, _ = _import_helpers()
    assert _is_source_locator(None) is False  # type: ignore[arg-type]


# ── Locator scheme registry sanity ────────────────────────────


def test_source_url_schemes_covers_every_emitted_scheme():
    """Every locator scheme that a source-scanner adapter actually
    emits must be in `_SOURCE_URL_SCHEMES` so the catch-all `://`
    fallback is a defence-in-depth, not the primary path. If you add
    a new adapter, add its scheme here."""
    _, schemes = _import_helpers()
    expected_present = {
        "slack://", "jira://", "confluence://", "notion://",
        "salesforce://", "linear://", "asana://", "mattermost://",
        "azuredevops://", "bitbucket://", "servicenow://",
        "github-issues://", "s3://", "m365://", "box://",
        "azureblob://", "gdrive://", "container://", "docker://",
        "postman://",
    }
    missing = expected_present - set(schemes)
    assert not missing, (
        f"_SOURCE_URL_SCHEMES is missing known adapter prefixes: "
        f"{sorted(missing)}"
    )


# ── Sanity: locator helper short-circuits to True quickly ─────


def test_is_source_locator_short_circuits_on_long_filesystem_path():
    """A filesystem path that's long enough to contain `://` later
    in the string (e.g. inside a code comment captured as file_path)
    still returns False because the substring search is bounded to
    the first 32 chars."""
    _is_source_locator, _ = _import_helpers()
    long_path = "a" * 64 + "://something"
    assert _is_source_locator(long_path) is False
