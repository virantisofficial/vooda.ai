"""GitHubIssuesAdapter — issue + PR bodies + comments.

Test contract:
- /repos/{owner}/{repo}/issues paginated via ?page query.
- `since` watermark filters at the server.
- PRs (issue.pull_request truthy) skipped when include_pull_requests=False.
- Each issue's comments_url is followed; comments yielded as separate items.
"""
from __future__ import annotations

import pytest

from services.source_scanners.adapters.github_issues import GitHubIssuesAdapter
from tests.source_scanners.conftest import FakeResponse


def _handler(method, url, **kw):
    if url.endswith("/repos/acme/api/issues"):
        # Page 1, then page 2 = empty
        params = (kw.get("params") or {})
        if params.get("page") == "2":
            return FakeResponse(200, _json=[])
        return FakeResponse(200, _json=[
            {
                "number": 1, "title": "Default password baked in",
                "body": "found admin/admin in prod", "updated_at": "2026-04-30T08:00:00Z",
                "user": {"login": "alice"},
                "html_url": "https://github.com/acme/api/issues/1",
                "comments_url": "https://api.github.com/repos/acme/api/issues/1/comments",
            },
            {
                "number": 2, "title": "PR adding hardcoded key",
                "body": "AWS_KEY=AKIAEXAMPLE", "updated_at": "2026-04-30T08:05:00Z",
                "user": {"login": "bob"},
                "html_url": "https://github.com/acme/api/pull/2",
                "comments_url": "https://api.github.com/repos/acme/api/issues/2/comments",
                "pull_request": {"url": "https://api.github.com/repos/acme/api/pulls/2"},
            },
        ])
    if "/issues/1/comments" in url:
        return FakeResponse(200, _json=[{
            "id": 100, "body": "the password is changeme",
            "user": {"login": "carol"},
            "updated_at": "2026-04-30T08:01:00Z",
            "html_url": "https://github.com/acme/api/issues/1#issuecomment-100",
        }])
    if "/issues/2/comments" in url:
        return FakeResponse(200, _json=[])
    return FakeResponse(404)


@pytest.mark.asyncio
async def test_gh_issues_yields_issues_prs_and_comments(http_stub):
    http_stub(_handler)
    adapter = GitHubIssuesAdapter(token="ghp_dummy", repos="acme/api")
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]

    assert "github://acme/api/issue/1" in locators
    # PR yields under its own kind; comment surfaces too
    assert "github://acme/api/pull_request/2" in locators
    assert "github://acme/api/issue/1/comment/100" in locators


@pytest.mark.asyncio
async def test_gh_issues_skips_prs_when_disabled(http_stub):
    http_stub(_handler)
    adapter = GitHubIssuesAdapter(
        token="ghp_dummy", repos="acme/api", include_pull_requests=False,
    )
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]
    assert not any("/pull_request/" in l for l in locators)
    # Issue 1 still there
    assert "github://acme/api/issue/1" in locators


@pytest.mark.asyncio
async def test_gh_issues_advances_sync_watermark(http_stub):
    http_stub(_handler)
    adapter = GitHubIssuesAdapter(token="ghp_dummy", repos="acme/api")
    async for _ in adapter.extract_content({}):
        pass
    # Latest seen = PR-2's 08:05
    assert adapter.get_updated_sync_state()["last_sync"] == "2026-04-30T08:05:00Z"
