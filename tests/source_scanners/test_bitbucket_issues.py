"""BitbucketIssuesAdapter — issue + PR descriptions / comments."""
from __future__ import annotations

import pytest

from services.source_scanners.adapters.bitbucket_issues import BitbucketIssuesAdapter
from tests.source_scanners.conftest import FakeResponse


def _handler(method, url, **kw):
    if url.endswith("/user"):
        return FakeResponse(200, _json={"display_name": "Tester"})
    if "/repositories/acme/api/issues" in url and "/comments" not in url:
        return FakeResponse(200, _json={
            "values": [{
                "id": 1, "title": "Default password leaked",
                "content": {"raw": "the prod password is hunter2-real"},
                "updated_on": "2026-04-30T08:00:00.000Z",
                "reporter": {"display_name": "Alice"},
                "links": {
                    "html": {"href": "https://bitbucket.org/acme/api/issues/1"},
                    "comments": {"href": "https://api.bitbucket.org/2.0/repositories/acme/api/issues/1/comments"},
                },
            }],
            "next": None,
        })
    if "/issues/1/comments" in url:
        return FakeResponse(200, _json={
            "values": [{
                "id": 100, "content": {"raw": "rotated to letmein-456"},
                "user": {"display_name": "Bob"},
                "updated_on": "2026-04-30T08:01:00.000Z",
            }],
            "next": None,
        })
    if "/pullrequests" in url and "/comments" not in url:
        return FakeResponse(200, _json={
            "values": [{
                "id": 5, "title": "PR with hardcoded creds",
                "description": "AWS_KEY=AKIATEST",
                "updated_on": "2026-04-30T08:05:00.000Z",
                "author": {"display_name": "Carol"},
                "links": {
                    "html": {"href": "https://bitbucket.org/acme/api/pull-requests/5"},
                    "comments": {"href": "https://api.bitbucket.org/2.0/repositories/acme/api/pullrequests/5/comments"},
                },
            }],
            "next": None,
        })
    if "/pullrequests/5/comments" in url:
        return FakeResponse(200, _json={"values": [], "next": None})
    return FakeResponse(404)


@pytest.mark.asyncio
async def test_bitbucket_yields_issues_prs_and_comments(http_stub):
    http_stub(_handler)
    adapter = BitbucketIssuesAdapter(
        username="u", app_password="p", repos="acme/api",
    )
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]
    assert "bitbucket://acme/api/issue/1" in locators
    assert "bitbucket://acme/api/issue/1/comment/100" in locators
    assert "bitbucket://acme/api/pull_request/5" in locators


@pytest.mark.asyncio
async def test_bitbucket_skips_prs_when_disabled(http_stub):
    http_stub(_handler)
    adapter = BitbucketIssuesAdapter(
        username="u", app_password="p", repos="acme/api",
        include_pull_requests=False,
    )
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]
    assert not any("/pull_request/" in l for l in locators)
