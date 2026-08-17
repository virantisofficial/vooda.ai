"""LinearAdapter — extracts issues + comments via GraphQL."""
from __future__ import annotations

import pytest

from services.source_scanners.adapters.linear import LinearAdapter
from tests.source_scanners.conftest import FakeResponse


def _handler(method, url, **kw):
    if "api.linear.app/graphql" in url:
        body = (kw.get("json") or {})
        if (body.get("query") or "").strip().startswith("query { viewer"):
            return FakeResponse(200, _json={"data": {"viewer": {"id": "u1", "name": "Tester"}}})
        # Issues query
        return FakeResponse(200, _json={"data": {"issues": {
            "pageInfo": {"hasNextPage": False, "endCursor": None},
            "nodes": [{
                "id": "i1", "identifier": "ENG-42",
                "title": "Reset DB password",
                "description": "the prod password is hunter2-real",
                "updatedAt": "2026-04-30T08:00:00Z",
                "url": "https://linear.app/team/issue/ENG-42",
                "team": {"key": "ENG", "name": "Engineering"},
                "creator": {"name": "Alice"},
                "comments": {"nodes": [
                    {"id": "c1", "body": "rotated to letmein456",
                     "updatedAt": "2026-04-30T08:01:00Z",
                     "user": {"name": "Bob"}},
                ]},
            }],
        }}})
    return FakeResponse(404)


@pytest.mark.asyncio
async def test_linear_yields_issue_and_comment(http_stub):
    http_stub(_handler)
    adapter = LinearAdapter(api_key="lin_api_xxx")
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]
    assert "linear://ENG-42/description" in locators
    assert "linear://ENG-42/comment/c1" in locators


@pytest.mark.asyncio
async def test_linear_watermark_advances(http_stub):
    http_stub(_handler)
    adapter = LinearAdapter(api_key="lin_api_xxx")
    async for _ in adapter.extract_content({}):
        pass
    assert adapter.get_updated_sync_state()["last_sync"] == "2026-04-30T08:01:00Z"


@pytest.mark.asyncio
async def test_linear_test_connection(http_stub):
    http_stub(_handler)
    adapter = LinearAdapter(api_key="lin_api_xxx")
    res = await adapter.test_connection()
    assert res["status"] == "success"
