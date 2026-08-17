"""NotionAdapter — walks the workspace via /search + /blocks/{id}/children.

Test contract:
- /search is paginated via cursor (start_cursor + has_more / next_cursor).
- For each page, /blocks/{page_id}/children is walked one level deep.
- rich_text plain_text values are flattened into scannable content.
- Pages whose last_edited_time <= sync watermark are skipped.
"""
from __future__ import annotations

import pytest

from services.source_scanners.adapters.notion import NotionAdapter
from tests.source_scanners.conftest import FakeResponse


def _handler(method, url, **kw):
    if url.endswith("/v1/search"):
        body = (kw.get("json") or {})
        if body.get("start_cursor") == "page-2":
            return FakeResponse(200, _json={
                "results": [{
                    "id": "p2", "url": "https://notion/p2",
                    "last_edited_time": "2026-04-30T09:00:00Z",
                    "properties": {"Name": {"type": "title", "title": [{"plain_text": "Runbook"}]}},
                }],
                "has_more": False,
                "next_cursor": None,
            })
        return FakeResponse(200, _json={
            "results": [{
                "id": "p1", "url": "https://notion/p1",
                "last_edited_time": "2026-04-30T08:00:00Z",
                "properties": {"title": {"type": "title", "title": [{"plain_text": "Onboarding"}]}},
            }],
            "has_more": True,
            "next_cursor": "page-2",
        })

    if "/blocks/p1/children" in url:
        return FakeResponse(200, _json={
            "results": [
                {"type": "paragraph", "paragraph": {"rich_text": [
                    {"plain_text": "Set DATABASE_URL=postgres://leak:secret@db"},
                ]}},
                {"type": "code", "code": {"rich_text": [
                    {"plain_text": "AWS_KEY=AKIA-FAKE"}
                ]}},
            ],
            "has_more": False,
            "next_cursor": None,
        })
    if "/blocks/p2/children" in url:
        return FakeResponse(200, _json={
            "results": [{"type": "paragraph", "paragraph": {"rich_text": [
                {"plain_text": "newer page content"}
            ]}}],
            "has_more": False,
            "next_cursor": None,
        })
    return FakeResponse(404)


@pytest.mark.asyncio
async def test_notion_paginates_and_flattens_blocks(http_stub):
    http_stub(_handler)
    adapter = NotionAdapter(token="secret_dummy")
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]
    assert "notion://p1" in locators
    assert "notion://p2" in locators

    p1 = next(i for i in items if i.source_locator == "notion://p1")
    assert "DATABASE_URL" in p1.content
    assert "AKIA-FAKE" in p1.content   # code block content surfaced


@pytest.mark.asyncio
async def test_notion_respects_watermark(http_stub):
    http_stub(_handler)
    adapter = NotionAdapter(token="secret_dummy")
    items = [i async for i in adapter.extract_content({"last_sync": "2026-04-30T08:30:00Z"})]
    locators = [i.source_locator for i in items]
    assert "notion://p1" not in locators       # older than watermark, skipped
    assert "notion://p2" in locators           # newer, kept
    # Watermark advances to the latest seen
    assert adapter.get_updated_sync_state()["last_sync"] == "2026-04-30T09:00:00Z"


@pytest.mark.asyncio
async def test_notion_test_connection(http_stub):
    http_stub(_handler)
    adapter = NotionAdapter(token="secret_dummy")
    res = await adapter.test_connection()
    assert res["status"] == "success"
