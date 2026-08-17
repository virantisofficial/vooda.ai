"""BoxAdapter — text-like file extraction."""
from __future__ import annotations

import pytest

from services.source_scanners.adapters.box import BoxAdapter
from tests.source_scanners.conftest import FakeResponse


def _handler(method, url, **kw):
    if url.endswith("/users/me"):
        return FakeResponse(200, _json={"name": "Tester", "login": "test@x.com"})
    if "/folders/0/items" in url:
        return FakeResponse(200, _json={
            "entries": [
                {"id": "f1", "type": "file", "name": "config.env",
                 "extension": "env", "size": 200,
                 "modified_at": "2026-04-30T08:00:00Z"},
                {"id": "f2", "type": "file", "name": "screenshot.png",
                 "extension": "png", "size": 5_000_000,
                 "modified_at": "2026-04-30T08:00:00Z"},
                {"id": "fold1", "type": "folder", "name": "configs"},
            ],
            "total_count": 3,
        })
    if "/folders/fold1/items" in url:
        return FakeResponse(200, _json={
            "entries": [
                {"id": "f3", "type": "file", "name": "prod.yaml",
                 "extension": "yaml", "size": 100,
                 "modified_at": "2026-04-30T08:00:00Z"},
            ],
            "total_count": 1,
        })
    if "/files/f1/content" in url:
        return FakeResponse(200, text="DB_PASSWORD=hunter2-real")
    if "/files/f3/content" in url:
        return FakeResponse(200, text="api_key: AKIATEST")
    return FakeResponse(404)


@pytest.mark.asyncio
async def test_box_yields_text_files_skips_binary(http_stub):
    http_stub(_handler)
    adapter = BoxAdapter(access_token="box_dev_tok")
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]
    assert any("config.env" in l for l in locators)
    assert any("prod.yaml" in l for l in locators)
    # PNG skipped
    assert not any("screenshot.png" in l for l in locators)


@pytest.mark.asyncio
async def test_box_recurses_into_folders(http_stub):
    http_stub(_handler)
    adapter = BoxAdapter(access_token="box_dev_tok")
    items = [i async for i in adapter.extract_content({})]
    nested = next(i for i in items if "prod.yaml" in i.source_locator)
    assert "AKIATEST" in nested.content


@pytest.mark.asyncio
async def test_box_test_connection(http_stub):
    http_stub(_handler)
    adapter = BoxAdapter(access_token="box_dev_tok")
    res = await adapter.test_connection()
    assert res["status"] == "success"
