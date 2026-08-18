"""MattermostAdapter — channel posts, skipping DMs + system messages."""
from __future__ import annotations

import pytest

from services.source_scanners.adapters.mattermost import MattermostAdapter
from tests.source_scanners.conftest import FakeResponse


def _handler(method, url, **kw):
    if url.endswith("/api/v4/users/me"):
        return FakeResponse(200, _json={"username": "tester"})
    if "/api/v4/teams" in url and "/channels" not in url:
        return FakeResponse(200, _json=[{"id": "t1", "name": "engineering",
                                         "display_name": "Engineering"}])
    if "/api/v4/teams/t1/channels" in url:
        return FakeResponse(200, _json=[
            {"id": "c-pub", "name": "general", "type": "O"},
            {"id": "c-dm", "name": "alice__bob", "type": "D"},
        ])
    if "/channels/c-pub/posts" in url:
        return FakeResponse(200, _json={
            "order": ["p1", "p2"],
            "posts": {
                "p1": {"id": "p1", "message": "the prod password is hunter2",
                       "user_id": "u1", "create_at": 1714464000000,
                       "update_at": 1714464000000, "type": ""},
                "p2": {"id": "p2", "message": "alice joined the channel",
                       "user_id": "u2", "create_at": 1714464060000,
                       "update_at": 1714464060000, "type": "system_join_channel"},
            },
        })
    if "/channels/c-dm/posts" in url:
        return FakeResponse(200, _json={"order": [], "posts": {}})
    return FakeResponse(404)


@pytest.mark.asyncio
async def test_mattermost_yields_posts_skips_dms_and_system(http_stub):
    http_stub(_handler)
    adapter = MattermostAdapter(site_url="https://chat.example.com", token="pat")
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]
    assert "mattermost://t1/c-pub/p1" in locators
    # System message skipped
    assert not any("/p2" in l for l in locators)
    # DM channel skipped (type=D)
    assert not any("/c-dm/" in l for l in locators)


@pytest.mark.asyncio
async def test_mattermost_test_connection(http_stub):
    http_stub(_handler)
    adapter = MattermostAdapter(site_url="https://chat.example.com", token="pat")
    res = await adapter.test_connection()
    assert res["status"] == "success"
