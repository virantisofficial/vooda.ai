"""AsanaAdapter — task notes + story comments."""
from __future__ import annotations

import pytest

from services.source_scanners.adapters.asana import AsanaAdapter
from tests.source_scanners.conftest import FakeResponse


def _handler(method, url, **kw):
    if url.endswith("/users/me"):
        return FakeResponse(200, _json={"data": {"name": "Tester", "gid": "u1"}})
    if url.endswith("/workspaces"):
        return FakeResponse(200, _json={"data": [{"gid": "ws1", "name": "Acme"}]})
    if "/projects" in url and "/tasks" not in url:
        return FakeResponse(200, _json={"data": [{"gid": "p1", "name": "Onboarding"}]})
    if "/projects/p1/tasks" in url:
        return FakeResponse(200, _json={
            "data": [{
                "gid": "t1", "name": "Reset DB password",
                "notes": "the prod password is hunter2-leak",
                "modified_at": "2026-04-30T08:00:00Z",
                "permalink_url": "https://app.asana.com/0/p1/t1",
                "assignee": {"name": "Alice"},
            }],
            "next_page": None,
        })
    if "/tasks/t1/stories" in url:
        return FakeResponse(200, _json={"data": [
            {"gid": "s1", "type": "comment",
             "text": "rotated to letmein-456",
             "created_at": "2026-04-30T08:01:00Z",
             "created_by": {"name": "Bob"}},
            {"gid": "s2", "type": "system", "text": "added a tag"},
        ]})
    return FakeResponse(404)


@pytest.mark.asyncio
async def test_asana_yields_task_notes_and_comments(http_stub):
    http_stub(_handler)
    adapter = AsanaAdapter(token="1/asana_pat")
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]
    assert "asana://ws1/task/t1/notes" in locators
    assert "asana://ws1/task/t1/comment/s1" in locators
    # System "story" stays out
    assert not any("comment/s2" in l for l in locators)


@pytest.mark.asyncio
async def test_asana_test_connection(http_stub):
    http_stub(_handler)
    adapter = AsanaAdapter(token="1/asana_pat")
    res = await adapter.test_connection()
    assert res["status"] == "success"
