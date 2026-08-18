"""MicrosoftTeamsAdapter — extracts channel messages + replies.

Test contract (the adapter's job, not the scanner's):
- A token request must be made before any Graph call.
- It enumerates teams → channels → messages → replies.
- Private channels are skipped unless include_private=True.
- HTML message bodies are stripped to scannable text.
- Attachment URLs (when configured) are appended to the scanned text.
- Sync watermark advances to the latest message lastModifiedDateTime.

The secret detector itself is out of scope here — adapters yield
raw text; the engine's tests cover whether a given pattern matches.
"""
from __future__ import annotations

import asyncio

import pytest

from services.source_scanners.adapters.teams import MicrosoftTeamsAdapter
from tests.source_scanners.conftest import FakeResponse


@pytest.fixture
def fake_teams_payload():
    return {
        "teams": {"value": [{"id": "team-1", "displayName": "Engineering"}]},
        "channels": {"value": [
            {"id": "ch-public", "displayName": "general", "membershipType": "standard"},
            {"id": "ch-private", "displayName": "leak-channel", "membershipType": "private"},
        ]},
        "messages-public": {"value": [{
            "id": "msg-1",
            "lastModifiedDateTime": "2026-04-30T08:00:00Z",
            "createdDateTime": "2026-04-30T08:00:00Z",
            "from": {"user": {"displayName": "Alice"}},
            "body": {"contentType": "html", "content": "<p>aws_key=<b>AKIAFAKE</b> &amp; rotated</p>"},
            "attachments": [{"contentUrl": "https://onedrive/share?sig=ABC"}],
            "webUrl": "https://teams.example/msg/msg-1",
        }]},
        "replies": {"value": [{
            "id": "reply-1",
            "lastModifiedDateTime": "2026-04-30T08:01:00Z",
            "createdDateTime": "2026-04-30T08:01:00Z",
            "from": {"user": {"displayName": "Bob"}},
            "body": {"contentType": "text", "content": "rotated to aws_key=AKIAROTATED"},
        }]},
    }


def _make_handler(payload):
    """Tiny URL-prefix dispatcher mirroring the Graph endpoints
    the Teams adapter calls."""
    def handler(method, url, **kw):
        if "login.microsoftonline.com" in url:
            return FakeResponse(200, _json={"access_token": "test-token", "expires_in": 3600})
        if url.endswith("/teams"):
            return FakeResponse(200, _json=payload["teams"])
        if "/teams/team-1/channels" in url and "messages" not in url:
            return FakeResponse(200, _json=payload["channels"])
        if "ch-public/messages/msg-1/replies" in url:
            return FakeResponse(200, _json=payload["replies"])
        if "ch-public/messages" in url:
            return FakeResponse(200, _json=payload["messages-public"])
        if "ch-private/messages" in url:
            return FakeResponse(200, _json={"value": []})
        return FakeResponse(404)
    return handler


@pytest.mark.asyncio
async def test_teams_extracts_messages_and_replies(http_stub, fake_teams_payload):
    rec, _ctor = http_stub(_make_handler(fake_teams_payload))
    adapter = MicrosoftTeamsAdapter(
        tenant_id="t", client_id="c", client_secret="s",
        teams="*", include_private=False,
    )
    items = []
    async for item in adapter.extract_content({}):
        items.append(item)

    locators = [i.source_locator for i in items]
    assert "msteams://team-1/ch-public/msg-1" in locators
    assert "msteams://team-1/ch-public/msg-1/reply/reply-1" in locators
    # Private channel skipped by default
    assert not any("ch-private" in l for l in locators)
    # Auth roundtrip happened
    assert any("login.microsoftonline.com" in u for u in rec.post_urls())


@pytest.mark.asyncio
async def test_teams_strips_html_and_appends_attachment_urls(http_stub, fake_teams_payload):
    rec, _ctor = http_stub(_make_handler(fake_teams_payload))
    adapter = MicrosoftTeamsAdapter(
        tenant_id="t", client_id="c", client_secret="s", include_attachment_urls=True,
    )
    items = [i async for i in adapter.extract_content({})]
    msg = next(i for i in items if i.source_locator.endswith("/msg-1"))
    # HTML tags gone
    assert "<p>" not in msg.content and "<b>" not in msg.content
    # Text + entity decoded
    assert "AKIAFAKE" in msg.content
    assert " & rotated" in msg.content   # entity-decoded
    # Attachment URL appended (catches SAS tokens in shared-link params)
    assert "https://onedrive/share?sig=ABC" in msg.content


@pytest.mark.asyncio
async def test_teams_includes_private_when_flag_on(http_stub, fake_teams_payload):
    fake_teams_payload["messages-public"]["value"] = []  # silence the public path
    rec, _ctor = http_stub(_make_handler(fake_teams_payload))
    # Add a message in the private channel for this test
    def handler(method, url, **kw):
        if "ch-private/messages" in url:
            return FakeResponse(200, _json={"value": [{
                "id": "private-msg",
                "lastModifiedDateTime": "2026-04-30T08:05:00Z",
                "createdDateTime": "2026-04-30T08:05:00Z",
                "from": {"user": {"displayName": "Carol"}},
                "body": {"contentType": "text", "content": "private password=hunter2-leaky"},
            }]})
        return _make_handler(fake_teams_payload)(method, url, **kw)
    # Re-stub with the augmented handler
    from unittest.mock import patch as mock_patch, AsyncMock
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    async def fake_get(url, **kw):
        return handler("GET", url, **kw)
    async def fake_post(url, **kw):
        return handler("POST", url, **kw)
    client.get = fake_get
    client.post = fake_post
    with mock_patch("httpx.AsyncClient", return_value=client):
        adapter = MicrosoftTeamsAdapter(
            tenant_id="t", client_id="c", client_secret="s",
            include_private=True,
        )
        items = [i async for i in adapter.extract_content({})]
    assert any(i.source_locator == "msteams://team-1/ch-private/private-msg" for i in items)


@pytest.mark.asyncio
async def test_teams_advances_sync_watermark(http_stub, fake_teams_payload):
    http_stub(_make_handler(fake_teams_payload))
    adapter = MicrosoftTeamsAdapter(tenant_id="t", client_id="c", client_secret="s")
    async for _ in adapter.extract_content({}):
        pass
    # Latest seen timestamp = the reply at 08:01 (newer than the 08:00 message).
    assert adapter.get_updated_sync_state()["last_sync"] == "2026-04-30T08:01:00Z"
