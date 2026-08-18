"""SalesforceAdapter — Cases + Knowledge + Chatter via SOQL."""
from __future__ import annotations

import pytest

from services.source_scanners.adapters.salesforce import SalesforceAdapter
from tests.source_scanners.conftest import FakeResponse


def _handler(method, url, **kw):
    if url.endswith("/services/oauth2/token"):
        return FakeResponse(200, _json={
            "access_token": "00DTOKEN",
            "instance_url": "https://acme.my.salesforce.com",
        })
    if url.endswith("/limits"):
        return FakeResponse(200, _json={"DailyApiRequests": {"Max": 100000}})
    if "FROM+Case+WHERE" in url:
        return FakeResponse(200, _json={"records": [{
            "Id": "5001x000000abc",
            "CaseNumber": "00001234",
            "Subject": "DB password reset request",
            "Description": "the prod password is hunter2-real",
            "LastModifiedDate": "2026-04-30T08:00:00.000+0000",
        }]})
    if "FROM+CaseComment+WHERE+ParentId" in url:
        return FakeResponse(200, _json={"records": [{
            "Id": "00aXX0000001",
            "CommentBody": "rotated to letmein-456",
            "LastModifiedDate": "2026-04-30T08:01:00.000+0000",
        }]})
    if "FROM+Knowledge__kav" in url:
        return FakeResponse(200, _json={"records": [{
            "Id": "ka00001",
            "Title": "Default credentials",
            "Summary": "default admin/admin for setup",
            "LastModifiedDate": "2026-04-30T08:02:00.000+0000",
        }]})
    if "FROM+FeedItem" in url:
        return FakeResponse(200, _json={"records": [{
            "Id": "0D5xxxx",
            "Body": "anyone have the staging API key?",
            "ParentId": "0011x000000abc",
            "LastModifiedDate": "2026-04-30T08:03:00.000+0000",
        }]})
    return FakeResponse(404)


@pytest.mark.asyncio
async def test_salesforce_yields_cases_knowledge_chatter(http_stub):
    http_stub(_handler)
    adapter = SalesforceAdapter(
        login_url="https://login.salesforce.com",
        client_id="c", client_secret="s",
        username="u", password="p",
    )
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]
    # Case subject + description + comment all yield separate items
    assert "salesforce://Case/00001234/subject" in locators
    assert "salesforce://Case/00001234/description" in locators
    assert any(l.startswith("salesforce://Case/00001234/comment/") for l in locators)
    # Knowledge article + Chatter post
    assert any(l.startswith("salesforce://Knowledge/") for l in locators)
    assert any(l.startswith("salesforce://Chatter/") for l in locators)


@pytest.mark.asyncio
async def test_salesforce_per_object_watermarks(http_stub):
    http_stub(_handler)
    adapter = SalesforceAdapter(
        login_url="https://login.salesforce.com",
        client_id="c", client_secret="s",
        username="u", password="p",
    )
    async for _ in adapter.extract_content({}):
        pass
    state = adapter.get_updated_sync_state()
    wm = state.get("table_watermarks") or {}
    assert wm.get("Case", "") >= "2026-04-30T08:00:00"
    assert wm.get("Knowledge", "") >= "2026-04-30T08:02:00"
    assert wm.get("FeedItem", "") >= "2026-04-30T08:03:00"


@pytest.mark.asyncio
async def test_salesforce_respects_per_surface_toggles(http_stub):
    http_stub(_handler)
    adapter = SalesforceAdapter(
        login_url="https://login.salesforce.com",
        client_id="c", client_secret="s",
        username="u", password="p",
        scan_cases=True, scan_knowledge=False, scan_chatter=False,
    )
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]
    assert any(l.startswith("salesforce://Case/") for l in locators)
    assert not any(l.startswith("salesforce://Knowledge/") for l in locators)
    assert not any(l.startswith("salesforce://Chatter/") for l in locators)


@pytest.mark.asyncio
async def test_salesforce_test_connection(http_stub):
    http_stub(_handler)
    adapter = SalesforceAdapter(
        login_url="https://login.salesforce.com",
        client_id="c", client_secret="s",
        username="u", password="p",
    )
    res = await adapter.test_connection()
    assert res["status"] == "success"
