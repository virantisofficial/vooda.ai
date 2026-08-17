"""ServiceNowAdapter — incident / change_request / sc_request tables.

Test contract:
- Iterates the configured tables.
- Pulls short_description / description / work_notes / comments per row.
- Emits one ScanableContent per (row, field) so locators uniquely point.
- Watermarks tracked per-table.
"""
from __future__ import annotations

import pytest

from services.source_scanners.adapters.servicenow import ServiceNowAdapter
from tests.source_scanners.conftest import FakeResponse


def _handler(method, url, **kw):
    if "/api/now/table/incident" in url:
        return FakeResponse(200, _json={"result": [{
            "sys_id": "abc-123", "number": "INC0001",
            "short_description": "DB password leaked in pager email",
            "description": "the prod DB password is hunter2-leaky",
            "work_notes": "rotated; old key was admin/admin",
            "comments": "",
            "sys_updated_on": "2026-04-30 08:00:00",
        }]})
    if "/api/now/table/change_request" in url:
        return FakeResponse(200, _json={"result": []})
    if "/api/now/table/sc_request" in url:
        return FakeResponse(200, _json={"result": []})
    if "/api/now/table/sys_user_group" in url:
        return FakeResponse(200, _json={"result": [{"sys_id": "gid", "name": "L1"}]})
    return FakeResponse(404)


@pytest.mark.asyncio
async def test_servicenow_yields_per_field_items(http_stub):
    http_stub(_handler)
    adapter = ServiceNowAdapter(
        instance_url="https://acme.service-now.com",
        username="u", password="p",
    )
    items = [i async for i in adapter.extract_content({})]
    locators = sorted(i.source_locator for i in items)

    # One yield per non-empty (row, field). Empty `comments` is skipped.
    assert "servicenow://incident/INC0001/short_description" in locators
    assert "servicenow://incident/INC0001/description" in locators
    assert "servicenow://incident/INC0001/work_notes" in locators
    assert "servicenow://incident/INC0001/comments" not in locators


@pytest.mark.asyncio
async def test_servicenow_watermark_per_table(http_stub):
    http_stub(_handler)
    adapter = ServiceNowAdapter(
        instance_url="https://acme.service-now.com",
        username="u", password="p",
    )
    async for _ in adapter.extract_content({}):
        pass
    state = adapter.get_updated_sync_state()
    assert state["table_watermarks"]["incident"] == "2026-04-30 08:00:00"
    # change_request + sc_request had no rows so they don't get a stamp
    assert "change_request" not in state["table_watermarks"]


@pytest.mark.asyncio
async def test_servicenow_test_connection(http_stub):
    http_stub(_handler)
    adapter = ServiceNowAdapter(
        instance_url="https://acme.service-now.com",
        username="u", password="p",
    )
    res = await adapter.test_connection()
    assert res["status"] == "success"
