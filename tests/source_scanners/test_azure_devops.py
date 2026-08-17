"""AzureDevOpsBoardsAdapter — work item descriptions + comments."""
from __future__ import annotations

import pytest

from services.source_scanners.adapters.azure_devops import AzureDevOpsBoardsAdapter
from tests.source_scanners.conftest import FakeResponse


def _handler(method, url, **kw):
    if "/_apis/wit/workitemtypes" in url:
        return FakeResponse(200, _json={"value": [{"name": "Bug"}, {"name": "Task"}]})
    if url.endswith("/_apis/wit/wiql?api-version=7.0"):
        return FakeResponse(200, _json={"workItems": [{"id": 42}]})
    if "/_apis/wit/workitems?ids=42" in url:
        return FakeResponse(200, _json={"value": [{
            "id": 42,
            "fields": {
                "System.Id": 42,
                "System.WorkItemType": "Bug",
                "System.Title": "DB password leak",
                "System.Description": "<p>the prod password is <b>hunter2-leak</b></p>",
                "System.ChangedDate": "2026-04-30T08:00:00Z",
                "System.AreaPath": "Acme\\Backend",
            },
        }]})
    if "/_apis/wit/workItems/42/comments" in url:
        return FakeResponse(200, _json={"comments": [{
            "id": 100,
            "text": "rotated to letmein456",
            "createdBy": {"displayName": "Bob"},
        }]})
    return FakeResponse(404)


@pytest.mark.asyncio
async def test_ado_yields_title_description_comments(http_stub):
    http_stub(_handler)
    adapter = AzureDevOpsBoardsAdapter(organization="org", project="proj", pat="p")
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]
    assert "azuredevops://org/proj/42/title" in locators
    assert "azuredevops://org/proj/42/description" in locators
    assert "azuredevops://org/proj/42/comment/100" in locators


@pytest.mark.asyncio
async def test_ado_strips_html_in_description(http_stub):
    http_stub(_handler)
    adapter = AzureDevOpsBoardsAdapter(organization="org", project="proj", pat="p")
    items = [i async for i in adapter.extract_content({})]
    desc = next(i for i in items if i.source_locator.endswith("/description"))
    assert "<p>" not in desc.content
    assert "<b>" not in desc.content
    assert "hunter2-leak" in desc.content


@pytest.mark.asyncio
async def test_ado_test_connection(http_stub):
    http_stub(_handler)
    adapter = AzureDevOpsBoardsAdapter(organization="org", project="proj", pat="p")
    res = await adapter.test_connection()
    assert res["status"] == "success"
