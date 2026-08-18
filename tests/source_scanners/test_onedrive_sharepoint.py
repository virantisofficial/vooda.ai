"""OneDriveSharePointAdapter — walks SharePoint sites + drives.

Test contract:
- Enumerates sites via /sites?search=*
- For each site, enumerates drives, recursively walks folders.
- Downloads only text-like files (MIME or filename suffix).
- Skips files larger than max_file_size_mb.
- Yields ScanableContent with deep_link_url + filename + size in metadata.
"""
from __future__ import annotations

import pytest

from services.source_scanners.adapters.onedrive_sharepoint import OneDriveSharePointAdapter
from tests.source_scanners.conftest import FakeResponse


def _make_handler():
    def handler(method, url, **kw):
        if "login.microsoftonline.com" in url:
            return FakeResponse(200, _json={"access_token": "tok", "expires_in": 3600})
        if "/sites?search=*" in url:
            return FakeResponse(200, _json={"value": [
                {"id": "site-1", "displayName": "Engineering"}
            ]})
        if "/sites/site-1/drives" in url:
            return FakeResponse(200, _json={"value": [
                {"id": "drive-1", "name": "Documents"}
            ]})
        if "/items/root/children" in url:
            return FakeResponse(200, _json={"value": [
                {"id": "f-text", "name": "config.yaml", "size": 256,
                 "file": {"mimeType": "application/yaml"},
                 "lastModifiedDateTime": "2026-04-30T08:00:00Z",
                 "webUrl": "https://sp/config.yaml"},
                {"id": "f-binary", "name": "logo.png", "size": 5_000_000,
                 "file": {"mimeType": "image/png"},
                 "lastModifiedDateTime": "2026-04-30T08:00:00Z"},
                {"id": "f-too-big", "name": "huge.json", "size": 50 * 1024 * 1024,
                 "file": {"mimeType": "application/json"},
                 "lastModifiedDateTime": "2026-04-30T08:00:00Z"},
                {"id": "subfolder", "name": "configs", "folder": {"childCount": 1}},
            ]})
        if "/items/subfolder/children" in url:
            return FakeResponse(200, _json={"value": [
                {"id": "f-nested", "name": "prod.env", "size": 100,
                 "file": {"mimeType": "text/plain"},
                 "lastModifiedDateTime": "2026-04-30T08:00:00Z",
                 "webUrl": "https://sp/configs/prod.env"},
            ]})
        if "/items/f-text/content" in url:
            return FakeResponse(200, text="api_key: AKIA-leaked-yaml")
        if "/items/f-nested/content" in url:
            return FakeResponse(200, text="DB_PASSWORD=p@ssw0rd")
        # Anything else → not reachable, including the binary/too-big files
        return FakeResponse(404)
    return handler


@pytest.mark.asyncio
async def test_onedrive_yields_text_files_only(http_stub):
    rec, _ctor = http_stub(_make_handler())
    adapter = OneDriveSharePointAdapter(
        tenant_id="t", client_id="c", client_secret="s",
        max_file_size_mb=10,
    )
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]

    # Text files in
    assert any("config.yaml" in l for l in locators)
    assert any("prod.env" in l for l in locators)
    # Binary skipped
    assert not any("logo.png" in l for l in locators)
    # Oversized skipped
    assert not any("huge.json" in l for l in locators)


@pytest.mark.asyncio
async def test_onedrive_recurses_into_folders(http_stub):
    http_stub(_make_handler())
    adapter = OneDriveSharePointAdapter(
        tenant_id="t", client_id="c", client_secret="s",
    )
    items = [i async for i in adapter.extract_content({})]
    nested = next(i for i in items if i.source_locator.endswith("prod.env"))
    assert "DB_PASSWORD" in nested.content
    assert nested.metadata["filename"] == "prod.env"
    assert nested.metadata["mimetype"] == "text/plain"


@pytest.mark.asyncio
async def test_onedrive_carries_deep_link(http_stub):
    http_stub(_make_handler())
    adapter = OneDriveSharePointAdapter(
        tenant_id="t", client_id="c", client_secret="s",
    )
    items = [i async for i in adapter.extract_content({})]
    yaml_item = next(i for i in items if i.source_locator.endswith("config.yaml"))
    assert yaml_item.deep_link_url == "https://sp/config.yaml"
