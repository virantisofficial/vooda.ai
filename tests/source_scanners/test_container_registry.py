"""ContainerRegistryAdapter — Docker Registry HTTP API V2.

Test contract:
- /v2/_catalog enumerates repositories.
- /v2/{repo}/tags/list enumerates tags.
- max_tags_per_repo caps how many tags per repo are emitted.
- Locator uses oci:// scheme so downstream image-scan dispatch is identifiable.
"""
from __future__ import annotations

import pytest

from services.source_scanners.adapters.container_registry import ContainerRegistryAdapter
from tests.source_scanners.conftest import FakeResponse


def _handler(method, url, **kw):
    if url.endswith("/v2/"):
        return FakeResponse(200, _json={})
    if url.endswith("/v2/_catalog?n=100") or url.endswith("/v2/_catalog"):
        return FakeResponse(200, _json={"repositories": ["acme/api", "acme/worker"]}, headers={})
    if "/v2/acme/api/tags/list" in url:
        return FakeResponse(200, _json={"tags": ["v1", "v2", "v3", "v4", "v5", "v6", "latest"]})
    if "/v2/acme/worker/tags/list" in url:
        return FakeResponse(200, _json={"tags": ["latest"]})
    return FakeResponse(404)


@pytest.mark.asyncio
async def test_registry_lists_repos_and_tags(http_stub):
    http_stub(_handler)
    adapter = ContainerRegistryAdapter(
        registry_url="https://r.example.com",
        username="u", password="p", max_tags_per_repo=5,
    )
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]

    assert any(l.startswith("oci://r.example.com/acme/api:") for l in locators)
    assert any(l.startswith("oci://r.example.com/acme/worker:") for l in locators)


@pytest.mark.asyncio
async def test_registry_caps_tags_per_repo(http_stub):
    http_stub(_handler)
    adapter = ContainerRegistryAdapter(
        registry_url="https://r.example.com",
        username="u", password="p", max_tags_per_repo=3,
    )
    items = [i async for i in adapter.extract_content({})]
    api_items = [i for i in items if "acme/api:" in i.source_locator]
    # Only 3 tags despite the registry exposing 7
    assert len(api_items) == 3


@pytest.mark.asyncio
async def test_registry_emits_pending_image_scan_marker(http_stub):
    http_stub(_handler)
    adapter = ContainerRegistryAdapter(
        registry_url="https://r.example.com",
        username="u", password="p", max_tags_per_repo=1,
    )
    items = [i async for i in adapter.extract_content({})]
    # Carries the marker that downstream layer-scanning code uses to
    # decide "this is a registry-emitted image, schedule per-image scan".
    assert all(i.metadata.get("_pending_image_scan") is True for i in items)
    assert all(i.metadata.get("repository") in ("acme/api", "acme/worker") for i in items)


@pytest.mark.asyncio
async def test_registry_test_connection(http_stub):
    http_stub(_handler)
    adapter = ContainerRegistryAdapter(
        registry_url="https://r.example.com",
        username="u", password="p",
    )
    res = await adapter.test_connection()
    assert res["status"] == "success"
