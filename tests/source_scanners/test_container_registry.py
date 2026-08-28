"""ContainerRegistryAdapter — Docker Registry HTTP API V2.

Test contract:
- /v2/_catalog enumerates repositories.
- /v2/{repo}/tags/list enumerates tags.
- A tag is emitted only once its image CONFIG has been read: manifest →
  config digest → blob. That is where image secrets actually live
  (``ENV DATABASE_URL=...``, build args, labels), so an image whose
  config cannot be fetched has nothing to scan and is skipped.
- Multi-arch manifest lists resolve to their first child manifest.
- max_tags_per_repo caps how many tags per repo are emitted.
- Locator uses the oci:// scheme so downstream dispatch is identifiable.

These tests previously asserted a ``_pending_image_scan`` marker and
expected one item per tag with no manifest or blob fetch. That contract
no longer exists: the adapter reads image config rather than deferring to
a later per-image scan, and the marker appears nowhere in the product.
The stub answered only /v2/, _catalog and tags/list, so every image
config resolved to "" and the adapter emitted nothing at all.

Note the shape of the assertions below. ``all(...)`` over an empty list
is vacuously true, which is precisely how the marker test kept passing
while nothing was being emitted — so every test here asserts a non-empty
result before inspecting it.
"""
from __future__ import annotations

import json

import pytest

from services.source_scanners.adapters.container_registry import ContainerRegistryAdapter
from tests.source_scanners.conftest import FakeResponse


_CONFIG_DIGEST = "sha256:" + "c0" * 32
_CHILD_DIGEST = "sha256:" + "d1" * 32

# What a registry returns for the config blob: the env / labels / history
# a secret scanner actually cares about.
_IMAGE_CONFIG = {
    "architecture": "amd64",
    "config": {
        "Env": ["PATH=/usr/bin", "DATABASE_URL=postgres://u:p@db/app"],
        "Labels": {"org.opencontainers.image.source": "https://github.com/acme/api"},
    },
    "history": [{"created_by": "ENV DATABASE_URL=postgres://u:p@db/app"}],
}


def _handler(method, url, **kw):
    """Canned Registry V2 API, including the manifest → blob chain."""
    if url.endswith("/v2/"):
        return FakeResponse(200, _json={})
    if "/v2/_catalog" in url:
        return FakeResponse(200, _json={"repositories": ["acme/api", "acme/worker"]}, headers={})
    if "/v2/acme/api/tags/list" in url:
        return FakeResponse(200, _json={"tags": ["v1", "v2", "v3", "v4", "v5", "v6", "latest"]})
    if "/v2/acme/worker/tags/list" in url:
        return FakeResponse(200, _json={"tags": ["latest"]})
    if "/manifests/" in url:
        return FakeResponse(200, _json={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": _CONFIG_DIGEST},
            "layers": [],
        })
    if f"/blobs/{_CONFIG_DIGEST}" in url:
        return FakeResponse(200, text=json.dumps(_IMAGE_CONFIG), _json=_IMAGE_CONFIG)
    return FakeResponse(404)


def _multiarch_handler(method, url, **kw):
    """Same registry, but the tag resolves to a manifest LIST."""
    if url.endswith("/v2/"):
        return FakeResponse(200, _json={})
    if "/v2/_catalog" in url:
        return FakeResponse(200, _json={"repositories": ["acme/api"]}, headers={})
    if "/tags/list" in url:
        return FakeResponse(200, _json={"tags": ["latest"]})
    if f"/manifests/{_CHILD_DIGEST}" in url:
        return FakeResponse(200, _json={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": _CONFIG_DIGEST},
        })
    if "/manifests/" in url:
        return FakeResponse(200, _json={
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{"digest": _CHILD_DIGEST, "platform": {"architecture": "amd64"}}],
        })
    if f"/blobs/{_CONFIG_DIGEST}" in url:
        return FakeResponse(200, text=json.dumps(_IMAGE_CONFIG), _json=_IMAGE_CONFIG)
    return FakeResponse(404)


def _adapter(**kw):
    return ContainerRegistryAdapter(
        registry_url="https://r.example.com", username="u", password="p", **kw
    )


@pytest.mark.asyncio
async def test_registry_lists_repos_and_tags(http_stub):
    http_stub(_handler)
    items = [i async for i in _adapter(max_tags_per_repo=5).extract_content({})]

    assert items, "nothing emitted — every image config resolved to empty"
    locators = [i.source_locator for i in items]
    assert any(l.startswith("oci://r.example.com/acme/api:") for l in locators)
    assert any(l.startswith("oci://r.example.com/acme/worker:") for l in locators)


@pytest.mark.asyncio
async def test_registry_caps_tags_per_repo(http_stub):
    http_stub(_handler)
    items = [i async for i in _adapter(max_tags_per_repo=3).extract_content({})]

    api_items = [i for i in items if "acme/api:" in i.source_locator]
    # Only 3 tags despite the registry exposing 7.
    assert len(api_items) == 3


@pytest.mark.asyncio
async def test_emitted_content_is_the_image_config(http_stub):
    """The payload must be the config JSON — that is what carries the
    secrets. An item pointing at an image with no readable config would
    give the scanner nothing to work on."""
    http_stub(_handler)
    items = [i async for i in _adapter(max_tags_per_repo=1).extract_content({})]

    assert items
    for i in items:
        assert i.metadata.get("scanned") == "image_config"
        assert i.metadata.get("repository") in ("acme/api", "acme/worker")
        assert i.metadata.get("tag")
        assert i.source_locator.endswith("#config")
        assert "DATABASE_URL" in i.content, "image env never reached the scanner"


@pytest.mark.asyncio
async def test_multiarch_manifest_list_resolves_to_a_child(http_stub):
    """A manifest list carries no config of its own; without following it
    to a child manifest the image is silently skipped."""
    http_stub(_multiarch_handler)
    items = [i async for i in _adapter(max_tags_per_repo=1).extract_content({})]

    assert items, "manifest list was not resolved to a child manifest"
    assert "DATABASE_URL" in items[0].content


@pytest.mark.asyncio
async def test_image_without_readable_config_is_skipped(http_stub):
    """Best-effort per image: one unreadable blob must not abort the scan,
    and must not emit an item with nothing in it."""

    def handler(method, url, **kw):
        if "/blobs/" in url:
            return FakeResponse(500)
        return _handler(method, url, **kw)

    http_stub(handler)
    items = [i async for i in _adapter(max_tags_per_repo=1).extract_content({})]
    assert items == []


@pytest.mark.asyncio
async def test_registry_test_connection(http_stub):
    http_stub(_handler)
    res = await _adapter().test_connection()
    assert res["status"] == "success"
