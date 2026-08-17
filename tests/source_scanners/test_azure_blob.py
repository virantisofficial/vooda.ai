"""AzureBlobAdapter — lists containers + blobs, downloads text-like.

Test contract:
- SharedKey HMAC-SHA256 signature is computed (we don't reverse-engineer
  the signature here; we just confirm the adapter sends an Authorization
  header that starts with "SharedKey {account}:").
- Lists containers via /?comp=list.
- Lists blobs per container via /{container}?restype=container&comp=list.
- Downloads only text-like blobs by MIME / filename suffix.
- Skips blobs larger than max_blob_size_mb.
"""
from __future__ import annotations

import base64

import pytest

from services.source_scanners.adapters.azure_blob import AzureBlobAdapter
from tests.source_scanners.conftest import FakeResponse


_LIST_CONTAINERS_XML = """<?xml version="1.0"?>
<EnumerationResults>
  <Containers>
    <Container><Name>configs</Name></Container>
    <Container><Name>archive</Name></Container>
  </Containers>
</EnumerationResults>"""

_LIST_BLOBS_XML = """<?xml version="1.0"?>
<EnumerationResults>
  <Blobs>
    <Blob>
      <Name>app.env</Name>
      <Content-Type>text/plain</Content-Type>
      <Content-Length>200</Content-Length>
      <Last-Modified>Wed, 30 Apr 2026 08:00:00 GMT</Last-Modified>
    </Blob>
    <Blob>
      <Name>screenshot.png</Name>
      <Content-Type>image/png</Content-Type>
      <Content-Length>500000</Content-Length>
      <Last-Modified>Wed, 30 Apr 2026 08:00:00 GMT</Last-Modified>
    </Blob>
    <Blob>
      <Name>too-big.json</Name>
      <Content-Type>application/json</Content-Type>
      <Content-Length>52428800</Content-Length>
      <Last-Modified>Wed, 30 Apr 2026 08:00:00 GMT</Last-Modified>
    </Blob>
  </Blobs>
</EnumerationResults>"""


def _handler(method, url, **kw):
    auth = (kw.get("headers") or {}).get("Authorization", "")
    # Every request must carry SharedKey auth; without this assertion
    # the test still passes when the adapter forgets to sign.
    assert auth.startswith("SharedKey mycorp:"), f"missing/bad auth: {auth}"

    if "?comp=list" in url and "/configs" not in url and "/archive" not in url:
        return FakeResponse(200, text=_LIST_CONTAINERS_XML)
    if "/configs?" in url and "comp=list" in url:
        return FakeResponse(200, text=_LIST_BLOBS_XML)
    if "/archive?" in url and "comp=list" in url:
        return FakeResponse(200, text='<?xml version="1.0"?><EnumerationResults><Blobs></Blobs></EnumerationResults>')
    if url.endswith("/configs/app.env"):
        return FakeResponse(200, text="DB_URL=postgres://leaky:secret@db/prod")
    return FakeResponse(404)


def _key():
    return base64.b64encode(b"k" * 32).decode()


@pytest.mark.asyncio
async def test_azure_blob_skips_binaries_and_oversized(http_stub):
    rec, _ctor = http_stub(_handler)
    adapter = AzureBlobAdapter(
        account_name="mycorp", account_key=_key(), max_blob_size_mb=10,
    )
    items = [i async for i in adapter.extract_content({})]
    locators = [i.source_locator for i in items]

    assert any("app.env" in l for l in locators)
    assert not any("screenshot.png" in l for l in locators)
    assert not any("too-big.json" in l for l in locators)


@pytest.mark.asyncio
async def test_azure_blob_carries_metadata(http_stub):
    http_stub(_handler)
    adapter = AzureBlobAdapter(account_name="mycorp", account_key=_key())
    items = [i async for i in adapter.extract_content({})]
    item = next(i for i in items if "app.env" in i.source_locator)
    assert item.metadata["account"] == "mycorp"
    assert item.metadata["container"] == "configs"
    assert item.metadata["blob_name"] == "app.env"
    assert "DB_URL" in item.content


@pytest.mark.asyncio
async def test_azure_blob_test_connection(http_stub):
    http_stub(_handler)
    adapter = AzureBlobAdapter(account_name="mycorp", account_key=_key())
    res = await adapter.test_connection()
    assert res["status"] == "success"
    # Surface visible-container preview so the customer sees auth worked
    assert "configs" in res["details"]["containers"]
