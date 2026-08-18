"""Shared fixtures for source-scanner adapter tests.

Each adapter test follows the same pattern: stub `httpx.AsyncClient`
to return canned JSON / XML / text responses, then drive the adapter
and assert on the `ScanableContent` items it yields. The fixtures
here let the per-adapter tests stay short and focused on the assertions.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import AsyncMock, patch

import pytest


@dataclass
class FakeResponse:
    """Minimal httpx-compatible response for adapter tests.

    We intentionally don't subclass httpx.Response — instantiating
    that class requires a Request object and adds noise. Adapter code
    only ever touches `.status_code`, `.json()`, `.text`, `.headers`
    so a small dataclass is enough.
    """
    status_code: int = 200
    _json: object = None
    text: str = ""
    headers: dict | None = None

    def json(self):
        # Mirrors httpx behaviour: raises if body wasn't JSON-shaped.
        if self._json is None:
            raise ValueError("FakeResponse has no JSON body")
        return self._json


class _Recorder:
    """Lightweight method recorder so tests can assert on what URLs the
    adapter actually hit. Keeps the test code readable — `assert
    "/rest/api/3/myself" in r.calls.get_urls` instead of inspecting
    Mock call args."""
    def __init__(self):
        self.gets: list[tuple[str, dict]] = []
        self.posts: list[tuple[str, dict]] = []

    def get_urls(self) -> list[str]:
        return [u for u, _ in self.gets]

    def post_urls(self) -> list[str]:
        return [u for u, _ in self.posts]


@pytest.fixture
def http_stub():
    """Yield a function that takes a `route_handler(method, url, **kw)`
    function and patches httpx.AsyncClient so every method routes
    through it. Returns the recorder for assertions.

    The route_handler returns a FakeResponse (or raises) per call.
    Tests express their canned API contract as a small dispatch.
    """
    rec = _Recorder()
    # `patch(...).start()` below replaces httpx.AsyncClient globally and
    # stays in effect until stopped. Leaving that to each test meant any
    # test that forgot left the stub installed for the rest of the
    # session, so every later test doing real HTTP silently got a
    # FakeResponse back. It surfaced as the Azure and GCP contract tests
    # passing alone and failing in the full run with "'FakeResponse'
    # object has no attribute 'raise_for_status'". Track every patcher
    # and unwind on teardown so a forgetful test can only affect itself.
    started: list = []

    def install(handler):
        # Accept arbitrary kwargs because httpx clients pass `timeout`,
        # `follow_redirects`, etc. that we don't care about in tests
        # but the adapters legitimately use.
        async def fake_get(url, **kw):
            rec.gets.append((url, kw))
            return handler("GET", url, **kw)

        async def fake_post(url, **kw):
            rec.posts.append((url, kw))
            return handler("POST", url, **kw)

        client = AsyncMock()
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None
        client.get = fake_get
        client.post = fake_post

        ctor = patch("httpx.AsyncClient", return_value=client)
        ctor.start()
        started.append(ctor)
        return rec, ctor

    yield install

    # Tests that already stop the patcher themselves are fine — a second
    # stop raises RuntimeError, which is not a failure here.
    for ctor in started:
        try:
            ctor.stop()
        except RuntimeError:
            pass
