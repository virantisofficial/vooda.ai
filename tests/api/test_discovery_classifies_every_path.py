"""Discovery must classify what it lists, by whichever route it lists it.

An OpenRouter key listed 458 models and every one came back a
candidate — including 72 asynchronous `:batch` endpoints that cannot
answer a request at all. The classifier was fine; it was never called.

Two faults, stacked, each hiding the other:

  1. The operator pastes the base URL their provider documents, which
     ends in ``/v1``. Discovery asked for ``{base}/v1/models`` — that is
     ``.../v1/v1/models``, a 404. ``openai_compatible_root`` exists for
     exactly this and its docstring says "one rule for both", but only
     the completion path and the cloud-compatible discovery used it.

  2. The 404 fell through to a bare ``/models`` attempt, which answered.
     That fallback built its rows by hand and never applied suitability,
     so discovery looked healthy while silently taking a lesser path —
     no filter, no description, no context window.

A fallback that quietly drops the filter is worse than one that fails,
because nothing downstream can tell the difference. These tests pin
both halves: the URL, and the guarantee that no route returns an
unclassified row.
"""
from __future__ import annotations

import pytest

from apps.api.app.routers.ai_models import _discover_local


class _Resp:
    def __init__(self, status: int, payload: dict | None = None):
        self.status_code = status
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


def _fake_httpx(monkeypatch, routes: dict[str, _Resp], asked: list[str]):
    """Serve only the URLs named; everything else 404s, as a real host would."""
    import httpx

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None):
            asked.append(url)
            return routes.get(url, _Resp(404))

    monkeypatch.setattr(httpx, "AsyncClient", _Client)


#: One asynchronous batch endpoint and one multimodal chat model. Both
#: declare text output; only the first is unusable, and the difference
#: is not visible in the prose.
_PAYLOAD = {
    "data": [
        {
            "id": "vendor/model-x:batch",
            "name": "Model X (batch)",
            "description": "Same underlying model, submitted asynchronously.",
            "architecture": {"output_modalities": ["text"]},
            "context_length": 200000,
        },
        {
            "id": "vendor/model-x",
            "name": "Model X",
            "description": "Accepts text and image input and replies in text.",
            "architecture": {"output_modalities": ["text"]},
            "context_length": 200000,
        },
    ]
}


@pytest.mark.asyncio
async def test_a_documented_base_url_is_not_doubled(monkeypatch):
    asked: list[str] = []
    _fake_httpx(monkeypatch, {
        "https://example.test/api/v1/models": _Resp(200, _PAYLOAD),
    }, asked)

    res = await _discover_local("https://example.test/api/v1", "k", "custom")

    assert res.status == "success", res.message
    assert "https://example.test/api/v1/v1/models" not in asked, asked
    assert "https://example.test/api/v1/models" in asked, asked


@pytest.mark.asyncio
async def test_an_endpoint_without_a_version_segment_still_works(monkeypatch):
    """The normalisation must not break the case that already worked."""
    asked: list[str] = []
    _fake_httpx(monkeypatch, {
        "http://localhost:11434/v1/models": _Resp(200, _PAYLOAD),
    }, asked)

    res = await _discover_local("http://localhost:11434", "", "ollama")
    assert res.status == "success", res.message
    assert len(res.models) == 2


def _assert_classified(res):
    assert res.status == "success", res.message
    assert len(res.models) == 2

    by_id = {m.model_id: m for m in res.models}
    assert all(m.suitability for m in res.models), "a row with no verdict"

    batch = by_id["vendor/model-x:batch"]
    assert batch.suitability != "candidate", (
        "an asynchronous endpoint cannot answer a triage request")

    # Declared text output outranks the word "image" in the prose. A
    # model that reads images and answers in text is a triage model.
    chat = by_id["vendor/model-x"]
    assert chat.suitability == "candidate", chat.suitability_reason


@pytest.mark.asyncio
async def test_the_openai_compatible_route_classifies(monkeypatch):
    asked: list[str] = []
    _fake_httpx(monkeypatch, {
        "https://example.test/api/v1/models": _Resp(200, _PAYLOAD),
    }, asked)
    _assert_classified(
        await _discover_local("https://example.test/api/v1", "k", "custom"))


@pytest.mark.asyncio
async def test_the_bare_fallback_route_classifies(monkeypatch):
    """The route taken when a server offers no versioned listing.

    This is the one that shipped without a verdict on any row.
    """
    asked: list[str] = []
    _fake_httpx(monkeypatch, {
        "https://example.test/api/models": _Resp(200, _PAYLOAD),
    }, asked)
    res = await _discover_local("https://example.test/api", "k", "custom")
    assert "https://example.test/api/v1/models" in asked, (
        "the versioned listing must be tried first")
    _assert_classified(res)
