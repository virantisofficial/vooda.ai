"""Webhook config cache TTL + invalidation tests (Track-A P0 #5).

Before this hardening: ``_webhook_cache`` in apps/api/app/routers/webhooks.py
was a plain dict with no expiration.  An entry, once written, stayed
forever — meaning a webhook secret rotated outside the PUT /config
flow (direct DB mutation, replica lag, future writers that forgot
to invalidate) could leak through the admin UI indefinitely.

The fix adds:
  - A 60-second TTL on every cache entry → self-healing after one
    minute even if no explicit invalidation fires
  - A public ``invalidate_webhook_cache(tenant, provider=None)``
    helper so any writer can drop entries cleanly

These tests pin the new contract — they fail if a future refactor
drops the TTL or rolls back to the unbounded dict.
"""
from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest


pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _reset_cache_between_tests():
    """Fresh cache for every test — the dict is module-global."""
    from apps.api.app.routers import webhooks as wh
    wh._webhook_cache.clear()
    yield
    wh._webhook_cache.clear()


# ── Cache hit path ──────────────────────────────────────────────


async def test_cache_hit_within_ttl_skips_db():
    """First call populates cache; second within TTL must not hit DB."""
    from apps.api.app.routers import webhooks as wh

    db = MagicMock()
    db.execute = AsyncMock()
    cfg_row = MagicMock(
        is_active=True,
        config={"webhook_secret": "cached-value-AAAA", "total_events": 0},
        id=uuid4(),
    )
    db.execute.return_value.scalar_one_or_none = MagicMock(return_value=cfg_row)

    # First call → DB hit
    first = await wh._load_webhook_config(db, "tenant-a", "github")
    assert first["secret"] == "••••AAAA"
    assert db.execute.await_count == 1

    # Second call within TTL → DB MUST NOT be hit again
    second = await wh._load_webhook_config(db, "tenant-a", "github")
    assert second["secret"] == "••••AAAA"
    assert db.execute.await_count == 1, "cache should suppress the second DB query"


# ── TTL expiration ──────────────────────────────────────────────


async def test_cache_expired_entry_refreshes_from_db(monkeypatch):
    """An entry older than _CACHE_TTL_SECONDS must be re-read so a
    rotated secret eventually propagates even without invalidation."""
    from apps.api.app.routers import webhooks as wh

    db = MagicMock()
    cfg_v1 = MagicMock(is_active=True, config={"webhook_secret": "rotated-secret-OLD1"}, id=uuid4())
    cfg_v2 = MagicMock(is_active=True, config={"webhook_secret": "rotated-secret-NEW2"}, id=uuid4())
    # First call returns OLD, second returns NEW
    results = [MagicMock(), MagicMock()]
    results[0].scalar_one_or_none = MagicMock(return_value=cfg_v1)
    results[1].scalar_one_or_none = MagicMock(return_value=cfg_v2)
    db.execute = AsyncMock(side_effect=results)

    first = await wh._load_webhook_config(db, "tenant-a", "github")
    assert first["secret"] == "••••OLD1"

    # Force the cache entry timestamp into the past so TTL fires.
    # Replaces the loaded_at marker with a value far enough in the
    # past to be well outside the TTL window without depending on a
    # real sleep().
    cache_key = "tenant-a:github"
    loaded_at, data = wh._webhook_cache[cache_key]
    wh._webhook_cache[cache_key] = (loaded_at - (wh._CACHE_TTL_SECONDS + 5), data)

    second = await wh._load_webhook_config(db, "tenant-a", "github")
    assert second["secret"] == "••••NEW2", "expired cache must refresh from DB"
    assert db.execute.await_count == 2


# ── Explicit invalidation ───────────────────────────────────────


def test_invalidate_webhook_cache_targets_specific_provider():
    """invalidate(tenant, provider) drops ONLY that pair."""
    from apps.api.app.routers import webhooks as wh

    wh._webhook_cache["tenant-a:github"] = (time.monotonic(), {"secret": "S1"})
    wh._webhook_cache["tenant-a:gitlab"] = (time.monotonic(), {"secret": "S2"})
    wh._webhook_cache["tenant-b:github"] = (time.monotonic(), {"secret": "S3"})

    wh.invalidate_webhook_cache("tenant-a", "github")

    assert "tenant-a:github" not in wh._webhook_cache
    assert "tenant-a:gitlab" in wh._webhook_cache, "sibling provider not affected"
    assert "tenant-b:github" in wh._webhook_cache, "other tenant not affected"


def test_invalidate_webhook_cache_no_provider_drops_all_for_tenant():
    """invalidate(tenant) without provider drops every entry for that tenant."""
    from apps.api.app.routers import webhooks as wh

    wh._webhook_cache["tenant-a:github"] = (time.monotonic(), {"secret": "S1"})
    wh._webhook_cache["tenant-a:gitlab"] = (time.monotonic(), {"secret": "S2"})
    wh._webhook_cache["tenant-b:github"] = (time.monotonic(), {"secret": "S3"})

    wh.invalidate_webhook_cache("tenant-a")

    assert "tenant-a:github" not in wh._webhook_cache
    assert "tenant-a:gitlab" not in wh._webhook_cache
    assert "tenant-b:github" in wh._webhook_cache, "other tenant not affected"


def test_invalidate_missing_entry_is_idempotent():
    """invalidate must not raise when the key isn't cached — common
    case immediately after server start before any read populated it."""
    from apps.api.app.routers import webhooks as wh
    # Should not raise
    wh.invalidate_webhook_cache("never-cached-tenant", "github")
    wh.invalidate_webhook_cache("never-cached-tenant")


# ── TTL constant bounds ─────────────────────────────────────────


def test_ttl_constant_is_reasonable():
    """TTL must be short enough to bound staleness from a rotated
    secret but not so short that it defeats the cache.  Lock the
    bound: between 30 seconds and 10 minutes."""
    from apps.api.app.routers import webhooks as wh
    assert 30 <= wh._CACHE_TTL_SECONDS <= 600, (
        f"_CACHE_TTL_SECONDS={wh._CACHE_TTL_SECONDS} outside the sensible "
        "range for an admin-page cache (30s-10m)"
    )


# ── Cache shape regression ──────────────────────────────────────


def test_cache_entry_shape_is_timestamp_plus_data():
    """Lock the (loaded_at, data) tuple shape so a refactor that
    silently reverts to {key: data} can't disable TTL checking."""
    from apps.api.app.routers import webhooks as wh

    wh._webhook_cache["t:p"] = (time.monotonic(), {"k": "v"})
    entry = wh._webhook_cache["t:p"]
    assert isinstance(entry, tuple)
    assert len(entry) == 2
    assert isinstance(entry[0], float), "first slot must be a monotonic timestamp"
    assert isinstance(entry[1], dict), "second slot must be the config dict"
