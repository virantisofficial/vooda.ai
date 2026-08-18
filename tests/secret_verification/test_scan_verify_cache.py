"""Unit tests for the S1 scan-time verification wrapper
(`_verify_with_cache` in apps/worker/tasks.py).

Proves the wrapper that routes scan-time verification through the shared Redis
result-cache + per-provider rate limiter:

* a cache HIT short-circuits — no provider call, no rate-limit token spent;
* a MISS goes through the limiter, calls verify_finding, and caches
  active/inactive verdicts (but NOT error/unsupported);
* it degrades to a plain verify (non-breaking) when the Redis-backed cache /
  limiter raise (e.g. Redis unreachable);
* it skips the cache entirely when there is no secret_hash.

The wrapper lazily imports its infra from the source modules each call, so we
patch the source-module attributes (not a local alias).
"""
from __future__ import annotations

import pytest

import services.secret_verification.verification_cache as vc
import services.secret_verification.rate_limiter as rl
import services.secret_verification.verifier as vf
from services.secret_verification.verifier import VerificationResult
from apps.worker.tasks import _verify_with_cache

SM = {"_raw_value": "ghp_" + "A" * 36, "provider": "github", "detection_method": "regex"}


@pytest.fixture
def calls(monkeypatch):
    rec = {"get": 0, "set": [], "acquire": [], "verify": 0,
           "_cached": None, "_verify_result": None}

    async def fake_get(tid, h):
        rec["get"] += 1
        return rec["_cached"]

    async def fake_set(tid, h, **kw):
        rec["set"].append(kw)
        return True

    async def fake_acquire(provider, **kw):
        rec["acquire"].append(provider)
        return True

    async def fake_verify(sm):
        rec["verify"] += 1
        return rec["_verify_result"]

    monkeypatch.setattr(vc, "get_cached_verification", fake_get)
    monkeypatch.setattr(vc, "set_cached_verification", fake_set)
    monkeypatch.setattr(rl, "acquire", fake_acquire)
    monkeypatch.setattr(vf, "verify_finding", fake_verify)
    return rec


@pytest.mark.asyncio
async def test_cache_hit_skips_provider_and_limiter(calls):
    calls["_cached"] = {"status": "active", "details": "cached", "permissions": "repo"}
    result = await _verify_with_cache(SM, "t1", "h1")
    assert result.status == "active"
    assert result.details == "cached"
    assert calls["verify"] == 0      # provider NOT called
    assert calls["acquire"] == []    # limiter NOT touched
    assert calls["set"] == []        # nothing re-cached on a hit


@pytest.mark.asyncio
async def test_miss_acquires_limit_verifies_and_caches_active(calls):
    calls["_cached"] = None
    calls["_verify_result"] = VerificationResult(
        status="active", details="live", provider="github", permissions="repo")
    result = await _verify_with_cache(SM, "t1", "h1")
    assert result.status == "active"
    assert calls["verify"] == 1
    assert calls["acquire"] == ["github"]
    assert len(calls["set"]) == 1 and calls["set"][0]["status"] == "active"


@pytest.mark.asyncio
async def test_inactive_is_cached(calls):
    calls["_cached"] = None
    calls["_verify_result"] = VerificationResult(
        status="inactive", details="rejected", provider="github")
    result = await _verify_with_cache(SM, "t1", "h1")
    assert result.status == "inactive"
    assert len(calls["set"]) == 1 and calls["set"][0]["status"] == "inactive"


@pytest.mark.asyncio
async def test_error_result_not_cached(calls):
    calls["_cached"] = None
    calls["_verify_result"] = VerificationResult(
        status="error", details="boom", provider="github", transient=True)
    result = await _verify_with_cache(SM, "t1", "h1")
    assert result.status == "error"
    assert calls["set"] == []        # never cache a (possibly transient) error


@pytest.mark.asyncio
async def test_redis_down_still_verifies(calls, monkeypatch):
    # cache lookup + limiter raise (Redis unreachable) → wrapper must still
    # verify and return the live result. This is the non-breaking guarantee.
    async def boom(*a, **k):
        raise RuntimeError("redis down")
    monkeypatch.setattr(vc, "get_cached_verification", boom)
    monkeypatch.setattr(rl, "acquire", boom)
    calls["_verify_result"] = VerificationResult(
        status="active", details="live", provider="github")
    result = await _verify_with_cache(SM, "t1", "h1")
    assert result.status == "active"
    assert calls["verify"] == 1      # degraded to plain verify


@pytest.mark.asyncio
async def test_no_secret_hash_skips_cache_but_verifies(calls):
    calls["_verify_result"] = VerificationResult(
        status="active", details="live", provider="github")
    result = await _verify_with_cache(SM, "t1", "")   # no hash
    assert result.status == "active"
    assert calls["get"] == 0         # cache not consulted without a hash
    assert calls["set"] == []        # not cached without a hash
    assert calls["verify"] == 1
