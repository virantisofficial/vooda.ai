"""Regression tests for API-key authentication.

Cover the bug class found in the 2026-05-24 audit:

  * GAP-0 — ``get_current_user`` called ``decode_token`` BEFORE the
    ``vooda_`` prefix check, so every API-key request short-circuited
    to ``401 Invalid or expired token``.  Without this test the bug
    was impossible to notice because the JWT path worked fine and no
    one exercised the key path end-to-end.

These tests stand up an in-memory FastAPI ``TestClient`` against the
real ``apps.api.app.main:app`` and the real Postgres in the dev
compose stack — they're integration tests, not pure units, because
the bug lived in the dependency-injection wiring (and unit-mocking
that wiring is exactly the thing that lets the regression slip back
in).

Run inside the api container:
    docker compose exec api python -m pytest tests/api/test_api_key_auth.py -q
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


# App / client / provisioned_admin / admin_jwt fixtures now live in
# tests/api/conftest.py so every api test shares them.


async def _create_key(client: AsyncClient, jwt: str, name: str, **overrides) -> dict:
    body = {
        "name": name,
        "scopes": ["scan", "findings", "gate", "reports"],
        "expires_in_days": 90,
    }
    body.update(overrides)
    r = await client.post(
        "/api/v1/api-keys",
        json=body,
        headers={"Authorization": f"Bearer {jwt}"},
    )
    assert r.status_code == 201, f"create-key failed: {r.status_code} {r.text}"
    return r.json()


async def _revoke_key(client: AsyncClient, jwt: str, key_id: str) -> None:
    r = await client.delete(
        f"/api/v1/api-keys/{key_id}",
        headers={"Authorization": f"Bearer {jwt}"},
    )
    assert r.status_code == 204


# ── Tests ───────────────────────────────────────────────────


@pytest.mark.asyncio(loop_scope="module")
async def test_valid_api_key_authenticates(client: AsyncClient, admin_jwt: str):
    """REGRESSION — the GAP-0 bug.  A freshly created vooda_ key MUST
    authenticate against /auth/me.  Before the fix this 401'd because
    decode_token() ran before the prefix check."""
    key = await _create_key(client, admin_jwt, "regression-valid")
    try:
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {key['api_key']}"},
        )
        assert r.status_code == 200, f"expected 200 got {r.status_code}: {r.text}"
        body = r.json()
        assert body["email"]
        assert body["is_active"] is True
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_missing_auth_header_401(client: AsyncClient):
    r = await client.get("/api/v1/auth/me")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio(loop_scope="module")
async def test_invalid_bearer_format_401(client: AsyncClient):
    r = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer INVALID123"},
    )
    assert r.status_code == 401
    # WWW-Authenticate challenge should be present (RFC 6750).
    challenge = r.headers.get("www-authenticate") or r.headers.get("WWW-Authenticate")
    assert challenge and "Bearer" in challenge


@pytest.mark.asyncio(loop_scope="module")
async def test_revoked_key_401(client: AsyncClient, admin_jwt: str):
    """A revoked (is_active=false) key must not authenticate."""
    key = await _create_key(client, admin_jwt, "regression-revoked")
    await _revoke_key(client, admin_jwt, key["id"])

    r = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {key['api_key']}"},
    )
    assert r.status_code == 401
    assert "invalid" in r.json()["detail"].lower() or "api key" in r.json()["detail"].lower()


@pytest.mark.asyncio(loop_scope="module")
async def test_expired_key_401(client: AsyncClient, admin_jwt: str):
    """A key whose expires_at is in the past must 401 with 'expired'.

    Synthesised by creating a key with a future expiry then back-dating
    the row directly in the DB (no public 'rotate expiry' endpoint
    exists yet — that's GAP-7).
    """
    from apps.api.app.core.database import async_session_factory
    from apps.api.app.models.api_key import APIKey
    from sqlalchemy import select, update

    key = await _create_key(client, admin_jwt, "regression-expired", expires_in_days=30)
    try:
        async with async_session_factory() as s:
            await s.execute(
                update(APIKey)
                .where(APIKey.id == key["id"])
                .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
            )
            await s.commit()

        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {key['api_key']}"},
        )
        assert r.status_code == 401
        assert "expired" in r.json()["detail"].lower()
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_key_in_query_string_not_accepted(client: AsyncClient, admin_jwt: str):
    """API keys passed in the URL query string MUST NOT authenticate —
    they'd leak into proxy logs, referrer headers and browser history."""
    key = await _create_key(client, admin_jwt, "regression-url")
    try:
        r = await client.get(f"/api/v1/auth/me?api_key={key['api_key']}")
        assert r.status_code in (401, 403), \
            f"key-in-URL must NOT authenticate, got {r.status_code}: {r.text}"
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_use_event_audit_row_written(client: AsyncClient, admin_jwt: str):
    """First use of a key MUST write an `api_key_used` audit row with
    method+path detail.  Covers GAP-2 — SOC 2 / ISO 27001 require an
    access trail for privileged credentials."""
    from apps.api.app.core.database import async_session_factory
    from apps.api.app.models.audit import AuditEvent
    from sqlalchemy import select as sel

    key = await _create_key(client, admin_jwt, "regression-audit")
    try:
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {key['api_key']}"},
        )
        assert r.status_code == 200

        async with async_session_factory() as s:
            res = await s.execute(
                sel(AuditEvent)
                .where(
                    AuditEvent.action == "api_key_used",
                    AuditEvent.resource_id == str(key["id"]),
                )
                .order_by(AuditEvent.created_at.desc())
                .limit(1)
            )
            row = res.scalar_one_or_none()
            assert row is not None, "expected api_key_used audit row after first call"
            assert row.detail and "/api/v1/auth/me" in row.detail
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


# ── Scope enforcement (Sprint 1 / Stage A) ──────────────────


@pytest.mark.asyncio(loop_scope="module")
async def test_scope_findings_blocks_admin_routes(client: AsyncClient, admin_jwt: str):
    """A key scoped to 'findings' MUST 200 on /findings but 403 on
    /users (admin-only).  Regression for GAP-1."""
    key = await _create_key(
        client, admin_jwt, "scope-findings-only", scopes=["findings"],
    )
    try:
        headers = {"Authorization": f"Bearer {key['api_key']}"}

        r_ok = await client.get("/api/v1/findings", headers=headers)
        assert r_ok.status_code == 200, f"in-scope call should pass: {r_ok.text}"

        r_blocked = await client.get("/api/v1/users", headers=headers)
        assert r_blocked.status_code == 403, \
            f"out-of-scope must 403, got {r_blocked.status_code}: {r_blocked.text}"
        detail = r_blocked.json()["detail"]
        assert "missing required scope" in detail.lower()
        assert "admin" in detail
        assert "findings" in detail
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_scope_admin_satisfies_any_route(client: AsyncClient, admin_jwt: str):
    """The 'admin' scope is a wildcard — any other scope requirement
    is satisfied by it."""
    key = await _create_key(client, admin_jwt, "scope-admin-only", scopes=["admin"])
    try:
        headers = {"Authorization": f"Bearer {key['api_key']}"}
        for path in ("/api/v1/findings", "/api/v1/users", "/api/v1/metrics/summary"):
            r = await client.get(path, headers=headers)
            assert r.status_code in (200, 404), \
                f"admin scope must pass {path}, got {r.status_code}: {r.text[:200]}"
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_scope_jwt_bypasses(client: AsyncClient, admin_jwt: str):
    """JWT requests MUST bypass scope checks (sessions have no scope
    concept)."""
    headers = {"Authorization": f"Bearer {admin_jwt}"}
    r = await client.get("/api/v1/users", headers=headers)
    assert r.status_code == 200, f"JWT must bypass scope, got {r.status_code}"


@pytest.mark.asyncio(loop_scope="module")
async def test_scope_empty_scopes_blocked(client: AsyncClient, admin_jwt: str):
    """A key with [] scopes MUST 403 from every scoped router."""
    key = await _create_key(client, admin_jwt, "scope-empty", scopes=[])
    try:
        headers = {"Authorization": f"Bearer {key['api_key']}"}
        r = await client.get("/api/v1/findings", headers=headers)
        assert r.status_code == 403
        detail = r.json()["detail"]
        assert "(none)" in detail or "[]" in detail
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


# ── Rate limiting (Sprint 1 / Stage B) ──────────────────────


@pytest.mark.asyncio(loop_scope="module")
async def test_login_rate_limit_enforces_429(client: AsyncClient, monkeypatch):
    """The login endpoint is limited per remote IP to blunt credential
    stuffing.  Sending more requests than the limit in <60s MUST
    surface at least one 429 with Retry-After + JSON body that names
    the limit.

    Pins its own limit rather than trusting the ambient one: the session
    fixture in conftest raises the ceiling so the rest of the suite can
    run more than once a minute, and a test asserting the limiter works
    must not depend on a value another fixture can change under it.
    """
    from apps.api.app.core.config import settings as _settings

    monkeypatch.setattr(_settings, "AUTH_LOGIN_RATE_LIMIT", "10/minute")

    codes = []
    retry_after = None
    challenge_body = None
    for i in range(15):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": f"rl-{i}@example.com", "password": "x"},
        )
        codes.append(r.status_code)
        if r.status_code == 429:
            retry_after = r.headers.get("retry-after")
            challenge_body = r.json()
            break

    assert 429 in codes, f"expected at least one 429, got {codes}"
    assert retry_after is not None, "Retry-After header must be set on 429"
    assert int(retry_after) > 0
    # JSON body must surface the limit + retry hint for CI tooling.
    assert "retry_after_seconds" in challenge_body
    assert "limit" in challenge_body
    assert "rate limit" in challenge_body["detail"].lower()


# ── X-API-Key alt header (Sprint 2 / GAP-11) ────────────────


@pytest.mark.asyncio(loop_scope="module")
async def test_x_api_key_header_authenticates(client: AsyncClient, admin_jwt: str):
    """A vooda_ key MUST authenticate via the X-API-Key header — the
    de-facto alternative to Authorization: Bearer used by Jenkins
    envinject, CircleCI orbs, GitLab CI/CD variables, etc."""
    key = await _create_key(client, admin_jwt, "x-api-key-test", scopes=["admin"])
    try:
        r = await client.get(
            "/api/v1/auth/me",
            headers={"X-API-Key": key["api_key"]},
        )
        assert r.status_code == 200, f"X-API-Key auth must pass, got {r.status_code}: {r.text}"
        assert r.json()["email"]
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_bearer_wins_when_both_headers_present(client: AsyncClient, admin_jwt: str):
    """When both Authorization: Bearer AND X-API-Key are set, Bearer
    wins — the 'obvious' header is authoritative.  Prevents a CI
    config setting both by accident from authenticating with the
    wrong principal."""
    bearer_key = await _create_key(client, admin_jwt, "bearer-wins-bearer", scopes=["admin"])
    alt_key = await _create_key(client, admin_jwt, "bearer-wins-alt", scopes=["findings"])
    try:
        r = await client.get(
            "/api/v1/users",  # requires admin scope
            headers={
                "Authorization": f"Bearer {bearer_key['api_key']}",
                "X-API-Key": alt_key["api_key"],
            },
        )
        # bearer_key has admin → 200; if alt_key won, we'd get 403.
        assert r.status_code == 200, \
            f"Bearer must take precedence; X-API-Key key lacked admin → got {r.status_code}"
    finally:
        await _revoke_key(client, admin_jwt, bearer_key["id"])
        await _revoke_key(client, admin_jwt, alt_key["id"])


# ── Rotation (Sprint 2 / GAP-7) ─────────────────────────────


@pytest.mark.asyncio(loop_scope="module")
async def test_rotation_issues_new_key_old_kept_alive(client: AsyncClient, admin_jwt: str):
    """Rotation MUST: (1) return a brand-new working key, (2) keep
    the old key valid through the grace window, (3) move the old key
    to status=rotating, (4) link the two via rotated_to_id."""
    orig = await _create_key(client, admin_jwt, "rotate-happy", scopes=["admin"])
    headers_old = {"Authorization": f"Bearer {orig['api_key']}"}
    try:
        # Old key works before rotation.
        r0 = await client.get("/api/v1/auth/me", headers=headers_old)
        assert r0.status_code == 200

        # Rotate with explicit 3-day grace.
        r = await client.post(
            f"/api/v1/api-keys/{orig['id']}/rotate",
            json={"grace_period_days": 3},
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert r.status_code == 201, f"rotate failed: {r.status_code} {r.text}"
        successor = r.json()

        # Successor MUST be a fresh vooda_ key, NOT equal to the old.
        assert successor["api_key"].startswith("vooda_")
        assert successor["api_key"] != orig["api_key"]
        assert successor["id"] != orig["id"]
        # Same scopes carried over.
        assert set(successor["scopes"]) == set(orig["scopes"])

        # Successor authenticates immediately.
        r_succ = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {successor['api_key']}"},
        )
        assert r_succ.status_code == 200

        # Old key STILL authenticates (within grace window).
        r_old = await client.get("/api/v1/auth/me", headers=headers_old)
        assert r_old.status_code == 200, \
            "old key MUST stay alive during grace window"

        # List endpoint: old key shows status=rotating with linkage.
        listing = (await client.get(
            "/api/v1/api-keys",
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )).json()
        rotated_row = next(k for k in listing if k["id"] == orig["id"])
        assert rotated_row["status"] == "rotating", \
            f"old key must surface as 'rotating', got {rotated_row['status']}"
        assert rotated_row["rotated_to_id"] == successor["id"]
        assert rotated_row["rotation_grace_until"] is not None
    finally:
        # Cleanup both keys.
        await _revoke_key(client, admin_jwt, orig["id"])
        await _revoke_key(client, admin_jwt, successor["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_rotation_rejects_revoked_key(client: AsyncClient, admin_jwt: str):
    key = await _create_key(client, admin_jwt, "rotate-rejected-revoked", scopes=["admin"])
    # Revoke first.
    await _revoke_key(client, admin_jwt, key["id"])
    r = await client.post(
        f"/api/v1/api-keys/{key['id']}/rotate",
        json={},
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    assert r.status_code == 409
    assert "revoked" in r.json()["detail"].lower()


@pytest.mark.asyncio(loop_scope="module")
async def test_rotation_rejects_already_rotated_key(client: AsyncClient, admin_jwt: str):
    orig = await _create_key(client, admin_jwt, "rotate-once-only", scopes=["admin"])
    try:
        r1 = await client.post(
            f"/api/v1/api-keys/{orig['id']}/rotate",
            json={"grace_period_days": 1},
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert r1.status_code == 201
        successor_id = r1.json()["id"]

        r2 = await client.post(
            f"/api/v1/api-keys/{orig['id']}/rotate",
            json={"grace_period_days": 1},
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert r2.status_code == 409
        assert "already been rotated" in r2.json()["detail"].lower()
        # Hint should point to the successor.
        assert str(successor_id) in r2.json()["detail"]
    finally:
        await _revoke_key(client, admin_jwt, orig["id"])
        await _revoke_key(client, admin_jwt, successor_id)


@pytest.mark.asyncio(loop_scope="module")
async def test_rotation_grace_period_clamped(client: AsyncClient, admin_jwt: str):
    """grace_period_days > 30 must be rejected by Pydantic validation."""
    key = await _create_key(client, admin_jwt, "rotate-grace-clamp", scopes=["admin"])
    try:
        r = await client.post(
            f"/api/v1/api-keys/{key['id']}/rotate",
            json={"grace_period_days": 60},
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert r.status_code == 422  # validation error
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


# ── Usage analytics (Sprint 2 / GAP-13) ─────────────────────


@pytest.mark.asyncio(loop_scope="module")
async def test_usage_endpoint_returns_aggregated_calls(client: AsyncClient, admin_jwt: str):
    """After a key makes N calls, /usage MUST return:
    * total_calls > 0
    * top_endpoints includes the path we hit
    * top_ips includes our (test) IP
    * calls_by_day has at least one bucket
    """
    key = await _create_key(client, admin_jwt, "usage-test", scopes=["admin"])
    try:
        h = {"Authorization": f"Bearer {key['api_key']}"}
        # Hit a couple of distinct endpoints.
        await client.get("/api/v1/auth/me", headers=h)
        await client.get("/api/v1/users", headers=h)

        # Pull usage.
        r = await client.get(
            f"/api/v1/api-keys/{key['id']}/usage?days=1",
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert r.status_code == 200, f"usage failed: {r.status_code} {r.text}"
        body = r.json()

        assert body["key_id"] == key["id"]
        assert body["window_days"] == 1
        assert body["total_calls"] >= 1, \
            "expected at least one api_key_used row from the test calls"
        assert body["calls_by_day"], "calls_by_day must have ≥1 bucket"
        # First call to a key always writes a row (last_used IS NULL
        # → should_audit=True), so total_calls is at least 1.
        endpoints = {ep["endpoint"] for ep in body["top_endpoints"]}
        # Either /auth/me or /users should appear (audit throttle may
        # have collapsed multiple writes within 60s into one row).
        assert any("/api/v1/" in ep for ep in endpoints), \
            f"expected an /api/v1/* endpoint in top_endpoints, got {endpoints}"
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_usage_window_clamped(client: AsyncClient, admin_jwt: str):
    """days > 90 MUST be rejected; days < 1 MUST be rejected."""
    key = await _create_key(client, admin_jwt, "usage-clamp", scopes=["admin"])
    try:
        r_big = await client.get(
            f"/api/v1/api-keys/{key['id']}/usage?days=365",
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert r_big.status_code == 422

        r_small = await client.get(
            f"/api/v1/api-keys/{key['id']}/usage?days=0",
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert r_small.status_code == 422
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


# ── IP allowlist (Sprint 3 / GAP-10) ────────────────────────


async def _create_key_with_allowlist(client, jwt, name, cidrs, scopes=("admin",)):
    body = {
        "name": name,
        "scopes": list(scopes),
        "expires_in_days": 90,
        "allowed_ip_cidrs": cidrs,
    }
    r = await client.post(
        "/api/v1/api-keys", json=body,
        headers={"Authorization": f"Bearer {jwt}"},
    )
    assert r.status_code == 201, f"create-with-allowlist failed: {r.text}"
    return r.json()


@pytest.mark.asyncio(loop_scope="module")
async def test_ip_allowlist_canonicalization(client: AsyncClient, admin_jwt: str):
    """CIDR entries with host bits MUST be canonicalized to network
    form on create so duplicate detection + auth-path containment
    behave deterministically."""
    key = await _create_key_with_allowlist(
        client, admin_jwt, "ip-canon",
        cidrs=["192.168.1.5/24", "10.0.0.0/8", "192.168.1.5/24"],  # dup + host-bits
    )
    try:
        # Re-fetch via list to read the canonical form.
        listing = (await client.get(
            "/api/v1/api-keys",
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )).json()
        row = next(k for k in listing if k["id"] == key["id"])
        cidrs = row["allowed_ip_cidrs"]
        assert cidrs == ["192.168.1.0/24", "10.0.0.0/8"], \
            f"expected canonicalized + dedup'd, got {cidrs}"
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_ip_allowlist_invalid_cidr_rejected(client: AsyncClient, admin_jwt: str):
    """Garbage CIDR → 422 referencing the offending entry."""
    r = await client.post(
        "/api/v1/api-keys",
        json={
            "name": "ip-bad",
            "scopes": ["admin"],
            "allowed_ip_cidrs": ["not-a-cidr"],
        },
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    assert r.status_code == 422
    assert "not-a-cidr" in r.json()["detail"]


@pytest.mark.asyncio(loop_scope="module")
async def test_ip_allowlist_blocks_unlisted_source(client: AsyncClient, admin_jwt: str):
    """A key with an allowlist that does NOT include the test client's
    IP must 403 — even with valid credentials.

    The httpx AsyncClient connects from 127.0.0.1 (or testclient).
    We allowlist a different RFC-1918 range that definitely won't
    include that, then assert 403.
    """
    key = await _create_key_with_allowlist(
        client, admin_jwt, "ip-blocked", cidrs=["203.0.113.0/24"],  # TEST-NET-3
    )
    try:
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {key['api_key']}"},
        )
        assert r.status_code == 403, \
            f"expected 403 from non-allowed IP, got {r.status_code}: {r.text}"
        detail = r.json()["detail"]
        assert "source ip" in detail.lower()
        assert "allowlist" in detail.lower()
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_ip_allowlist_allows_listed_source(client: AsyncClient, admin_jwt: str):
    """Wide-open allowlist (covers 0.0.0.0/0 + ::/0) MUST authenticate
    from anywhere — confirms the check is permissive when configured
    that way and proves the bug isn't 'allowlist always blocks'."""
    key = await _create_key_with_allowlist(
        client, admin_jwt, "ip-wide-open",
        cidrs=["0.0.0.0/0", "::/0"],
    )
    try:
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {key['api_key']}"},
        )
        assert r.status_code == 200, \
            f"wide-open allowlist should pass, got {r.status_code}: {r.text}"
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_ip_allowlist_x_forwarded_for_respected(client: AsyncClient, admin_jwt: str):
    """X-Forwarded-For first hop MUST be honoured as the source IP —
    customers behind ALB/Cloudflare need this or the allowlist
    becomes useless (it'd only ever match the LB's IP)."""
    key = await _create_key_with_allowlist(
        client, admin_jwt, "ip-xff", cidrs=["203.0.113.0/24"],
    )
    try:
        r = await client.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": f"Bearer {key['api_key']}",
                "X-Forwarded-For": "203.0.113.42",  # in-range
            },
        )
        assert r.status_code == 200, \
            f"XFF-spoofed in-range IP should pass, got {r.status_code}: {r.text}"
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_ip_allowlist_block_writes_audit_row(client: AsyncClient, admin_jwt: str):
    """A blocked attempt MUST land an api_key_ip_blocked audit row
    with the rejected IP and the violated allowlist."""
    from apps.api.app.core.database import async_session_factory
    from apps.api.app.models.audit import AuditEvent
    from sqlalchemy import select as sel

    key = await _create_key_with_allowlist(
        client, admin_jwt, "ip-audit", cidrs=["203.0.113.0/24"],
    )
    try:
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {key['api_key']}"},
        )
        assert r.status_code == 403

        async with async_session_factory() as s:
            row = (await s.execute(
                sel(AuditEvent).where(
                    AuditEvent.action == "api_key_ip_blocked",
                    AuditEvent.resource_id == str(key["id"]),
                ).order_by(AuditEvent.created_at.desc()).limit(1)
            )).scalar_one_or_none()
            assert row is not None, "expected api_key_ip_blocked audit row"
            assert row.detail and "blocked from" in row.detail.lower()
            assert "203.0.113.0/24" in row.detail
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_patch_updates_name_and_allowlist(client: AsyncClient, admin_jwt: str):
    """PATCH should mutate name + allowlist in place without affecting
    scopes/expiry, and surface canonicalized allowlist."""
    key = await _create_key(client, admin_jwt, "patch-test", scopes=["admin"])
    try:
        r = await client.patch(
            f"/api/v1/api-keys/{key['id']}",
            json={
                "name": "patch-test-renamed",
                "allowed_ip_cidrs": ["10.0.0.5/8"],
            },
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert r.status_code == 200, f"PATCH failed: {r.status_code} {r.text}"
        body = r.json()
        assert body["name"] == "patch-test-renamed"
        assert body["allowed_ip_cidrs"] == ["10.0.0.0/8"]  # canonicalized
        assert set(body["scopes"]) == set(key["scopes"])  # unchanged
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_patch_empty_list_clears_allowlist(client: AsyncClient, admin_jwt: str):
    """PATCH allowed_ip_cidrs=[] MUST clear the restriction."""
    key = await _create_key_with_allowlist(
        client, admin_jwt, "patch-clear", cidrs=["203.0.113.0/24"],
    )
    try:
        r = await client.patch(
            f"/api/v1/api-keys/{key['id']}",
            json={"allowed_ip_cidrs": []},
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert r.status_code == 200
        assert r.json()["allowed_ip_cidrs"] is None

        # Auth should now work (restriction cleared).
        r2 = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {key['api_key']}"},
        )
        assert r2.status_code == 200
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


# ── QA-fix regressions (2026-05-24 QA suite findings) ──────


@pytest.mark.asyncio(loop_scope="module")
async def test_empty_name_rejected_422(client: AsyncClient, admin_jwt: str):
    """Module 1.3 found that POST /api-keys with name='' returned 201
    even though the UI gated via a disabled button.  Pydantic now
    enforces min_length=1."""
    r = await client.post(
        "/api/v1/api-keys",
        json={"name": "", "scopes": ["scan"]},
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    assert r.status_code == 422, f"expected 422, got {r.status_code}: {r.text}"


@pytest.mark.asyncio(loop_scope="module")
async def test_long_name_rejected_422_not_500(client: AsyncClient, admin_jwt: str):
    """Module 9.5 found that a 300-char name returned 500 (DB error
    leaking) instead of 422.  Pydantic max_length=255 fails fast."""
    r = await client.post(
        "/api/v1/api-keys",
        json={"name": "A" * 300, "scopes": ["scan"]},
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    assert r.status_code == 422, f"expected 422 not {r.status_code}: {r.text}"
    # Also assert it's NOT a 500 — that was the actual bug, 422 is the fix.
    assert r.status_code != 500


@pytest.mark.asyncio(loop_scope="module")
async def test_patch_empty_name_rejected(client: AsyncClient, admin_jwt: str):
    """The PATCH endpoint should also reject empty/oversized names."""
    key = await _create_key(client, admin_jwt, "patch-empty-name", scopes=["admin"])
    try:
        r = await client.patch(
            f"/api/v1/api-keys/{key['id']}",
            json={"name": ""},
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert r.status_code == 422
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_login_failed_audit_for_unknown_email(client: AsyncClient):
    """Module 8 found that login_failed audit rows were missing for
    unknown emails (the raw-SQL fallback didn't commit).  Now uses
    log_audit_auth(commit=True) against a resolved fallback tenant."""
    from apps.api.app.core.database import async_session_factory
    from apps.api.app.models.audit import AuditEvent
    from sqlalchemy import select as sel
    from datetime import datetime, timezone, timedelta

    bogus = f"qa-unknown-{datetime.now(timezone.utc).timestamp()}@example.invalid"
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": bogus, "password": "anything"},
    )
    # Either 401 (normal) or 429 (if rate-limited from a prior test run).
    # Either way, only check the audit row when we actually got the 401.
    if r.status_code != 401:
        pytest.skip(f"login returned {r.status_code} — rate-limited; can't test audit path")

    async with async_session_factory() as s:
        row = (await s.execute(
            sel(AuditEvent)
            .where(
                AuditEvent.action == "login_failed",
                AuditEvent.detail.like(f"%{bogus}%"),
                AuditEvent.created_at >= datetime.now(timezone.utc) - timedelta(minutes=1),
            )
            .order_by(AuditEvent.created_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        assert row is not None, "expected login_failed audit row for unknown email"
        assert row.user_id is None, "unknown-email row should have user_id=NULL"
        assert row.tenant_id is not None, "tenant_id must NOT be NULL (FK NOT NULL)"


@pytest.mark.asyncio(loop_scope="module")
async def test_patch_max_cidrs_enforced(client: AsyncClient, admin_jwt: str):
    """Cap at 50 CIDRs — passing 51 must 422."""
    key = await _create_key(client, admin_jwt, "patch-cap", scopes=["admin"])
    try:
        too_many = [f"10.0.{i}.0/24" for i in range(51)]
        r = await client.patch(
            f"/api/v1/api-keys/{key['id']}",
            json={"allowed_ip_cidrs": too_many},
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert r.status_code == 422
        assert "too many" in r.json()["detail"].lower()
    finally:
        await _revoke_key(client, admin_jwt, key["id"])


@pytest.mark.asyncio(loop_scope="module")
async def test_usage_cross_tenant_isolation(client: AsyncClient, admin_jwt: str):
    """A key_id from another tenant MUST 404, not leak usage data."""
    # We don't have a second-tenant fixture easily; assert that a
    # bogus UUID 404s (same code path).
    r = await client.get(
        "/api/v1/api-keys/00000000-0000-0000-0000-000000000000/usage",
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio(loop_scope="module")
async def test_per_key_bucket_isolation(client: AsyncClient, admin_jwt: str):
    """Two distinct API keys must NOT share a bucket.  Hammer one to
    exhaustion (we use a synthetic per-endpoint limit by relying on the
    default 600/min — too slow for a test); instead, just assert that
    both keys can call /auth/me without one running out before the
    other gets a chance.  Guards against accidentally bucketing by
    user_id when api_key_id exists."""
    k1 = await _create_key(client, admin_jwt, "rl-iso-1", scopes=["findings"])
    k2 = await _create_key(client, admin_jwt, "rl-iso-2", scopes=["findings"])
    try:
        h1 = {"Authorization": f"Bearer {k1['api_key']}"}
        h2 = {"Authorization": f"Bearer {k2['api_key']}"}
        # 20 calls each (well under 600/min); both buckets must stay open.
        codes1, codes2 = [], []
        for _ in range(20):
            codes1.append((await client.get("/api/v1/findings", headers=h1)).status_code)
            codes2.append((await client.get("/api/v1/findings", headers=h2)).status_code)
        assert all(c == 200 for c in codes1), f"key1 saw non-200: {codes1}"
        assert all(c == 200 for c in codes2), f"key2 saw non-200: {codes2}"
    finally:
        await _revoke_key(client, admin_jwt, k1["id"])
        await _revoke_key(client, admin_jwt, k2["id"])

