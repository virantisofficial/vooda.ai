# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Drive the triage endpoint for real and read back what it stored.

The sibling file guards the pieces in isolation. This one puts a
finding in the database, dismisses it through the HTTP endpoint the UI
calls, and checks the row — because the parts can each be right while
the request still stores nothing: the fields are written after
`set_classification`, which clears them, and an ordering mistake there
returns 200 with an empty acceptance.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import text

from apps.api.app.core.database import async_session_factory


pytestmark = pytest.mark.asyncio(loop_scope="module")


async def _one(sql, **params):
    async with async_session_factory() as db:
        return await db.scalar(text(sql), params)


async def _row(sql, **params):
    async with async_session_factory() as db:
        return (await db.execute(text(sql), params)).mappings().first()


async def _exec(sql, **params):
    async with async_session_factory() as db:
        await db.execute(text(sql), params)
        await db.commit()


@pytest_asyncio.fixture(loop_scope="module")
async def open_finding(client: AsyncClient, admin_jwt: str):
    tenant_id = await _one("SELECT id FROM tenants LIMIT 1")
    if tenant_id is None:
        pytest.skip("no tenant in the database — run the seed first")

    repo_id, scan_id, finding_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    await _exec(
        """
        INSERT INTO repositories (id, tenant_id, name, url, source_type,
                                  default_branch, is_active, languages,
                                  frameworks, created_at, updated_at)
        VALUES (:rid, :tid, :name, 'https://example.com/x', 'GIT_URL',
                'main', true, '[]'::jsonb, '[]'::jsonb, now(), now())
        """,
        rid=repo_id, tid=tenant_id, name=f"pytest-risk-{repo_id.hex[:8]}",
    )
    await _exec(
        """
        INSERT INTO scan_jobs (id, tenant_id, repository_id, scan_type,
                               status, progress_pct, config, stats,
                               created_at, updated_at)
        VALUES (:sid, :tid, :rid, 'STANDALONE', 'COMPLETED', 100,
                '{}'::jsonb, '{}'::jsonb, now(), now())
        """,
        sid=scan_id, tid=tenant_id, rid=repo_id,
    )
    await _exec(
        """
        INSERT INTO normalized_findings
            (id, tenant_id, repository_id, scan_job_id, scan_count, title,
             vulnerability_category, severity, file_path, scanner_name,
             classification, review_status, remediation_status, status,
             first_seen_at, last_seen_at, created_at, updated_at)
        VALUES (:fid, :tid, :rid, :sid, 1, 'risk acceptance fixture', 'secret',
                'HIGH', 'src/a.py', 'vooda', 'NEEDS_REVIEW', 'UNREVIEWED',
                'NONE', 'open', now(), now(), now(), now())
        """,
        fid=finding_id, tid=tenant_id, rid=repo_id, sid=scan_id,
    )
    try:
        yield {"id": finding_id, "repo": repo_id, "tenant": tenant_id}
    finally:
        await _exec("DELETE FROM finding_decisions WHERE finding_id = :fid", fid=finding_id)
        await _exec("DELETE FROM normalized_findings WHERE repository_id = :rid", rid=repo_id)
        await _exec("DELETE FROM scan_jobs WHERE repository_id = :rid", rid=repo_id)
        await _exec("DELETE FROM repositories WHERE id = :rid", rid=repo_id)


def _h(jwt):
    return {"Authorization": f"Bearer {jwt}"}


async def test_an_acceptance_is_stored_with_its_owner_and_end_date(
    client: AsyncClient, admin_jwt: str, open_finding
):
    me = (await client.get("/api/v1/auth/me", headers=_h(admin_jwt))).json()
    until = datetime.now(timezone.utc) + timedelta(days=90)

    r = await client.post(
        f"/api/v1/findings/{open_finding['id']}/triage",
        headers=_h(admin_jwt),
        json={
            "action": "dismiss",
            "resolution_reason": "acceptable_risk",
            "risk_owner": me["id"],
            "risk_accepted_until": until.isoformat(),
            "comment": "Signed off for the quarter.",
        },
    )
    assert r.status_code == 200, r.text

    row = await _row(
        "SELECT status, resolution_reason, risk_owner, risk_accepted_until "
        "FROM normalized_findings WHERE id = :fid",
        fid=open_finding["id"],
    )
    assert row["status"] == "dismissed"
    assert row["resolution_reason"] == "acceptable_risk"
    assert str(row["risk_owner"]) == me["id"]
    assert row["risk_accepted_until"] is not None
    # Same instant, whatever the column's timezone rendering.
    assert abs((row["risk_accepted_until"] - until).total_seconds()) < 2


async def test_reopening_clears_the_acceptance(
    client: AsyncClient, admin_jwt: str, open_finding
):
    """An owner left behind on a re-opened finding reads as a live
    sign-off for a decision nobody is making any more."""
    me = (await client.get("/api/v1/auth/me", headers=_h(admin_jwt))).json()
    await client.post(
        f"/api/v1/findings/{open_finding['id']}/triage",
        headers=_h(admin_jwt),
        json={
            "action": "dismiss",
            "resolution_reason": "acceptable_risk",
            "risk_owner": me["id"],
            "risk_accepted_until":
                (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        },
    )
    r = await client.post(
        f"/api/v1/findings/{open_finding['id']}/triage",
        headers=_h(admin_jwt),
        json={"action": "reopen"},
    )
    assert r.status_code == 200, r.text

    row = await _row(
        "SELECT status, risk_owner, risk_accepted_until "
        "FROM normalized_findings WHERE id = :fid",
        fid=open_finding["id"],
    )
    assert row["status"] == "open"
    assert row["risk_owner"] is None
    assert row["risk_accepted_until"] is None


async def test_the_terms_are_refused_on_an_unrelated_action(
    client: AsyncClient, admin_jwt: str, open_finding
):
    r = await client.post(
        f"/api/v1/findings/{open_finding['id']}/triage",
        headers=_h(admin_jwt),
        json={
            "action": "mark_tp",
            "risk_accepted_until":
                (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        },
    )
    assert r.status_code == 422, r.text


async def test_an_end_date_in_the_past_is_refused(
    client: AsyncClient, admin_jwt: str, open_finding
):
    """It would close the finding and stop applying in one request."""
    r = await client.post(
        f"/api/v1/findings/{open_finding['id']}/triage",
        headers=_h(admin_jwt),
        json={
            "action": "dismiss",
            "resolution_reason": "acceptable_risk",
            "risk_accepted_until":
                (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        },
    )
    assert r.status_code == 422, r.text
    row = await _row(
        "SELECT status FROM normalized_findings WHERE id = :fid",
        fid=open_finding["id"],
    )
    assert row["status"] == "open", "a refused request must not close the finding"


async def test_an_owner_from_outside_the_workspace_is_refused(
    client: AsyncClient, admin_jwt: str, open_finding
):
    r = await client.post(
        f"/api/v1/findings/{open_finding['id']}/triage",
        headers=_h(admin_jwt),
        json={
            "action": "dismiss",
            "resolution_reason": "acceptable_risk",
            "risk_owner": str(uuid.uuid4()),
        },
    )
    assert r.status_code == 422, r.text


async def test_a_reason_the_ui_can_now_reach_survives_the_round_trip(
    client: AsyncClient, admin_jwt: str, open_finding
):
    """mitigating_control collapses onto ACCEPTED_RISK in the legacy
    enum. Nothing in the UI could send it until the status control was
    split, so this is the first time it has been written from a
    screen."""
    r = await client.post(
        f"/api/v1/findings/{open_finding['id']}/triage",
        headers=_h(admin_jwt),
        json={"action": "dismiss", "resolution_reason": "mitigating_control"},
    )
    assert r.status_code == 200, r.text
    row = await _row(
        "SELECT status, resolution_reason, risk_owner "
        "FROM normalized_findings WHERE id = :fid",
        fid=open_finding["id"],
    )
    assert row["status"] == "dismissed"
    assert row["resolution_reason"] == "mitigating_control"
    # Not an acceptable-risk dismissal, so it carries no acceptance.
    assert row["risk_owner"] is None
