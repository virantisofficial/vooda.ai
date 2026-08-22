# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Deleting a scan through the API must not erase older findings.

Drives the real endpoint against the real database. Two scans are
created for one repository, a finding is carried from the first into the
second (``scan_count = 2``, anchored to the newer scan, exactly as a
re-scan leaves it), and the newer scan is then deleted.

The finding must still be there. Before the fix it was not: the endpoint
deleted findings by ``scan_job_id``, and a re-scan had already re-pointed
that column at the scan being removed.
"""
import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import text

from apps.api.app.core.database import async_session_factory


pytestmark = pytest.mark.asyncio(loop_scope="module")


async def _one(sql, **params):
    async with async_session_factory() as db:
        return await db.scalar(text(sql), params)


async def _exec(sql, **params):
    async with async_session_factory() as db:
        await db.execute(text(sql), params)
        await db.commit()


@pytest_asyncio.fixture(loop_scope="module")
async def repo_with_two_scans(client: AsyncClient, admin_jwt: str):
    """A repo, two scans, and one finding carried from the older into
    the newer — the state a second scan leaves behind."""
    tenant_id = await _one("SELECT id FROM tenants LIMIT 1")
    if tenant_id is None:
        pytest.skip("no tenant in the database — run the seed first")

    repo_id, old_scan, new_scan, finding_id = (uuid.uuid4() for _ in range(4))

    await _exec(
        """
        INSERT INTO repositories (id, tenant_id, name, url, source_type,
                                  default_branch, is_active, languages,
                                  frameworks, created_at, updated_at)
        VALUES (:rid, :tid, :name, 'https://example.com/x', 'GIT_URL',
                'main', true, '[]'::jsonb, '[]'::jsonb, now(), now())
        """,
        rid=repo_id, tid=tenant_id, name=f"pytest-delete-{repo_id.hex[:8]}",
    )
    for sid, offset in ((old_scan, "2 hours"), (new_scan, "1 hour")):
        await _exec(
            f"""
            INSERT INTO scan_jobs (id, tenant_id, repository_id, scan_type,
                                   status, progress_pct, config, stats,
                                   created_at, updated_at)
            VALUES (:sid, :tid, :rid, 'STANDALONE', 'COMPLETED', 100,
                    '{{}}'::jsonb, '{{}}'::jsonb,
                    now() - interval '{offset}', now())
            """,
            sid=sid, tid=tenant_id, rid=repo_id,
        )

    # Seen by both scans: anchored to the NEWER one, scan_count = 2.
    await _exec(
        """
        INSERT INTO normalized_findings
            (id, tenant_id, repository_id, scan_job_id, last_seen_scan_job_id,
             scan_count, title, vulnerability_category, severity, file_path,
             scanner_name, classification, review_status, remediation_status,
             first_seen_at, last_seen_at, created_at, updated_at)
        VALUES (:fid, :tid, :rid, :new, :new, 2, 'carried finding', 'secret',
                'HIGH', 'src/a.py', 'vooda', 'NEEDS_REVIEW', 'UNREVIEWED',
                'NONE', now() - interval '2 hours', now(), now(), now())
        """,
        fid=finding_id, tid=tenant_id, rid=repo_id, new=new_scan,
    )

    try:
        yield {"repo": repo_id, "old": old_scan, "new": new_scan, "finding": finding_id}
    finally:
        # try/finally, not a bare tail: a fixture that raises before the
        # yield otherwise leaves its rows behind, and a repository row the
        # response model cannot serialise fails the LIST endpoint for
        # every later test.
        await _exec("DELETE FROM normalized_findings WHERE repository_id = :rid", rid=repo_id)
        await _exec("DELETE FROM scan_jobs WHERE repository_id = :rid", rid=repo_id)
        await _exec("DELETE FROM repositories WHERE id = :rid", rid=repo_id)


async def test_deleting_the_newer_scan_keeps_the_older_finding(
    client: AsyncClient, admin_jwt: str, repo_with_two_scans
):
    ctx = repo_with_two_scans
    r = await client.delete(
        f"/api/v1/repositories/{ctx['repo']}/scans/{ctx['new']}",
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    assert r.status_code == 204, r.text

    survived = await _one(
        "SELECT count(*) FROM normalized_findings WHERE id = :fid", fid=ctx["finding"]
    )
    assert survived == 1, (
        "the finding predated the deleted scan and must survive it — "
        "deleting one scan erased the repository's finding history"
    )


async def test_surviving_finding_is_reanchored_and_decremented(
    client: AsyncClient, admin_jwt: str, repo_with_two_scans
):
    ctx = repo_with_two_scans
    r = await client.delete(
        f"/api/v1/repositories/{ctx['repo']}/scans/{ctx['new']}",
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    assert r.status_code == 204, r.text

    row = None
    async with async_session_factory() as db:
        row = (await db.execute(text(
            "SELECT scan_job_id, last_seen_scan_job_id, scan_count "
            "FROM normalized_findings WHERE id = :fid"
        ), {"fid": ctx["finding"]})).first()

    assert row is not None
    anchor, last_seen, count = row
    assert anchor == ctx["old"], "must re-anchor to the surviving scan"
    assert last_seen == ctx["old"], "last_seen must not dangle at a deleted scan"
    assert count == 1, "one sighting was removed, so the count drops by one"


async def test_single_sighting_finding_is_still_removed(
    client: AsyncClient, admin_jwt: str, repo_with_two_scans
):
    """Only-seen-once findings have no history and go with the scan."""
    ctx = repo_with_two_scans
    solo = uuid.uuid4()
    tenant_id = await _one("SELECT id FROM tenants LIMIT 1")
    await _exec(
        """
        INSERT INTO normalized_findings
            (id, tenant_id, repository_id, scan_job_id, last_seen_scan_job_id,
             scan_count, title, vulnerability_category, severity, file_path,
             scanner_name, classification, review_status, remediation_status,
             first_seen_at, last_seen_at, created_at, updated_at)
        VALUES (:fid, :tid, :rid, :new, :new, 1, 'new this scan', 'secret',
                'LOW', 'src/b.py', 'vooda', 'NEEDS_REVIEW', 'UNREVIEWED',
                'NONE', now(), now(), now(), now())
        """,
        fid=solo, tid=tenant_id, rid=ctx["repo"], new=ctx["new"],
    )

    r = await client.delete(
        f"/api/v1/repositories/{ctx['repo']}/scans/{ctx['new']}",
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    assert r.status_code == 204, r.text

    assert await _one("SELECT count(*) FROM normalized_findings WHERE id = :fid", fid=solo) == 0
    assert await _one("SELECT count(*) FROM normalized_findings WHERE id = :fid", fid=ctx["finding"]) == 1


async def test_deleting_the_only_scan_removes_its_findings(
    client: AsyncClient, admin_jwt: str, repo_with_two_scans
):
    """No survivor to re-anchor to, so nothing is left behind."""
    ctx = repo_with_two_scans
    for sid in (ctx["new"], ctx["old"]):
        r = await client.delete(
            f"/api/v1/repositories/{ctx['repo']}/scans/{sid}",
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert r.status_code == 204, r.text

    assert await _one(
        "SELECT count(*) FROM normalized_findings WHERE repository_id = :rid",
        rid=ctx["repo"],
    ) == 0
    assert await _one(
        "SELECT count(*) FROM scan_jobs WHERE repository_id = :rid", rid=ctx["repo"]
    ) == 0
