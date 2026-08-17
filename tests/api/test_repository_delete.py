"""Deleting a repository must not 500 on tables that no longer exist.

The delete cascade lists child tables by name and DELETEs from each.
Six of those names — policy_evaluation_results, supply_chain_components,
supply_chain_scans, sbom_records, policy_definitions, policies — belong
to product lines removed in 2026-05, so their tables are never created.
The first DELETE against a missing table raised UndefinedTableError and
aborted the transaction, so deleting ANY repository returned 500 and the
row could never be removed through the UI.
"""

import pytest

from apps.api.app.routers.repositories import _existing_tables


@pytest.mark.asyncio(loop_scope="module")
async def test_existing_tables_filters_out_removed_ones(client):
    """The guard that prevents the 500: absent tables are filtered out."""
    from apps.api.app.core.database import async_session_factory

    async with async_session_factory() as db:
        present = await _existing_tables(
            db,
            (
                "normalized_findings",        # real
                "metric_snapshots",          # real
                "policy_evaluation_results",  # removed
                "supply_chain_scans",        # removed
                "policies",                  # removed
            ),
        )

    assert "normalized_findings" in present
    assert "metric_snapshots" in present
    assert "policy_evaluation_results" not in present
    assert "supply_chain_scans" not in present
    assert "policies" not in present


@pytest.mark.asyncio(loop_scope="module")
async def test_create_then_delete_repository_returns_204(client, admin_jwt):
    """End-to-end regression: a repo can actually be deleted.

    Uses a URL with no remote work — the delete path is what is under
    test, not scanning — so it stays fast and offline.
    """
    h = {"Authorization": f"Bearer {admin_jwt}"}

    created = await client.post(
        "/api/v1/repositories",
        json={"name": "pytest-delete-me", "url": "https://github.com/example/none"},
        headers=h,
    )
    assert created.status_code == 201, created.text
    repo_id = created.json()["id"]

    deleted = await client.delete(f"/api/v1/repositories/{repo_id}", headers=h)
    assert deleted.status_code == 204, (
        f"delete returned {deleted.status_code}: {deleted.text}"
    )

    listing = await client.get("/api/v1/repositories", headers=h)
    names = [r["name"] for r in listing.json().get("items", listing.json())]
    assert "pytest-delete-me" not in names
