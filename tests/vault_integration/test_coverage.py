"""Coverage matching, and the failure mode that matters most.

The one result this module must never produce is a false all-clear: a
vault that could not be reached being reported as "this credential is
not under management". That reads as an action item when the truth is
"we do not know", and it is the difference between a user rotating a
secret and a user ignoring it.
"""

import pytest

from services.vault_integration.coverage import (
    CoverageStatus,
    check_coverage,
)


class FakeVault:
    def __init__(self, paths, fail=False):
        self.paths = paths
        self.fail = fail

    async def list_secrets(self):
        if self.fail:
            raise ConnectionError("vault unreachable")

        class _S:
            def __init__(self, p):
                self.path = p

        return [_S(p) for p in self.paths]


INCIDENTS = [
    {"id": "1", "title": "src/app.py: STRIPE_API_KEY", "secret_type": "stripe"},
    {"id": "2", "title": "config/db.yml: DATABASE_PASSWORD", "secret_type": "generic"},
    {"id": "3", "title": "lib/aws.js: AWS_ACCESS_KEY_ID", "secret_type": "aws"},
]
VAULT = ["prod/stripe/api_key", "prod/database/password"]


@pytest.mark.asyncio
async def test_unreachable_vault_is_unknown_not_uncovered():
    """The critical safety property — never a false all-clear."""
    results = await check_coverage(INCIDENTS, FakeVault([], fail=True))
    assert {r.status for r in results} == {CoverageStatus.UNKNOWN}


@pytest.mark.asyncio
async def test_reachable_but_empty_vault_is_uncovered():
    """An empty vault genuinely means not-managed, and should say so."""
    results = await check_coverage(INCIDENTS, FakeVault([]))
    assert {r.status for r in results} == {CoverageStatus.UNCOVERED}


@pytest.mark.asyncio
async def test_matches_despite_file_path_noise():
    """`src/app.py: STRIPE_API_KEY` must match `prod/stripe/api_key`.

    Regression test: scoring over the whole title let the file path
    dominate and scored this pair 0.25, reporting a managed credential
    as unmanaged.
    """
    results = {r.incident_id: r for r in await check_coverage(INCIDENTS, FakeVault(VAULT))}
    assert results["1"].status is CoverageStatus.COVERED
    assert results["1"].vault_path == "prod/stripe/api_key"
    assert results["2"].status is CoverageStatus.COVERED
    assert results["3"].status is CoverageStatus.UNCOVERED


@pytest.mark.asyncio
async def test_explicit_mapping_beats_fuzzy_matching():
    results = {
        r.incident_id: r
        for r in await check_coverage(
            INCIDENTS, FakeVault(VAULT), explicit_paths={"3": "prod/stripe/api_key"}
        )
    }
    assert results["3"].status is CoverageStatus.COVERED
    assert results["3"].confidence == 1.0


@pytest.mark.asyncio
async def test_explicit_mapping_to_a_missing_path_is_uncovered():
    """A hand-mapped path that does not exist is a real finding, not a match."""
    results = {
        r.incident_id: r
        for r in await check_coverage(
            INCIDENTS, FakeVault(VAULT), explicit_paths={"1": "does/not/exist"}
        )
    }
    assert results["1"].status is CoverageStatus.UNCOVERED
    assert "no such path" in results["1"].detail.lower()


@pytest.mark.asyncio
async def test_unrelated_credentials_do_not_match():
    """Sharing a generic word like `key` must not read as covered."""
    results = await check_coverage(
        [{"id": "9", "title": "a.py: TWILIO_AUTH_TOKEN", "secret_type": "twilio"}],
        FakeVault(["prod/github/api_key"]),
    )
    assert results[0].status is CoverageStatus.UNCOVERED
