# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""A guess must never be enough to call a credential dead.

All eight paired verifiers send values Vooda never detected. Only one
half of a pair is a secret and gets its own detector rule; the rest —
an AWS secret key, an Azure client id, a Snowflake account — are read
off a nearby line by regex because they had to come from somewhere.

When the provider rejects the request it almost never says which value
it disliked. Mapping that to "inactive" means telling someone their
exposed credential is harmless because a regex picked the wrong line,
which is the worst answer this product can give: the finding closes and
nobody looks again.

So an inactive verdict survives only when the verifier could attribute
it, or when nothing was guessed. Everything else becomes check_failed —
unhelpful, honest, and already forbidden by the validity vocabulary
from reading as safe.
"""
import pytest

from services.secret_verification import verifier as v


def _inactive(**kw):
    return v.VerificationResult(
        status="inactive", details="rejected", provider="x", **kw)


def test_a_guess_downgrades_an_inactive_verdict():
    out = v.apply_pairing_attribution(
        _inactive(), {"_inferred_partners": ["aws_secret"]})
    assert out.status == "check_failed"
    assert "aws_secret" in out.details
    assert "cannot be pinned" in out.details


def test_an_attributed_rejection_survives():
    """Azure can prove it: 'invalid client secret' is only reached once
    the application has been found, so the guessed client id was right."""
    out = v.apply_pairing_attribution(
        _inactive(attributed=True), {"_inferred_partners": ["azure_client_id"]})
    assert out.status == "inactive"


def test_nothing_guessed_means_nothing_to_doubt():
    """Both halves detected in their own right."""
    out = v.apply_pairing_attribution(_inactive(), {"_inferred_partners": []})
    assert out.status == "inactive"
    out = v.apply_pairing_attribution(_inactive(), {})
    assert out.status == "inactive"


@pytest.mark.parametrize("status", ["active", "check_failed", "unsupported", "error"])
def test_only_inactive_is_touched(status):
    """An active credential found via a guessed partner is still active
    — the provider accepted every value, so all of them were right."""
    r = v.VerificationResult(status=status, details="d", provider="x")
    out = v.apply_pairing_attribution(r, {"_inferred_partners": ["anything"]})
    assert out.status == status


def test_pairing_records_what_it_guessed(tmp_path):
    from services.secret_verification.credential_pairing import (
        find_partner_credential, enrich_source_metadata_with_pair,
    )
    (tmp_path / "creds").write_text(
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY123\n",
        encoding="utf-8",
    )
    partners = find_partner_credential(
        primary_secret_type="aws_access_key",
        primary_file_path="creds",
        primary_line=1,
        all_findings=[],
        repo_root=str(tmp_path),
    )
    assert partners, "the secret key should be found beside the access key"
    assert partners["_inferred_partners"], "and recorded as inferred"
    enriched = enrich_source_metadata_with_pair({"_raw_value": "x"}, partners)
    assert enriched["_inferred_partners"], "the marker must survive enrichment"


@pytest.mark.asyncio
async def test_the_manual_path_applies_the_downgrade(tmp_path, monkeypatch):
    """End to end: a rejection on a guessed pair comes back as
    check_failed, not inactive."""
    async def _rejects(*a, **kw):
        return v.VerificationResult(
            status="inactive", details="AWS rejected", provider="aws")

    monkeypatch.setitem(v.VERIFIERS, "aws_paired", _rejects)
    (tmp_path / "creds").write_text(
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY123\n",
        encoding="utf-8",
    )
    result = await v.verify_finding_with_pairing(
        {"provider": "aws", "secret_type": "aws_access_key",
         "detection_method": "regex", "_raw_value": "AKIAIOSFODNN7EXAMPLE"},
        repo_root=str(tmp_path), file_path="creds", line_start=1,
    )
    assert result.status == "check_failed", result.details


# ── The three inversions ────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("pair_key,sm,expected", [
    ("paypal_paired",
     {"_raw_value": "the-secret", "paypal_client_id": "the-id"},
     ("the-id", "the-secret")),
    ("mongodb_atlas_paired",
     {"_raw_value": "the-private", "mongodb_atlas_public_key": "the-public"},
     ("the-public", "the-private")),
])
async def test_the_detected_value_is_passed_as_the_secret(pair_key, sm, expected, monkeypatch):
    seen = {}

    async def _spy(identifier, secret, *rest, **kw):
        # PayPal's lambda also passes `live=` by keyword.
        seen["args"] = (identifier, secret)
        return None

    fn = {"paypal_paired": "verify_paypal_oauth",
          "mongodb_atlas_paired": "verify_mongodb_atlas_paired"}[pair_key]
    monkeypatch.setattr(v, fn, _spy)
    await v.VERIFIERS[pair_key](sm)
    assert seen["args"] == expected


@pytest.mark.asyncio
async def test_snowflake_passes_the_detected_value_as_the_password(monkeypatch):
    seen = {}

    async def _spy(account, user, password):
        seen["args"] = (account, user, password)
        return None

    monkeypatch.setattr(v, "verify_snowflake_paired", _spy)
    await v.VERIFIERS["snowflake_paired"]({
        "_raw_value": "the-password",
        "snowflake_account": "acct", "snowflake_user": "usr",
    })
    assert seen["args"] == ("acct", "usr", "the-password")


@pytest.mark.asyncio
async def test_a_snowflake_account_that_does_not_exist_is_not_a_dead_password():
    """404 means the account subdomain does not resolve. The account
    came from the file; the password was never sent anywhere. This was
    reported as 'creds rejected', which closed the finding."""
    from contextlib import asynccontextmanager
    from unittest.mock import AsyncMock, MagicMock, patch

    resp = MagicMock()
    resp.status_code = 404
    resp.headers = {"content-type": "application/json"}
    resp.json = MagicMock(return_value={})

    @asynccontextmanager
    async def _cm(*a, **kw):
        c = AsyncMock()
        c.post = AsyncMock(return_value=resp)
        yield c

    with patch.object(v, "verification_client", _cm):
        result = await v.verify_snowflake_paired("acct", "usr", "pw")
    assert result.status == "check_failed"
    assert "never tested" in result.details


def test_the_scan_path_applies_the_same_guard():
    """The worker verifies paired credentials during the scan, calling
    the verifier directly. Guarding only the manual re-verify path
    would leave the one that runs on every scan unprotected."""
    import pathlib
    src = pathlib.Path("apps/worker/tasks.py").read_text(encoding="utf-8")
    assert "apply_pairing_attribution(" in src
