# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Azure AD: the pair was the wrong way round, and failing was unsafe.

Verifying an Azure AD application needs three values — client id,
client secret and tenant. Only one of them is a secret, and only one is
detected: VOODA-SEC-AZ-002, "Azure AD Client Secret". The client id and
tenant are plain UUIDs; on their own they are configuration, so no rule
detects them and none should.

The pairing table was keyed on `azure_client_id` as the primary and the
verifier took the detected value as the client id. Both wrong, in a way
that cancelled out into silence: no rule emits `azure_client_id`, so
the pairing never fired and the mis-ordered arguments were never
reached.

Inverting it is only safe because of the second half of this file.
Azure answers a bad client-credentials request with 400 whether the
secret was wrong or the client id was, and the verifier mapped every
400/401/403 to "inactive". A client id recovered by scanning the file
is a guess — so a wrong guess would have reported a live, exposed
secret as dead. Only the AADSTS code distinguishes them.
"""
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.secret_verification import verifier as v


def _response(status_code: int, description: str = ""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-type": "application/json"}
    resp.json = MagicMock(return_value={"error_description": description})
    return resp


def _client(response):
    @asynccontextmanager
    async def _cm(*a, **kw):
        c = AsyncMock()
        c.post = AsyncMock(return_value=response)
        c.get = AsyncMock(return_value=response)
        yield c
    return _cm


async def _verify(response):
    with patch.object(v, "verification_client", _client(response)):
        return await v.verify_azure_ad("cid", "secret", "tid")


# ── The mapping that makes pairing safe ─────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("description", [
    "AADSTS7000215: Invalid client secret provided.",
    "AADSTS7000222: The provided client secret keys are expired.",
])
async def test_a_rejected_secret_is_reported_dead(description):
    """The case that should still say inactive: Azure named the secret
    as the problem."""
    result = await _verify(_response(401, description))
    assert result.status == "inactive"


@pytest.mark.asyncio
@pytest.mark.parametrize("description", [
    "AADSTS700016: Application with identifier 'x' was not found in the directory.",
    "AADSTS90002: Tenant 'x' not found.",
    "AADSTS900023: Specified tenant identifier is neither a valid DNS name nor a valid external domain.",
])
async def test_a_wrong_client_id_never_reports_the_secret_dead(description):
    """The regression this file exists for. The client id and tenant
    come from scanning the file beside the secret; when Azure says it
    did not recognise them, nothing was learned about the secret.

    Reporting "inactive" here would close a live, exposed credential."""
    result = await _verify(_response(400, description))
    assert result.status != "inactive"
    assert result.status == "check_failed"
    assert "never tested" in result.details


@pytest.mark.asyncio
async def test_an_unrecognised_rejection_is_not_treated_as_dead():
    """Absence of evidence is not evidence of absence — the rule the
    validity vocabulary is built on."""
    result = await _verify(_response(400, "AADSTS50000: Something new."))
    assert result.status == "check_failed"


@pytest.mark.asyncio
async def test_a_working_application_is_still_active():
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {"content-type": "application/json"}
    resp.json = MagicMock(return_value={"scope": "https://graph.microsoft.com/.default",
                                        "expires_in": 3599})
    with patch.object(v, "verification_client", _client(resp)):
        result = await v.verify_azure_ad("cid", "secret", "tid")
    assert result.status == "active"


@pytest.mark.asyncio
async def test_a_missing_partner_is_not_a_verdict():
    """Pairing can find the tenant and miss the client id."""
    result = await v.verify_azure_ad("", "secret", "tid")
    assert result.status == "unsupported"


# ── The inversion ───────────────────────────────────────────────────

def test_the_pair_is_keyed_on_the_half_that_is_detected():
    from services.secret_scan.detectors.registry import get_all_rules
    from services.secret_verification.credential_pairing import KNOWN_PAIRS
    azure = next(p for p in KNOWN_PAIRS if p.verifier_key == "azure_ad_paired")
    emitted = {(r.secret_type or "").lower() for r in get_all_rules()}
    assert azure.primary_secret_type in emitted, (
        "the pairing primary must be something a rule actually emits"
    )
    assert azure.primary_secret_type == "azure_ad_secret"


def test_the_client_id_and_tenant_are_recoverable_from_a_file():
    """Neither is detected, so both must come from the inline scan."""
    from services.secret_verification.credential_pairing import KNOWN_PAIRS
    azure = next(p for p in KNOWN_PAIRS if p.verifier_key == "azure_ad_paired")
    for partner in azure.partner_secret_types:
        assert partner in (azure.partner_inline_regex or {}), partner


def test_pairing_finds_both_partners_beside_the_secret(tmp_path):
    from services.secret_verification.credential_pairing import find_partner_credential
    (tmp_path / "app.env").write_text(
        "AZURE_TENANT_ID=11111111-2222-3333-4444-555555555555\n"
        "AZURE_CLIENT_ID=66666666-7777-8888-9999-aaaaaaaaaaaa\n"
        "AZURE_CLIENT_SECRET=Abc8Q~qwertyuiopasdfghjklzxcvbnm1234567890\n",
        encoding="utf-8",
    )
    partners = find_partner_credential(
        primary_secret_type="azure_ad_secret",
        primary_file_path="app.env",
        primary_line=3,
        all_findings=[],
        repo_root=str(tmp_path),
    )
    assert partners is not None
    assert partners["azure_client_id"] == "66666666-7777-8888-9999-aaaaaaaaaaaa"
    assert partners["azure_tenant_id"] == "11111111-2222-3333-4444-555555555555"
    assert partners["_pair_key"] == "azure_ad_paired"


@pytest.mark.asyncio
async def test_the_detected_value_is_passed_as_the_secret(monkeypatch):
    """The argument order. `_raw_value` is the client SECRET — passing
    it as the client id is what the old lambda did, and it would have
    authenticated with a UUID-shaped secret against a secret-shaped id."""
    seen = {}

    async def _spy(client_id, client_secret, tenant_id):
        seen.update(cid=client_id, secret=client_secret, tid=tenant_id)
        return None

    monkeypatch.setattr(v, "verify_azure_ad", _spy)
    await v.VERIFIERS["azure_ad_paired"]({
        "_raw_value": "the-client-secret",
        "azure_client_id": "the-client-id",
        "azure_tenant_id": "the-tenant",
    })
    assert seen == {"cid": "the-client-id",
                    "secret": "the-client-secret",
                    "tid": "the-tenant"}
