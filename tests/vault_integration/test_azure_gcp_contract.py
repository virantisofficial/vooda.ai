"""Exercise the Azure and GCP data planes, which nothing else reaches.

These two providers cannot be run against a real service in this suite:
Microsoft and Google ship no emulator, and a test suite should not
require a cloud account. Until now that meant their connect, list,
pagination, metadata and write-back paths had never executed once — a
credential rejection at the authority proves the OAuth call is shaped
right and nothing whatsoever about the code after it.

So they run against local fakes implementing the published REST
contracts (see fakes.py). A pass means the client is correct against
the documented contract; it is not a substitute for one run against a
real tenant.
"""

import json

import pytest

from services.vault_integration.azure_kv import AzureKeyVaultProvider
from services.vault_integration.gcp_sm import GCPSecretManagerProvider
from tests.vault_integration.fakes import FakeVaultServer

SECRETS = {
    "stripe-api-key": "old",
    "database-password": "old",
    "sendgrid-api-key": "old",
}


# ── Azure Key Vault ───────────────────────────────────────────────
def _azure(server) -> AzureKeyVaultProvider:
    return AzureKeyVaultProvider({
        "vault_url": server.url,
        "tenant_id": "t",
        "client_id": "c",
        "client_secret": "s",
        "authority_host": server.url,
    })


@pytest.mark.asyncio
async def test_azure_connects():
    with FakeVaultServer("azure", SECRETS) as srv:
        assert await _azure(srv).test_connection() is True


@pytest.mark.asyncio
async def test_azure_lists_every_page():
    """The fake pages at 2, so 3 secrets forces a nextLink follow.

    Pagination is the part most likely to be silently wrong — a client
    that ignores nextLink still "works" against a small vault and then
    quietly under-reports a real one.
    """
    with FakeVaultServer("azure", SECRETS) as srv:
        got = await _azure(srv).list_secrets()
        assert sorted(s.name for s in got) == sorted(SECRETS)


@pytest.mark.asyncio
async def test_azure_parses_the_name_out_of_a_full_url_id():
    """Key Vault returns ids as https://…/secrets/<name>, not bare names."""
    with FakeVaultServer("azure", SECRETS) as srv:
        got = await _azure(srv).list_secrets()
        assert all("/" not in s.name for s in got)


@pytest.mark.asyncio
async def test_azure_write_back_is_readable():
    with FakeVaultServer("azure", SECRETS) as srv:
        assert await _azure(srv).rotate_secret("stripe-api-key", "rotated") is True
        assert srv.stored["stripe-api-key"] == "rotated"


@pytest.mark.asyncio
async def test_azure_metadata():
    with FakeVaultServer("azure", SECRETS) as srv:
        meta = await _azure(srv).get_secret_metadata("stripe-api-key")
        assert meta and meta["enabled"] is True


@pytest.mark.asyncio
async def test_azure_rejects_a_bad_token():
    with FakeVaultServer("azure", SECRETS) as srv:
        p = _azure(srv)
        p._get_token = lambda: _wrong_token()          # type: ignore[assignment]
        assert await p.test_connection() is False


async def _wrong_token() -> str:
    return "not-the-token"


@pytest.mark.parametrize(
    "vault_url,authority,scope_suffix",
    [
        ("https://v.vault.azure.net", "login.microsoftonline.com", "vault.azure.net"),
        ("https://v.vault.azure.cn", "login.chinacloudapi.cn", "vault.azure.cn"),
        ("https://v.vault.usgovcloudapi.net", "login.microsoftonline.us", "vault.usgovcloudapi.net"),
    ],
)
def test_azure_sovereign_clouds_pick_the_right_authority(vault_url, authority, scope_suffix):
    """A China or GovCloud tenant must not be sent to the public login.

    Both the authority and the token scope move together, and both were
    hardcoded to the public cloud — so those customers could not
    authenticate at all, with no setting to change it.
    """
    p = AzureKeyVaultProvider({"vault_url": vault_url})
    assert authority in p.authority_host
    assert p.scope == f"https://{scope_suffix}/.default"


# ── GCP Secret Manager ────────────────────────────────────────────
def _service_account_json(token_uri: str) -> str:
    """A structurally valid service account whose token_uri we control.

    google-auth signs a real JWT with this key and posts it to
    token_uri, so the auth path runs for real — only the endpoint that
    answers is local.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return json.dumps({
        "type": "service_account",
        "project_id": "p",
        "private_key_id": "k",
        "private_key": pem,
        "client_email": "vooda@p.iam.gserviceaccount.com",
        "client_id": "1",
        "token_uri": token_uri,
    })


def _gcp(server) -> GCPSecretManagerProvider:
    return GCPSecretManagerProvider({
        "project_id": "p",
        "service_account_json": _service_account_json(f"{server.url}/token"),
        "api_endpoint": server.url,
    })


@pytest.mark.asyncio
async def test_gcp_connects():
    with FakeVaultServer("gcp", SECRETS) as srv:
        assert await _gcp(srv).test_connection() is True


@pytest.mark.asyncio
async def test_gcp_lists_every_page():
    with FakeVaultServer("gcp", SECRETS) as srv:
        got = await _gcp(srv).list_secrets()
        assert sorted(s.name for s in got) == sorted(SECRETS)


@pytest.mark.asyncio
async def test_gcp_write_back_is_readable():
    with FakeVaultServer("gcp", SECRETS) as srv:
        assert await _gcp(srv).rotate_secret("stripe-api-key", "rotated") is True
        assert srv.stored["stripe-api-key"] == "rotated"


def test_gcp_defaults_to_the_global_endpoint():
    p = GCPSecretManagerProvider({"project_id": "p", "service_account_json": "{}"})
    assert p.api_endpoint == "https://secretmanager.googleapis.com"


def test_gcp_accepts_a_regional_endpoint():
    """Regional endpoints and Private Service Connect are real setups
    the provider could not reach while the host was hardcoded."""
    p = GCPSecretManagerProvider({
        "project_id": "p",
        "service_account_json": "{}",
        "api_endpoint": "https://secretmanager.europe-west4.rep.googleapis.com/",
    })
    assert p.api_endpoint == "https://secretmanager.europe-west4.rep.googleapis.com"
