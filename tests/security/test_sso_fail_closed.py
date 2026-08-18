"""SSO must never authenticate anyone while it is disabled.

The SAML ACS endpoint parsed the assertion XML and trusted the <NameID>
email with NO signature validation, so a forged SAMLResponse for any
address — admin included — minted a valid session: a complete
unauthenticated auth bypass. Until SSO is rebuilt on a vetted SAML
library, settings.SSO_ENABLED is False and every SSO endpoint that could
issue a session fails closed. This proves the bypass stays shut.
"""

import base64

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def sso_client():
    from apps.api.app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


def _forged_saml(email: str) -> str:
    xml = (
        '<?xml version="1.0"?>'
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        f"<saml:Assertion><saml:Subject><saml:NameID>{email}</saml:NameID>"
        "</saml:Subject></saml:Assertion></samlp:Response>"
    )
    return base64.b64encode(xml.encode()).decode()


@pytest.mark.asyncio
async def test_forged_saml_assertion_is_rejected(sso_client):
    """The exact exploit — a forged admin assertion — must not issue a
    token. Fails closed (503), never a 307 redirect carrying sso_token."""
    r = await sso_client.post(
        "/api/v1/sso/saml/acs",
        data={"SAMLResponse": _forged_saml("admin@vooda.ai")},
        follow_redirects=False,
    )
    assert r.status_code == 503, f"SSO ACS did not fail closed: {r.status_code}"
    assert "sso_token" not in (r.headers.get("location") or "")
    assert "sso_token" not in r.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/sso/oidc/authorize?provider=okta&tenant_slug=default",
        "/api/v1/sso/oidc/callback?code=x&state=y",
    ],
)
async def test_sso_login_endpoints_fail_closed(sso_client, path):
    r = await sso_client.get(path, follow_redirects=False)
    assert r.status_code == 503, f"{path} did not fail closed: {r.status_code}"


def test_sso_is_disabled_by_default():
    """The kill switch defaults off. If someone flips it on, they must
    have rebuilt SAML validation first — this makes the default explicit."""
    from apps.api.app.core.config import settings
    assert settings.SSO_ENABLED is False
