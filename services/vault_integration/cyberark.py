# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""CyberArk Conjur / Central Credential Provider integration.

Targets Conjur (Enterprise or OSS), which is CyberArk's REST-native
secrets API.  The older Central Credential Provider (CCP/AIM) exposes a
different, certificate-authenticated endpoint and is not covered here —
a CCP deployment should be fronted by Conjur, which is CyberArk's own
recommendation for programmatic access.

Auth is Conjur's two-step exchange: an API key is traded for a
short-lived access token, which is then sent base64-encoded in the
``Authorization: Token token="<b64>"`` header.  Tokens are valid for
roughly eight minutes, so we fetch one per operation rather than
caching — these calls are infrequent (a connection test, a coverage
sweep, a rotation write-back), and a cache would add expiry handling
for no real gain.
"""

import base64
import structlog
from typing import Optional
from urllib.parse import quote

from services.vault_integration.base import VaultProviderBase, VaultSecret

logger = structlog.get_logger()


class CyberArkProvider(VaultProviderBase):
    provider = "cyberark"

    def __init__(self, config: dict):
        self.url = config.get("url", "").rstrip("/")
        self.account = config.get("account", "")
        self.login = config.get("login", "")
        self.api_key = config.get("api_key", "")

    async def _get_token(self) -> str:
        """Exchange the API key for a short-lived access token."""
        import httpx

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{self.url}/authn/{quote(self.account, safe='')}"
                f"/{quote(self.login, safe='')}/authenticate",
                content=self.api_key,
                headers={"Content-Type": "text/plain", "Accept-Encoding": "base64"},
            )
            resp.raise_for_status()
            # With Accept-Encoding: base64 Conjur returns the token
            # already base64-encoded, ready for the header. Without it
            # the body is raw JSON that we must encode ourselves.
            body = resp.text.strip()
            if resp.headers.get("Content-Encoding") == "base64":
                return body
            return base64.b64encode(body.encode("utf-8")).decode("utf-8")

    def _headers(self, token: str) -> dict:
        return {"Authorization": f'Token token="{token}"'}

    async def test_connection(self) -> bool:
        try:
            import httpx

            token = await self._get_token()
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self.url}/resources/{quote(self.account, safe='')}",
                    headers=self._headers(token),
                    params={"kind": "variable", "limit": 1},
                )
                return resp.status_code == 200
        except Exception as e:
            logger.error("cyberark_connection_failed", error=str(e)[:200])
            return False

    async def list_secrets(self, prefix: str = "") -> list[VaultSecret]:
        secrets: list[VaultSecret] = []
        try:
            import httpx

            token = await self._get_token()
            # Conjur pages at 1000; walk until a short page comes back.
            offset, page_size = 0, 1000
            async with httpx.AsyncClient(timeout=30) as client:
                while True:
                    params = {"kind": "variable", "limit": page_size, "offset": offset}
                    if prefix:
                        params["search"] = prefix
                    resp = await client.get(
                        f"{self.url}/resources/{quote(self.account, safe='')}",
                        headers=self._headers(token),
                        params=params,
                    )
                    if resp.status_code != 200:
                        break
                    batch = resp.json()
                    if not isinstance(batch, list):
                        break
                    for item in batch:
                        # id looks like "account:variable:path/to/secret"
                        rid = item.get("id", "")
                        path = rid.split(":", 2)[2] if rid.count(":") >= 2 else rid
                        secrets.append(
                            VaultSecret(
                                path=path,
                                name=path.rsplit("/", 1)[-1],
                                metadata={"policy": item.get("policy", "")},
                            )
                        )
                    if len(batch) < page_size:
                        break
                    offset += page_size
        except Exception as e:
            logger.error("cyberark_list_failed", error=str(e)[:200])
        return secrets

    async def get_secret_metadata(self, path: str) -> Optional[dict]:
        """Return resource metadata, never the secret value itself."""
        try:
            import httpx

            token = await self._get_token()
            rid = f"{self.account}:variable:{path}"
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self.url}/resources/{quote(rid, safe='')}",
                    headers=self._headers(token),
                )
                if resp.status_code == 200:
                    data = resp.json()
                    versions = data.get("secrets", []) or []
                    latest = versions[-1] if versions else {}
                    return {
                        "policy": data.get("policy"),
                        "owner": data.get("owner"),
                        "version_count": len(versions),
                        "updated_at": latest.get("created_at"),
                        "annotations": data.get("annotations", []),
                    }
        except Exception as e:
            logger.error("cyberark_metadata_failed", error=str(e)[:200])
        return None

    async def rotate_secret(self, path: str, new_value: str) -> bool:
        try:
            import httpx

            token = await self._get_token()
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{self.url}/secrets/{quote(self.account, safe='')}"
                    f"/variable/{quote(path, safe='')}",
                    content=new_value,
                    headers={**self._headers(token), "Content-Type": "text/plain"},
                )
                return resp.status_code in (200, 201)
        except Exception as e:
            logger.error("cyberark_rotate_failed", error=str(e)[:200])
            return False

    async def get_secret_version_count(self, path: str) -> int:
        meta = await self.get_secret_metadata(path)
        return int(meta.get("version_count", 0)) if meta else 0
