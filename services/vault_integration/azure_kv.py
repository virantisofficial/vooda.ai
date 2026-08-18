# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Azure Key Vault integration."""

import structlog
from typing import Optional

from services.vault_integration.base import VaultProviderBase, VaultSecret

logger = structlog.get_logger()


class AzureKeyVaultProvider(VaultProviderBase):
    provider = "azure_key_vault"

    #: Login authority and token scope per Azure cloud. Both differ
    #: together — a sovereign tenant authenticates against its own
    #: authority AND requests a scope on its own vault suffix — so
    #: hardcoding the public pair locked out every Azure China,
    #: US Government and Germany customer, with no setting to change it.
    #: Keyed by the vault URL's DNS suffix, which is what the operator
    #: already pastes in.
    CLOUDS = {
        "vault.azure.net": ("https://login.microsoftonline.com", "https://vault.azure.net/.default"),
        "vault.azure.cn": ("https://login.chinacloudapi.cn", "https://vault.azure.cn/.default"),
        "vault.usgovcloudapi.net": ("https://login.microsoftonline.us", "https://vault.usgovcloudapi.net/.default"),
        "vault.microsoftazure.de": ("https://login.microsoftonline.de", "https://vault.microsoftazure.de/.default"),
    }

    def __init__(self, config: dict):
        self.vault_url = (config.get("vault_url") or "").rstrip("/")
        self.tenant_id = config.get("tenant_id", "")
        self.client_id = config.get("client_id", "")
        self.client_secret = config.get("client_secret", "")

        authority, scope = self._cloud_for(self.vault_url)
        # Explicit overrides win. Beyond the sovereign clouds these also
        # let the provider be pointed at a local emulator, which is the
        # only way its data plane gets exercised without a live tenant.
        self.authority_host = (config.get("authority_host") or authority).rstrip("/")
        self.scope = config.get("scope") or scope

    @classmethod
    def _cloud_for(cls, vault_url: str) -> tuple[str, str]:
        host = vault_url.split("//")[-1].split("/")[0].lower()
        for suffix, pair in cls.CLOUDS.items():
            if host.endswith(suffix):
                return pair
        return cls.CLOUDS["vault.azure.net"]

    async def _get_token(self) -> str:
        import httpx
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{self.authority_host}/{self.tenant_id}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": self.scope,
                },
            )
            resp.raise_for_status()
            return resp.json()["access_token"]

    async def test_connection(self) -> bool:
        try:
            token = await self._get_token()
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self.vault_url}/secrets?api-version=7.4&maxresults=1",
                    headers={"Authorization": f"Bearer {token}"},
                )
                return resp.status_code == 200
        except Exception as e:
            logger.error("azure_kv_connection_failed", error=str(e)[:200])
            return False

    async def list_secrets(self, prefix: str = "") -> list[VaultSecret]:
        secrets = []
        try:
            token = await self._get_token()
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                next_url = f"{self.vault_url}/secrets?api-version=7.4"
                while next_url:
                    resp = await client.get(next_url, headers={"Authorization": f"Bearer {token}"})
                    if resp.status_code != 200:
                        break
                    data = resp.json()
                    for s in data.get("value", []):
                        name = s["id"].split("/")[-1]
                        if prefix and not name.startswith(prefix):
                            continue
                        secrets.append(VaultSecret(
                            path=name, name=name,
                            metadata={"enabled": s.get("attributes", {}).get("enabled"), "content_type": s.get("contentType")},
                        ))
                    next_url = data.get("nextLink")
        except Exception as e:
            logger.error("azure_kv_list_failed", error=str(e)[:200])
        return secrets

    async def get_secret_metadata(self, path: str) -> Optional[dict]:
        try:
            token = await self._get_token()
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self.vault_url}/secrets/{path}?api-version=7.4",
                    headers={"Authorization": f"Bearer {token}"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    attrs = data.get("attributes", {})
                    return {"enabled": attrs.get("enabled"), "created": attrs.get("created"), "updated": attrs.get("updated"), "expires": attrs.get("exp"), "content_type": data.get("contentType")}
        except Exception as e:
            logger.error("azure_kv_metadata_failed", error=str(e)[:200])
        return None

    async def rotate_secret(self, path: str, new_value: str) -> bool:
        try:
            token = await self._get_token()
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.put(
                    f"{self.vault_url}/secrets/{path}?api-version=7.4",
                    json={"value": new_value},
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                )
                return resp.status_code == 200
        except Exception as e:
            logger.error("azure_kv_rotate_failed", error=str(e)[:200])
            return False
