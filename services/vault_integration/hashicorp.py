# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""HashiCorp Vault KV v2 integration."""

import structlog
from typing import Optional

from services.vault_integration.base import VaultProviderBase, VaultSecret

logger = structlog.get_logger()


class HashiCorpVaultProvider(VaultProviderBase):
    provider = "hashicorp_vault"

    def __init__(self, config: dict):
        self.url = config.get("url", "").rstrip("/")
        self.token = config.get("token", "")
        self.namespace = config.get("namespace")
        self.mount_point = config.get("mount_point", "secret")

    def _headers(self) -> dict:
        h = {"X-Vault-Token": self.token}
        if self.namespace:
            h["X-Vault-Namespace"] = self.namespace
        return h

    async def test_connection(self) -> bool:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.url}/v1/sys/health", headers=self._headers())
                return resp.status_code in (200, 429, 472, 473)  # Vault health codes
        except Exception as e:
            logger.error("vault_connection_failed", error=str(e)[:200])
            return False

    async def list_secrets(self, prefix: str = "") -> list[VaultSecret]:
        secrets = []
        try:
            import httpx
            path = f"{self.url}/v1/{self.mount_point}/metadata/{prefix}"
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.request("LIST", path, headers=self._headers())
                if resp.status_code == 200:
                    keys = resp.json().get("data", {}).get("keys", [])
                    for key in keys:
                        full_path = f"{prefix}{key}" if prefix else key
                        if key.endswith("/"):
                            # Recurse into subdirectory
                            sub = await self.list_secrets(full_path)
                            secrets.extend(sub)
                        else:
                            secrets.append(VaultSecret(path=full_path, name=key))
        except Exception as e:
            logger.error("vault_list_failed", error=str(e)[:200])
        return secrets

    async def get_secret_metadata(self, path: str) -> Optional[dict]:
        try:
            import httpx
            url = f"{self.url}/v1/{self.mount_point}/metadata/{path}"
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers=self._headers())
                if resp.status_code == 200:
                    return resp.json().get("data", {})
        except Exception as e:
            logger.error("vault_metadata_failed", error=str(e)[:200])
        return None

    async def rotate_secret(self, path: str, new_value: str) -> bool:
        try:
            import httpx
            url = f"{self.url}/v1/{self.mount_point}/data/{path}"
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, json={"data": {"value": new_value}}, headers=self._headers())
                return resp.status_code == 200
        except Exception as e:
            logger.error("vault_rotate_failed", error=str(e)[:200])
            return False
