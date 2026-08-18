# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""GCP Secret Manager integration."""

import structlog
from typing import Optional

from services.vault_integration.base import VaultProviderBase, VaultSecret

logger = structlog.get_logger()


class GCPSecretManagerProvider(VaultProviderBase):
    provider = "gcp_secret_manager"

    #: Google's global Secret Manager endpoint. Overridable because
    #: regional endpoints (secretmanager.<location>.rep.googleapis.com)
    #: and Private Service Connect are both real deployments this
    #: provider could not reach while the host was hardcoded in four
    #: places — and because pointing it at a local emulator is the only
    #: way its data plane gets exercised without a live GCP project.
    DEFAULT_ENDPOINT = "https://secretmanager.googleapis.com"

    def __init__(self, config: dict):
        self.project_id = config.get("project_id", "")
        self.service_account_json = config.get("service_account_json", "")
        self.api_endpoint = (config.get("api_endpoint") or self.DEFAULT_ENDPOINT).rstrip("/")

    async def _get_token(self) -> str:
        from google.oauth2 import service_account
        from google.auth.transport.requests import Request
        import json
        info = json.loads(self.service_account_json) if isinstance(self.service_account_json, str) else self.service_account_json
        creds = service_account.Credentials.from_service_account_info(info, scopes=["https://www.googleapis.com/auth/cloud-platform"])
        creds.refresh(Request())
        return creds.token

    async def test_connection(self) -> bool:
        try:
            token = await self._get_token()
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self.api_endpoint}/v1/projects/{self.project_id}/secrets?pageSize=1",
                    headers={"Authorization": f"Bearer {token}"},
                )
                return resp.status_code == 200
        except Exception as e:
            logger.error("gcp_sm_connection_failed", error=str(e)[:200])
            return False

    async def list_secrets(self, prefix: str = "") -> list[VaultSecret]:
        secrets = []
        try:
            token = await self._get_token()
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                next_token = None
                while True:
                    params = {"pageSize": 100}
                    if next_token:
                        params["pageToken"] = next_token
                    resp = await client.get(
                        f"{self.api_endpoint}/v1/projects/{self.project_id}/secrets",
                        headers={"Authorization": f"Bearer {token}"}, params=params,
                    )
                    if resp.status_code != 200:
                        break
                    data = resp.json()
                    for s in data.get("secrets", []):
                        name = s["name"].split("/")[-1]
                        if prefix and not name.startswith(prefix):
                            continue
                        secrets.append(VaultSecret(
                            path=name, name=name,
                            created_at=None,
                            metadata={"replication": s.get("replication", {}).get("automatic", {})},
                        ))
                    next_token = data.get("nextPageToken")
                    if not next_token:
                        break
        except Exception as e:
            logger.error("gcp_sm_list_failed", error=str(e)[:200])
        return secrets

    async def get_secret_metadata(self, path: str) -> Optional[dict]:
        try:
            token = await self._get_token()
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self.api_endpoint}/v1/projects/{self.project_id}/secrets/{path}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                if resp.status_code == 200:
                    return resp.json()
        except Exception as e:
            logger.error("gcp_sm_metadata_failed", error=str(e)[:200])
        return None

    async def rotate_secret(self, path: str, new_value: str) -> bool:
        try:
            token = await self._get_token()
            import httpx, base64
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{self.api_endpoint}/v1/projects/{self.project_id}/secrets/{path}:addVersion",
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    json={"payload": {"data": base64.b64encode(new_value.encode()).decode()}},
                )
                return resp.status_code == 200
        except Exception as e:
            logger.error("gcp_sm_rotate_failed", error=str(e)[:200])
            return False
