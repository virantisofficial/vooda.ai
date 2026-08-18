# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Postman source adapter — scans collections and environments for hardcoded tokens."""

import asyncio
import json
from typing import AsyncIterator

import httpx

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_http_error,
    classify_network_error,
)
from services.source_scanners.base import SourceAdapter, ScanableContent

POSTMAN_API = "https://api.getpostman.com"


class PostmanSourceAdapter(SourceAdapter):
    source_type = "postman"

    def __init__(self, api_key: str, workspace_id: str = ""):
        self.api_key = api_key
        self.workspace_id = workspace_id
        self._headers = {"X-Api-Key": api_key}
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Probe ``/me`` — proves the X-Api-Key works."""
        ctx = {"adapter": "postman"}
        try:
            async with make_async_client(timeout=15) as client:
                r = await client.get(f"{POSTMAN_API}/me", headers=self._headers)
                if r.status_code == 200:
                    user = (r.json() or {}).get("user", {})
                    return {
                        "status": "success",
                        "message": f"Connected as {user.get('username', 'user')}",
                    }
                err = classify_http_error(
                    r, provider="postman", context=ctx,
                    auth_fix_steps=[
                        "Open postman.com → Settings → API Keys",
                        "Generate a new key (the old one may have been auto-revoked) and update Vooda",
                    ],
                    permission_fix_steps=[
                        "Confirm the API key was issued by a workspace admin if you want full visibility",
                        "Personal-tier keys only see the user's private workspaces",
                    ],
                )
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)

        async with make_async_client(timeout=30) as client:
            # Scan collections
            collections = await self._list_collections(client)
            for col in collections:
                col_id = col.get("uid", col.get("id", ""))
                col_name = col.get("name", "")
                updated_at = col.get("updatedAt", "")

                if updated_at <= sync_state.get(f"col_{col_id}", ""):
                    continue

                # Fetch full collection
                r = await client.get(f"{POSTMAN_API}/collections/{col_id}", headers=self._headers)
                if r.status_code != 200:
                    continue
                full = r.json().get("collection", {})
                content = json.dumps(full, indent=2)

                if content.strip():
                    yield ScanableContent(
                        source_locator=f"postman://collection/{col_id}",
                        content=content,
                        content_type="file",
                        deep_link_url=f"https://go.postman.co/collection/{col_id}",
                        metadata={"collection_name": col_name, "type": "collection"},
                    )
                self._updated_sync_state[f"col_{col_id}"] = updated_at
                await asyncio.sleep(0.5)

            # Scan environments
            envs = await self._list_environments(client)
            for env in envs:
                env_id = env.get("uid", env.get("id", ""))
                env_name = env.get("name", "")
                updated_at = env.get("updatedAt", "")

                if updated_at <= sync_state.get(f"env_{env_id}", ""):
                    continue

                r = await client.get(f"{POSTMAN_API}/environments/{env_id}", headers=self._headers)
                if r.status_code != 200:
                    continue
                full = r.json().get("environment", {})
                # Extract key-value pairs
                values = full.get("values", [])
                content = "\n".join(f"{v.get('key', '')}={v.get('value', '')}" for v in values)

                if content.strip():
                    yield ScanableContent(
                        source_locator=f"postman://environment/{env_id}",
                        content=content,
                        content_type="env_var",
                        deep_link_url=f"https://go.postman.co/environment/{env_id}",
                        metadata={"environment_name": env_name, "type": "environment", "var_count": len(values)},
                    )
                self._updated_sync_state[f"env_{env_id}"] = updated_at
                await asyncio.sleep(0.5)

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state

    async def _list_collections(self, client: httpx.AsyncClient) -> list:
        params = {}
        if self.workspace_id:
            params["workspace"] = self.workspace_id
        r = await client.get(f"{POSTMAN_API}/collections", headers=self._headers, params=params)
        return r.json().get("collections", []) if r.status_code == 200 else []

    async def _list_environments(self, client: httpx.AsyncClient) -> list:
        params = {}
        if self.workspace_id:
            params["workspace"] = self.workspace_id
        r = await client.get(f"{POSTMAN_API}/environments", headers=self._headers, params=params)
        return r.json().get("environments", []) if r.status_code == 200 else []
