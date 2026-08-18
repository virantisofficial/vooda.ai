# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Box source adapter — text-like files in a Box account.

Auth: Box developer token (simplest path) or OAuth 2.0. We support
the developer-token flow first because it's a single secret to
manage. JWT app-auth is a follow-up.

Walks user's root folder recursively, downloads text-like files
under a configurable size cap, scans content. Same MIME / suffix
filter shape as the other file adapters.
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator, Optional

import httpx

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_http_error,
    classify_network_error,
)
from services.source_scanners.base import ScanableContent, SourceAdapter
from services.source_scanners.file_routing import content_type_for_path


_API = "https://api.box.com/2.0"

_TEXT_MIME_PREFIXES = (
    "text/", "application/json", "application/xml",
    "application/yaml", "application/x-yaml",
    "application/javascript", "application/x-sh",
)
_TEXT_FILENAME_SUFFIXES = (
    ".env", ".env.example", ".env.local", ".env.dev", ".env.prod",
    ".properties", ".conf", ".cfg", ".ini",
    ".log", ".csv", ".tsv", ".tf", ".tfvars",
    ".sh", ".bash", ".zsh", ".ps1", ".bat",
    ".kubeconfig", ".pem", ".key", ".crt", ".pub",
    ".dockerfile", ".gitconfig",
    ".md", ".txt", ".json", ".yml", ".yaml", ".xml",
)


class BoxAdapter(SourceAdapter):
    source_type = "box"

    def __init__(
        self,
        access_token: str,
        root_folder_id: str = "0",
        max_file_size_mb: int = 10,
    ):
        if not access_token:
            raise ValueError("Box adapter requires an access_token")
        self.access_token = access_token
        self.root_folder_id = root_folder_id or "0"  # 0 = user root
        self.max_file_bytes = max(1, int(max_file_size_mb)) * 1024 * 1024
        self._headers = {"Authorization": f"Bearer {access_token}",
                         "Accept": "application/json"}
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Probe ``/users/me`` — small, every Box account has it."""
        ctx = {"adapter": "box"}
        try:
            async with make_async_client(timeout=15) as c:
                r = await c.get(f"{_API}/users/me", headers=self._headers)
                if r.status_code == 200:
                    user = r.json() or {}
                    name = user.get("name") or user.get("login", "Box user")
                    return {"status": "success", "message": f"Connected as {name}"}
                err = classify_http_error(
                    r, provider="box", context=ctx,
                    auth_fix_steps=[
                        "Box developer tokens expire after 60 minutes — generate a fresh one at developer.box.com",
                        "For long-running scans, switch to a JWT app or OAuth 2.0 with refresh",
                    ],
                    permission_fix_steps=[
                        "Confirm the user has at least Viewer access on the target folders",
                        "If using a JWT app, the service account must be added as a collaborator on each folder",
                    ],
                )
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        last_sync = sync_state.get("last_sync", "")

        async with make_async_client(timeout=60) as c:
            async for item in self._walk_folder(c, self.root_folder_id, last_sync, depth=0):
                yield item

    async def _walk_folder(
        self,
        c: httpx.AsyncClient,
        folder_id: str,
        last_sync: str,
        depth: int = 0,
    ) -> AsyncIterator[ScanableContent]:
        if depth > 50:
            return
        offset = 0
        while True:
            r = await c.get(
                f"{_API}/folders/{folder_id}/items",
                headers=self._headers,
                params={
                    "fields": "id,name,type,size,modified_at,extension",
                    "limit": "1000",
                    "offset": str(offset),
                },
            )
            if r.status_code != 200:
                return
            data = r.json() or {}
            entries = data.get("entries") or []
            for entry in entries:
                etype = entry.get("type")
                if etype == "folder":
                    async for sub in self._walk_folder(
                        c, entry.get("id"), last_sync, depth + 1,
                    ):
                        yield sub
                    continue
                if etype != "file":
                    continue

                filename = entry.get("name", "") or ""
                ext = (entry.get("extension") or "").lower()
                size = int(entry.get("size") or 0)
                modified = entry.get("modified_at", "")

                if size > self.max_file_bytes or size == 0:
                    continue
                if last_sync and modified and modified <= last_sync:
                    continue

                is_text = (
                    any(filename.lower().endswith(s) for s in _TEXT_FILENAME_SUFFIXES)
                    or (ext and f".{ext}" in _TEXT_FILENAME_SUFFIXES)
                )
                if not is_text:
                    continue

                try:
                    content_url = f"{_API}/files/{entry['id']}/content"
                    fr = await c.get(content_url, headers=self._headers,
                                     follow_redirects=True, timeout=60)
                    if fr.status_code != 200:
                        continue
                    text = fr.text[: self.max_file_bytes]
                except Exception:
                    continue

                if not text.strip():
                    continue
                if modified > self._updated_sync_state.get("last_sync", ""):
                    self._updated_sync_state["last_sync"] = modified

                yield ScanableContent(
                    source_locator=f"box://file/{entry['id']}/{filename}",
                    content=text,
                    # Route prose extensions to "page" so COLLAB rules
                    # fire (notes/runbooks); structured files stay at
                    # "file" for the strict CODE rules.
                    content_type=content_type_for_path(filename, default="file"),
                    deep_link_url=f"https://app.box.com/file/{entry['id']}",
                    metadata={"file_id": entry["id"], "filename": filename,
                              "extension": ext, "size_bytes": size,
                              "folder_id": folder_id},
                )

            total = int(data.get("total_count") or 0)
            offset += len(entries)
            if offset >= total or not entries:
                break
            await asyncio.sleep(0.2)

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
