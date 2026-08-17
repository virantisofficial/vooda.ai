# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""OneDrive / SharePoint source adapter — scans text-like files in M365 file storage.

Coverage:
  - SharePoint sites the app can see via /sites
  - OneDrive (per-user) is reachable via /users/{id}/drive — we focus
    SHAREDPOINT-side here because per-user OneDrive scanning is a
    privacy-heavy surface that needs explicit per-tenant consent.
  - Recursively walks folders, downloads text-like files, scans contents.

Auth + setup matches the Teams adapter (Microsoft Graph application
permissions, shared MicrosoftGraphClient). Required scopes:
  - Sites.Read.All
  - Files.Read.All

Out of scope (deliberate):
  - Per-user OneDrive (one drive per user × thousands of users would
    be enormous; better as a separate adapter once we have Files.Read
    delegated permissions wired).
  - Office document binary parsing — we read .docx / .xlsx as text
    only via the `?format=text` Graph download trick where applicable;
    real binary Office parsing (which would catch e.g. macros) is a
    follow-up.
"""
from __future__ import annotations

from typing import AsyncIterator

import httpx

from packages.common.outbound_http import make_async_client
from services.source_scanners.adapters._msgraph import (
    GRAPH_ROOT,
    MicrosoftGraphClient,
)
from services.source_scanners.base import ScanableContent, SourceAdapter
from services.source_scanners.file_routing import content_type_for_path


# Whitelist of MIME prefixes / filename suffixes for download-and-scan.
# Mirrors the Jira adapter's list — same rationale (text-like only,
# binaries skipped to save bandwidth + CPU).
_TEXT_MIME_PREFIXES = (
    "text/", "application/json", "application/xml",
    "application/yaml", "application/x-yaml",
    "application/javascript", "application/x-sh",
    "application/x-properties",
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


class OneDriveSharePointAdapter(SourceAdapter):
    source_type = "onedrive_sharepoint"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        site_filter: str = "*",
        max_file_size_mb: int = 10,
    ):
        self.client = MicrosoftGraphClient(
            tenant_id, client_id, client_secret,
            source_type="onedrive_sharepoint",
        )
        self.site_filter = (
            [s.strip() for s in site_filter.split(",") if s.strip()] if site_filter != "*" else []
        )
        self.max_file_bytes = max(1, int(max_file_size_mb)) * 1024 * 1024
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        # Probe /sites — checks Sites.Read.All, the scope this adapter
        # actually needs. The default /teams probe in MicrosoftGraphClient
        # would fail with 403 even on a correctly-permissioned OneDrive
        # app registration that was never granted Team.ReadBasic.All.
        return await self.client.test_connection(probe_path="/sites?search=*&$top=1")

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        last_sync = sync_state.get("last_sync", "")

        async with make_async_client(timeout=60) as client:
            # SharePoint sites: /sites?search=* lists every site the
            # app can see. Empty search returns the root site only;
            # we use `?search=*` to enumerate.
            async for site in self.client.get_paged(client, f"{GRAPH_ROOT}/sites?search=*"):
                site_id = site.get("id")
                site_name = site.get("displayName") or site.get("name", site_id)
                if not site_id:
                    continue
                if self.site_filter and site_name not in self.site_filter:
                    continue

                # Each site can have multiple drives (default
                # "Documents" + any custom document libraries).
                drives_url = f"{GRAPH_ROOT}/sites/{site_id}/drives"
                async for drive in self.client.get_paged(client, drives_url):
                    drive_id = drive.get("id")
                    drive_name = drive.get("name", drive_id)
                    if not drive_id:
                        continue

                    # Walk the drive's root recursively. delta API
                    # would be more efficient but adds state-tracking
                    # complexity; deferred to a follow-up.
                    async for item in self._walk_folder(client, drive_id, "root", path=""):
                        # Only files, only text-like.
                        if "folder" in item:
                            continue
                        f = item.get("file") or {}
                        filename = item.get("name", "") or ""
                        size = int(item.get("size") or 0)
                        mime = (f.get("mimeType") or "").lower()
                        modified = item.get("lastModifiedDateTime", "")

                        if size > self.max_file_bytes:
                            continue
                        if last_sync and modified and modified <= last_sync:
                            continue
                        is_text = (
                            any(mime.startswith(p) for p in _TEXT_MIME_PREFIXES)
                            or any(filename.lower().endswith(s) for s in _TEXT_FILENAME_SUFFIXES)
                        )
                        if not is_text:
                            continue

                        # Download content. Graph offers a
                        # /content endpoint that 302s to a transient
                        # CDN URL; httpx follow_redirects=True picks
                        # it up.
                        item_id = item.get("id", "")
                        download_url = f"{GRAPH_ROOT}/drives/{drive_id}/items/{item_id}/content"
                        try:
                            h = await self.client.headers(client)
                            r = await client.get(
                                download_url, headers=h,
                                follow_redirects=True, timeout=60,
                            )
                            if r.status_code != 200:
                                continue
                            text = r.text[: self.max_file_bytes]
                        except Exception:
                            continue

                        if modified > self._updated_sync_state.get("last_sync", ""):
                            self._updated_sync_state["last_sync"] = modified

                        if text.strip():
                            yield ScanableContent(
                                source_locator=f"m365://{site_id}/{drive_id}/{item_id}/{filename}",
                                content=text,
                                # Route prose extensions to "page" so COLLAB
                                # rules fire on Office docs / runbooks;
                                # structured files stay at "file".
                                content_type=content_type_for_path(filename, default="file"),
                                deep_link_url=item.get("webUrl") or "",
                                metadata={
                                    "site_id": site_id, "site_name": site_name,
                                    "drive_id": drive_id, "drive_name": drive_name,
                                    "filename": filename, "mimetype": mime,
                                    "size_bytes": size,
                                },
                            )

    async def _walk_folder(
        self,
        client: httpx.AsyncClient,
        drive_id: str,
        item_id: str,
        path: str,
        depth: int = 0,
    ) -> AsyncIterator[dict]:
        # Hard recursion cap to defend against pathological symlink-y
        # SharePoint structures. 50 levels is more than any sane
        # document library would have.
        if depth > 50:
            return
        url = f"{GRAPH_ROOT}/drives/{drive_id}/items/{item_id}/children"
        async for child in self.client.get_paged(client, url):
            yield child
            if "folder" in child:
                child_id = child.get("id")
                child_name = child.get("name", "")
                if child_id:
                    async for grand in self._walk_folder(
                        client, drive_id, child_id,
                        f"{path}/{child_name}".strip("/"), depth + 1,
                    ):
                        yield grand

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
