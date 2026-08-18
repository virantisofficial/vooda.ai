# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Azure Blob Storage source adapter — scans text-like blobs in a storage account.

Coverage:
  - Lists containers in the configured storage account
  - Walks each container's blobs (all or a prefix)
  - Downloads text-like blobs (MIME-filtered, size-capped) and scans contents

Auth modes (Vooda accepts the simplest one — storage key auth):
  - Storage account key (REST API + SharedKey signature)
  - Future: Azure AD OAuth (app-only) for customers who use RBAC
    instead of account keys; SAS tokens; managed identity.

Why we ship key-auth first: it's by far the most common shape we see
in customer environments — most teams have an account key kicking
around, and AAD-RBAC for storage requires one extra app-registration
step that's worth its own follow-up.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
from datetime import datetime, timezone
from typing import AsyncIterator, Optional
from urllib.parse import quote

import httpx

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_azure_blob_error,
    classify_network_error,
)
from services.source_scanners.base import ScanableContent, SourceAdapter
from services.source_scanners.file_routing import content_type_for_path


_TEXT_MIME_PREFIXES = (
    "text/", "application/json", "application/xml",
    "application/yaml", "application/x-yaml",
    "application/javascript", "application/x-sh",
    "application/x-properties",
)
_TEXT_FILENAME_SUFFIXES = (
    ".env", ".env.example", ".env.local",
    ".properties", ".conf", ".cfg", ".ini",
    ".log", ".csv", ".tsv", ".tf", ".tfvars",
    ".sh", ".bash", ".ps1",
    ".kubeconfig", ".pem", ".key", ".crt",
    ".dockerfile", ".gitconfig",
    ".md", ".txt", ".json", ".yml", ".yaml", ".xml",
)


def _looks_text(blob: dict) -> bool:
    mime = (blob.get("ContentType") or "").lower()
    name = (blob.get("Name") or "").lower()
    return (
        any(mime.startswith(p) for p in _TEXT_MIME_PREFIXES)
        or any(name.endswith(s) for s in _TEXT_FILENAME_SUFFIXES)
    )


def _parse_blob_list_xml(xml: str) -> tuple[list[dict], Optional[str]]:
    """Parse the XML response from List Blobs. Returns (blobs, next_marker).

    Azure's List Blobs API returns XML, not JSON. Rather than pulling
    in an XML library for one-shot parsing, we use a small regex-based
    extractor — narrow scope, keeps the dependency surface small.
    """
    blobs: list[dict] = []
    for m in re.finditer(r"<Blob>(.*?)</Blob>", xml, re.DOTALL):
        chunk = m.group(1)
        def _get(tag: str) -> str:
            mm = re.search(rf"<{tag}>([^<]*)</{tag}>", chunk)
            return mm.group(1) if mm else ""
        size = _get("Content-Length") or _get("Content-Length")
        try:
            size_i = int(size) if size else 0
        except ValueError:
            size_i = 0
        blobs.append({
            "Name": _get("Name"),
            "ContentType": _get("Content-Type"),
            "Size": size_i,
            "LastModified": _get("Last-Modified"),
            "Etag": _get("Etag"),
        })
    nm = re.search(r"<NextMarker>([^<]*)</NextMarker>", xml)
    next_marker = nm.group(1) if (nm and nm.group(1)) else None
    return blobs, next_marker


class AzureBlobAdapter(SourceAdapter):
    source_type = "azure_blob"

    def __init__(
        self,
        account_name: str,
        account_key: str,
        container_name: str = "*",
        prefix: str = "",
        max_blob_size_mb: int = 10,
    ):
        if not (account_name and account_key):
            raise ValueError("Azure Blob requires account_name and account_key")
        self.account_name = account_name
        self.account_key = account_key
        self.container_filter = (
            [c.strip() for c in container_name.split(",") if c.strip()]
            if container_name != "*" else []
        )
        self.prefix = prefix or ""
        self.max_blob_bytes = max(1, int(max_blob_size_mb)) * 1024 * 1024
        self._updated_sync_state: dict = {}
        self._base = f"https://{account_name}.blob.core.windows.net"

    # ── SharedKey signing ──────────────────────────────────────
    # Azure's REST API uses a custom HMAC-SHA256 signature scheme.
    # See https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
    # We implement the minimal subset needed for List Containers,
    # List Blobs, and Get Blob.

    def _sign(self, method: str, path: str, params: dict, headers: dict) -> str:
        """Build the Authorization: SharedKey {account}:{signature} header value."""
        # Canonicalised headers: every x-ms-* header, lowercased,
        # alpha-sorted, joined with newlines.
        canon_headers = "\n".join(
            f"{k.lower()}:{v}" for k, v in sorted(headers.items())
            if k.lower().startswith("x-ms-")
        )
        # Canonicalised resource: /{account}{path}\n{param=value sorted}
        canon_resource = f"/{self.account_name}{path}"
        if params:
            sorted_params = sorted(params.items())
            canon_resource += "\n" + "\n".join(f"{k.lower()}:{v}" for k, v in sorted_params)
        # The string-to-sign is the protocol-defined order. Most
        # fields are blank for our use case.
        string_to_sign = "\n".join([
            method.upper(),
            headers.get("Content-Encoding", ""),
            headers.get("Content-Language", ""),
            headers.get("Content-Length", ""),
            headers.get("Content-MD5", ""),
            headers.get("Content-Type", ""),
            "",  # Date — using x-ms-date instead
            headers.get("If-Modified-Since", ""),
            headers.get("If-Match", ""),
            headers.get("If-None-Match", ""),
            headers.get("If-Unmodified-Since", ""),
            headers.get("Range", ""),
            canon_headers,
            canon_resource,
        ])
        key_bytes = base64.b64decode(self.account_key)
        sig = hmac.new(key_bytes, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        return base64.b64encode(sig).decode()

    def _auth_headers(self, method: str, path: str, params: dict) -> dict:
        from email.utils import formatdate
        headers = {
            "x-ms-date": formatdate(usegmt=True),
            "x-ms-version": "2021-08-06",
        }
        sig = self._sign(method, path, params, headers)
        headers["Authorization"] = f"SharedKey {self.account_name}:{sig}"
        return headers

    # ── REST helpers ──────────────────────────────────────────

    async def _list_containers(self, client: httpx.AsyncClient) -> list[str]:
        """Return all container names. Azure's list endpoint paginates,
        but Vooda customer accounts rarely have >5000 containers, so
        the single-page response covers ~99% of real cases."""
        params = {"comp": "list"}
        path = "/"
        url = f"{self._base}/?{('&'.join(f'{k}={v}' for k, v in params.items()))}"
        h = self._auth_headers("GET", path, params)
        r = await client.get(url, headers=h, timeout=30)
        if r.status_code != 200:
            return []
        return [m.group(1) for m in re.finditer(r"<Name>([^<]+)</Name>", r.text)]

    async def _list_blobs(
        self, client: httpx.AsyncClient, container: str, marker: Optional[str] = None,
    ) -> tuple[list[dict], Optional[str]]:
        params = {"restype": "container", "comp": "list", "maxresults": "500"}
        if self.prefix:
            params["prefix"] = self.prefix
        if marker:
            params["marker"] = marker
        path = f"/{container}"
        param_str = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
        url = f"{self._base}/{container}?{param_str}"
        h = self._auth_headers("GET", path, params)
        r = await client.get(url, headers=h, timeout=30)
        if r.status_code != 200:
            return [], None
        return _parse_blob_list_xml(r.text)

    async def _get_blob(
        self, client: httpx.AsyncClient, container: str, name: str,
    ) -> Optional[str]:
        path = f"/{container}/{name}"
        url = f"{self._base}{path}"
        h = self._auth_headers("GET", path, {})
        r = await client.get(url, headers=h, timeout=60)
        if r.status_code != 200:
            return None
        return r.text[: self.max_blob_bytes]

    # ── SourceAdapter API ─────────────────────────────────────

    async def test_connection(self) -> dict:
        """List containers — exercises the SharedKey signing path
        end-to-end (most signing bugs surface here, not on a follow-up
        blob fetch).

        We replicate the list-containers call inline rather than
        going through ``_list_containers`` because the helper swallows
        non-200 responses (so the iterator can keep going); for the
        probe we want the full response so the classifier can read
        it.
        """
        ctx = {"adapter": "azure_blob", "account_name": self.account_name}
        try:
            async with make_async_client() as client:
                params = {"comp": "list"}
                path = "/"
                url = f"{self._base}/?comp=list"
                h = self._auth_headers("GET", path, params)
                r = await client.get(url, headers=h, timeout=30)
                if r.status_code == 200:
                    names = [m.group(1) for m in re.finditer(r"<Name>([^<]+)</Name>", r.text)]
                    return {
                        "status": "success",
                        "message": f"Connected to storage account {self.account_name}: {len(names)} container(s) visible",
                        "details": {"containers": names[:5]},
                    }
                err = classify_azure_blob_error(r, ctx)
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        last_sync = sync_state.get("last_sync", "")

        async with make_async_client() as client:
            containers = await self._list_containers(client)
            if self.container_filter:
                containers = [c for c in containers if c in self.container_filter]

            for container in containers:
                marker: Optional[str] = None
                page = 0
                MAX_PAGES = 200
                while page < MAX_PAGES:
                    blobs, marker = await self._list_blobs(client, container, marker)
                    for blob in blobs:
                        name = blob.get("Name", "")
                        size = blob.get("Size", 0)
                        modified = blob.get("LastModified", "")
                        if size > self.max_blob_bytes or size == 0:
                            continue
                        if not _looks_text(blob):
                            continue
                        if last_sync and modified and modified <= last_sync:
                            continue

                        text = await self._get_blob(client, container, name)
                        if not text or not text.strip():
                            continue

                        if modified > self._updated_sync_state.get("last_sync", ""):
                            self._updated_sync_state["last_sync"] = modified

                        yield ScanableContent(
                            source_locator=f"azureblob://{self.account_name}/{container}/{name}",
                            content=text,
                            # Route prose blobs (.md/.txt/.rst/.csv/.log)
                            # to "page" so COLLAB rules fire on free-form
                            # content; structured blobs stay at "file".
                            content_type=content_type_for_path(name, default="file"),
                            deep_link_url=f"{self._base}/{container}/{name}",
                            metadata={
                                "account": self.account_name,
                                "container": container,
                                "blob_name": name,
                                "size_bytes": size,
                                "content_type": blob.get("ContentType", ""),
                            },
                        )
                    if not marker:
                        break
                    page += 1

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
