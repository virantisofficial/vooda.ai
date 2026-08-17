# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Confluence source adapter — scans pages, attachments, and comments."""

import asyncio
import re
from base64 import b64encode
from typing import AsyncIterator

import httpx
import structlog

from services.source_scanners.base import SourceAdapter, ScanableContent
from services.integration_errors.classifiers import (
    classify_atlassian_error,
    classify_network_error,
)
from packages.common.outbound_http import make_async_client

# Module logger — adapters share the structlog pipeline configured at
# process boot (see packages/common/logging_config.py).  Used here to
# emit a structured ``scan_request_failed`` line when an in-scan call
# returns non-200, so operators can grep one error code across the
# scan log and the provider's audit log instead of seeing a silent
# items_scanned=0.
logger = structlog.get_logger(__name__)

HTML_TAG_RE = re.compile(r"<[^>]+>")


class ConfluenceSourceAdapter(SourceAdapter):
    source_type = "confluence"

    def __init__(self, base_url: str, email: str, api_token: str, spaces: str = "*", include_attachments: bool = True):
        self.base_url = base_url.rstrip("/")
        self.auth = b64encode(f"{email}:{api_token}".encode()).decode()
        self.space_filter = [s.strip() for s in spaces.split(",")] if spaces != "*" else []
        self.include_attachments = include_attachments
        self._headers = {"Authorization": f"Basic {self.auth}", "Accept": "application/json"}
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Two-stage probe so a green 'Connected' actually means we can scan.

        Atlassian's Cloud REST v2 returns an opaque space *id* (numeric
        string) and a separate *key* (the user-facing 'SD' / 'ENG' label).
        The pages endpoint requires *id*. Earlier versions of this
        adapter passed the key, which made test_connection look healthy
        (because /spaces?limit=1 succeeds with any read access) while
        every actual page-fetch returned 400. We now follow the spaces
        probe with one pages call so a 'Connected' result implies the
        full read path works.

        Returns the legacy ``{status, message}`` dict for backward
        compatibility, but on failure also includes the structured
        ``IntegrationError`` fields (title, summary, fix_steps,
        details). New clients should read the structured fields;
        old clients that only read ``message`` keep working unchanged.
        """
        ctx = {"adapter": "confluence", "site_url": self.base_url}
        try:
            async with make_async_client(timeout=15) as client:
                r = await client.get(f"{self.base_url}/wiki/api/v2/spaces?limit=1", headers=self._headers)
                if r.status_code != 200:
                    err = classify_atlassian_error(r, ctx)
                    return err.to_user_dict()

                spaces = r.json().get("results", [])
                if not spaces:
                    return {"status": "success", "message": "Connected to Confluence (no spaces visible to this user yet)"}

                # Probe the page-fetch path on the first space using its
                # ID — the only way to confirm /spaces/{id}/pages works
                # before a real scan is dispatched.
                space_id = spaces[0].get("id", "")
                r2 = await client.get(
                    f"{self.base_url}/wiki/api/v2/spaces/{space_id}/pages?limit=1&body-format=storage",
                    headers=self._headers,
                )
                if r2.status_code == 200:
                    return {"status": "success", "message": "Connected to Confluence"}
                err = classify_atlassian_error(r2, {**ctx, "phase": "page_fetch_probe"})
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)

        async with make_async_client(timeout=30) as client:
            spaces = await self._list_spaces(client)
            for space in spaces:
                # Atlassian Cloud REST v2 keys pages by space *id*
                # (numeric); the human-readable *key* (e.g. 'SD') is
                # only used in the URL for the deep-link / locator.
                space_id = space.get("id", "")
                space_key = space.get("key", "")
                if not space_id:
                    # Defensive — can't scan a space we can't address.
                    continue
                async for page in self._get_pages(client, space_id, space_key, sync_state):
                    page_id = page.get("id", "")
                    title = page.get("title", "")
                    body = page.get("body", {}).get("storage", {}).get("value", "")
                    text = HTML_TAG_RE.sub("", body)  # Strip HTML tags
                    version = page.get("version", {}).get("number", 0)

                    if text.strip():
                        yield ScanableContent(
                            source_locator=f"confluence://{space_key or space_id}/{page_id}",
                            content=text,
                            content_type="page",
                            author=page.get("version", {}).get("by", {}).get("displayName", ""),
                            # Deep-link uses key (what humans see in
                            # the URL bar of Confluence). Fall back to
                            # numeric id if the space has no key set.
                            deep_link_url=f"{self.base_url}/wiki/spaces/{space_key or space_id}/pages/{page_id}",
                            metadata={
                                "space_id": space_id,
                                "space_key": space_key,
                                "page_title": title,
                                "version": version,
                            },
                        )

                    # Watermark is keyed by id so renames of the human
                    # key don't lose incremental state.
                    self._updated_sync_state[f"{space_id}/{page_id}"] = version
                await asyncio.sleep(0.5)

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state

    async def _list_spaces(self, client: httpx.AsyncClient) -> list[dict]:
        r = await client.get(f"{self.base_url}/wiki/api/v2/spaces?limit=100", headers=self._headers)
        if r.status_code != 200:
            # Classify + emit one structured log line so operators can see
            # *why* the scan returned zero items.  We deliberately do NOT
            # raise here — a single bad spaces call shouldn't kill an
            # in-progress scan that's already produced findings from
            # other sources — but we DO want the error_code + trace_id
            # in the log stream for support-ticket correlation.
            err = classify_atlassian_error(
                r,
                {
                    "adapter": "confluence",
                    "site_url": self.base_url,
                    "phase": "list_spaces",
                },
            )
            logger.warning(
                "scan_request_failed",
                source_type="confluence",
                error_code=err.code,
                error_title=err.title,
                trace_id=err.trace_id,
                http_status=err.http_status,
                phase="list_spaces",
            )
            return []
        spaces = r.json().get("results", [])
        if self.space_filter:
            # Filter is user-supplied; allow either the key (typical:
            # 'ENG,SEC') or the numeric id (less common but valid).
            wanted = set(self.space_filter)
            spaces = [s for s in spaces if s.get("key") in wanted or s.get("id") in wanted]
        return spaces

    async def _get_pages(self, client: httpx.AsyncClient, space_id: str, space_key: str, sync_state: dict):
        """Fetch pages for a single space.

        Path note: v2 takes the numeric *id* — passing the human key
        produces 400 Bad Request. ``space_key`` is forwarded only so
        we can keep using it as the watermark and locator label that
        survives across renames. Bug fix 2026-05-08.
        """
        cursor = None
        while True:
            url = f"{self.base_url}/wiki/api/v2/spaces/{space_id}/pages?limit=25&body-format=storage"
            if cursor:
                url += f"&cursor={cursor}"
            r = await client.get(url, headers=self._headers)
            if r.status_code != 200:
                # Stop iterating this space on first non-200, but emit
                # a structured log line first so the silent failure is
                # visible in operator logs.  Mid-scan token expiry,
                # rate-limit, and per-space permission failures all
                # land here — the error_code distinguishes them.
                err = classify_atlassian_error(
                    r,
                    {
                        "adapter": "confluence",
                        "site_url": self.base_url,
                        "phase": "list_pages",
                        "space_id": space_id,
                        "space_key": space_key,
                    },
                )
                logger.warning(
                    "scan_request_failed",
                    source_type="confluence",
                    error_code=err.code,
                    error_title=err.title,
                    trace_id=err.trace_id,
                    http_status=err.http_status,
                    phase="list_pages",
                    space_id=space_id,
                    space_key=space_key,
                )
                break
            data = r.json()
            for page in data.get("results", []):
                page_id = page.get("id", "")
                version = page.get("version", {}).get("number", 0)
                # Watermark by space *id* — see method docstring.
                prev_version = sync_state.get(f"{space_id}/{page_id}", 0)
                if version > prev_version:
                    yield page
            cursor = data.get("_links", {}).get("next")
            if not cursor:
                break
            await asyncio.sleep(0.5)
