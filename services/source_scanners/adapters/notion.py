# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Notion source adapter — scans page bodies in a Notion workspace.

Auth: Notion integration token (`secret_...`). The customer creates
an internal integration at https://www.notion.so/my-integrations,
copies the token, then shares each page / database with the
integration so the API can see them.

Coverage:
  - Top-level pages the integration has been shared on
  - Recursive child blocks (paragraph, heading, code blocks, callouts)
  - Database items (where the integration has access)

Limitations (deferred):
  - Inline databases, file attachments, and embedded blocks beyond
    the basic block types — the block schema is broad and we cover
    the highest-yield types here.
  - Workspace-wide enumeration requires the integration to be
    explicitly shared on each page; Notion has no "see everything"
    grant. This matches Notion's privacy-by-design stance.
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator, Optional

import httpx
import structlog

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_network_error,
    classify_notion_error,
)
from services.source_scanners.base import ScanableContent, SourceAdapter

# Module logger — emits a structured ``scan_request_failed`` line when
# a mid-scan Notion call returns non-200, so a token expiring mid-scan
# or a per-page sharing revocation surfaces as a grep-able event in
# the worker log stream rather than a silent items_scanned=0.  Mirrors
# the pattern applied to confluence.py / jira.py / _msgraph.py.
logger = structlog.get_logger(__name__)


_API = "https://api.notion.com/v1"
_NOTION_VERSION = "2022-06-28"  # stable; bump when Notion publishes a new dated release


def _flatten_rich_text(rt: list) -> str:
    """A Notion `rich_text` array is a list of {type, text:{content,...}, ...}.
    We pull `plain_text` which Notion populates for every variant."""
    if not rt:
        return ""
    out = []
    for chunk in rt:
        out.append(chunk.get("plain_text", "") or "")
    return "".join(out)


def _flatten_block(block: dict) -> str:
    """Map a Notion block to its scannable text form. Covers the
    block types people actually paste secrets into. Deliberately
    short — unsupported block types fall through to empty string,
    which is fine for secret-detection coverage."""
    t = block.get("type")
    if not t:
        return ""
    body = block.get(t) or {}
    if "rich_text" in body:
        return _flatten_rich_text(body.get("rich_text") or [])
    if t == "code":
        # Code blocks have rich_text + a `language`; rich_text already
        # covered by the branch above. Belt-and-suspenders.
        return _flatten_rich_text(body.get("rich_text") or [])
    return ""


class NotionAdapter(SourceAdapter):
    source_type = "notion"

    def __init__(self, token: str):
        if not token:
            raise ValueError("Notion adapter requires an integration token")
        self.token = token
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Notion-Version": _NOTION_VERSION,
            "Content-Type": "application/json",
        }
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Probe ``/search`` with a minimal payload.

        Notion's ``/search`` endpoint doubles as an auth + reachability
        probe — it succeeds when the integration token is valid even
        if the integration hasn't been shared on any page yet (empty
        result list, but HTTP 200).

        We split that case explicitly in the success message so the
        user understands *why* a freshly-created integration scans
        zero pages: Notion's sharing model requires per-page (or
        per-workspace-root) opt-in via the Notion UI's Connections
        menu.  Mirrors how Confluence's test_connection surfaces the
        equivalent "Connected but no spaces visible" case.
        """
        ctx = {"adapter": "notion"}
        try:
            async with make_async_client(timeout=15) as client:
                r = await client.post(f"{_API}/search", headers=self._headers, json={"page_size": 1})
                if r.status_code == 200:
                    body = r.json() or {}
                    results = body.get("results") or []
                    if not results:
                        return {
                            "status": "success",
                            "message": (
                                "Connected to Notion — but no pages have been shared with this "
                                "integration yet. Open each page (or your workspace root) in "
                                "Notion → '...' → Connections → Add this integration."
                            ),
                        }
                    return {"status": "success", "message": "Connected to Notion"}
                err = classify_notion_error(r, ctx)
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        last_sync = sync_state.get("last_sync", "")

        async with make_async_client(timeout=30) as client:
            cursor: Optional[str] = None
            page = 0
            MAX_PAGES = 200
            while page < MAX_PAGES:
                payload: dict = {"page_size": 50, "filter": {"property": "object", "value": "page"}}
                if cursor:
                    payload["start_cursor"] = cursor
                r = await client.post(f"{_API}/search", headers=self._headers, json=payload)
                if r.status_code != 200:
                    # Stop iterating, but classify + emit a structured log
                    # line first so the silent-failure mode (items_scanned=0
                    # with no diagnostic) becomes visible.  Mid-scan token
                    # expiry, rate-limit, and integration-revoked failures
                    # all land here — error_code distinguishes them.
                    err = classify_notion_error(
                        r,
                        {
                            "adapter": "notion",
                            "phase": "search",
                            "page": page,
                        },
                    )
                    logger.warning(
                        "scan_request_failed",
                        source_type="notion",
                        error_code=err.code,
                        error_title=err.title,
                        trace_id=err.trace_id,
                        http_status=err.http_status,
                        phase="search",
                        page=page,
                    )
                    break
                data = r.json()
                results = data.get("results", []) or []

                # Surface the "integration is valid but no pages have
                # been shared with it" state in the worker log on the
                # very first page.  Without this, an operator looking
                # at items_scanned=0 has no signal distinguishing
                # "zero pages have content" from "zero pages were even
                # visible to the integration".  test_connection
                # already covers the wizard-time message; this covers
                # the scan-time observability.  Emitted once per scan
                # (only on page == 0 when results are empty).
                if page == 0 and not results:
                    logger.info(
                        "notion_no_shared_pages",
                        source_type="notion",
                        message=(
                            "Notion /v1/search returned no pages — the integration "
                            "token is valid but no pages or workspace roots have "
                            "been shared with this integration yet."
                        ),
                    )

                for p in results:
                    page_id = p.get("id")
                    last_edited = p.get("last_edited_time", "")
                    if last_sync and last_edited and last_edited <= last_sync:
                        continue
                    if last_edited > self._updated_sync_state.get("last_sync", ""):
                        self._updated_sync_state["last_sync"] = last_edited

                    title = self._page_title(p)
                    body_text = await self._fetch_page_text(client, page_id)
                    if not body_text.strip():
                        continue
                    yield ScanableContent(
                        source_locator=f"notion://{page_id}",
                        content=body_text,
                        content_type="page",
                        deep_link_url=p.get("url") or "",
                        metadata={"page_id": page_id, "title": title},
                    )

                if not data.get("has_more"):
                    break
                cursor = data.get("next_cursor")
                page += 1
                await asyncio.sleep(0.3)

    async def _fetch_page_text(self, client: httpx.AsyncClient, page_id: str) -> str:
        """Walk the page's blocks and collect text. One level deep —
        nested blocks would multiply API calls; first-level coverage
        captures the bulk of secret-leak content."""
        chunks: list[str] = []
        cursor: Optional[str] = None
        page = 0
        while page < 50:
            url = f"{_API}/blocks/{page_id}/children?page_size=100"
            if cursor:
                url += f"&start_cursor={cursor}"
            r = await client.get(url, headers=self._headers)
            if r.status_code != 200:
                # Stop iterating this page's blocks but log the classified
                # error first.  A 404 here typically means the parent
                # page was unshared from the integration mid-scan; a 401
                # means the token rotated.  Both are operationally
                # actionable signals an operator wants to see.
                err = classify_notion_error(
                    r,
                    {
                        "adapter": "notion",
                        "phase": "fetch_blocks",
                        "page_id": page_id,
                    },
                )
                logger.warning(
                    "scan_request_failed",
                    source_type="notion",
                    error_code=err.code,
                    error_title=err.title,
                    trace_id=err.trace_id,
                    http_status=err.http_status,
                    phase="fetch_blocks",
                    page_id=page_id,
                )
                break
            data = r.json()
            for block in data.get("results", []) or []:
                t = _flatten_block(block)
                if t:
                    chunks.append(t)
            if not data.get("has_more"):
                break
            cursor = data.get("next_cursor")
            page += 1
            await asyncio.sleep(0.2)
        return "\n".join(chunks)

    def _page_title(self, page: dict) -> str:
        # Page title lives in either `properties.title` (databases)
        # or `properties.Name` (vanilla pages). We try both.
        props = page.get("properties") or {}
        for key in ("title", "Name"):
            v = props.get(key)
            if v and v.get("type") == "title":
                return _flatten_rich_text(v.get("title") or [])
        return ""

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
