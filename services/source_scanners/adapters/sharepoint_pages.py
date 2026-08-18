# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""SharePoint Pages source adapter — scans wiki-like page content
across the customer's SharePoint sites.

How this differs from the OneDrive/SharePoint adapter
-----------------------------------------------------
OneDrive/SharePoint already exists in the catalog under Cloud Storage
and scans **files** inside SharePoint document libraries (the
``/sites/{id}/drives/{id}/items`` surface).  That covers .docx /
.xlsx / .json / etc. file uploads.

This adapter covers the **page content** surface — the wiki-like
SharePoint Pages (formerly "wiki pages") + Site Lists that live in
SharePoint's own database, not in a drive.  Two different Graph
endpoints:

  - Pages:  GET /sites/{id}/pages         (Site.Read.All)
            GET /sites/{id}/pages/{id}/microsoft.graph.sitePage?$expand=canvasLayout

  - Lists:  GET /sites/{id}/lists         (Sites.Read.All)
            GET /sites/{id}/lists/{id}/items?expand=fields

Why this exists as a separate source vs an option on OneDrive
-------------------------------------------------------------
- Different category positioning: Pages is Docs & Wikis (wiki-style
  knowledge content), OneDrive is Cloud Storage (file shares).
  Customers expect to find Pages under Docs & Wikis next to
  Confluence and Notion, not under Cloud Storage.
- Different default scan profile: Pages content is small and dense,
  scan-cheap.  Drive files vary widely (image binaries, archives,
  CAD) and need size caps + mime filters.  Sharing a single source
  would conflate the two profiles.
- Different scope filter: Pages users care about site-level filters
  (which wiki spaces to scan); Drive users care about library-level
  filters.  Easier to keep the surfaces separate.

Auth model: same Microsoft Entra (Azure AD) app registration that
backs ms_teams and onedrive_sharepoint.  Reuses
``MicrosoftGraphClient``.  Required application permission:
``Sites.Read.All`` — already what onedrive_sharepoint asks for in
its wizard, so customers with that source connected don't need a new
consent.
"""

from __future__ import annotations

import asyncio
import re
from typing import AsyncIterator
from html import unescape

import httpx

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_graph_error,
    classify_network_error,
)
from services.source_scanners.adapters._msgraph import (
    MicrosoftGraphClient,
    GRAPH_ROOT,
)
from services.source_scanners.base import SourceAdapter, ScanableContent


# Strip basic HTML tags from page canvas content — SharePoint Pages
# bodies come back as HTML fragments.  We don't need a full parser
# (just want to feed plain text to the secret detector); a regex
# stripper handles the canvas layout shape Graph returns.
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WS_COLLAPSE_RE = re.compile(r"\s+")


def _html_to_text(html: str) -> str:
    """Strip HTML tags + decode entities + collapse whitespace.

    Not a security boundary — we're just normalizing the canvas
    content for secret-pattern matching.  The detector regexes are
    insensitive to surrounding whitespace, so we don't need to
    preserve paragraph structure.
    """
    if not html:
        return ""
    no_tags = _HTML_TAG_RE.sub(" ", html)
    no_entities = unescape(no_tags)
    return _WS_COLLAPSE_RE.sub(" ", no_entities).strip()


class SharePointPagesAdapter(SourceAdapter):
    source_type = "sharepoint_pages"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        site_filter: str = "*",
        include_lists: bool = True,
    ):
        """Construct from the same Microsoft Entra credentials the
        OneDrive/SharePoint source uses.

        Args:
            tenant_id / client_id / client_secret: Microsoft Entra
                app registration credentials.  Same app as ms_teams /
                onedrive_sharepoint; just add ``Sites.Read.All`` to
                the granted application permissions (likely already
                granted for OneDrive customers).
            site_filter: Comma-separated SharePoint site display
                names, or "*" for every site the app can see.
            include_lists: Whether to also scan SharePoint List item
                fields (FAQ lists, internal directory lists, etc.).
                On by default — Lists often contain runbook-style
                content with embedded credentials.  Off skips them
                and scans only Pages.
        """
        self.client = MicrosoftGraphClient(
            tenant_id, client_id, client_secret,
            source_type="sharepoint_pages",
        )
        self.site_filter = (
            [s.strip() for s in site_filter.split(",") if s.strip()] if site_filter != "*" else []
        )
        self.include_lists = include_lists
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Probe /sites — same scope (Sites.Read.All) the page scanner
        needs.  Reuses ``MicrosoftGraphClient.test_connection`` so the
        wizard's Test Connection button surfaces the same structured
        IntegrationError shape every other M365 adapter uses.
        """
        return await self.client.test_connection(probe_path="/sites?search=*&$top=1")

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        """Walk every accessible SharePoint site, yield page bodies +
        list-item fields as ScanableContent.

        Incremental behaviour: each site's lastModifiedDateTime cursor
        is tracked in sync_state.  On the first scan, all pages are
        yielded.  On subsequent scans, only pages where
        lastModifiedDateTime > stored cursor are yielded.  Same
        pattern as the OneDrive/SharePoint adapter uses for files.
        """
        self._updated_sync_state = dict(sync_state)
        last_sync = sync_state.get("last_sync", "")
        latest_modified = last_sync

        async with make_async_client(timeout=60) as client:
            # Enumerate every site Vooda's Entra app can read.
            async for site in self.client.get_paged(client, f"{GRAPH_ROOT}/sites?search=*"):
                site_id = site.get("id")
                site_name = site.get("displayName") or site.get("name", site_id)
                if not site_id:
                    continue
                if self.site_filter and site_name not in self.site_filter:
                    continue

                # ── SharePoint Pages ──────────────────────────────
                # /sites/{id}/pages returns SitePage resources.  Each
                # has webUrl (for the deep-link finding URL) and
                # lastModifiedDateTime (for incremental cursor).  To
                # get the actual page text, request the page detail
                # with $expand=canvasLayout — canvasLayout holds the
                # text blocks rendered on the page.
                pages_url = f"{GRAPH_ROOT}/sites/{site_id}/pages"
                async for page in self.client.get_paged(client, pages_url):
                    page_id = page.get("id")
                    if not page_id:
                        continue
                    page_title = page.get("title") or page.get("name", "")
                    page_url = page.get("webUrl", "")
                    modified = page.get("lastModifiedDateTime", "") or ""

                    if last_sync and modified and modified <= last_sync:
                        continue
                    if modified > latest_modified:
                        latest_modified = modified

                    # Fetch the canvas layout for body text.
                    detail_url = (
                        f"{GRAPH_ROOT}/sites/{site_id}/pages/{page_id}"
                        "/microsoft.graph.sitePage?$expand=canvasLayout"
                    )
                    body_text = await self._fetch_page_body(client, detail_url)
                    if not body_text:
                        continue

                    # Title + URL go alongside the body so secrets
                    # pasted into the page title (rare but happens)
                    # don't slip past the scanner.
                    combined = f"{page_title}\n{page_url}\n{body_text}"
                    yield ScanableContent(
                        source_locator=f"sharepoint-page://{site_id}/{page_id}",
                        content=combined,
                        content_type="page",
                        deep_link_url=page_url,
                        metadata={
                            "site_name": site_name,
                            "page_title": page_title,
                            "last_modified": modified,
                        },
                    )

                # ── SharePoint Lists (optional) ───────────────────
                # List items live in /sites/{id}/lists/{id}/items.
                # Each item has a `fields` blob with arbitrary column
                # values — the columns customers actually use for
                # docs (Description, Notes, Runbook, etc.) all live
                # here.  We don't try to pick which fields matter;
                # we concatenate every string field per item.
                if self.include_lists:
                    lists_url = f"{GRAPH_ROOT}/sites/{site_id}/lists"
                    async for lst in self.client.get_paged(client, lists_url):
                        list_id = lst.get("id")
                        list_name = lst.get("displayName") or lst.get("name", list_id)
                        # Skip system / hidden lists — they're internal SharePoint
                        # plumbing (workflow tasks, IDs, audit lists) with no
                        # user-authored content worth scanning.
                        list_info = lst.get("list") or {}
                        if list_info.get("hidden"):
                            continue
                        if not list_id:
                            continue

                        items_url = f"{GRAPH_ROOT}/sites/{site_id}/lists/{list_id}/items?expand=fields"
                        async for item in self.client.get_paged(client, items_url):
                            item_id = item.get("id")
                            fields = item.get("fields") or {}
                            item_modified = item.get("lastModifiedDateTime", "") or ""

                            if last_sync and item_modified and item_modified <= last_sync:
                                continue
                            if item_modified > latest_modified:
                                latest_modified = item_modified

                            # Concatenate every string field — SharePoint
                            # lists are schema-flexible; we don't know
                            # which field a customer named "RunbookText"
                            # vs "Notes".  Numbers, dates, lookup IDs
                            # are filtered out as non-content.
                            text_parts: list[str] = []
                            for key, value in fields.items():
                                if isinstance(value, str) and value.strip():
                                    text_parts.append(value)
                            if not text_parts:
                                continue
                            body = "\n".join(text_parts)
                            web_url = item.get("webUrl", "") or fields.get("LinkTitle", "")
                            yield ScanableContent(
                                source_locator=f"sharepoint-list://{site_id}/{list_id}/{item_id}",
                                content=body,
                                content_type="list_item",
                                deep_link_url=web_url,
                                metadata={
                                    "site_name": site_name,
                                    "list_name": list_name,
                                    "last_modified": item_modified,
                                },
                            )

                # Per-site backoff to stay friendly with Graph's
                # 15K req / 15 min default.
                await asyncio.sleep(0.2)

            self._updated_sync_state["last_sync"] = latest_modified

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state

    async def _fetch_page_body(self, client: httpx.AsyncClient, detail_url: str) -> str:
        """Fetch a single page's canvasLayout and extract plain text.

        canvasLayout is structured as:
          { horizontalSections: [{ columns: [{ webparts: [{ innerHtml: "..." }] }] }] }

        We walk the structure, accumulate every innerHtml fragment,
        strip tags, return one normalized string.  Schemas vary
        slightly across page templates; this is intentionally lenient
        — if a field doesn't exist we just skip it.
        """
        try:
            h = await self.client.headers(client)
            r = await client.get(detail_url, headers=h, timeout=30)
        except httpx.RequestError:
            return ""
        if r.status_code != 200:
            return ""
        data = r.json() or {}
        canvas = data.get("canvasLayout") or {}

        text_chunks: list[str] = []
        for section in canvas.get("horizontalSections") or []:
            for column in section.get("columns") or []:
                for webpart in column.get("webparts") or []:
                    inner = webpart.get("innerHtml") or ""
                    if inner:
                        text_chunks.append(_html_to_text(inner))
        # Some templates also carry a flat ``vertical`` section.
        for section in canvas.get("verticalSection", {}).get("webparts") or []:
            inner = section.get("innerHtml") or ""
            if inner:
                text_chunks.append(_html_to_text(inner))
        return "\n".join(c for c in text_chunks if c)
