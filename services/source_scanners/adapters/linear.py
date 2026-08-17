# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Linear source adapter — scans issue descriptions and comments.

Linear is GraphQL-only. We use a single paginated query per resource
type (issues, comments) keyed off the `updatedAt` watermark for
incremental sync.

Auth: Linear API key (Personal API key from
https://linear.app/settings/api). Sent as `Authorization: <key>`
(no `Bearer` prefix per Linear's docs). Vooda encrypts at rest.

Out of scope (deferred):
  - Project documents (separate API)
  - Cycle / Initiative descriptions
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator, Optional

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_linear_error,
    classify_network_error,
)
from services.source_scanners.base import ScanableContent, SourceAdapter


_API = "https://api.linear.app/graphql"


_ISSUES_QUERY = """
query Issues($after: String, $filter: IssueFilter) {
  issues(first: 50, after: $after, filter: $filter, orderBy: updatedAt) {
    pageInfo { hasNextPage endCursor }
    nodes {
      id identifier title description updatedAt
      url
      team { key name }
      creator { name email }
      comments(first: 50) {
        nodes { id body updatedAt user { name email } }
      }
    }
  }
}
"""


class LinearAdapter(SourceAdapter):
    source_type = "linear"

    def __init__(self, api_key: str, teams: str = "*"):
        if not api_key:
            raise ValueError("Linear adapter requires an API key")
        self.api_key = api_key
        self.team_filter = (
            [t.strip() for t in teams.split(",") if t.strip()] if teams != "*" else []
        )
        self._headers = {
            "Authorization": api_key,
            "Content-Type": "application/json",
        }
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Run the canonical ``viewer { id name }`` GraphQL probe.

        Linear (like all GraphQL APIs) returns HTTP 200 even on
        logical errors; the failure signal lives in the body's
        ``errors`` array.  Both shapes — HTTP-level and GraphQL-level
        — route through :func:`classify_linear_error`, so the caller
        gets one structured error envelope regardless of which layer
        rejected the call.
        """
        ctx = {"adapter": "linear"}
        try:
            async with make_async_client(timeout=15) as c:
                r = await c.post(_API, headers=self._headers,
                                 json={"query": "query { viewer { id name } }"})
                try:
                    body = r.json()
                except ValueError:
                    body = {}
                viewer = ((body or {}).get("data") or {}).get("viewer") if isinstance(body, dict) else None
                if r.status_code == 200 and viewer:
                    return {
                        "status": "success",
                        "message": f"Connected as {viewer.get('name', 'Linear user')}",
                    }
                err = classify_linear_error(r, ctx)
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        # Watermark on updatedAt — Linear filters via IssueFilter
        # natively so the API does the filtering for us.
        self._updated_sync_state = dict(sync_state)
        last_sync = sync_state.get("last_sync")

        filt: dict = {}
        if last_sync:
            filt["updatedAt"] = {"gt": last_sync}

        async with make_async_client(timeout=30) as c:
            after: Optional[str] = None
            page = 0
            MAX_PAGES = 200
            while page < MAX_PAGES:
                payload = {"query": _ISSUES_QUERY,
                           "variables": {"after": after, "filter": filt or None}}
                r = await c.post(_API, headers=self._headers, json=payload)
                if r.status_code != 200:
                    break
                data = (r.json() or {}).get("data", {}) or {}
                connection = data.get("issues") or {}
                nodes = connection.get("nodes", []) or []
                for issue in nodes:
                    iid = issue.get("identifier") or issue.get("id")
                    team = (issue.get("team") or {}).get("key", "")
                    if self.team_filter and team not in self.team_filter:
                        continue
                    updated = issue.get("updatedAt", "")
                    if updated > self._updated_sync_state.get("last_sync", ""):
                        self._updated_sync_state["last_sync"] = updated

                    desc = issue.get("description") or ""
                    if desc.strip():
                        yield ScanableContent(
                            source_locator=f"linear://{iid}/description",
                            content=desc,
                            content_type="page",
                            author=(issue.get("creator") or {}).get("name", ""),
                            deep_link_url=issue.get("url") or "",
                            metadata={"issue_id": iid, "team": team,
                                      "title": issue.get("title", "")},
                        )

                    for comment in ((issue.get("comments") or {}).get("nodes") or []):
                        body = comment.get("body") or ""
                        if not body.strip():
                            continue
                        cid = comment.get("id")
                        c_updated = comment.get("updatedAt", "")
                        if c_updated > self._updated_sync_state.get("last_sync", ""):
                            self._updated_sync_state["last_sync"] = c_updated
                        yield ScanableContent(
                            source_locator=f"linear://{iid}/comment/{cid}",
                            content=body,
                            content_type="comment",
                            author=(comment.get("user") or {}).get("name", ""),
                            deep_link_url=issue.get("url") or "",
                            metadata={"issue_id": iid, "team": team},
                        )

                page_info = connection.get("pageInfo") or {}
                if not page_info.get("hasNextPage"):
                    break
                after = page_info.get("endCursor")
                page += 1
                await asyncio.sleep(0.3)

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
