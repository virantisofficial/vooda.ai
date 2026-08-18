# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Azure DevOps Boards source adapter — scans work item descriptions and comments.

Microsoft-stack equivalent of Jira / GitHub Issues. Work items
(User Stories, Bugs, Tasks, Epics) carry a System.Description field
+ a separate Comments REST endpoint per work item.

Auth: Personal Access Token with "Work Items (read)" scope at
minimum. Sent as HTTP Basic with empty username — Azure DevOps's
documented PAT pattern.

Out of scope (deferred):
  - Pull request comments (lives under /git/repositories — separate
    surface; Bitbucket-style adapter would be the right shape but
    Microsoft's PR API is different enough to warrant its own
    adapter file).
  - Wiki pages (separate /wiki/wikis API).
"""
from __future__ import annotations

import asyncio
import re
from base64 import b64encode
from typing import AsyncIterator, Optional

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_azure_devops_error,
    classify_network_error,
)
from services.source_scanners.base import ScanableContent, SourceAdapter


_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HTML_ENTITY_RE = re.compile(r"&(?:amp|lt|gt|quot|apos|nbsp|#x?[0-9a-fA-F]+);")
_ENTITY_MAP = {
    "&amp;": "&", "&lt;": "<", "&gt;": ">",
    "&quot;": '"', "&apos;": "'", "&nbsp;": " ",
}


def _flatten_html(s: str) -> str:
    """Azure DevOps stores Description as HTML. Strip tags + decode
    common entities the same way the Teams adapter does — small
    regex pass is enough for the secret-detection use case."""
    if not s:
        return ""
    out = _HTML_TAG_RE.sub(" ", s)
    out = _HTML_ENTITY_RE.sub(lambda m: _ENTITY_MAP.get(m.group(0), m.group(0)), out)
    return " ".join(out.split())


class AzureDevOpsBoardsAdapter(SourceAdapter):
    source_type = "azure_devops"

    def __init__(
        self,
        organization: str,
        project: str,
        pat: str,
    ):
        if not (organization and project and pat):
            raise ValueError("Azure DevOps adapter requires organization, project, and PAT")
        self.organization = organization.strip("/").rstrip()
        self.project = project.strip("/")
        self.pat = pat
        # PATs are sent as Basic auth with empty username per Azure
        # DevOps's documented pattern.
        auth = b64encode(f":{pat}".encode()).decode()
        self._headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
        self._base = f"https://dev.azure.com/{self.organization}/{self.project}"
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Probe ``/wit/workitemtypes`` — confirms the PAT can read
        work-item metadata, which is the same scope the scan uses.
        """
        ctx = {
            "adapter": "azure_devops",
            "organization": self.organization,
            "project": self.project,
        }
        try:
            async with make_async_client(timeout=15) as c:
                r = await c.get(
                    f"{self._base}/_apis/wit/workitemtypes?api-version=7.0",
                    headers=self._headers,
                )
                if r.status_code == 200:
                    return {
                        "status": "success",
                        "message": f"Connected to {self.organization}/{self.project}",
                    }
                err = classify_azure_devops_error(r, ctx)
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        last_sync = sync_state.get("last_sync", "2000-01-01")

        async with make_async_client(timeout=30) as c:
            # 1. WIQL query to get work item IDs updated since last_sync.
            wiql = {
                "query": (
                    "SELECT [System.Id] FROM workitems "
                    f"WHERE [System.ChangedDate] > '{last_sync}' "
                    "ORDER BY [System.ChangedDate] ASC"
                )
            }
            r = await c.post(
                f"{self._base}/_apis/wit/wiql?api-version=7.0",
                headers={**self._headers, "Content-Type": "application/json"},
                json=wiql,
            )
            if r.status_code != 200:
                return
            ids = [w["id"] for w in (r.json() or {}).get("workItems", [])]
            if not ids:
                return

            # 2. Batch-fetch up to 200 ids per call to /workitems.
            for batch_start in range(0, len(ids), 200):
                batch = ids[batch_start:batch_start + 200]
                wr = await c.get(
                    f"{self._base}/_apis/wit/workitems"
                    f"?ids={','.join(map(str, batch))}"
                    "&fields=System.Id,System.WorkItemType,System.Title,"
                    "System.Description,System.ChangedDate,System.AreaPath"
                    "&api-version=7.0",
                    headers=self._headers,
                )
                if wr.status_code != 200:
                    continue

                for wi in (wr.json() or {}).get("value", []) or []:
                    wid = wi.get("id")
                    fields = wi.get("fields") or {}
                    changed = fields.get("System.ChangedDate", "")
                    if changed > self._updated_sync_state.get("last_sync", ""):
                        self._updated_sync_state["last_sync"] = changed

                    deep_link = f"{self._base}/_workitems/edit/{wid}"
                    title = fields.get("System.Title") or ""
                    if title.strip():
                        yield ScanableContent(
                            source_locator=f"azuredevops://{self.organization}/{self.project}/{wid}/title",
                            content=title,
                            content_type="page",
                            deep_link_url=deep_link,
                            metadata={"work_item_id": wid,
                                      "work_item_type": fields.get("System.WorkItemType", ""),
                                      "area_path": fields.get("System.AreaPath", "")},
                        )

                    desc = _flatten_html(fields.get("System.Description") or "")
                    if desc.strip():
                        yield ScanableContent(
                            source_locator=f"azuredevops://{self.organization}/{self.project}/{wid}/description",
                            content=desc,
                            content_type="page",
                            deep_link_url=deep_link,
                            metadata={"work_item_id": wid,
                                      "title": title},
                        )

                    # Comments via /comments endpoint
                    cr = await c.get(
                        f"{self._base}/_apis/wit/workItems/{wid}/comments?api-version=7.0-preview.3",
                        headers=self._headers,
                    )
                    if cr.status_code != 200:
                        continue
                    for cmt in (cr.json() or {}).get("comments", []) or []:
                        cid = cmt.get("id")
                        body = _flatten_html(cmt.get("text") or "")
                        if not body.strip():
                            continue
                        yield ScanableContent(
                            source_locator=f"azuredevops://{self.organization}/{self.project}/{wid}/comment/{cid}",
                            content=body,
                            content_type="comment",
                            deep_link_url=deep_link,
                            author=((cmt.get("createdBy") or {}).get("displayName")),
                            metadata={"work_item_id": wid},
                        )

                await asyncio.sleep(0.3)

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
