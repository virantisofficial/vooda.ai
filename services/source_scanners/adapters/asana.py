# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Asana source adapter — scans task notes (descriptions) and stories (comments).

Auth: Asana Personal Access Token from
https://app.asana.com/0/my-apps. Sent as `Authorization: Bearer <pat>`.

Workflow:
  1. List all workspaces the PAT can see.
  2. For each workspace, paginate through projects → tasks.
  3. For each task: yield `notes` (description) + each `story` of
     type "comment" as a separate ScanableContent.

We use Asana's `modified_since` query param to do server-side
incremental filtering against our sync_state.last_sync watermark.
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


_API = "https://app.asana.com/api/1.0"


class AsanaAdapter(SourceAdapter):
    source_type = "asana"

    def __init__(self, token: str, workspaces: str = "*"):
        if not token:
            raise ValueError("Asana adapter requires a personal access token")
        self.token = token
        self.workspace_filter = (
            [w.strip() for w in workspaces.split(",") if w.strip()] if workspaces != "*" else []
        )
        self._headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Probe ``/users/me`` — confirms the PAT works and reveals
        the authenticated user for the success message.
        """
        ctx = {"adapter": "asana"}
        try:
            async with make_async_client(timeout=15) as c:
                r = await c.get(f"{_API}/users/me", headers=self._headers)
                if r.status_code == 200:
                    user = (r.json() or {}).get("data", {})
                    return {
                        "status": "success",
                        "message": f"Connected as {user.get('name', 'Asana user')}",
                    }
                err = classify_http_error(
                    r, provider="asana", context=ctx,
                    auth_fix_steps=[
                        "Open app.asana.com → My Apps → Personal Access Tokens",
                        "Confirm the token is still listed; if not, generate a new one and update Vooda",
                    ],
                    permission_fix_steps=[
                        "Confirm the token's owner is a member of the workspace",
                        "Asana PATs scope to whatever workspaces the user can see",
                    ],
                )
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        last_sync = sync_state.get("last_sync", "")

        async with make_async_client(timeout=30) as c:
            # Workspaces
            r = await c.get(f"{_API}/workspaces", headers=self._headers)
            if r.status_code != 200:
                return
            workspaces = (r.json() or {}).get("data", []) or []

            for ws in workspaces:
                ws_gid = ws.get("gid")
                ws_name = ws.get("name", ws_gid)
                if self.workspace_filter and ws_name not in self.workspace_filter:
                    continue

                # Projects in workspace
                offset: Optional[str] = None
                while True:
                    params: dict = {"workspace": ws_gid, "limit": "100"}
                    if offset:
                        params["offset"] = offset
                    pr = await c.get(f"{_API}/projects",
                                     headers=self._headers, params=params)
                    if pr.status_code != 200:
                        break
                    pdata = pr.json() or {}
                    projects = pdata.get("data") or []
                    for project in projects:
                        async for item in self._iter_project_tasks(
                            c, ws_gid, ws_name, project, last_sync,
                        ):
                            yield item
                    offset = (pdata.get("next_page") or {}).get("offset")
                    if not offset:
                        break
                    await asyncio.sleep(0.3)

    async def _iter_project_tasks(
        self, c: httpx.AsyncClient, ws_gid: str, ws_name: str,
        project: dict, last_sync: str,
    ) -> AsyncIterator[ScanableContent]:
        proj_gid = project.get("gid")
        proj_name = project.get("name", proj_gid)
        offset: Optional[str] = None
        while True:
            params: dict = {
                "limit": "100",
                "opt_fields": "name,notes,modified_at,permalink_url,assignee.name",
            }
            if last_sync:
                params["modified_since"] = last_sync
            if offset:
                params["offset"] = offset
            tr = await c.get(f"{_API}/projects/{proj_gid}/tasks",
                             headers=self._headers, params=params)
            if tr.status_code != 200:
                break
            tdata = tr.json() or {}
            tasks = tdata.get("data") or []
            for task in tasks:
                task_gid = task.get("gid")
                modified = task.get("modified_at", "")
                if modified > self._updated_sync_state.get("last_sync", ""):
                    self._updated_sync_state["last_sync"] = modified

                notes = task.get("notes") or ""
                if notes.strip():
                    yield ScanableContent(
                        source_locator=f"asana://{ws_gid}/task/{task_gid}/notes",
                        content=notes,
                        content_type="page",
                        deep_link_url=task.get("permalink_url", ""),
                        author=(task.get("assignee") or {}).get("name", ""),
                        metadata={"workspace": ws_name, "project": proj_name,
                                  "task_id": task_gid, "title": task.get("name", "")},
                    )

                # Stories (comments) — separate API
                async for comment in self._iter_task_comments(
                    c, ws_gid, ws_name, proj_name, task_gid, task.get("permalink_url", ""),
                ):
                    yield comment

            offset = (tdata.get("next_page") or {}).get("offset")
            if not offset:
                break
            await asyncio.sleep(0.3)

    async def _iter_task_comments(
        self, c: httpx.AsyncClient, ws_gid: str, ws_name: str, proj_name: str,
        task_gid: str, deep_link: str,
    ) -> AsyncIterator[ScanableContent]:
        sr = await c.get(f"{_API}/tasks/{task_gid}/stories",
                         headers=self._headers,
                         params={"opt_fields": "type,text,created_at,created_by.name"})
        if sr.status_code != 200:
            return
        for story in (sr.json() or {}).get("data", []) or []:
            if story.get("type") != "comment":
                continue
            text = story.get("text") or ""
            if not text.strip():
                continue
            sid = story.get("gid", "")
            yield ScanableContent(
                source_locator=f"asana://{ws_gid}/task/{task_gid}/comment/{sid}",
                content=text,
                content_type="comment",
                deep_link_url=deep_link,
                author=(story.get("created_by") or {}).get("name", ""),
                metadata={"workspace": ws_name, "project": proj_name, "task_id": task_gid},
            )

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
