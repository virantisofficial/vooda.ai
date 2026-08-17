# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Bitbucket Cloud — issue + pull request descriptions and comments.

Note: Bitbucket *code* is scanned via the Repositories git path
already. This adapter covers the discussion surface that lives in
Bitbucket's database, NOT in the repo — same secret-leak profile
as Jira / GitHub Issues.

Auth: Username + App password (Bitbucket Cloud) or PAT (Bitbucket
Server). Sent as HTTP Basic auth — `username:app_password`.

Note on Bitbucket Cloud: the issues feature is per-repository and
must be explicitly enabled. We probe and skip silently if disabled.

Fields scanned:
  - issues: title, content.raw, comments[].content.raw
  - pull requests: title, description, comments[].content.raw
  - PR inline comments are skipped (they're tied to specific code
    diffs which the git scan path covers).
"""
from __future__ import annotations

import asyncio
from base64 import b64encode
from typing import AsyncIterator, Optional

import httpx

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_bitbucket_error,
    classify_network_error,
)
from services.source_scanners.base import ScanableContent, SourceAdapter


_API_CLOUD = "https://api.bitbucket.org/2.0"


class BitbucketIssuesAdapter(SourceAdapter):
    source_type = "bitbucket_issues"

    def __init__(
        self,
        username: str,
        app_password: str,
        repos: str = "",
        api_base: str = _API_CLOUD,
        include_pull_requests: bool = True,
    ):
        if not (username and app_password):
            raise ValueError("Bitbucket adapter requires username + app_password")
        if not repos.strip():
            raise ValueError("Bitbucket adapter requires `repos` (comma-separated workspace/repo)")
        self.username = username
        self.app_password = app_password
        self.api_base = api_base.rstrip("/")
        self.repos = [r.strip() for r in repos.split(",") if r.strip()]
        self.include_pull_requests = include_pull_requests
        auth = b64encode(f"{username}:{app_password}".encode()).decode()
        self._headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Probe ``/user`` — the auth + identity check.

        Note: this proves the credential works, but doesn't prove
        the Issues feature is enabled on every repo (that's a
        per-repo configuration that can return 404 at scan time —
        the bitbucket classifier handles that as a distinct code
        with its own fix step).
        """
        ctx = {"adapter": "bitbucket", "api_base": self.api_base}
        try:
            async with make_async_client(timeout=15) as c:
                r = await c.get(f"{self.api_base}/user", headers=self._headers)
                if r.status_code == 200:
                    user = r.json() or {}
                    name = user.get("display_name") or user.get("username", "Bitbucket user")
                    return {"status": "success", "message": f"Connected as {name}"}
                err = classify_bitbucket_error(r, ctx)
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        last_sync = sync_state.get("last_sync", "")

        async with make_async_client(timeout=30) as c:
            for repo in self.repos:
                async for item in self._iter_issues(c, repo, last_sync):
                    yield item
                if self.include_pull_requests:
                    async for item in self._iter_pulls(c, repo, last_sync):
                        yield item

    async def _iter_issues(
        self, c: httpx.AsyncClient, repo: str, last_sync: str,
    ) -> AsyncIterator[ScanableContent]:
        url: Optional[str] = f"{self.api_base}/repositories/{repo}/issues"
        params = {"pagelen": 50, "sort": "-updated_on"}
        if last_sync:
            params["q"] = f'updated_on > "{last_sync}"'
        page = 0
        while url and page < 200:
            r = await c.get(url, headers=self._headers, params=params if page == 0 else None)
            if r.status_code == 404:
                # Issues feature not enabled on this repo.
                return
            if r.status_code != 200:
                return
            data = r.json() or {}
            for issue in data.get("values") or []:
                iid = issue.get("id")
                updated = issue.get("updated_on", "")
                if updated > self._updated_sync_state.get("last_sync", ""):
                    self._updated_sync_state["last_sync"] = updated

                body = ((issue.get("content") or {}).get("raw")) or ""
                deep_link = ((issue.get("links") or {}).get("html") or {}).get("href", "")
                if body.strip():
                    yield ScanableContent(
                        source_locator=f"bitbucket://{repo}/issue/{iid}",
                        content=body,
                        content_type="page",
                        deep_link_url=deep_link,
                        author=((issue.get("reporter") or {}).get("display_name", "")),
                        metadata={"repo": repo, "issue_id": iid,
                                  "title": issue.get("title", "")},
                    )

                # Comments
                comments_url = (
                    ((issue.get("links") or {}).get("comments") or {}).get("href")
                    or f"{self.api_base}/repositories/{repo}/issues/{iid}/comments"
                )
                async for cmt in self._iter_comments(
                    c, comments_url, scheme="bitbucket", repo=repo,
                    parent_kind="issue", parent_id=str(iid),
                    parent_deep_link=deep_link,
                ):
                    yield cmt

            url = data.get("next")
            page += 1
            await asyncio.sleep(0.3)

    async def _iter_pulls(
        self, c: httpx.AsyncClient, repo: str, last_sync: str,
    ) -> AsyncIterator[ScanableContent]:
        url: Optional[str] = f"{self.api_base}/repositories/{repo}/pullrequests"
        params = {"pagelen": 50, "state": "OPEN,MERGED,DECLINED,SUPERSEDED"}
        if last_sync:
            params["q"] = f'updated_on > "{last_sync}"'
        page = 0
        while url and page < 200:
            r = await c.get(url, headers=self._headers, params=params if page == 0 else None)
            if r.status_code != 200:
                return
            data = r.json() or {}
            for pr in data.get("values") or []:
                pid = pr.get("id")
                updated = pr.get("updated_on", "")
                if updated > self._updated_sync_state.get("last_sync", ""):
                    self._updated_sync_state["last_sync"] = updated

                deep_link = ((pr.get("links") or {}).get("html") or {}).get("href", "")
                desc = pr.get("description") or ""
                if desc.strip():
                    yield ScanableContent(
                        source_locator=f"bitbucket://{repo}/pull_request/{pid}",
                        content=desc,
                        content_type="page",
                        deep_link_url=deep_link,
                        author=((pr.get("author") or {}).get("display_name", "")),
                        metadata={"repo": repo, "pr_id": pid,
                                  "title": pr.get("title", "")},
                    )
                comments_url = (
                    ((pr.get("links") or {}).get("comments") or {}).get("href")
                    or f"{self.api_base}/repositories/{repo}/pullrequests/{pid}/comments"
                )
                async for cmt in self._iter_comments(
                    c, comments_url, scheme="bitbucket", repo=repo,
                    parent_kind="pull_request", parent_id=str(pid),
                    parent_deep_link=deep_link,
                ):
                    yield cmt

            url = data.get("next")
            page += 1
            await asyncio.sleep(0.3)

    async def _iter_comments(
        self, c: httpx.AsyncClient, url: str, scheme: str, repo: str,
        parent_kind: str, parent_id: str, parent_deep_link: str,
    ) -> AsyncIterator[ScanableContent]:
        next_url: Optional[str] = url
        page = 0
        while next_url and page < 50:
            r = await c.get(next_url, headers=self._headers)
            if r.status_code != 200:
                return
            data = r.json() or {}
            for cmt in data.get("values") or []:
                # Skip inline (PR diff) comments — tied to code lines,
                # not to the discussion thread.
                if cmt.get("inline"):
                    continue
                body = ((cmt.get("content") or {}).get("raw")) or ""
                if not body.strip():
                    continue
                cid = cmt.get("id")
                updated = cmt.get("updated_on") or cmt.get("created_on", "")
                if updated > self._updated_sync_state.get("last_sync", ""):
                    self._updated_sync_state["last_sync"] = updated
                yield ScanableContent(
                    source_locator=f"{scheme}://{repo}/{parent_kind}/{parent_id}/comment/{cid}",
                    content=body,
                    content_type="comment",
                    deep_link_url=parent_deep_link,
                    author=((cmt.get("user") or {}).get("display_name", "")),
                    metadata={"repo": repo, f"{parent_kind}_id": parent_id},
                )
            next_url = data.get("next")
            page += 1

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
