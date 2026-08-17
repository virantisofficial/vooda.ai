# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""GitHub Issues source adapter — scans issue + PR descriptions and comments.

Why a separate source: code repos are scanned by the git-scan path
(commit history, file content). Issue and PR bodies — and their
discussion comments — live in GitHub's database, NOT in the repo,
and are routinely missed by code-only scanners. Same secret-leak
profile as Jira issues.

Auth: GitHub PAT or fine-grained token. Reuses the existing
`github` IntegrationConfig fields (token, optionally a list of
repos).

Coverage:
  - Issues (open and closed) on the configured repos
  - Pull request bodies (PRs are issues at the API level)
  - Comments on both
  - Discussions are deferred — separate API surface, less common
    secret-leak vector

Out of scope:
  - Code review comments inline on diffs (the diff itself is in the
    repo and gets scanned by git-scan; inline comments rarely contain
    secrets).
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator, Optional

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_github_error,
    classify_network_error,
)
from services.source_scanners.base import ScanableContent, SourceAdapter


class GitHubIssuesAdapter(SourceAdapter):
    source_type = "github_issues"

    def __init__(
        self,
        token: str,
        repos: str = "",
        api_base: str = "https://api.github.com",
        include_pull_requests: bool = True,
    ):
        if not token:
            raise ValueError("GitHub Issues adapter requires a token")
        if not repos.strip():
            raise ValueError("GitHub Issues adapter requires `repos` (comma-separated owner/name)")
        self.token = token
        self.api_base = api_base.rstrip("/")
        self.repos = [r.strip() for r in repos.split(",") if r.strip()]
        self.include_pull_requests = include_pull_requests
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Probe ``/user`` — proves the token works AND reveals the
        authenticated identity for the success message.

        Returns the legacy ``{status, message}`` dict for backward
        compatibility, plus the structured ``IntegrationError``
        envelope on failure (title / summary / fix_steps / details).
        """
        ctx = {"adapter": "github", "api_base": self.api_base}
        try:
            async with make_async_client(timeout=15) as client:
                r = await client.get(f"{self.api_base}/user", headers=self._headers)
                if r.status_code == 200:
                    user = r.json() or {}
                    return {
                        "status": "success",
                        "message": f"Connected as {user.get('login', 'user')}",
                    }
                err = classify_github_error(r, ctx)
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        last_sync = sync_state.get("last_sync", "")  # ISO 8601

        async with make_async_client(timeout=30) as client:
            for repo in self.repos:
                # GitHub's /repos/{owner}/{repo}/issues endpoint returns
                # both issues and PRs (PRs are issues at the API level).
                # `since` filters by updated time on the server.
                params = {"state": "all", "per_page": "100", "sort": "updated", "direction": "asc"}
                if last_sync:
                    params["since"] = last_sync
                page = 1
                MAX_PAGES = 200
                while page <= MAX_PAGES:
                    url = f"{self.api_base}/repos/{repo}/issues"
                    r = await client.get(
                        url, headers=self._headers,
                        params={**params, "page": str(page)},
                    )
                    if r.status_code != 200:
                        break
                    issues = r.json() or []
                    if not issues:
                        break

                    for issue in issues:
                        is_pr = bool(issue.get("pull_request"))
                        if is_pr and not self.include_pull_requests:
                            continue
                        number = issue.get("number")
                        body = issue.get("body") or ""
                        updated = issue.get("updated_at", "")
                        if updated > self._updated_sync_state.get("last_sync", ""):
                            self._updated_sync_state["last_sync"] = updated

                        if body.strip():
                            kind = "pull_request" if is_pr else "issue"
                            yield ScanableContent(
                                source_locator=f"github://{repo}/{kind}/{number}",
                                content=body,
                                content_type="page",
                                author=(issue.get("user") or {}).get("login", ""),
                                deep_link_url=issue.get("html_url", ""),
                                metadata={"repo": repo, "kind": kind, "number": number,
                                          "title": issue.get("title", "")},
                            )

                        # Pull comments inline. We could batch via the
                        # /repos/{owner}/{repo}/issues/comments endpoint
                        # but that doesn't anchor each comment to its
                        # parent issue cheaply.
                        comments_url = issue.get("comments_url")
                        if not comments_url:
                            continue
                        cr = await client.get(comments_url, headers=self._headers)
                        if cr.status_code != 200:
                            continue
                        for comment in (cr.json() or []):
                            cbody = comment.get("body") or ""
                            cupdated = comment.get("updated_at", "")
                            if cupdated > self._updated_sync_state.get("last_sync", ""):
                                self._updated_sync_state["last_sync"] = cupdated
                            if cbody.strip():
                                yield ScanableContent(
                                    source_locator=f"github://{repo}/issue/{number}/comment/{comment.get('id')}",
                                    content=cbody,
                                    content_type="comment",
                                    author=(comment.get("user") or {}).get("login", ""),
                                    deep_link_url=comment.get("html_url", ""),
                                    metadata={"repo": repo, "issue_number": number},
                                )
                    if len(issues) < 100:
                        break
                    page += 1
                    await asyncio.sleep(0.5)

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
