# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Bitbucket Git provider — creates branches, commits, and PRs via Bitbucket REST API 2.0.
"""

import base64
import structlog
from typing import Optional

import httpx

from services.git_integration.base import GitProvider, PRResult, PRRequest, FileChange

logger = structlog.get_logger()


class BitbucketProvider(GitProvider):
    """Bitbucket Cloud REST API 2.0 implementation."""

    API_BASE = "https://api.bitbucket.org/2.0"

    def __init__(self, workspace: str, repo_slug: str, username: str, app_password: str):
        self.workspace = workspace
        self.repo_slug = repo_slug
        self.auth = (username, app_password)

    def _url(self, path: str) -> str:
        return f"{self.API_BASE}/repositories/{self.workspace}/{self.repo_slug}{path}"

    async def create_branch(self, branch_name: str, from_branch: str) -> bool:
        async with httpx.AsyncClient(timeout=15) as client:
            # Get target commit
            r = await client.get(
                self._url(f"/refs/branches/{from_branch}"),
                auth=self.auth,
            )
            if r.status_code != 200:
                return False
            target_hash = r.json()["target"]["hash"]

            r = await client.post(
                self._url("/refs/branches"),
                auth=self.auth,
                json={"name": branch_name, "target": {"hash": target_hash}},
            )
            return r.status_code in (200, 201)

    async def commit_files(
        self,
        branch: str,
        files: list[FileChange],
        commit_message: str,
    ) -> bool:
        async with httpx.AsyncClient(timeout=30) as client:
            # Bitbucket uses form-data for commits
            form_data = {"message": commit_message, "branch": branch}
            files_data = {}
            for fc in files:
                files_data[fc.file_path] = (fc.file_path, fc.content.encode(), "text/plain")

            r = await client.post(
                self._url("/src"),
                auth=self.auth,
                data=form_data,
                files=files_data,
            )
            return r.status_code in (200, 201)

    async def create_pull_request(self, request: PRRequest) -> PRResult:
        async with httpx.AsyncClient(timeout=15) as client:
            payload = {
                "title": request.title,
                "description": request.description,
                "source": {"branch": {"name": request.source_branch}},
                "destination": {"branch": {"name": request.target_branch}},
                "close_source_branch": True,
            }
            if request.reviewers:
                payload["reviewers"] = [{"username": r} for r in request.reviewers]

            r = await client.post(
                self._url("/pullrequests"),
                auth=self.auth,
                json=payload,
            )
            if r.status_code in (200, 201):
                data = r.json()
                return PRResult(
                    success=True,
                    pr_url=data.get("links", {}).get("html", {}).get("href"),
                    pr_number=data.get("id"),
                    branch_name=request.source_branch,
                )
            else:
                logger.error("bitbucket_pr_failed", status=r.status_code)
                return PRResult(success=False, error=f"Bitbucket API returned {r.status_code}")

    async def get_file_content(self, file_path: str, branch: str) -> Optional[str]:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                self._url(f"/src/{branch}/{file_path}"),
                auth=self.auth,
            )
            return r.text if r.status_code == 200 else None

    async def branch_exists(self, branch_name: str) -> bool:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                self._url(f"/refs/branches/{branch_name}"),
                auth=self.auth,
            )
            return r.status_code == 200
