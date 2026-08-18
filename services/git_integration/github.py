# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
GitHub Git provider — creates branches, commits, and PRs via GitHub REST API.
"""

import base64
import structlog
from typing import Optional

import httpx

from services.git_integration.base import GitProvider, PRResult, PRRequest, FileChange

logger = structlog.get_logger()


class GitHubProvider(GitProvider):
    """GitHub REST API v3 implementation."""

    API_BASE = "https://api.github.com"

    def __init__(self, owner: str, repo: str, token: str):
        self.owner = owner
        self.repo = repo
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _url(self, path: str) -> str:
        return f"{self.API_BASE}/repos/{self.owner}/{self.repo}{path}"

    async def create_branch(self, branch_name: str, from_branch: str) -> bool:
        async with httpx.AsyncClient(timeout=15) as client:
            # Get the SHA of the source branch
            r = await client.get(
                self._url(f"/git/ref/heads/{from_branch}"),
                headers=self.headers,
            )
            if r.status_code != 200:
                logger.error("github_get_ref_failed", branch=from_branch, status=r.status_code)
                return False

            sha = r.json()["object"]["sha"]

            # Create the new branch
            r = await client.post(
                self._url("/git/refs"),
                headers=self.headers,
                json={"ref": f"refs/heads/{branch_name}", "sha": sha},
            )
            if r.status_code == 201:
                return True
            elif r.status_code == 422:
                # Branch already exists
                logger.info("github_branch_exists", branch=branch_name)
                return True
            else:
                logger.error("github_create_branch_failed", status=r.status_code, body=r.text[:200])
                return False

    async def commit_files(
        self,
        branch: str,
        files: list[FileChange],
        commit_message: str,
    ) -> bool:
        async with httpx.AsyncClient(timeout=30) as client:
            for file_change in files:
                # Get current file SHA (needed for update)
                existing_sha = None
                r = await client.get(
                    self._url(f"/contents/{file_change.file_path}"),
                    headers=self.headers,
                    params={"ref": branch},
                )
                if r.status_code == 200:
                    existing_sha = r.json()["sha"]

                # Create or update file
                payload = {
                    "message": commit_message,
                    "content": base64.b64encode(file_change.content.encode()).decode(),
                    "branch": branch,
                }
                if existing_sha:
                    payload["sha"] = existing_sha

                r = await client.put(
                    self._url(f"/contents/{file_change.file_path}"),
                    headers=self.headers,
                    json=payload,
                )
                if r.status_code not in (200, 201):
                    logger.error("github_commit_failed", file=file_change.file_path, status=r.status_code)
                    return False

            return True

    async def create_pull_request(self, request: PRRequest) -> PRResult:
        async with httpx.AsyncClient(timeout=15) as client:
            payload = {
                "title": request.title,
                "body": request.description,
                "head": request.source_branch,
                "base": request.target_branch,
                "draft": request.draft,
            }

            r = await client.post(
                self._url("/pulls"),
                headers=self.headers,
                json=payload,
            )

            if r.status_code == 201:
                data = r.json()
                pr_number = data["number"]
                pr_url = data["html_url"]

                # Add labels if specified
                if request.labels:
                    await client.post(
                        self._url(f"/issues/{pr_number}/labels"),
                        headers=self.headers,
                        json={"labels": request.labels},
                    )

                # Request reviewers if specified
                if request.reviewers:
                    await client.post(
                        self._url(f"/pulls/{pr_number}/requested_reviewers"),
                        headers=self.headers,
                        json={"reviewers": request.reviewers},
                    )

                logger.info("github_pr_created", pr_number=pr_number, url=pr_url)
                return PRResult(success=True, pr_url=pr_url, pr_number=pr_number, branch_name=request.source_branch)

            elif r.status_code == 422:
                # PR already exists for this branch
                error_msg = r.json().get("errors", [{}])[0].get("message", "PR already exists")
                logger.warning("github_pr_exists", message=error_msg)
                return PRResult(success=False, error=error_msg, branch_name=request.source_branch)
            else:
                logger.error("github_pr_failed", status=r.status_code, body=r.text[:200])
                return PRResult(success=False, error=f"GitHub API returned {r.status_code}")

    async def get_file_content(self, file_path: str, branch: str) -> Optional[str]:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                self._url(f"/contents/{file_path}"),
                headers=self.headers,
                params={"ref": branch},
            )
            if r.status_code == 200:
                data = r.json()
                content = base64.b64decode(data["content"]).decode()
                return content
            return None

    async def branch_exists(self, branch_name: str) -> bool:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                self._url(f"/branches/{branch_name}"),
                headers=self.headers,
            )
            return r.status_code == 200
