# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
GitLab Git provider — creates branches, commits, and MRs via GitLab REST API v4.
"""

import base64
import urllib.parse
import structlog
from typing import Optional

import httpx

from services.git_integration.base import GitProvider, PRResult, PRRequest, FileChange

logger = structlog.get_logger()


class GitLabProvider(GitProvider):
    """GitLab REST API v4 implementation."""

    def __init__(self, host: str, project_path: str, token: str):
        self.host = host.rstrip("/")
        self.project_id = urllib.parse.quote(project_path, safe="")
        self.headers = {"PRIVATE-TOKEN": token}

    def _url(self, path: str) -> str:
        return f"{self.host}/api/v4/projects/{self.project_id}{path}"

    async def create_branch(self, branch_name: str, from_branch: str) -> bool:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                self._url("/repository/branches"),
                headers=self.headers,
                json={"branch": branch_name, "ref": from_branch},
            )
            if r.status_code in (200, 201):
                return True
            elif r.status_code == 400 and "already exists" in r.text.lower():
                return True
            else:
                logger.error("gitlab_create_branch_failed", status=r.status_code)
                return False

    async def commit_files(
        self,
        branch: str,
        files: list[FileChange],
        commit_message: str,
    ) -> bool:
        async with httpx.AsyncClient(timeout=30) as client:
            actions = []
            for fc in files:
                # Check if file exists
                encoded_path = urllib.parse.quote(fc.file_path, safe="")
                r = await client.get(
                    self._url(f"/repository/files/{encoded_path}"),
                    headers=self.headers,
                    params={"ref": branch},
                )
                action = "update" if r.status_code == 200 else "create"
                actions.append({
                    "action": action,
                    "file_path": fc.file_path,
                    "content": fc.content,
                })

            r = await client.post(
                self._url("/repository/commits"),
                headers=self.headers,
                json={
                    "branch": branch,
                    "commit_message": commit_message,
                    "actions": actions,
                },
            )
            if r.status_code in (200, 201):
                return True
            else:
                logger.error("gitlab_commit_failed", status=r.status_code, body=r.text[:200])
                return False

    async def create_pull_request(self, request: PRRequest) -> PRResult:
        async with httpx.AsyncClient(timeout=15) as client:
            payload = {
                "source_branch": request.source_branch,
                "target_branch": request.target_branch,
                "title": request.title,
                "description": request.description,
            }
            if request.labels:
                payload["labels"] = ",".join(request.labels)
            if request.reviewers:
                # GitLab uses user IDs for reviewers — simplified to assignee
                pass

            r = await client.post(
                self._url("/merge_requests"),
                headers=self.headers,
                json=payload,
            )
            if r.status_code in (200, 201):
                data = r.json()
                return PRResult(
                    success=True,
                    pr_url=data.get("web_url"),
                    pr_number=data.get("iid"),
                    branch_name=request.source_branch,
                )
            elif r.status_code == 409:
                return PRResult(success=False, error="MR already exists", branch_name=request.source_branch)
            else:
                logger.error("gitlab_mr_failed", status=r.status_code, body=r.text[:200])
                return PRResult(success=False, error=f"GitLab API returned {r.status_code}")

    async def get_file_content(self, file_path: str, branch: str) -> Optional[str]:
        async with httpx.AsyncClient(timeout=15) as client:
            encoded_path = urllib.parse.quote(file_path, safe="")
            r = await client.get(
                self._url(f"/repository/files/{encoded_path}/raw"),
                headers=self.headers,
                params={"ref": branch},
            )
            if r.status_code == 200:
                return r.text
            return None

    async def branch_exists(self, branch_name: str) -> bool:
        async with httpx.AsyncClient(timeout=10) as client:
            encoded = urllib.parse.quote(branch_name, safe="")
            r = await client.get(
                self._url(f"/repository/branches/{encoded}"),
                headers=self.headers,
            )
            return r.status_code == 200
