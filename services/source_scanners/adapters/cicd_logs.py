# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""CI/CD Logs source adapter — scans build logs from Jenkins, GitHub Actions, CircleCI."""

import asyncio
from typing import AsyncIterator

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_github_error,
    classify_http_error,
    classify_network_error,
)
from services.source_scanners.base import SourceAdapter, ScanableContent


class CICDLogsSourceAdapter(SourceAdapter):
    source_type = "cicd_logs"

    def __init__(self, provider: str, base_url: str, token: str, project: str = "", max_builds: int = 50):
        self.provider = provider  # jenkins, github_actions, circleci
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.project = project
        self.max_builds = max_builds
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Dispatch to the per-provider probe.

        Each branch routes its own failures through the right
        classifier — GitHub errors via the GitHub classifier (for
        rate-limit / scope diagnostics), Jenkins + CircleCI through
        the generic classifier with provider-specific fix steps.
        """
        ctx = {"adapter": "cicd_logs", "provider": self.provider}
        try:
            if self.provider == "jenkins":
                return await self._test_jenkins(ctx)
            elif self.provider == "github_actions":
                return await self._test_github_actions(ctx)
            elif self.provider == "circleci":
                return await self._test_circleci(ctx)
            return {
                "status": "error",
                "message": f"Unknown CI/CD provider: {self.provider}",
                "title": "Configuration error",
                "summary": f"Unknown CI/CD provider: {self.provider}. Supported: jenkins, github_actions, circleci.",
                "fix_steps": ["Set provider to one of: jenkins, github_actions, circleci"],
                "details": {"code": "cicd_logs.config.unknown_provider", "trace_id": None,
                            "occurred_at": None},
            }
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        if self.provider == "jenkins":
            async for item in self._scan_jenkins(sync_state):
                yield item
        elif self.provider == "github_actions":
            async for item in self._scan_github_actions(sync_state):
                yield item
        elif self.provider == "circleci":
            async for item in self._scan_circleci(sync_state):
                yield item

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state

    # ── Jenkins ──────────────────────────────────────────────

    async def _test_jenkins(self, ctx: dict) -> dict:
        async with make_async_client(timeout=15) as client:
            r = await client.get(
                f"{self.base_url}/api/json",
                auth=(self.token.split(":")[0], self.token.split(":")[-1]) if ":" in self.token else None,
            )
            if r.status_code == 200:
                return {"status": "success", "message": "Connected to Jenkins"}
            err = classify_http_error(
                r, provider="jenkins", context=ctx,
                auth_fix_steps=[
                    "Open Jenkins → People → your user → Configure → API Token",
                    "Generate a new token; pass it to Vooda as `username:apiToken`",
                ],
                permission_fix_steps=[
                    "Confirm the user has Overall: Read + Job: Read",
                    "If using folder-level permissions, ensure the project path is reachable",
                ],
            )
            return err.to_user_dict()

    async def _scan_jenkins(self, sync_state: dict):
        auth = (self.token.split(":")[0], self.token.split(":")[-1]) if ":" in self.token else None
        last_build = int(sync_state.get("last_build", 0))

        async with make_async_client(timeout=30) as client:
            job_path = f"/job/{self.project}" if self.project else ""
            r = await client.get(f"{self.base_url}{job_path}/api/json?tree=builds[number,url]{{0,{self.max_builds}}}", auth=auth)
            if r.status_code != 200:
                return

            builds = r.json().get("builds", [])
            for build in builds:
                build_num = build.get("number", 0)
                if build_num <= last_build:
                    continue

                log_r = await client.get(f"{build['url']}consoleText", auth=auth)
                if log_r.status_code == 200:
                    yield ScanableContent(
                        source_locator=f"jenkins://{self.project or 'default'}/{build_num}",
                        content=log_r.text[:500_000],
                        content_type="log_line",
                        deep_link_url=f"{build['url']}console",
                        metadata={"provider": "jenkins", "build_number": build_num, "project": self.project},
                    )

                if build_num > int(self._updated_sync_state.get("last_build", 0)):
                    self._updated_sync_state["last_build"] = str(build_num)
                await asyncio.sleep(0.3)

    # ── GitHub Actions ───────────────────────────────────────

    async def _test_github_actions(self, ctx: dict) -> dict:
        async with make_async_client(timeout=15) as client:
            r = await client.get(
                f"https://api.github.com/repos/{self.project}/actions/runs?per_page=1",
                headers={"Authorization": f"Bearer {self.token}"},
            )
            if r.status_code == 200:
                return {"status": "success", "message": f"Connected to {self.project} Actions"}
            err = classify_github_error(r, ctx)
            return err.to_user_dict()

    async def _scan_github_actions(self, sync_state: dict):
        last_run = int(sync_state.get("last_run_id", 0))
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json"}

        async with make_async_client(timeout=30) as client:
            r = await client.get(
                f"https://api.github.com/repos/{self.project}/actions/runs?per_page={self.max_builds}&status=completed",
                headers=headers,
            )
            if r.status_code != 200:
                return

            for run in r.json().get("workflow_runs", []):
                run_id = run.get("id", 0)
                if run_id <= last_run:
                    continue

                # Get logs
                log_r = await client.get(f"https://api.github.com/repos/{self.project}/actions/runs/{run_id}/logs",
                                         headers=headers, follow_redirects=True)
                if log_r.status_code == 200:
                    yield ScanableContent(
                        source_locator=f"github-actions://{self.project}/{run_id}",
                        content=log_r.text[:500_000],
                        content_type="log_line",
                        deep_link_url=run.get("html_url", ""),
                        metadata={"provider": "github_actions", "run_id": run_id, "workflow": run.get("name", "")},
                    )

                if run_id > int(self._updated_sync_state.get("last_run_id", 0)):
                    self._updated_sync_state["last_run_id"] = str(run_id)
                await asyncio.sleep(0.3)

    # ── CircleCI ─────────────────────────────────────────────

    async def _test_circleci(self, ctx: dict) -> dict:
        async with make_async_client(timeout=15) as client:
            r = await client.get(
                "https://circleci.com/api/v2/me",
                headers={"Circle-Token": self.token},
            )
            if r.status_code == 200:
                return {"status": "success", "message": "Connected to CircleCI"}
            err = classify_http_error(
                r, provider="circleci", context=ctx,
                auth_fix_steps=[
                    "Open app.circleci.com → User Settings → Personal API Tokens",
                    "Generate a new token (the old one may be revoked) and update Vooda",
                ],
                permission_fix_steps=[
                    "CircleCI personal tokens see whatever orgs the user is a member of",
                    "For org-wide visibility, the user needs at least 'member' on each org's project",
                ],
            )
            return err.to_user_dict()

    async def _scan_circleci(self, sync_state: dict):
        last_num = int(sync_state.get("last_build_num", 0))
        headers = {"Circle-Token": self.token}
        slug = self.project  # e.g., "gh/org/repo"

        async with make_async_client(timeout=30) as client:
            r = await client.get(f"https://circleci.com/api/v2/project/{slug}/pipeline?page-token=&limit={self.max_builds}", headers=headers)
            if r.status_code != 200:
                return

            for pipeline in r.json().get("items", []):
                p_id = pipeline.get("id", "")
                p_num = pipeline.get("number", 0)
                if p_num <= last_num:
                    continue

                # Get workflow jobs and their logs
                wf_r = await client.get(f"https://circleci.com/api/v2/pipeline/{p_id}/workflow", headers=headers)
                if wf_r.status_code != 200:
                    continue

                for wf in wf_r.json().get("items", []):
                    jobs_r = await client.get(f"https://circleci.com/api/v2/workflow/{wf['id']}/job", headers=headers)
                    if jobs_r.status_code != 200:
                        continue
                    for job in jobs_r.json().get("items", []):
                        job_num = job.get("job_number", "")
                        log_r = await client.get(
                            f"https://circleci.com/api/v2/project/{slug}/{job_num}/tests",
                            headers=headers,
                        )
                        # CircleCI doesn't have a simple log endpoint — output steps
                        steps_url = f"https://circleci.com/api/v1.1/project/{slug}/{job_num}"
                        steps_r = await client.get(steps_url, headers=headers)
                        if steps_r.status_code == 200:
                            steps_data = steps_r.json()
                            log_parts = []
                            for step in steps_data.get("steps", []):
                                for action in step.get("actions", []):
                                    if action.get("output_url"):
                                        out_r = await client.get(action["output_url"], headers=headers)
                                        if out_r.status_code == 200:
                                            log_parts.append(out_r.text[:50_000])

                            if log_parts:
                                yield ScanableContent(
                                    source_locator=f"circleci://{slug}/{p_num}/{job_num}",
                                    content="\n".join(log_parts)[:500_000],
                                    content_type="log_line",
                                    deep_link_url=f"https://app.circleci.com/pipelines/{slug}/{p_num}",
                                    metadata={"provider": "circleci", "pipeline": p_num, "job": job_num},
                                )

                if p_num > int(self._updated_sync_state.get("last_build_num", 0)):
                    self._updated_sync_state["last_build_num"] = str(p_num)
                await asyncio.sleep(0.5)
