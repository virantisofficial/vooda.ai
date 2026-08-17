# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Mattermost source adapter — channel posts.

Open-source Slack alternative, often a hard requirement in
government, defense, and regulated verticals where Slack's cloud
hosting fails compliance review. Self-hosted typically; the API
shape is similar to Slack but the auth is simpler (PAT or
session token, no OAuth dance).

Auth: Personal Access Token from System Console → Integrations →
Personal Access Tokens. Sent as `Authorization: Bearer <pat>`.

Out of scope (deferred):
  - Direct messages (1:1 / group DMs) — privacy-heavy, separate
    consent flow needed.
  - File attachments (Mattermost stores them on the server, similar
    to Slack — wire later if customers ask).
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator, Optional

import httpx
import structlog

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_http_error,
    classify_network_error,
)
from services.source_scanners.base import ScanableContent, SourceAdapter

# Module logger — emits a structured ``scan_request_failed`` line when
# a mid-scan Mattermost call returns non-200, so a token expiring mid-scan
# or a per-team membership revocation surfaces as a grep-able event in
# the worker log stream rather than a silent items_scanned=0.  Mirrors
# the pattern applied to confluence.py / jira.py / _msgraph.py / notion.py.
logger = structlog.get_logger(__name__)


class MattermostAdapter(SourceAdapter):
    source_type = "mattermost"

    def __init__(
        self,
        site_url: str,
        token: str,
        teams: str = "*",
    ):
        if not (site_url and token):
            raise ValueError("Mattermost adapter requires site_url and token")
        self.site_url = site_url.rstrip("/")
        self.token = token
        self.team_filter = (
            [t.strip() for t in teams.split(",") if t.strip()] if teams != "*" else []
        )
        self._headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Probe ``/users/me`` — every authenticated Mattermost user
        can read their own user record.
        """
        ctx = {"adapter": "mattermost", "site_url": self.site_url}
        try:
            async with make_async_client(timeout=15) as c:
                r = await c.get(f"{self.site_url}/api/v4/users/me", headers=self._headers)
                if r.status_code == 200:
                    user = r.json() or {}
                    return {
                        "status": "success",
                        "message": f"Connected as {user.get('username', 'Mattermost user')}",
                    }
                err = classify_http_error(
                    r, provider="mattermost", context=ctx,
                    auth_fix_steps=[
                        "Open Mattermost → Account Settings → Security → Personal Access Tokens",
                        "Confirm the token is still listed; if not, ask an admin to enable PATs and generate a new one",
                    ],
                    permission_fix_steps=[
                        "Confirm the token's user is a member of the teams you want to scan",
                        "System Console → User Management → Channels can grant per-team membership",
                    ],
                )
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        last_sync_ms = int(sync_state.get("last_sync_ms", 0))

        async with make_async_client(timeout=30) as c:
            teams = await self._list_teams(c)
            for team in teams:
                if self.team_filter and team.get("name") not in self.team_filter \
                        and team.get("display_name") not in self.team_filter:
                    continue
                async for chan in self._list_channels(c, team["id"]):
                    if chan.get("type") == "D":
                        # Direct message — skip per scope guidance.
                        continue
                    async for item in self._iter_posts(
                        c, team, chan, last_sync_ms,
                    ):
                        yield item

    async def _list_teams(self, c: httpx.AsyncClient) -> list[dict]:
        # PATs see every team they belong to. /teams returns all
        # teams in a system-admin context; per-user it returns the
        # subset they're on.
        teams: list[dict] = []
        page = 0
        while page < 50:
            r = await c.get(f"{self.site_url}/api/v4/teams",
                            headers=self._headers,
                            params={"page": str(page), "per_page": "60"})
            if r.status_code != 200:
                # Stop iterating, but classify + emit a structured log
                # line first so the silent-failure mode (items_scanned=0
                # with no diagnostic) becomes visible.  Mid-scan token
                # expiry, locked accounts, and rate-limit fall-throughs
                # all land here — error_code distinguishes them.
                err = classify_http_error(
                    r,
                    provider="mattermost",
                    context={
                        "adapter": "mattermost",
                        "site_url": self.site_url,
                        "phase": "list_teams",
                        "page": page,
                    },
                )
                logger.warning(
                    "scan_request_failed",
                    source_type="mattermost",
                    error_code=err.code,
                    error_title=err.title,
                    trace_id=err.trace_id,
                    http_status=err.http_status,
                    phase="list_teams",
                    page=page,
                )
                break
            chunk = r.json() or []
            if not chunk:
                break
            teams.extend(chunk)
            if len(chunk) < 60:
                break
            page += 1
        return teams

    async def _list_channels(
        self, c: httpx.AsyncClient, team_id: str,
    ) -> AsyncIterator[dict]:
        page = 0
        while page < 50:
            r = await c.get(
                f"{self.site_url}/api/v4/teams/{team_id}/channels",
                headers=self._headers,
                params={"page": str(page), "per_page": "100"},
            )
            if r.status_code != 200:
                err = classify_http_error(
                    r,
                    provider="mattermost",
                    context={
                        "adapter": "mattermost",
                        "site_url": self.site_url,
                        "phase": "list_channels",
                        "team_id": team_id,
                        "page": page,
                    },
                )
                logger.warning(
                    "scan_request_failed",
                    source_type="mattermost",
                    error_code=err.code,
                    error_title=err.title,
                    trace_id=err.trace_id,
                    http_status=err.http_status,
                    phase="list_channels",
                    team_id=team_id,
                    page=page,
                )
                return
            chunk = r.json() or []
            if not chunk:
                return
            for ch in chunk:
                yield ch
            if len(chunk) < 100:
                return
            page += 1

    async def _iter_posts(
        self, c: httpx.AsyncClient, team: dict, chan: dict, last_sync_ms: int,
    ) -> AsyncIterator[ScanableContent]:
        # /channels/{id}/posts returns up to 200 posts at a time,
        # ordered newest-first. We page until we hit something older
        # than last_sync_ms.
        page = 0
        max_seen_ms = last_sync_ms
        while page < 50:
            r = await c.get(
                f"{self.site_url}/api/v4/channels/{chan['id']}/posts",
                headers=self._headers,
                params={"page": str(page), "per_page": "200",
                        # `since` filters to posts updated >= timestamp;
                        # only set on first page so we don't get an
                        # endless overlap.
                        **({"since": str(last_sync_ms)} if last_sync_ms else {})},
            )
            if r.status_code != 200:
                # Most-likely cause for a per-channel failure: bot lacks
                # membership on this channel (private channel never
                # invited the bot).  Surface as a classified event so an
                # operator can see exactly which channel and team the
                # bot was rejected from.
                err = classify_http_error(
                    r,
                    provider="mattermost",
                    context={
                        "adapter": "mattermost",
                        "site_url": self.site_url,
                        "phase": "list_posts",
                        "team_id": team.get("id"),
                        "channel_id": chan.get("id"),
                        "channel_name": chan.get("name"),
                        "page": page,
                    },
                )
                logger.warning(
                    "scan_request_failed",
                    source_type="mattermost",
                    error_code=err.code,
                    error_title=err.title,
                    trace_id=err.trace_id,
                    http_status=err.http_status,
                    phase="list_posts",
                    team_id=team.get("id"),
                    channel_id=chan.get("id"),
                    channel_name=chan.get("name"),
                    page=page,
                )
                return
            data = r.json() or {}
            order = data.get("order") or []
            posts = data.get("posts") or {}
            if not order:
                return
            for pid in order:
                post = posts.get(pid) or {}
                update_at = int(post.get("update_at") or post.get("create_at") or 0)
                if last_sync_ms and update_at < last_sync_ms:
                    continue
                if update_at > max_seen_ms:
                    max_seen_ms = update_at
                msg = post.get("message") or ""
                if not msg.strip():
                    continue
                # Skip system messages (channel join/leave/etc).
                if (post.get("type") or "").strip():
                    continue
                yield ScanableContent(
                    source_locator=f"mattermost://{team['id']}/{chan['id']}/{pid}",
                    content=msg,
                    content_type="message",
                    author=post.get("user_id"),
                    deep_link_url=f"{self.site_url}/{team.get('name','')}/pl/{pid}",
                    metadata={
                        "team_id": team["id"], "team_name": team.get("name", ""),
                        "channel_id": chan["id"], "channel_name": chan.get("name", ""),
                        "channel_type": chan.get("type", ""),
                    },
                )
            if len(order) < 200:
                break
            page += 1
            await asyncio.sleep(0.2)
        if max_seen_ms > int(self._updated_sync_state.get("last_sync_ms", 0) or 0):
            self._updated_sync_state["last_sync_ms"] = max_seen_ms

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
