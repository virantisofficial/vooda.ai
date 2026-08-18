# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Slack source adapter — scans messages, files, and snippets for secrets."""

import asyncio
from typing import AsyncIterator, Optional
from datetime import datetime, timezone

import httpx

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_network_error,
    classify_slack_error,
)
from services.source_scanners.base import SourceAdapter, ScanableContent


class SlackSourceAdapter(SourceAdapter):
    source_type = "slack"

    def __init__(
        self,
        bot_token: str,
        channels: str = "*",
        include_private: bool = False,
        include_files: bool = True,
    ):
        self.bot_token = bot_token
        self.channel_filter = [c.strip().lstrip("#") for c in channels.split(",")] if channels != "*" else []
        self.include_private = include_private
        self.include_files = include_files
        self._updated_sync_state: dict = {}
        self._headers = {"Authorization": f"Bearer {bot_token}"}

    async def test_connection(self) -> dict:
        """Probe ``auth.test`` — Slack's canonical "are you alive" check.

        Slack's API returns HTTP 200 even on logical errors (the body
        carries the success/failure signal via ``ok``).  We parse the
        body first and route non-OK responses through
        :func:`classify_slack_error`, which decodes the ``error``
        string into one of the structured slack.* codes.
        """
        ctx = {"adapter": "slack"}
        try:
            async with make_async_client(timeout=15) as client:
                r = await client.get("https://slack.com/api/auth.test", headers=self._headers)
                try:
                    data = r.json()
                except ValueError:
                    data = {}
                if r.status_code == 200 and data.get("ok"):
                    return {
                        "status": "success",
                        "message": f"Connected to {data.get('team', 'Slack')} workspace as {data.get('user', 'bot')}",
                        "details": {"team": data.get("team"), "user": data.get("user")},
                    }
                err = classify_slack_error(data, response=r, context=ctx)
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)  # Start from previous state

        async with make_async_client(timeout=30) as client:
            channels = await self._list_channels(client)

            for ch in channels:
                ch_id = ch["id"]
                ch_name = ch.get("name", ch_id)
                oldest = sync_state.get(ch_id, "0")

                async for msg in self._get_messages(client, ch_id, oldest):
                    ts = msg.get("ts", "")
                    text = msg.get("text", "")
                    user = msg.get("user", "unknown")

                    if text.strip():
                        yield ScanableContent(
                            source_locator=f"slack://{ch_id}/{ts}",
                            content=text,
                            content_type="message",
                            timestamp=datetime.fromtimestamp(float(ts), tz=timezone.utc) if ts else None,
                            author=user,
                            deep_link_url=f"https://slack.com/archives/{ch_id}/p{ts.replace('.', '')}",
                            metadata={"channel_name": ch_name, "channel_id": ch_id},
                        )

                    # Scan file attachments
                    if self.include_files:
                        for f in msg.get("files", []):
                            content = await self._get_file_content(client, f)
                            if content:
                                yield ScanableContent(
                                    source_locator=f"slack://{ch_id}/{ts}/file/{f.get('id', '')}",
                                    content=content,
                                    content_type="file",
                                    timestamp=datetime.fromtimestamp(float(ts), tz=timezone.utc) if ts else None,
                                    author=user,
                                    deep_link_url=f.get("permalink", ""),
                                    metadata={
                                        "channel_name": ch_name,
                                        "file_name": f.get("name", ""),
                                        "file_type": f.get("filetype", ""),
                                    },
                                )

                    # Track latest message per channel for incremental sync
                    if ts > self._updated_sync_state.get(ch_id, "0"):
                        self._updated_sync_state[ch_id] = ts

                # Rate limit: ~1.2s between channels (Tier 3)
                await asyncio.sleep(1.2)

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state

    async def estimate_scope(self) -> dict:
        async with make_async_client(timeout=30) as client:
            channels = await self._list_channels(client)
            return {"estimated_channels": len(channels)}

    # ── Private helpers ──────────────────────────────────────────

    async def _list_channels(self, client: httpx.AsyncClient) -> list[dict]:
        """List channels the bot has access to."""
        channels = []
        cursor = None
        types = "public_channel,private_channel" if self.include_private else "public_channel"

        while True:
            params: dict = {"types": types, "limit": 200, "exclude_archived": "true"}
            if cursor:
                params["cursor"] = cursor

            r = await client.get("https://slack.com/api/conversations.list", headers=self._headers, params=params)
            data = r.json()
            if not data.get("ok"):
                break

            for ch in data.get("channels", []):
                if not self.channel_filter or ch.get("name") in self.channel_filter:
                    channels.append(ch)

            cursor = data.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                break
            await asyncio.sleep(1.2)

        return channels

    async def _get_messages(self, client: httpx.AsyncClient, channel_id: str, oldest: str):
        """Paginate through channel messages since `oldest` timestamp."""
        cursor = None
        while True:
            params: dict = {"channel": channel_id, "limit": 200, "oldest": oldest}
            if cursor:
                params["cursor"] = cursor

            r = await client.get("https://slack.com/api/conversations.history", headers=self._headers, params=params)
            data = r.json()
            if not data.get("ok"):
                break

            for msg in data.get("messages", []):
                if msg.get("type") == "message" and not msg.get("subtype"):
                    yield msg

            if not data.get("has_more"):
                break
            cursor = data.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                break
            await asyncio.sleep(1.2)

    async def _get_file_content(self, client: httpx.AsyncClient, file_info: dict) -> Optional[str]:
        """Download text content of a file attachment."""
        # Only scan text-like files
        text_types = {"text", "python", "javascript", "json", "yaml", "xml", "shell", "markdown", "csv", "conf", "env", "ini", "toml", "dockerfile"}
        if file_info.get("filetype", "").lower() not in text_types:
            return None

        # Skip large files (>1MB)
        if file_info.get("size", 0) > 1_000_000:
            return None

        url = file_info.get("url_private")
        if not url:
            return None

        try:
            r = await client.get(url, headers=self._headers)
            if r.status_code == 200:
                return r.text[:500_000]  # Cap at 500KB of text
        except Exception:
            pass
        return None
