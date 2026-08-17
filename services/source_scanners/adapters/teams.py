# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Microsoft Teams source adapter — scans channel messages and replies.

Coverage:
  - Standard channels (every team the app has been granted access to)
  - Top-level message body (HTML, flattened)
  - Threaded replies on each message
  - Optional: attachments listed against messages (URLs only — file
    download requires Files.Read.All scope and is opt-in)

Out of scope (low yield, big extra surface):
  - Private channels (`channelType=private`) — require a separate
    membership grant. Skipped unless `include_private` is on.
  - Chat (1:1 / group DMs) — Microsoft requires special "RSC"
    permissions or per-user delegation; not appropriate for the
    application-permission flow this adapter uses.

Auth: Microsoft Graph application permissions, granted via admin
consent on the customer's app registration. See the M365 setup
section in docs (scopes: Channel.ReadBasic.All, ChannelMessage.Read.All;
optional: Files.Read.All for attachment download).

Rate limit story: Graph caps each app at ~15K requests / 15 min by
default per tenant; the shared MicrosoftGraphClient honours 429
Retry-After so this adapter doesn't need its own backoff logic.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import AsyncIterator, Optional

from packages.common.outbound_http import make_async_client
from services.source_scanners.adapters._msgraph import (
    GRAPH_ROOT,
    MicrosoftGraphClient,
)
from services.source_scanners.base import ScanableContent, SourceAdapter


_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HTML_ENTITY_RE = re.compile(r"&(?:amp|lt|gt|quot|apos|nbsp);")
_ENTITY_MAP = {
    "&amp;": "&", "&lt;": "<", "&gt;": ">",
    "&quot;": '"', "&apos;": "'", "&nbsp;": " ",
}


def _flatten_message_body(body: dict) -> str:
    """Teams message bodies are { contentType: 'html'|'text', content: '...' }.

    HTML bodies include rich formatting; we strip tags + decode the
    common entities so the secret scanner sees clean text. We don't
    pull a full HTML parser — the body is bounded in size and our
    regex strip is fine for the secret-detection use case.
    """
    if not body:
        return ""
    ctype = (body.get("contentType") or "").lower()
    content = body.get("content") or ""
    if ctype == "text":
        return content
    # html or unknown — strip tags + decode common entities
    s = _HTML_TAG_RE.sub(" ", content)
    s = _HTML_ENTITY_RE.sub(lambda m: _ENTITY_MAP.get(m.group(0), m.group(0)), s)
    return " ".join(s.split())


class MicrosoftTeamsAdapter(SourceAdapter):
    source_type = "ms_teams"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        teams: str = "*",
        include_private: bool = False,
        include_attachment_urls: bool = True,
    ):
        self.client = MicrosoftGraphClient(
            tenant_id, client_id, client_secret,
            source_type="ms_teams",
        )
        self.team_filter = (
            [t.strip() for t in teams.split(",") if t.strip()] if teams != "*" else []
        )
        self.include_private = include_private
        self.include_attachment_urls = include_attachment_urls
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        return await self.client.test_connection()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        # Sync watermark: Graph messages have an `lastModifiedDateTime`
        # that changes on edits; we track the latest value seen and
        # use it on the next scan to skip untouched messages. First
        # scan = no watermark = full backfill.
        self._updated_sync_state = dict(sync_state)
        last_sync = sync_state.get("last_sync", "")

        async with make_async_client(timeout=30) as client:
            # 1. Enumerate teams the app can see.
            async for team in self.client.get_paged(client, f"{GRAPH_ROOT}/teams"):
                team_id = team.get("id")
                team_name = team.get("displayName", team_id)
                if not team_id:
                    continue
                if self.team_filter and team_name not in self.team_filter and team_id not in self.team_filter:
                    continue

                # 2. Channels of this team.
                ch_url = f"{GRAPH_ROOT}/teams/{team_id}/channels"
                async for channel in self.client.get_paged(client, ch_url):
                    ch_id = channel.get("id")
                    ch_name = channel.get("displayName", ch_id)
                    ch_type = (channel.get("membershipType") or "standard").lower()
                    if not ch_id:
                        continue
                    if ch_type == "private" and not self.include_private:
                        continue

                    # 3. Top-level messages with delta if we have a
                    #    watermark. Graph supports a `delta` endpoint
                    #    on messages — first call is full, subsequent
                    #    calls return only changed items.
                    msg_url = f"{GRAPH_ROOT}/teams/{team_id}/channels/{ch_id}/messages"
                    async for msg in self.client.get_paged(client, msg_url):
                        msg_id = msg.get("id")
                        last_modified = msg.get("lastModifiedDateTime", "") or msg.get("createdDateTime", "")
                        if last_sync and last_modified and last_modified <= last_sync:
                            continue
                        if last_modified > self._updated_sync_state.get("last_sync", ""):
                            self._updated_sync_state["last_sync"] = last_modified

                        text = _flatten_message_body(msg.get("body"))
                        author = ((msg.get("from") or {}).get("user") or {}).get("displayName", "")
                        deep_link = (
                            (msg.get("webUrl"))
                            or f"https://teams.microsoft.com/l/message/{ch_id}/{msg_id}"
                        )

                        # Append attachment URLs (not file content) so
                        # the scanner sees `?sig=…` style SAS tokens
                        # in shared-link URLs. File-content scanning
                        # requires Files.Read.All — separate path.
                        if self.include_attachment_urls:
                            for att in (msg.get("attachments") or []):
                                url = att.get("contentUrl") or att.get("url") or ""
                                if url:
                                    text = f"{text}\n{url}" if text else url

                        if text.strip():
                            yield ScanableContent(
                                source_locator=f"msteams://{team_id}/{ch_id}/{msg_id}",
                                content=text,
                                content_type="message",
                                timestamp=_parse_iso(last_modified),
                                author=author,
                                deep_link_url=deep_link,
                                metadata={
                                    "team_id": team_id, "team_name": team_name,
                                    "channel_id": ch_id, "channel_name": ch_name,
                                    "channel_type": ch_type,
                                },
                            )

                        # 4. Replies on each message.
                        rep_url = f"{GRAPH_ROOT}/teams/{team_id}/channels/{ch_id}/messages/{msg_id}/replies"
                        async for reply in self.client.get_paged(client, rep_url):
                            r_id = reply.get("id")
                            r_modified = reply.get("lastModifiedDateTime", "") or reply.get("createdDateTime", "")
                            if last_sync and r_modified and r_modified <= last_sync:
                                continue
                            if r_modified > self._updated_sync_state.get("last_sync", ""):
                                self._updated_sync_state["last_sync"] = r_modified
                            r_text = _flatten_message_body(reply.get("body"))
                            r_author = ((reply.get("from") or {}).get("user") or {}).get("displayName", "")
                            if r_text.strip():
                                yield ScanableContent(
                                    source_locator=f"msteams://{team_id}/{ch_id}/{msg_id}/reply/{r_id}",
                                    content=r_text,
                                    content_type="comment",
                                    timestamp=_parse_iso(r_modified),
                                    author=r_author,
                                    deep_link_url=deep_link,
                                    metadata={
                                        "team_id": team_id, "team_name": team_name,
                                        "channel_id": ch_id, "channel_name": ch_name,
                                        "parent_message_id": msg_id,
                                    },
                                )

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state


def _parse_iso(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None
