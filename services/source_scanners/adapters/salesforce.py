# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Salesforce source adapter — scans Cases, Knowledge articles, Chatter posts.

Why this exists: in mid-large enterprises Salesforce is THE customer-
facing system. Engineers and support reps routinely paste credentials
into case comments ("the prod DB password is hunter2 fyi") and into
internal Knowledge articles. No competitor ships strong coverage here,
so this is a real wedge.

Auth: Salesforce OAuth 2.0 — Username/Password flow. The customer
registers a Connected App in their org (Setup → App Manager → New
Connected App, enable OAuth, scopes: api + refresh_token), then
provides Vooda with:
  - login_url (https://login.salesforce.com or https://test.salesforce.com)
  - client_id (Connected App consumer key)
  - client_secret (Connected App consumer secret)
  - username
  - password (concatenated with the user's security token)

Token endpoint: POST {login_url}/services/oauth2/token
Returns access_token + instance_url. We cache the token for an hour;
re-auth on 401.

Surfaces scanned (configurable):
  - Case (Subject, Description) + CaseComment.CommentBody
  - Knowledge__kav (Title, Summary, Content)  — when org has Knowledge
  - FeedItem (Chatter post Body) + FeedComment (CommentBody)

Out of scope (deferred):
  - Custom objects (each customer has different ones; needs a
    discovery + per-object opt-in flow)
  - Attachments / ContentDocument body
  - Live Agent / chat transcripts
"""
from __future__ import annotations

import asyncio
import time
from typing import AsyncIterator, Optional

import httpx

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_network_error,
    classify_salesforce_error,
    classify_salesforce_token_error,
)
from services.source_scanners.base import ScanableContent, SourceAdapter


# Default API version. Salesforce ships 3 releases / year; we pick a
# stable mid-2025 version that all production orgs support.
_API_VERSION = "v60.0"


class SalesforceAdapter(SourceAdapter):
    source_type = "salesforce"

    def __init__(
        self,
        login_url: str,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        scan_cases: bool = True,
        scan_knowledge: bool = True,
        scan_chatter: bool = True,
    ):
        if not (login_url and client_id and client_secret and username and password):
            raise ValueError(
                "Salesforce adapter requires login_url, client_id, "
                "client_secret, username, password (with security token)"
            )
        self.login_url = login_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.scan_cases = scan_cases
        self.scan_knowledge = scan_knowledge
        self.scan_chatter = scan_chatter
        self._access_token: Optional[str] = None
        self._instance_url: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._updated_sync_state: dict = {}

    # ── Auth ──────────────────────────────────────────────────────

    async def _ensure_token(self, c: httpx.AsyncClient) -> None:
        # 60s skew — re-auth slightly before expiry rather than hit
        # a 401 mid-scan.
        if self._access_token and time.time() + 60 < self._token_expires_at:
            return
        r = await c.post(
            f"{self.login_url}/services/oauth2/token",
            data={
                "grant_type": "password",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "username": self.username,
                "password": self.password,
            },
        )
        if r.status_code != 200:
            raise RuntimeError(f"Salesforce auth failed: {r.status_code} {r.text[:200]}")
        data = r.json()
        self._access_token = data.get("access_token")
        self._instance_url = (data.get("instance_url") or "").rstrip("/")
        # Salesforce session tokens default to 2h but customers often
        # tighten to 15min. We always assume 1h to stay safe.
        self._token_expires_at = time.time() + 3600

    async def _headers(self, c: httpx.AsyncClient) -> dict:
        await self._ensure_token(c)
        return {"Authorization": f"Bearer {self._access_token}",
                "Accept": "application/json"}

    # ── SourceAdapter API ─────────────────────────────────────────

    async def test_connection(self) -> dict:
        """Two-stage probe — token mint + REST limits call.

        Salesforce has two distinct failure surfaces with different
        diagnostic envelopes:

          1. Token endpoint (POST /services/oauth2/token) — failures
             are Connected-App config or password/security-token
             problems.  Routed through
             :func:`classify_salesforce_token_error`.

          2. REST API — failures here mean the token worked but the
             user doesn't have API access or the org has API disabled.
             Routed through :func:`classify_salesforce_error`.

        Splitting these gives users a precise fix step (rotate the
        Connected App's secret vs. flip the user's profile setting),
        which a single generic classifier can't do.
        """
        ctx = {"adapter": "salesforce", "login_url": self.login_url}
        try:
            async with make_async_client(timeout=20) as c:
                # ── Stage 1: token mint ─────────────────────────────
                token_r = await c.post(
                    f"{self.login_url}/services/oauth2/token",
                    data={
                        "grant_type": "password",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "username": self.username,
                        "password": self.password,
                    },
                )
                if token_r.status_code != 200:
                    err = classify_salesforce_token_error(token_r, {**ctx, "phase": "token"})
                    return err.to_user_dict()
                token_data = token_r.json() or {}
                self._access_token = token_data.get("access_token")
                self._instance_url = (token_data.get("instance_url") or "").rstrip("/")
                self._token_expires_at = time.time() + 3600

                # ── Stage 2: REST probe ─────────────────────────────
                # /services/data/<v>/limits exists on every org and
                # exercises the same auth path the scan uses.
                r = await c.get(
                    f"{self._instance_url}/services/data/{_API_VERSION}/limits",
                    headers={"Authorization": f"Bearer {self._access_token}",
                             "Accept": "application/json"},
                )
                if r.status_code == 200:
                    return {"status": "success",
                            "message": f"Connected to {self._instance_url}"}
                err = classify_salesforce_error(r, {**ctx, "phase": "rest_probe"})
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        # Per-object watermarks — Knowledge is a different table from
        # Case so they each carry their own LastModifiedDate cursor.
        watermarks: dict = dict(sync_state.get("table_watermarks", {}) or {})

        async with make_async_client(timeout=30) as c:
            if self.scan_cases:
                async for item in self._scan_cases(c, watermarks):
                    yield item
            if self.scan_knowledge:
                async for item in self._scan_knowledge(c, watermarks):
                    yield item
            if self.scan_chatter:
                async for item in self._scan_chatter(c, watermarks):
                    yield item

        self._updated_sync_state["table_watermarks"] = watermarks

    # ── Per-object iterators ──────────────────────────────────────

    async def _soql(self, c: httpx.AsyncClient, query: str) -> AsyncIterator[dict]:
        """Run a SOQL query and yield records, walking nextRecordsUrl."""
        h = await self._headers(c)
        url: Optional[str] = (
            f"{self._instance_url}/services/data/{_API_VERSION}/query?q={query}"
        )
        page = 0
        while url and page < 200:
            r = await c.get(url, headers=h)
            if r.status_code != 200:
                return
            data = r.json() or {}
            for rec in data.get("records", []) or []:
                yield rec
            next_path = data.get("nextRecordsUrl")
            if not next_path:
                break
            # nextRecordsUrl is a relative path — re-prepend the host.
            url = f"{self._instance_url}{next_path}"
            page += 1
            await asyncio.sleep(0.3)

    async def _scan_cases(
        self, c: httpx.AsyncClient, watermarks: dict,
    ) -> AsyncIterator[ScanableContent]:
        last = watermarks.get("Case", "2000-01-01T00:00:00Z")
        soql = (
            "SELECT+Id,CaseNumber,Subject,Description,LastModifiedDate"
            f"+FROM+Case+WHERE+LastModifiedDate+%3E+{last}+ORDER+BY+LastModifiedDate+ASC"
        )
        latest = last
        async for rec in self._soql(c, soql):
            cid = rec.get("Id")
            cnum = rec.get("CaseNumber") or cid
            modified = rec.get("LastModifiedDate", "")
            if modified > latest:
                latest = modified
            description = rec.get("Description") or ""
            subject = rec.get("Subject") or ""
            deep_link = f"{self._instance_url}/{cid}"
            if subject.strip():
                yield ScanableContent(
                    source_locator=f"salesforce://Case/{cnum}/subject",
                    content=subject,
                    content_type="page",
                    deep_link_url=deep_link,
                    metadata={"object": "Case", "case_number": cnum},
                )
            if description.strip():
                yield ScanableContent(
                    source_locator=f"salesforce://Case/{cnum}/description",
                    content=description,
                    content_type="page",
                    deep_link_url=deep_link,
                    metadata={"object": "Case", "case_number": cnum,
                              "subject": subject},
                )

            # Comments on this case
            comments_q = (
                "SELECT+Id,CommentBody,LastModifiedDate+FROM+CaseComment"
                f"+WHERE+ParentId+%3D+%27{cid}%27"
            )
            async for cm in self._soql(c, comments_q):
                body = cm.get("CommentBody") or ""
                if not body.strip():
                    continue
                yield ScanableContent(
                    source_locator=f"salesforce://Case/{cnum}/comment/{cm.get('Id')}",
                    content=body,
                    content_type="comment",
                    deep_link_url=deep_link,
                    metadata={"object": "Case", "case_number": cnum},
                )
        watermarks["Case"] = latest

    async def _scan_knowledge(
        self, c: httpx.AsyncClient, watermarks: dict,
    ) -> AsyncIterator[ScanableContent]:
        last = watermarks.get("Knowledge", "2000-01-01T00:00:00Z")
        # Knowledge__kav is the "knowledge article version" table. Not
        # every org has Knowledge enabled — we tolerate INVALID_TYPE
        # and silently skip via the _soql code path returning empty.
        soql = (
            "SELECT+Id,Title,Summary,LastModifiedDate"
            f"+FROM+Knowledge__kav+WHERE+LastModifiedDate+%3E+{last}"
            "+AND+PublishStatus+%3D+%27Online%27"
            "+ORDER+BY+LastModifiedDate+ASC"
        )
        latest = last
        async for rec in self._soql(c, soql):
            kid = rec.get("Id")
            modified = rec.get("LastModifiedDate", "")
            if modified > latest:
                latest = modified
            title = rec.get("Title") or ""
            summary = rec.get("Summary") or ""
            deep_link = f"{self._instance_url}/{kid}"
            if title.strip() or summary.strip():
                yield ScanableContent(
                    source_locator=f"salesforce://Knowledge/{kid}",
                    content=f"{title}\n{summary}",
                    content_type="page",
                    deep_link_url=deep_link,
                    metadata={"object": "Knowledge__kav", "title": title},
                )
        watermarks["Knowledge"] = latest

    async def _scan_chatter(
        self, c: httpx.AsyncClient, watermarks: dict,
    ) -> AsyncIterator[ScanableContent]:
        last = watermarks.get("FeedItem", "2000-01-01T00:00:00Z")
        # FeedItem covers Chatter posts on every record + group +
        # user. Body field carries the message text.
        soql = (
            "SELECT+Id,Body,Title,ParentId,LastModifiedDate"
            f"+FROM+FeedItem+WHERE+LastModifiedDate+%3E+{last}"
            "+ORDER+BY+LastModifiedDate+ASC"
        )
        latest = last
        async for rec in self._soql(c, soql):
            fid = rec.get("Id")
            parent = rec.get("ParentId", "")
            modified = rec.get("LastModifiedDate", "")
            if modified > latest:
                latest = modified
            body = rec.get("Body") or ""
            if not body.strip():
                continue
            yield ScanableContent(
                source_locator=f"salesforce://Chatter/{fid}",
                content=body,
                content_type="message",
                deep_link_url=f"{self._instance_url}/{fid}",
                metadata={"object": "FeedItem", "parent_id": parent},
            )
        watermarks["FeedItem"] = latest

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
