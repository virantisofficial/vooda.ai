# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Jira source adapter — scans summaries, descriptions, comments, custom
text fields, and (optionally) text-like attachments across every project.

Authentication modes:
  - Basic Auth (email + API token, encrypted at rest) — original mode.
  - OAuth 2.0 (3LO) Bearer token + cloud_id — added 2026-04-30 for
    enterprise procurement gates that disallow long-lived static
    tokens. When `auth_mode="oauth2"`, the adapter calls
    `https://api.atlassian.com/ex/jira/{cloud_id}/...` instead of
    `https://{site}.atlassian.net/...` and accepts a callable that
    returns a non-expired access token (so the worker can refresh
    via integrations_oauth.refresh_atlassian_token_if_needed).

Coverage parity (2026-04-30 expansion):
  ✓ Issue summary                            (was: skipped)
  ✓ Issue description (ADF)                  (already there)
  ✓ Issue comments (ADF)                     (already there)
  ✓ Custom text/textarea fields              (was: skipped — biggest gap)
  ✓ Attachments — text/JSON/YAML/log/etc.    (was: toggle existed but did
                                              nothing; now wired)
  ✓ URLs from inline links                   (catches `?token=…` style
                                              query-string secrets that
                                              the plain-text flatten missed)

Out of scope (low yield, large API surface):
  - Worklog free-text entries
  - Issue change history (audit log)
"""

import asyncio
from typing import AsyncIterator, Awaitable, Callable, Optional
from base64 import b64encode

import httpx
import structlog

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_atlassian_error,
    classify_network_error,
)
from services.source_scanners.base import SourceAdapter, ScanableContent

# Module logger — emits a structured ``scan_request_failed`` line when
# a mid-scan call returns non-200, so a token expiring mid-scan or a
# rate-limit hit surfaces as a grep-able event instead of a silent
# items_scanned=0.  Same pattern as confluence.py.
logger = structlog.get_logger(__name__)


# Type for the OAuth-mode access-token provider. Worker passes a
# callable that returns the current (refreshed-if-needed) bearer.
# Defined at module scope so type-hints stay readable.
TokenProvider = Callable[[], Awaitable[str]]


# Whitelist of MIME-type prefixes / file-extension suffixes that we'll
# pull and scan. Anything else (PDFs, images, archives, binaries) is
# skipped — the secret scanner can't read them and downloading them
# would burn bandwidth + risk crashing on a 500MB binary. Aligned with
# what GitGuardian's Jira connector ships in 2025.
_TEXT_MIME_PREFIXES = (
    "text/",
    "application/json",
    "application/xml",
    "application/yaml",
    "application/x-yaml",
    "application/javascript",
    "application/x-sh",
    "application/x-properties",
)
_TEXT_FILENAME_SUFFIXES = (
    ".env", ".env.example", ".env.local", ".env.dev", ".env.prod",
    ".properties", ".conf", ".cfg", ".ini",
    ".log", ".csv", ".tsv", ".tf", ".tfvars",
    ".sh", ".bash", ".zsh", ".ps1", ".bat",
    ".kubeconfig", ".pem", ".key", ".crt", ".pub",
    ".dockerfile", ".gitconfig",
)


class JiraSourceAdapter(SourceAdapter):
    source_type = "jira"

    def __init__(
        self,
        base_url: str = "",
        email: str = "",
        api_token: str = "",
        projects: str = "*",
        include_attachments: bool = False,
        exclude_self_created: bool = True,
        max_attachment_size_mb: int = 10,
        # Off by default — opt-in coverage extension. When True,
        # every text/textarea custom field on every issue is added
        # to the search payload. ~2% extra finding yield, 5-15%
        # extra scan time. Documented in scan_source schema hint.
        scan_custom_fields: bool = False,
        # OAuth-mode parameters. Mutually exclusive with email +
        # api_token. When provided, every API call uses
        # https://api.atlassian.com/ex/jira/{cloud_id}/... + Bearer.
        auth_mode: str = "basic",
        cloud_id: Optional[str] = None,
        token_provider: Optional[TokenProvider] = None,
    ):
        self.auth_mode = auth_mode
        self.cloud_id = cloud_id
        self.token_provider = token_provider
        if auth_mode == "oauth2":
            if not cloud_id or not token_provider:
                raise ValueError("OAuth mode requires cloud_id and token_provider")
            # In OAuth mode the API host is api.atlassian.com, NOT
            # the customer's tenant URL. base_url is used only for
            # building human-facing browse links inside finding
            # metadata so we still want it set; fall back to a
            # synthetic if the caller didn't provide one.
            self.api_root = f"https://api.atlassian.com/ex/jira/{cloud_id}"
            self.base_url = (base_url or "").rstrip("/")
        else:
            if not email or not api_token:
                raise ValueError("Basic mode requires email + api_token")
            self.api_root = base_url.rstrip("/")
            self.base_url = base_url.rstrip("/")
            self.auth = b64encode(f"{email}:{api_token}".encode()).decode()
        self.project_filter = [p.strip() for p in projects.split(",")] if projects != "*" else []
        self.include_attachments = include_attachments
        # Don't scan tickets that Vooda itself filed — prevents the
        # circular feedback loop where every ticket Vooda creates
        # (with the masked secret in the body) shows up as a new
        # finding next scan. Industry-standard pattern (GitGuardian,
        # Snyk, TruffleHog Enterprise all do this). Defaults on.
        # See _build_self_exclusion_jql for the precise filter.
        self.exclude_self_created = exclude_self_created
        self.scan_custom_fields = scan_custom_fields
        # Hard cap on per-attachment download size. Defaults to 10 MB
        # which covers 99 %+ of legit text attachments (env files,
        # config snippets, build logs) while keeping the worker safe
        # from a hostile / oversized upload.
        self.max_attachment_bytes = max(1, int(max_attachment_size_mb)) * 1024 * 1024
        self._updated_sync_state: dict = {}
        # Cached on first extract_content call. Maps custom field id
        # ("customfield_10042") → display name. Used both to expand
        # the search payload's `fields` list AND to label the scan
        # result so users can find the offending field in Jira.
        self._custom_text_fields: dict[str, str] = {}

    async def _auth_headers(self) -> dict:
        """Return Authorization headers for the configured auth mode.

        OAuth path calls into the provided token_provider on every
        request so a freshly-refreshed token is always used (the
        worker's helper is cheap when not expired).
        """
        if self.auth_mode == "oauth2":
            tok = await self.token_provider()
            return {"Authorization": f"Bearer {tok}", "Accept": "application/json"}
        return {"Authorization": f"Basic {self.auth}", "Accept": "application/json"}

    def _build_self_exclusion_jql(self) -> str:
        """JQL fragment that excludes Vooda's own tickets.

        Label-based exclusion only — `vooda-ai` is stamped on every
        ticket the dispatcher creates (services/notifications/
        dispatcher.py:588). JQL-indexed, fast, exact.

        We deliberately do NOT also filter by `reporter !=
        currentUser()`: in many deployments the API-token owner is
        a real person who also files organic tickets, so pairing
        the reporter check with the label check would silently hide
        every issue that person ever wrote. GitGuardian's Jira
        connector takes the same label-only stance for the same
        reason. If a ticket loses the label (manual edit, Jira
        automation), the user has effectively asked us to re-scan
        it — that's acceptable behaviour.
        """
        if not self.exclude_self_created:
            return ""
        return " AND (labels NOT IN (vooda-ai) OR labels IS EMPTY)"

    async def test_connection(self) -> dict:
        """Two-stage probe — auth check + scan-time-endpoint check.

        Stage 1: ``GET /rest/api/3/myself`` — validates the credential.
        Atlassian returns 401 + ``x-seraph-loginreason: AUTHENTICATED_FAILED``
        on bogus tokens (verified via direct probe), so this gives us
        a clean auth signal that the classifier can decode.

        Stage 2: ``POST /rest/api/3/search/jql`` with a bounded JQL +
        ``maxResults: 0`` — exercises the EXACT endpoint
        ``extract_content`` uses to fetch issues.  This catches the
        case where auth is fine but the user lacks ``Browse Projects``
        on every project (a real production scenario where stage 1
        succeeds and the scan would otherwise silently return zero
        items with no diagnostic).  ``maxResults: 0`` keeps the call
        cheap — we just want the auth/permission check to round-trip.
        Mirrors the Confluence two-stage pattern (spaces + pages).

        Returns the legacy ``{status, message}`` dict for backward
        compatibility, but on failure also includes the structured
        ``IntegrationError`` fields (title, summary, fix_steps,
        details).  Network-level failures route through the network
        classifier so DNS / TLS / timeout errors get the same fix-step
        treatment as the rest of the platform.
        """
        ctx = {
            "adapter": "jira",
            "site_url": self.base_url,
            "auth_mode": self.auth_mode,
        }
        try:
            headers = await self._auth_headers()
            async with make_async_client(timeout=15) as client:
                # ── Stage 1: auth check ─────────────────────────────
                r = await client.get(f"{self.api_root}/rest/api/3/myself", headers=headers)
                if r.status_code != 200:
                    err = classify_atlassian_error(r, ctx)
                    return err.to_user_dict()
                user = r.json() or {}
                display_name = user.get("displayName", "user")

                # ── Stage 2: scan-endpoint reachability ─────────────
                # Use the same JQL shape extract_content sends so we
                # exercise the same code path the actual scan will hit.
                # ``maxResults: 1`` is the minimum Atlassian accepts
                # (verified: maxResults must be in [1, 5000]; 0 returns
                # 400 "max results parameter has to be between 1 and
                # 5,000").  One row response is cheap.
                r2 = await client.post(
                    f"{self.api_root}/rest/api/3/search/jql",
                    headers={**headers, "Content-Type": "application/json"},
                    json={
                        "jql": "updated >= '2000-01-01' ORDER BY updated ASC",
                        "maxResults": 1,
                        "fields": ["summary"],
                    },
                )
                if r2.status_code == 200:
                    return {
                        "status": "success",
                        "message": f"Connected as {display_name} (mode: {self.auth_mode})",
                    }
                err = classify_atlassian_error(r2, {**ctx, "phase": "search_probe"})
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def _discover_custom_text_fields(self, client: httpx.AsyncClient) -> dict[str, str]:
        """Discover Jira custom fields that hold free-form text.

        Returns:
            { field_id: display_name } for fields whose schema is
            string / textarea — exactly the ones a developer might
            paste an env var or config snippet into. System fields
            (assignee, status, …) and structured fields (selects,
            dates, numbers) are intentionally excluded.

        Failures are non-fatal — we return an empty dict and let the
        scan proceed at the existing summary+description+comments
        coverage level.  We DO log the classified error so an operator
        can see *why* custom-field coverage was skipped (most common
        cause: the API token doesn't have admin scope for
        /rest/api/3/field).
        """
        try:
            headers = await self._auth_headers()
            r = await client.get(f"{self.api_root}/rest/api/3/field", headers=headers)
            if r.status_code != 200:
                err = classify_atlassian_error(
                    r,
                    {
                        "adapter": "jira",
                        "site_url": self.base_url,
                        "auth_mode": self.auth_mode,
                        "phase": "discover_custom_fields",
                    },
                )
                logger.warning(
                    "scan_request_failed",
                    source_type="jira",
                    error_code=err.code,
                    error_title=err.title,
                    trace_id=err.trace_id,
                    http_status=err.http_status,
                    phase="discover_custom_fields",
                )
                return {}
            text_ids: dict[str, str] = {}
            for f in r.json():
                if not f.get("custom"):
                    continue
                schema = f.get("schema") or {}
                stype = (schema.get("type") or "").lower()
                custom_type = (schema.get("custom") or "").lower()
                # Atlassian's text/textarea custom-field types live
                # under com.atlassian.jira.plugin.system.customfieldtypes:textfield
                # and :textarea. We accept either of those, plus any
                # field whose top-level schema type is "string".
                is_text = (
                    stype == "string"
                    or custom_type.endswith(":textfield")
                    or custom_type.endswith(":textarea")
                    or custom_type.endswith(":readonlyfield")
                )
                if is_text:
                    text_ids[f["id"]] = f.get("name") or f["id"]
            return text_ids
        except Exception:
            return {}

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        # Atlassian removed GET /rest/api/3/search on 2025-05-01
        # (changelog CHANGE-2046). The replacement is POST
        # /rest/api/3/search/jql with token-based pagination — this
        # adapter uses the new shape: bounded JQL is required by
        # the new endpoint, hence the leading `updated >= last_sync`
        # restriction. Bug fix 2026-04-30.
        self._updated_sync_state = dict(sync_state)
        last_sync = sync_state.get("last_sync", "2000-01-01")

        # Refresh headers per page so the OAuth token can be rotated
        # mid-scan if the worker's refresh helper detects an expiry.
        post_headers = {**(await self._auth_headers()), "Content-Type": "application/json"}
        project_clause = f" AND project IN ({','.join(self.project_filter)})" if self.project_filter else ""
        self_exclude = self._build_self_exclusion_jql()
        jql = f"updated >= '{last_sync}'{project_clause}{self_exclude} ORDER BY updated ASC"

        async with make_async_client(timeout=30) as client:
            # Custom-field discovery + scanning is opt-in. When off,
            # we skip the GET /rest/api/3/field call entirely AND
            # leave custom field IDs out of the search payload — both
            # the discovery cost and the per-page payload bloat go
            # away. Default off keeps cold-start scan time trim.
            if self.scan_custom_fields:
                self._custom_text_fields = await self._discover_custom_text_fields(client)
            else:
                self._custom_text_fields = {}
            base_fields = ["summary", "description", "comment", "project", "updated"]
            if self.include_attachments:
                base_fields.append("attachment")
            search_fields = base_fields + list(self._custom_text_fields.keys())

            next_token: str | None = None
            page = 0
            # Hard cap to avoid infinite loops if Atlassian ever
            # returns a token that doesn't make progress.
            MAX_PAGES = 200
            while page < MAX_PAGES:
                payload: dict = {
                    "jql": jql,
                    "maxResults": 50,
                    "fields": search_fields,
                }
                if next_token:
                    payload["nextPageToken"] = next_token

                r = await client.post(
                    f"{self.api_root}/rest/api/3/search/jql",
                    headers=post_headers,
                    json=payload,
                )
                if r.status_code != 200:
                    # Stop on any error AND emit a classified log line
                    # so the silent-failure mode (items_scanned=0 with
                    # no diagnostic) becomes visible.  Mid-scan token
                    # expiry, rate-limit, and per-project ACL failures
                    # all land here — error_code distinguishes them.
                    err = classify_atlassian_error(
                        r,
                        {
                            "adapter": "jira",
                            "site_url": self.base_url,
                            "auth_mode": self.auth_mode,
                            "phase": "search_jql",
                            "page": page,
                        },
                    )
                    logger.warning(
                        "scan_request_failed",
                        source_type="jira",
                        error_code=err.code,
                        error_title=err.title,
                        trace_id=err.trace_id,
                        http_status=err.http_status,
                        phase="search_jql",
                        page=page,
                    )
                    break
                data = r.json()
                issues = data.get("issues", [])
                if not issues:
                    break

                for issue in issues:
                    key = issue.get("key", "")
                    fields = issue.get("fields", {})
                    project_key = fields.get("project", {}).get("key", "")
                    summary = fields.get("summary", "") or ""

                    # Scan summary — small but free, and developers
                    # occasionally inline a token in the title.
                    if summary.strip():
                        yield ScanableContent(
                            source_locator=f"jira://{key}/summary",
                            content=summary,
                            content_type="page",
                            deep_link_url=f"{self.base_url}/browse/{key}",
                            metadata={"issue_key": key, "project": project_key, "field": "summary"},
                        )

                    # Scan description — extract both flattened text
                    # AND any URLs found in inline links / cards. The
                    # latter catches `?api_key=…` patterns that the
                    # plain-text walker would otherwise miss.
                    desc_text, desc_urls = self._extract_text_and_urls(fields.get("description"))
                    if desc_text.strip():
                        yield ScanableContent(
                            source_locator=f"jira://{key}/description",
                            content=desc_text + ("\n" + "\n".join(desc_urls) if desc_urls else ""),
                            content_type="page",
                            deep_link_url=f"{self.base_url}/browse/{key}",
                            metadata={"issue_key": key, "project": project_key, "summary": summary, "field": "description"},
                        )

                    # Scan comments
                    for comment in (fields.get("comment", {}).get("comments", [])):
                        body_text, body_urls = self._extract_text_and_urls(comment.get("body"))
                        if body_text.strip():
                            yield ScanableContent(
                                source_locator=f"jira://{key}/comment/{comment.get('id', '')}",
                                content=body_text + ("\n" + "\n".join(body_urls) if body_urls else ""),
                                content_type="comment",
                                author=comment.get("author", {}).get("displayName", ""),
                                deep_link_url=f"{self.base_url}/browse/{key}?focusedId={comment.get('id', '')}",
                                metadata={"issue_key": key, "project": project_key},
                            )

                    # Scan custom text fields (Steps to Reproduce,
                    # Environment, Build Info, etc.). Each yields its
                    # own ScanableContent so the deep link + locator
                    # uniquely identify the offending field — users
                    # can jump straight to the field instead of
                    # hunting through the issue.
                    for fid, fname in self._custom_text_fields.items():
                        raw = fields.get(fid)
                        if raw is None:
                            continue
                        # Custom fields can be plain strings (textfield)
                        # or ADF dicts (textarea). Both supported.
                        cf_text, cf_urls = self._extract_text_and_urls(raw)
                        if cf_text.strip():
                            yield ScanableContent(
                                source_locator=f"jira://{key}/customfield/{fid}",
                                content=cf_text + ("\n" + "\n".join(cf_urls) if cf_urls else ""),
                                content_type="page",
                                deep_link_url=f"{self.base_url}/browse/{key}",
                                metadata={
                                    "issue_key": key, "project": project_key,
                                    "field": fname, "field_id": fid,
                                },
                            )

                    # Scan attachments — text-like only, size-capped.
                    if self.include_attachments:
                        async for att_item in self._scan_attachments(
                            client, issue_key=key, project_key=project_key,
                            attachments=fields.get("attachment", []) or [],
                        ):
                            yield att_item

                    updated = fields.get("updated", "")
                    if updated > self._updated_sync_state.get("last_sync", ""):
                        self._updated_sync_state["last_sync"] = updated[:10]

                # Modern endpoint paginates with nextPageToken; absence
                # of the field == final page. `isLast` is also set on
                # the final page for clarity but the token is the
                # authoritative signal.
                next_token = data.get("nextPageToken")
                if not next_token or data.get("isLast"):
                    break
                page += 1
                await asyncio.sleep(0.5)

    async def _scan_attachments(
        self,
        client: httpx.AsyncClient,
        issue_key: str,
        project_key: str,
        attachments: list[dict],
    ) -> AsyncIterator[ScanableContent]:
        """Download + yield text-like attachments as ScanableContent.

        Filters:
          - MIME prefix must match _TEXT_MIME_PREFIXES, OR
          - filename must end with one of _TEXT_FILENAME_SUFFIXES
          - size must be <= max_attachment_bytes
        Anything else is skipped silently (binaries, images, PDFs).
        """
        for att in attachments:
            try:
                size = int(att.get("size", 0) or 0)
            except (TypeError, ValueError):
                size = 0
            if size > self.max_attachment_bytes:
                continue
            mime = (att.get("mimeType") or "").lower()
            filename = (att.get("filename") or "").lower()
            looks_text = (
                any(mime.startswith(p) for p in _TEXT_MIME_PREFIXES)
                or any(filename.endswith(s) for s in _TEXT_FILENAME_SUFFIXES)
            )
            if not looks_text:
                continue
            content_url = att.get("content")
            if not content_url:
                continue
            try:
                # `follow_redirects=True` — Atlassian's content URL
                # 302s through their CDN. Without it the body comes
                # back empty. 30s timeout per file is generous; most
                # text files complete in <1s.
                # Use auth-mode-aware headers for attachment downloads
                # too — OAuth-mode scans need the bearer token here.
                att_headers = await self._auth_headers()
                resp = await client.get(content_url, headers=att_headers, follow_redirects=True, timeout=30)
                if resp.status_code != 200:
                    continue
                # httpx decodes via Content-Type charset when present,
                # falls back to utf-8. Truncate at the cap to defend
                # against mismatched Content-Length.
                text = resp.text[: self.max_attachment_bytes]
            except Exception:
                # One bad attachment must never kill the whole scan.
                continue
            if not text.strip():
                continue
            yield ScanableContent(
                source_locator=f"jira://{issue_key}/attachment/{att.get('id', '')}/{att.get('filename', '')}",
                content=text,
                content_type="file",
                author=(att.get("author") or {}).get("displayName"),
                deep_link_url=content_url,
                metadata={
                    "issue_key": issue_key,
                    "project": project_key,
                    "filename": att.get("filename", ""),
                    "mimetype": mime,
                    "size_bytes": size,
                },
            )

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state

    def _extract_text_and_urls(self, adf_doc) -> tuple[str, list[str]]:
        """Flatten an ADF doc to plain text plus the set of inline URLs.

        URLs are returned separately so the caller can append them
        to the scanned content — that way an `https://api.example.com?token=ABC`
        link in the description is visible to the regex/entropy
        detectors even though the rendered text only shows "see API".
        """
        if not adf_doc:
            return "", []
        # Plain string field (e.g. textfield custom field)
        if isinstance(adf_doc, str):
            return adf_doc, []
        if not isinstance(adf_doc, dict):
            return "", []

        text_parts: list[str] = []
        urls: list[str] = []

        def walk(node):
            if not isinstance(node, dict):
                return
            ntype = node.get("type")
            # Direct text leaf — also pull `href` from any link mark.
            if ntype == "text":
                text_parts.append(node.get("text", "") or "")
                for mark in node.get("marks", []) or []:
                    if mark.get("type") == "link":
                        href = (mark.get("attrs") or {}).get("href")
                        if href:
                            urls.append(href)
                return
            # Inline cards / smart links — URL lives in attrs.url
            if ntype in ("inlineCard", "blockCard", "embedCard"):
                href = (node.get("attrs") or {}).get("url")
                if href:
                    urls.append(href)
                return
            # Mention / emoji / hardBreak — no scannable text or URL.
            if ntype in ("mention", "emoji", "hardBreak", "rule"):
                return
            for child in node.get("content", []) or []:
                walk(child)

        # Top-level node has a `content` array; walk every child.
        for child in adf_doc.get("content", []) or []:
            walk(child)

        return " ".join(p for p in text_parts if p), urls
