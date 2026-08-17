# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Container Registry source adapter — enumerates and scans images in
a container registry (ECR, GCR, Harbor, Quay, Docker Hub, GHCR).

Why this replaces the single-image flow as the primary Docker option:
real customer workflow is "scan our whole registry," not "scan one
image." Single-image stays available for ad-hoc / dev triage but is
demoted in the catalog UX.

It enumerates repositories and tags, then scans each image's CONFIG
document (env vars, build history / build args, labels, cmd) — the
cheap, high-signal surface where image secrets actually leak. Full
per-file layer scanning is heavier (multi-GB downloads) and is a
separate task, intentionally out of scope here.

Registries supported via uniform Docker Registry HTTP API V2:
  - Docker Hub:   index.docker.io
  - ECR:          {acct}.dkr.ecr.{region}.amazonaws.com (token via aws-cli IAM)
  - GCR:          gcr.io / region-docker.pkg.dev (token via gcloud)
  - GHCR:         ghcr.io (PAT)
  - Harbor:       customer-hosted (basic auth)
  - Quay:         quay.io (token)

For ECR / GCR we treat the upstream-issued bearer token as opaque —
the customer puts it in `password`. Token rotation is the customer's
problem; we don't auto-mint via aws-cli / gcloud (that requires a
sidecar with cloud SDKs which is out of scope for the worker).
"""
from __future__ import annotations

import asyncio
import base64
from typing import AsyncIterator, Optional
from urllib.parse import quote

import httpx

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_http_error,
    classify_network_error,
)
from services.source_scanners.base import ScanableContent, SourceAdapter


class ContainerRegistryAdapter(SourceAdapter):
    source_type = "container_registry"

    def __init__(
        self,
        registry_url: str,
        username: str = "",
        password: str = "",
        repositories: str = "*",
        max_tags_per_repo: int = 5,
    ):
        if not registry_url:
            raise ValueError("Container Registry adapter requires registry_url")
        self.registry_url = registry_url.rstrip("/")
        # Most registries expect Basic auth on the registry HTTP API
        # V2; ECR / GCR use a Bearer token where username is irrelevant
        # but the basic-auth `username:password` form still works
        # (`AWS:{token}` for ECR, `oauth2accesstoken:{gcloud_token}`
        # for GCR).
        self.username = username
        self.password = password
        self.repo_filter = (
            [r.strip() for r in repositories.split(",") if r.strip()]
            if repositories != "*" else []
        )
        # Real registries can have hundreds of tags per repo
        # (semantic version churn). Default to scanning the most
        # recent few — usually `latest` plus N — to stay fast.
        self.max_tags_per_repo = max(1, int(max_tags_per_repo))
        if username and password:
            auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            self._headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
        else:
            self._headers = {"Accept": "application/json"}
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Per Docker Registry V2 spec, ``GET /v2/`` returns 200 on
        success OR 401 with a ``WWW-Authenticate`` header to advertise
        the auth scheme.  Both signal "reachable + speaking V2".

        We treat 200 + 401 as success (reachable) and route everything
        else through the generic classifier.  401 without WWW-Authenticate
        on the other hand DOES indicate creds are wrong — that's the
        case the classifier picks up.
        """
        ctx = {"adapter": "container_registry", "registry_url": self.registry_url}
        try:
            async with make_async_client(timeout=15) as client:
                r = await client.get(f"{self.registry_url}/v2/", headers=self._headers)
                if r.status_code == 200 or (r.status_code == 401 and "WWW-Authenticate" in r.headers):
                    return {"status": "success", "message": f"Reachable: {self.registry_url}"}
                err = classify_http_error(
                    r, provider="container_registry", context=ctx,
                    auth_fix_steps=[
                        "Confirm the username + password / token combo is current",
                        "For ECR: re-issue with `aws ecr get-login-password` and paste under `password`",
                        "For GCR: re-issue with `gcloud auth print-access-token` and paste under `password`",
                    ],
                    permission_fix_steps=[
                        "Confirm the credential has read access on the registry's repositories",
                        "For Harbor / Quay: tick the right project memberships on the user account",
                    ],
                )
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    # Media types we accept when fetching a manifest — both Docker and OCI,
    # single-image and multi-arch index shapes.
    _MANIFEST_ACCEPT = ", ".join([
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
    ])

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        # For each (repo, tag) we fetch the image CONFIG blob — the small
        # JSON document holding env vars, the build history (RUN commands /
        # build args), labels, cmd, and entrypoint. That's where the vast
        # majority of image secrets actually leak (`ENV DATABASE_URL=...`,
        # `--build-arg TOKEN=...`), and it's cheap: a few KB per image, no
        # multi-GB layer downloads. Full-layer file scanning is a separate,
        # heavier task and is intentionally out of scope here.
        self._updated_sync_state = dict(sync_state)
        async with make_async_client(timeout=45) as client:
            repos = await self._list_repositories(client)
            for repo in repos:
                if self.repo_filter and repo not in self.repo_filter:
                    continue
                tags = await self._list_tags(client, repo)
                for tag in tags[: self.max_tags_per_repo]:
                    image_ref = f"{self.registry_url.replace('https://', '').replace('http://', '')}/{repo}:{tag}"
                    config_text = await self._fetch_image_config(client, repo, tag)
                    if config_text:
                        yield ScanableContent(
                            source_locator=f"oci://{image_ref}#config",
                            content=config_text[:500_000],
                            content_type="env_var",
                            deep_link_url=f"{self.registry_url}/{repo}",
                            metadata={
                                "registry": self.registry_url, "repository": repo, "tag": tag,
                                "image_ref": image_ref, "scanned": "image_config",
                            },
                        )
                    await asyncio.sleep(0.1)

    async def _fetch_image_config(self, client: httpx.AsyncClient, repo: str, tag: str) -> str:
        """Return the image's config JSON (env / history / labels), or "".

        Resolves a multi-arch manifest list to its first child, reads the
        config digest, and fetches the config blob. Best-effort: any failure
        on one image yields "" so a whole-registry scan never aborts.
        """
        headers = {**self._headers, "Accept": self._MANIFEST_ACCEPT}
        rp = quote(repo, safe="/")
        try:
            r = await client.get(f"{self.registry_url}/v2/{rp}/manifests/{quote(tag, safe='')}", headers=headers)
            if r.status_code != 200:
                return ""
            manifest = r.json()
            media = manifest.get("mediaType", "")
            # Multi-arch index → descend into the first child manifest.
            if "manifest.list" in media or "image.index" in media or (
                "manifests" in manifest and "config" not in manifest
            ):
                children = manifest.get("manifests", []) or []
                if not children:
                    return ""
                child = children[0].get("digest")
                if not child:
                    return ""
                r = await client.get(f"{self.registry_url}/v2/{rp}/manifests/{child}", headers=headers)
                if r.status_code != 200:
                    return ""
                manifest = r.json()
            digest = (manifest.get("config") or {}).get("digest")
            if not digest:
                return ""
            cr = await client.get(f"{self.registry_url}/v2/{rp}/blobs/{digest}", headers=self._headers)
            if cr.status_code != 200:
                return ""
            # Extract the high-signal fields into newline-separated text
            # rather than handing over the raw (minified, single-line) config
            # JSON — the scanner works line-by-line and skips over-long lines,
            # so a minified blob hides secrets sitting in a long `Env` array.
            try:
                cfg = cr.json()
            except Exception:
                return cr.text[:500_000]
            conf = cfg.get("config") or {}
            lines: list[str] = []
            lines.extend(str(e) for e in (conf.get("Env") or []))
            lines.extend(f"{k}={v}" for k, v in (conf.get("Labels") or {}).items())
            if conf.get("Cmd"):
                lines.append("CMD " + " ".join(str(x) for x in conf["Cmd"]))
            if conf.get("Entrypoint"):
                lines.append("ENTRYPOINT " + " ".join(str(x) for x in conf["Entrypoint"]))
            lines.extend((h.get("created_by") or "") for h in (cfg.get("history") or []))
            return "\n".join(ln for ln in lines if ln)
        except Exception:
            return ""

    async def _list_repositories(self, client: httpx.AsyncClient) -> list[str]:
        # GET /v2/_catalog?n=100 → {"repositories": ["foo/bar", ...]}
        repos: list[str] = []
        url: Optional[str] = f"{self.registry_url}/v2/_catalog?n=100"
        page = 0
        while url and page < 50:
            r = await client.get(url, headers=self._headers)
            if r.status_code != 200:
                break
            data = r.json()
            repos.extend(data.get("repositories", []) or [])
            link = r.headers.get("Link", "")
            # Some registries paginate via Link header (RFC 5988).
            if 'rel="next"' in link:
                next_url = link.split(";")[0].strip("<> ")
                url = (
                    next_url if next_url.startswith("http")
                    else f"{self.registry_url}{next_url}"
                )
            else:
                url = None
            page += 1
            await asyncio.sleep(0.2)
        return repos

    async def _list_tags(self, client: httpx.AsyncClient, repo: str) -> list[str]:
        # GET /v2/{repo}/tags/list → {"tags": ["v1", "v2", ...]}
        r = await client.get(
            f"{self.registry_url}/v2/{quote(repo, safe='/')}/tags/list",
            headers=self._headers,
        )
        if r.status_code != 200:
            return []
        return list(reversed(r.json().get("tags", []) or []))  # newest-ish first

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
