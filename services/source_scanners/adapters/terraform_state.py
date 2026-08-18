# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Terraform State source adapter — scans Terraform / OpenTofu state for secrets.

Terraform state stores resource attributes and outputs as plaintext JSON, so
database passwords, cloud keys, private keys, and connection strings routinely
end up in it verbatim — it is one of the highest-yield secret-leak surfaces in
an IaC shop. This adapter fetches the state document over HTTPS (a Terraform
HTTP backend address, a Terraform Cloud / Enterprise state-version download
URL, or a presigned S3 / GCS / Azure Blob URL) and hands the raw JSON to the
scanner, which finds the credentials embedded in it directly.

Incremental: Terraform state carries a monotonic ``serial`` that increments on
every apply. We record it and skip re-scanning a state whose serial hasn't
advanced since the last run.
"""
import json
from typing import AsyncIterator

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_http_error,
    classify_network_error,
)
from services.source_scanners.base import SourceAdapter, ScanableContent


class TerraformStateAdapter(SourceAdapter):
    source_type = "terraform_state"

    def __init__(self, state_url: str, auth_token: str = "", max_bytes: int = 8_000_000):
        self.state_url = (state_url or "").strip()
        self.auth_token = (auth_token or "").strip()
        self.max_bytes = int(max_bytes)
        self._updated_sync_state: dict = {}

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    @staticmethod
    def _looks_like_state(doc) -> bool:
        return isinstance(doc, dict) and (
            "terraform_version" in doc or "resources" in doc or "outputs" in doc
        )

    async def test_connection(self) -> dict:
        ctx = {"adapter": "terraform_state"}
        if not self.state_url:
            return {
                "status": "error",
                "message": "State URL is required",
                "title": "Configuration error",
                "summary": "No Terraform state URL was provided.",
                "fix_steps": ["Paste the HTTPS URL that returns your Terraform state JSON."],
                "details": {"code": "terraform_state.config.missing_url", "trace_id": None, "occurred_at": None},
            }
        try:
            async with make_async_client(timeout=20) as client:
                r = await client.get(self.state_url, headers=self._headers(), follow_redirects=True)
                if r.status_code == 200:
                    try:
                        doc = r.json()
                    except Exception:
                        return {
                            "status": "error",
                            "message": "URL did not return valid JSON",
                            "title": "Not a Terraform state file",
                            "summary": "The URL responded, but the body was not valid JSON.",
                            "fix_steps": ["Confirm the URL returns the raw Terraform state document (JSON), not an HTML page."],
                            "details": {"code": "terraform_state.parse.not_json", "trace_id": None, "occurred_at": None},
                        }
                    if self._looks_like_state(doc):
                        n = len(doc.get("resources", []) or [])
                        return {"status": "success", "message": f"Reached Terraform state (serial {doc.get('serial', '?')}, {n} resources)"}
                    return {
                        "status": "error",
                        "message": "JSON is not a Terraform state document",
                        "title": "Not a Terraform state file",
                        "summary": "The JSON returned doesn't look like Terraform state (no terraform_version / resources / outputs).",
                        "fix_steps": ["Point the URL at the actual `.tfstate` document."],
                        "details": {"code": "terraform_state.parse.not_tfstate", "trace_id": None, "occurred_at": None},
                    }
                err = classify_http_error(
                    r, provider="terraform", context=ctx,
                    auth_fix_steps=[
                        "For Terraform Cloud/Enterprise, paste an API token (app.terraform.io → Settings → Tokens).",
                        "For an HTTP backend, provide the backend's bearer credentials.",
                    ],
                    permission_fix_steps=[
                        "Confirm the token can read this workspace's state.",
                        "For a presigned object-storage URL, confirm the link hasn't expired.",
                    ],
                )
                return err.to_user_dict()
        except Exception as exc:
            return classify_network_error(exc, ctx).to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        async with make_async_client(timeout=60) as client:
            r = await client.get(self.state_url, headers=self._headers(), follow_redirects=True)
            if r.status_code != 200:
                return
            text = r.text
            try:
                doc = json.loads(text)
            except Exception:
                doc = None

            serial = doc.get("serial") if isinstance(doc, dict) else None
            # Incremental skip: nothing changed since the last apply we saw.
            last = sync_state.get("last_serial")
            if serial is not None and last is not None:
                try:
                    if int(serial) <= int(last):
                        return
                except (TypeError, ValueError):
                    pass

            # Terraform stores secrets as plaintext JSON values, so the whole
            # state document is the scannable unit.
            yield ScanableContent(
                source_locator=self.state_url,
                content=text[: self.max_bytes],
                content_type="file",
                deep_link_url=self.state_url,
                metadata={
                    "provider": "terraform",
                    "serial": serial,
                    "terraform_version": doc.get("terraform_version") if isinstance(doc, dict) else None,
                    "resource_count": len(doc.get("resources", []) or []) if isinstance(doc, dict) else None,
                },
            )

            if serial is not None:
                self._updated_sync_state["last_serial"] = str(serial)

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state

    async def estimate_scope(self) -> dict:
        return {"estimated_items": 1}
