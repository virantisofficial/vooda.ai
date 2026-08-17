# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""ServiceNow source adapter — scans incident, change, and request descriptions.

Why: enterprises that route IT/security work through ServiceNow
routinely paste credentials into incident descriptions ("the prod
DB password is …"). This is the same secret-leak profile as a Jira
ticket but on the ITIL side of the house.

Auth: ServiceNow basic auth (username + password) or OAuth password
grant. Both work against `/api/now/table/...`. Vooda's existing
ServiceNow ticketing integration already stores these creds — this
adapter reuses them.

Coverage:
  - sys_id, short_description, description, work_notes, comments
  - Three tables by default (parametrisable via config):
      incident, change_request, sc_request
  - Server-side pagination via `sysparm_offset`

Out of scope:
  - CMDB records (low yield)
  - Knowledge base articles (different table; deferred — most
    enterprises auth-gate KB anyway, low secret-leak risk)
"""
from __future__ import annotations

import asyncio
from base64 import b64encode
from typing import AsyncIterator

from packages.common.outbound_http import make_async_client
from services.integration_errors.classifiers import (
    classify_network_error,
    classify_servicenow_error,
)
from services.source_scanners.base import ScanableContent, SourceAdapter


_DEFAULT_TABLES = ("incident", "change_request", "sc_request")
_TEXT_FIELDS = ("short_description", "description", "work_notes", "comments")


class ServiceNowAdapter(SourceAdapter):
    source_type = "servicenow"

    def __init__(
        self,
        instance_url: str,
        username: str,
        password: str,
        tables: str = ",".join(_DEFAULT_TABLES),
    ):
        if not (instance_url and username and password):
            raise ValueError("ServiceNow adapter requires instance_url, username, password")
        self.instance_url = instance_url.rstrip("/")
        self.tables = [t.strip() for t in tables.split(",") if t.strip()] or list(_DEFAULT_TABLES)
        auth = b64encode(f"{username}:{password}".encode()).decode()
        self._headers = {
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
        }
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Probe ``sys_user_group`` — a tiny read every authenticated
        ServiceNow user can do.

        Failures route through :func:`classify_servicenow_error`,
        which decodes the ``error.message`` envelope and best-effort
        detects the locked-account variant of 401 (which has its own
        fix step).
        """
        ctx = {"adapter": "servicenow", "instance_url": self.instance_url}
        try:
            async with make_async_client(timeout=15) as client:
                r = await client.get(
                    f"{self.instance_url}/api/now/table/sys_user_group",
                    headers=self._headers,
                    params={"sysparm_limit": "1"},
                )
                if r.status_code == 200:
                    return {"status": "success", "message": f"Connected to {self.instance_url}"}
                err = classify_servicenow_error(r, ctx)
                return err.to_user_dict()
        except Exception as exc:
            err = classify_network_error(exc, ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        # Per-table watermark — different tables have wildly different
        # update cadences; one watermark per table is more efficient
        # than a global one.
        watermarks: dict = dict(sync_state.get("table_watermarks", {}))

        async with make_async_client(timeout=30) as client:
            for table in self.tables:
                last_sync = watermarks.get(table, "")
                offset = 0
                page_size = 100
                MAX_PAGES = 200
                page = 0
                latest_seen = last_sync
                while page < MAX_PAGES:
                    params = {
                        "sysparm_limit": str(page_size),
                        "sysparm_offset": str(offset),
                        "sysparm_fields": "sys_id,number," + ",".join(_TEXT_FIELDS) + ",sys_updated_on",
                        "sysparm_query": f"sys_updated_on>={last_sync}^ORDERBYsys_updated_on" if last_sync else "ORDERBYsys_updated_on",
                    }
                    r = await client.get(
                        f"{self.instance_url}/api/now/table/{table}",
                        headers=self._headers, params=params,
                    )
                    if r.status_code != 200:
                        break
                    rows = (r.json() or {}).get("result", [])
                    if not rows:
                        break
                    for row in rows:
                        sys_id = row.get("sys_id")
                        number = row.get("number") or sys_id
                        updated = row.get("sys_updated_on", "")
                        if updated > latest_seen:
                            latest_seen = updated

                        for field in _TEXT_FIELDS:
                            value = row.get(field)
                            if not value or not str(value).strip():
                                continue
                            yield ScanableContent(
                                source_locator=f"servicenow://{table}/{number}/{field}",
                                content=str(value),
                                content_type="page" if field in ("short_description", "description") else "comment",
                                deep_link_url=f"{self.instance_url}/nav_to.do?uri={table}.do?sys_id={sys_id}",
                                metadata={"table": table, "number": number, "field": field},
                            )
                    if len(rows) < page_size:
                        break
                    offset += page_size
                    page += 1
                    await asyncio.sleep(0.3)
                if latest_seen:
                    watermarks[table] = latest_seen

        self._updated_sync_state["table_watermarks"] = watermarks

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
