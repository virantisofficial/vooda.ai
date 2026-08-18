# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Integration management API — connect, test, and manage scanner integrations.
Each provider (Checkmarx, Fortify, SonarQube, etc.) has specific connection
parameters and a test-connection implementation.
"""

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.integration import IntegrationConfig

router = APIRouter()


# ═══════════════════════════════════════════════════════════════════
#  Provider definitions — connection fields per scanner
# ═══════════════════════════════════════════════════════════════════

PROVIDER_SCHEMAS: dict[str, dict] = {
    # External scanner imports removed — Vooda AI is the secret scanner

    # ── Notification providers ──────────────────────────────────────
    "slack": {
        "label": "Slack",
        "type": "Notification",
        "category": "notification",
        "description": "Send scan results and critical finding alerts to Slack channels",
        "fields": [
            {"key": "webhook_url", "label": "Webhook URL", "type": "url", "placeholder": "https://hooks.slack.com/services/T.../B.../...", "required": True},
            {"key": "channel", "label": "Channel (override)", "type": "text", "placeholder": "#security-alerts", "required": False},
        ],
        "auth_type": "webhook",
    },
    "teams": {
        "label": "Microsoft Teams",
        "type": "Notification",
        "category": "notification",
        "description": "Send alerts via Microsoft Teams incoming webhook connector",
        "fields": [
            {"key": "webhook_url", "label": "Webhook URL", "type": "url", "placeholder": "https://outlook.office.com/webhook/...", "required": True},
        ],
        "auth_type": "webhook",
    },
    "email": {
        "label": "Email (SMTP)",
        "type": "Notification",
        "category": "notification",
        "description": "Send scan reports and finding alerts via email",
        "fields": [
            {"key": "smtp_host", "label": "SMTP Host", "type": "text", "placeholder": "smtp.gmail.com", "required": True},
            {"key": "smtp_port", "label": "SMTP Port", "type": "text", "placeholder": "587", "required": True},
            {"key": "smtp_user", "label": "Username", "type": "text", "required": True},
            {"key": "smtp_password", "label": "Password", "type": "password", "required": True},
            {"key": "from_address", "label": "From Address", "type": "text", "placeholder": "security@yourcompany.com", "required": True},
            {"key": "to_addresses", "label": "To Addresses (comma-separated)", "type": "text", "placeholder": "team@yourcompany.com, lead@yourcompany.com", "required": True},
            {"key": "use_tls", "label": "Use TLS", "type": "select", "options": ["true", "false"], "required": True},
        ],
        "auth_type": "credentials",
    },
    "webhook": {
        "label": "Webhook",
        "type": "Notification",
        "category": "notification",
        "description": "Send scan events as HTTP POST with optional HMAC signing",
        "fields": [
            {"key": "endpoint_url", "label": "Endpoint URL", "type": "url", "placeholder": "https://api.yourservice.com/hooks/vooda", "required": True},
            {"key": "secret", "label": "HMAC Secret (optional)", "type": "password", "required": False},
            {"key": "headers", "label": "Custom Headers (JSON)", "type": "text", "placeholder": '{"X-Custom": "value"}', "required": False},
        ],
        "auth_type": "custom",
    },
    "pagerduty": {
        "label": "PagerDuty",
        "type": "Notification",
        "category": "notification",
        "description": "Escalate critical findings to PagerDuty on-call teams",
        "fields": [
            {"key": "routing_key", "label": "Integration / Routing Key", "type": "password", "placeholder": "Events API v2 routing key", "required": True},
        ],
        "auth_type": "token",
    },

    # ── Ticketing providers ────────────────────────────────────────
    # These were missing from PROVIDER_SCHEMAS so the create endpoint
    # rejected POSTs with `{"detail": "Unknown provider: jira"}`. The
    # existing VOOD board worked because it was inserted directly
    # into the DB by the initial setup script, bypassing the check.
    # Adding minimal entries here unblocks the multi-board flow
    # (the FE's TICKETING_TOOLS still owns the rich field rendering).
    # Bug fix 2026-04-27.
    "jira": {
        "label": "Jira",
        "type": "Ticketing",
        "category": "ticketing",
        "description": "Create issues from secret findings on a Jira board",
        "fields": [
            {"key": "site_url",   "label": "Site URL",      "type": "url",      "placeholder": "https://yourteam.atlassian.net", "required": True},
            {"key": "email",      "label": "Account Email", "type": "email",    "required": True},
            {"key": "api_token",  "label": "API Token",     "type": "password", "required": True},
            {"key": "project_key","label": "Jira Project",  "type": "text",     "required": True},
            {"key": "issue_type", "label": "Issue Type",    "type": "text",     "required": True},
        ],
        "auth_type": "credentials",
    },
    "servicenow": {
        "label": "ServiceNow",
        "type": "Ticketing",
        "category": "ticketing",
        "description": "Create security incidents from secret findings",
        "fields": [
            {"key": "instance_url",     "label": "Instance URL",      "type": "url",      "placeholder": "https://yourinstance.service-now.com", "required": True},
            {"key": "username",         "label": "Username",          "type": "text",     "required": True},
            {"key": "password",         "label": "Password / Token",  "type": "password", "required": True},
            {"key": "assignment_group", "label": "Assignment Group",  "type": "text",     "required": False},
        ],
        "auth_type": "credentials",
    },
    "custom_ticketing": {
        "label": "Custom Webhook (Ticketing)",
        "type": "Ticketing",
        "category": "ticketing",
        "description": "POST findings to any ticketing system via webhook",
        "fields": [
            {"key": "webhook_url", "label": "Webhook URL",          "type": "url",      "required": True},
            {"key": "auth_header", "label": "Authorization Header", "type": "password", "required": False, "placeholder": "Bearer your-token"},
        ],
        "auth_type": "custom",
    },

    # ── Source-scan providers ──────────────────────────────────────
    # Distinct ``category="source"`` so the listing endpoint and the
    # IntegrationConfig.integration_type column can tell them apart
    # from ticketing/notification providers — they're INPUT (where
    # we read from), not OUTPUT (where we send alerts/tickets).
    #
    # Field schemas are intentionally minimal here. The
    # ``apps/web/src/app/sources/page.tsx`` registry owns the rich
    # per-adapter field rendering (with hints, validation, etc.);
    # this dict's job is just to (a) pass the validate-or-reject
    # gate in ``create_integration`` and (b) supply a default
    # ``label`` and ``category`` for the IntegrationConfig row.
    #
    # ``atlassian`` is the umbrella provider for Jira-as-source AND
    # Confluence-as-source. The shared Atlassian Cloud OAuth /
    # API-token surface means a single integration_config row can
    # back both; the actual scan_source.source_type ("jira" vs
    # "confluence") tells the worker's adapter factory which API
    # to call. Same pattern for ``ms_graph`` (OneDrive/SharePoint
    # + Teams chat), ``aws`` (S3), ``azure`` (Azure Blob + Azure
    # DevOps Boards).
    #
    # Bug fix 2026-05-07: previously these providers were missing
    # from PROVIDER_SCHEMAS so every Source connect attempt failed
    # with "Unknown provider: <X>" — Linear and Slack were the only
    # working sources because they happened to overlap with the
    # ticketing/notification entries above. Found via UI E2E.
    "atlassian": {
        "label": "Atlassian Cloud",
        "type": "Source",
        "category": "source",
        "description": "Jira and Confluence — shares the same Atlassian API token",
        "fields": [],
        "auth_type": "credentials",
    },
    "aws": {
        "label": "Amazon Web Services",
        "type": "Source",
        "category": "source",
        "description": "S3 buckets — IAM credentials or instance profile",
        "fields": [],
        "auth_type": "credentials",
    },
    "azure": {
        "label": "Microsoft Azure",
        "type": "Source",
        "category": "source",
        "description": "Azure Blob Storage and Azure DevOps Boards",
        "fields": [],
        "auth_type": "credentials",
    },
    "azure_devops": {
        "label": "Azure DevOps",
        "type": "Source",
        "category": "source",
        "description": "Azure DevOps work items and pipelines",
        "fields": [],
        "auth_type": "token",
    },
    "ms_graph": {
        "label": "Microsoft 365",
        "type": "Source",
        "category": "source",
        "description": "OneDrive, SharePoint, and Teams chat — shared Microsoft Graph API",
        "fields": [],
        "auth_type": "oauth2",
    },
    "github": {
        "label": "GitHub",
        "type": "Source",
        "category": "source",
        "description": "GitHub Issues, comments, and discussions",
        "fields": [],
        "auth_type": "token",
    },
    "bitbucket": {
        "label": "Bitbucket",
        "type": "Source",
        "category": "source",
        "description": "Bitbucket Issues and Pull Request comments",
        "fields": [],
        "auth_type": "credentials",
    },
    "notion": {
        "label": "Notion",
        "type": "Source",
        "category": "source",
        "description": "Notion pages and databases",
        "fields": [],
        "auth_type": "token",
    },
    "asana": {
        "label": "Asana",
        "type": "Source",
        "category": "source",
        "description": "Asana tasks and project notes",
        "fields": [],
        "auth_type": "token",
    },
    "salesforce": {
        "label": "Salesforce",
        "type": "Source",
        "category": "source",
        "description": "Salesforce cases, knowledge articles, support comments",
        "fields": [],
        "auth_type": "oauth2",
    },
    "box": {
        "label": "Box",
        "type": "Source",
        "category": "source",
        "description": "Box shared files and folders",
        "fields": [],
        "auth_type": "oauth2",
    },
    "mattermost": {
        "label": "Mattermost",
        "type": "Source",
        "category": "source",
        "description": "Mattermost channels and direct messages",
        "fields": [],
        "auth_type": "token",
    },
    "container_registry": {
        "label": "Container Registry",
        "type": "Source",
        "category": "source",
        "description": "Docker registries (Docker Hub, ECR, GCR, ACR, GHCR)",
        "fields": [],
        "auth_type": "credentials",
    },
    "docker": {
        "label": "Docker Image",
        "type": "Source",
        "category": "source",
        "description": "Single Docker image scans",
        "fields": [],
        "auth_type": "credentials",
    },
    "postman": {
        "label": "Postman",
        "type": "Source",
        "category": "source",
        "description": "Postman workspaces and collections",
        "fields": [],
        "auth_type": "token",
    },
    "cicd": {
        "label": "CI/CD Logs",
        "type": "Source",
        "category": "source",
        "description": "GitHub Actions / GitLab CI / CircleCI / Jenkins build logs",
        "fields": [],
        "auth_type": "token",
    },
    "terraform": {
        "label": "Terraform State",
        "type": "Source",
        "category": "source",
        "description": "Terraform / OpenTofu state (HTTP backend, Terraform Cloud, or presigned object-storage URL)",
        "fields": [],
        "auth_type": "credentials",
    },
}


# ═══════════════════════════════════════════════════════════════════
#  Schemas
# ═══════════════════════════════════════════════════════════════════

class IntegrationCreateRequest(BaseModel):
    provider: str
    name: Optional[str] = None
    config: dict = {}
    repository_id: Optional[UUID] = None
    # Notification scoping
    business_unit_id: Optional[UUID] = None
    scope_level: Optional[str] = None  # "organization" | "business_unit" | "project"


class IntegrationUpdateRequest(BaseModel):
    name: Optional[str] = None
    config: Optional[dict] = None
    scope_level: Optional[str] = None
    business_unit_id: Optional[UUID] = None
    repository_id: Optional[UUID] = None
    is_active: Optional[bool] = None


class IntegrationResponse(BaseModel):
    id: UUID
    name: str
    integration_type: str
    provider: str
    config: dict  # sensitive fields are returned as "" — see _mask_response
    # Names of sensitive fields that ARE currently stored (encrypted).
    # The frontend renders a "✓ currently set" hint next to each so
    # the user understands an empty input means "leave to keep" not
    # "field is unconfigured".  See _mask_response for the contract.
    secrets_present: list[str] = []
    is_active: bool
    repository_id: Optional[UUID]
    business_unit_id: Optional[UUID] = None
    scope_level: Optional[str] = None
    created_at: str

    model_config = {"from_attributes": True}


class TestConnectionRequest(BaseModel):
    provider: str
    config: dict


class TestConnectionResponse(BaseModel):
    status: str  # "success", "auth_failed", "connection_failed", "error"
    message: str
    details: dict = {}


# ═══════════════════════════════════════════════════════════════════
#  Endpoints
# ═══════════════════════════════════════════════════════════════════

@router.get("/providers")
async def list_providers(category: Optional[str] = None):
    """Return all available providers and their connection schemas. Optionally filter by category (scanner/notification)."""
    if category:
        return {k: v for k, v in PROVIDER_SCHEMAS.items() if v.get("category") == category}
    return PROVIDER_SCHEMAS


@router.get("/providers/{provider}")
async def get_provider_schema(provider: str):
    """Return the connection schema for a specific provider."""
    schema = PROVIDER_SCHEMAS.get(provider)
    if not schema:
        raise HTTPException(status_code=404, detail=f"Unknown provider: {provider}")
    return schema



@router.post("/test", response_model=TestConnectionResponse)
async def test_connection(
    body: TestConnectionRequest,
    user: User = Depends(get_current_user),
):
    """Test connection to a scanner without saving the configuration."""
    provider = body.provider.lower()
    config = body.config

    if provider not in PROVIDER_SCHEMAS:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    # Validate required fields
    schema = PROVIDER_SCHEMAS[provider]
    for field in schema["fields"]:
        if field["required"] and not config.get(field["key"]):
            return TestConnectionResponse(
                status="error",
                message=f"Missing required field: {field['label']}",
            )

    # Dispatch to provider-specific test
    try:
        return await _test_provider_connection(provider, config)
    except Exception as e:
        return TestConnectionResponse(
            status="error",
            message=f"Connection test failed: {str(e)}",
        )


def _decrypted_config(integration: "IntegrationConfig") -> dict:
    """Return the integration's config dict with sensitive fields decrypted.

    The PUT handler stores api_token / password / secret etc. as
    `enc:<base64>` ciphertext (see packages/common/encryption.py). Any
    code that hits a provider API on behalf of a saved integration —
    test endpoints, dropdown population, the dispatcher — must run the
    config through this helper first, otherwise it sends the
    ciphertext as the credential and the upstream API rejects it.

    Bug fix 2026-04-27: prior to this helper, the jira-projects /
    jira-issue-types / test_saved_integration paths all read
    `cfg["api_token"]` raw, sending `enc:gAAAAA…` to Atlassian. The
    /project/search endpoint silently returned anonymous-public data
    (looked like success); /project/<KEY> correctly 404'd.
    """
    from packages.common.encryption import decrypt_config_dict
    return decrypt_config_dict(dict(integration.config or {}))


@router.get("/{integration_id}/jira-projects")
async def list_jira_projects(
    integration_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the list of projects visible to the configured Jira credentials.

    The TicketingSection UI uses this to populate the Project Key dropdown
    after a successful Test Connection — instead of asking the user to
    type the project key from memory and risk a typo. Returns
    [{key, name, id}] in the order Jira returns them.
    """
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == integration_id,
            IntegrationConfig.tenant_id == user.tenant_id,
            IntegrationConfig.provider == "jira",
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Jira integration not found")

    cfg = _decrypted_config(integration)
    site = _normalize_atlassian_site_url(cfg.get("site_url") or cfg.get("server_url") or "")
    email = cfg.get("email", "")
    token = cfg.get("api_token", "")
    if not (site and email and token):
        raise HTTPException(status_code=400, detail="Integration missing site URL, email, or token")

    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{site}/rest/api/3/project/search?maxResults=100",
                auth=(email, token),
                headers={"Accept": "application/json"},
            )
        if r.status_code != 200 or "json" not in (r.headers.get("content-type") or "").lower():
            # Include a body preview so transient Jira errors (rate
            # limits, 5xx flaps, expired tokens) are diagnosable from
            # the API logs without re-running the request.
            preview = (r.text or "").strip()[:160]
            raise HTTPException(
                status_code=502,
                detail=f"Jira returned HTTP {r.status_code}: {preview}",
            )
        data = r.json()
        projects = [
            {"key": p.get("key"), "name": p.get("name"), "id": p.get("id")}
            for p in data.get("values", [])
            if p.get("key")
        ]
        return {"projects": projects}
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Jira: {str(e)[:160]}")


@router.get("/{integration_id}/jira-issue-types")
async def list_jira_issue_types(
    integration_id: UUID,
    project_key: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the issue types available on a specific Jira project.

    Different projects expose different issue types (a software project
    might have Bug/Task/Story; a service project might have
    Incident/Change/Service Request). Hardcoding "Bug" causes HTTP 400
    on projects that don't have it (the VOOD project hit this on
    2026-04-27 — it only has Task/Epic/Subtask). Populating the
    dropdown from the actual project metadata removes that trap.

    Filters out subtask types (subtasks need a parent — not appropriate
    as a top-level ticket created from a finding).
    """
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == integration_id,
            IntegrationConfig.tenant_id == user.tenant_id,
            IntegrationConfig.provider == "jira",
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Jira integration not found")

    cfg = _decrypted_config(integration)
    site = _normalize_atlassian_site_url(cfg.get("site_url") or cfg.get("server_url") or "")
    email = cfg.get("email", "")
    token = cfg.get("api_token", "")
    if not (site and email and token and project_key):
        raise HTTPException(status_code=400, detail="Missing site URL, email, token, or project_key")

    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Atlassian's /project/{key} response only includes
            # `issueTypes` when explicitly expanded — otherwise the
            # field is in the `expand` advert list but not the body.
            # ?expand=issueTypes brings them inline.
            r = await client.get(
                f"{site}/rest/api/3/project/{project_key}?expand=issueTypes",
                auth=(email, token),
                headers={"Accept": "application/json"},
            )
        if r.status_code != 200 or "json" not in (r.headers.get("content-type") or "").lower():
            preview = (r.text or "").strip()[:160]
            raise HTTPException(
                status_code=502,
                detail=f"Jira returned HTTP {r.status_code} for project {project_key}: {preview}",
            )
        data = r.json()
        issue_types = [
            {"id": t.get("id"), "name": t.get("name"), "subtask": t.get("subtask", False)}
            for t in data.get("issueTypes", [])
            if not t.get("subtask")  # exclude subtasks — they need a parent
        ]
        return {"project_key": project_key, "issue_types": issue_types}
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Jira: {str(e)[:160]}")


# ────────────────────────────────────────────────────────────────
#  Stateless preview endpoints — for the multi-board form UX
# ────────────────────────────────────────────────────────────────
#
# Why these exist:
#   The /jira-projects + /jira-issue-types endpoints above require a
#   saved IntegrationConfig row (so we can pull the encrypted token
#   from the DB). That works for editing an existing board, but not
#   for the "Add Board" flow where the user is filling in
#   credentials and we want the Project / Issue Type dropdowns to
#   auto-populate AS THEY TYPE — without forcing a save-then-reload
#   round trip.
#
# These two endpoints take credentials in the request body and
# proxy to Atlassian directly. No DB writes, no encryption — the
# credentials are used in-flight only and discarded with the
# request. Bug fix 2026-04-27 (user UX request: "JIRA Project and
# Issue Type should load automatically when after passing the
# credentials").

class JiraPreviewRequest(BaseModel):
    site_url: str
    email: str
    api_token: str
    project_key: Optional[str] = None  # only required for issue-types


def _normalize_atlassian_site_url(raw: str) -> str:
    """Strip everything after the hostname so REST paths can be appended cleanly.

    Customers paste the site URL straight from the browser address
    bar — that often picks up the path of whatever Atlassian page
    they were on (`/jira/for-you`, `/jira/your-work`, `/wiki/...`)
    instead of the bare workspace root. Without normalization we'd
    end up calling `https://acme.atlassian.net/jira/for-you/rest/api/3/...`
    which Atlassian routes to its UI handler and returns the login
    HTML — looks like an auth failure to anyone reading the response.

    Industry-standard defensive parsing: every well-behaved API
    client that takes a base URL (Atlassian's own python SDK, the
    GitHub octokit clients, etc.) strips path segments before
    appending its own. We do the same here. Trailing whitespace and
    slashes are also stripped.

    Bug fix 2026-04-27 — surfaced via the preview-projects 502 loop
    when the saved board's URL field had `/jira/for-you` appended.
    """
    s = (raw or "").strip().rstrip("/")
    if not s:
        return ""
    # Parse and rebuild as scheme://host[:port] only.
    try:
        from urllib.parse import urlparse
        p = urlparse(s if "://" in s else f"https://{s}")
        if not p.netloc:
            return s.rstrip("/")
        return f"{p.scheme or 'https'}://{p.netloc}".rstrip("/")
    except Exception:
        return s.rstrip("/")


@router.post("/jira/preview-projects")
async def preview_jira_projects(
    body: JiraPreviewRequest,
    user: User = Depends(get_current_user),
):
    """Return the project list for the Atlassian credentials in the
    request body. Used by the Add Board form to populate the Project
    dropdown without requiring a save first."""
    site = _normalize_atlassian_site_url(body.site_url or "")
    email = (body.email or "").strip()
    token = (body.api_token or "").strip()
    if not (site and email and token):
        raise HTTPException(status_code=400, detail="Missing site URL, email, or API token")
    # Skip preview if the token is masked — the FE shouldn't be
    # sending masked values, but if a user opens an existing board
    # form and triggers preview without re-typing, refuse rather
    # than silently 401 against Atlassian.
    if any(ch in token for ch in "•·●"):
        raise HTTPException(status_code=400, detail="Token appears masked — re-enter the API token to preview projects")

    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{site}/rest/api/3/project/search?maxResults=100",
                auth=(email, token),
                headers={"Accept": "application/json"},
            )
        if r.status_code == 401:
            raise HTTPException(status_code=401, detail="Atlassian rejected the credentials")
        if r.status_code != 200 or "json" not in (r.headers.get("content-type") or "").lower():
            preview = (r.text or "").strip()[:160]
            raise HTTPException(status_code=502, detail=f"Jira returned HTTP {r.status_code}: {preview}")
        data = r.json()
        projects = [
            {"key": p.get("key"), "name": p.get("name"), "id": p.get("id")}
            for p in data.get("values", [])
            if p.get("key")
        ]
        return {"projects": projects}
    except HTTPException:
        raise
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Jira: {str(e)[:160]}")


@router.post("/jira/preview-issue-types")
async def preview_jira_issue_types(
    body: JiraPreviewRequest,
    user: User = Depends(get_current_user),
):
    """Return the issue-type list for one project, using the
    credentials in the request body. Mirror of preview-projects but
    for the Issue Type dropdown."""
    site = _normalize_atlassian_site_url(body.site_url or "")
    email = (body.email or "").strip()
    token = (body.api_token or "").strip()
    project_key = (body.project_key or "").strip()
    if not (site and email and token and project_key):
        raise HTTPException(status_code=400, detail="Missing site URL, email, token, or project_key")
    if any(ch in token for ch in "•·●"):
        raise HTTPException(status_code=400, detail="Token appears masked — re-enter the API token to preview issue types")

    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{site}/rest/api/3/project/{project_key}?expand=issueTypes",
                auth=(email, token),
                headers={"Accept": "application/json"},
            )
        if r.status_code == 401:
            raise HTTPException(status_code=401, detail="Atlassian rejected the credentials")
        if r.status_code != 200 or "json" not in (r.headers.get("content-type") or "").lower():
            preview = (r.text or "").strip()[:160]
            raise HTTPException(status_code=502, detail=f"Jira returned HTTP {r.status_code} for project {project_key}: {preview}")
        data = r.json()
        issue_types = [
            {"id": t.get("id"), "name": t.get("name"), "subtask": t.get("subtask", False)}
            for t in data.get("issueTypes", [])
            if not t.get("subtask")
        ]
        return {"project_key": project_key, "issue_types": issue_types}
    except HTTPException:
        raise
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Jira: {str(e)[:160]}")


# ────────────────────────────────────────────────────────────────
#  ServiceNow lookup endpoints — assignment groups
# ────────────────────────────────────────────────────────────────
#
# Same shape as the Jira preview / saved-board endpoints. Lets
# the integrations UI populate the Assignment Group dropdown
# with the customer's actual ServiceNow groups instead of asking
# them to type the group name from memory (a common mis-key
# source — group names are case-sensitive in ServiceNow's REST
# API, but ServiceNow's UI sometimes shows them with different
# casing).

class ServiceNowPreviewRequest(BaseModel):
    instance_url: str
    username: str
    password: str


@router.post("/servicenow/preview-assignment-groups")
async def preview_servicenow_assignment_groups(
    body: ServiceNowPreviewRequest,
    user: User = Depends(get_current_user),
):
    """Return the ITIL assignment groups visible to the supplied
    ServiceNow credentials. Used by the Add ServiceNow form so the
    Assignment Group field auto-populates as the user fills in
    credentials — no save-then-reload trip required."""
    instance = _normalize_atlassian_site_url(body.instance_url or "")
    username = (body.username or "").strip()
    password = (body.password or "").strip()
    if not (instance and username and password):
        raise HTTPException(status_code=400, detail="Missing instance URL, username, or password")
    if any(ch in password for ch in "•·●"):
        raise HTTPException(status_code=400, detail="Password appears masked — re-enter to preview groups")

    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Filter to ITIL-type groups (the assignment groups that
            # can own incidents). Limit 100 — sufficient for
            # picker UX; customers with thousands of groups already
            # type ahead in their own ServiceNow UI.
            r = await client.get(
                f"{instance}/api/now/table/sys_user_group",
                params={
                    "sysparm_limit": 100,
                    "sysparm_query": "type=itil^active=true",
                    "sysparm_fields": "sys_id,name,description",
                },
                auth=(username, password),
                headers={"Accept": "application/json"},
            )
        if r.status_code == 401:
            raise HTTPException(status_code=401, detail="ServiceNow rejected the credentials")
        if r.status_code != 200 or "json" not in (r.headers.get("content-type") or "").lower():
            preview = (r.text or "").strip()[:160]
            raise HTTPException(status_code=502, detail=f"ServiceNow returned HTTP {r.status_code}: {preview}")
        data = r.json() or {}
        groups = [
            {"sys_id": g.get("sys_id"), "name": g.get("name"), "description": g.get("description") or ""}
            for g in data.get("result", [])
            if g.get("name")
        ]
        # Sort with "Security Operations" first (industry default
        # for security incidents), then alphabetical.
        groups.sort(key=lambda g: (g["name"] != "Security Operations", g["name"].lower()))
        return {"assignment_groups": groups}
    except HTTPException:
        raise
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Could not reach ServiceNow: {str(e)[:160]}")


@router.get("/{integration_id}/servicenow-assignment-groups")
async def list_servicenow_assignment_groups(
    integration_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Same lookup as the preview endpoint but using the saved
    integration's stored credentials (decrypted server-side)."""
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == integration_id,
            IntegrationConfig.tenant_id == user.tenant_id,
            IntegrationConfig.provider == "servicenow",
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="ServiceNow integration not found")

    cfg = _decrypted_config(integration)
    instance = _normalize_atlassian_site_url(cfg.get("instance_url") or "")
    username = cfg.get("username", "")
    password = cfg.get("password", "")
    if not (instance and username and password):
        raise HTTPException(status_code=400, detail="Integration missing instance URL, username, or password")

    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{instance}/api/now/table/sys_user_group",
                params={
                    "sysparm_limit": 100,
                    "sysparm_query": "type=itil^active=true",
                    "sysparm_fields": "sys_id,name,description",
                },
                auth=(username, password),
                headers={"Accept": "application/json"},
            )
        if r.status_code != 200 or "json" not in (r.headers.get("content-type") or "").lower():
            preview = (r.text or "").strip()[:160]
            raise HTTPException(
                status_code=502,
                detail=f"ServiceNow returned HTTP {r.status_code}: {preview}",
            )
        data = r.json() or {}
        groups = [
            {"sys_id": g.get("sys_id"), "name": g.get("name"), "description": g.get("description") or ""}
            for g in data.get("result", [])
            if g.get("name")
        ]
        groups.sort(key=lambda g: (g["name"] != "Security Operations", g["name"].lower()))
        return {"assignment_groups": groups}
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Could not reach ServiceNow: {str(e)[:160]}")


@router.post("/{integration_id}/test", response_model=TestConnectionResponse)
async def test_saved_integration(
    integration_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Test a previously-saved integration using its stored credentials.

    The TicketingSection UI's post-save Test button (the one beside Remove
    on the expanded tile) calls this. Bug-fix 2026-04-27: prior to this
    route existing, that button hit a 404 silently — the existing Test
    pathway only worked for unsaved configs (POST /integrations/test-
    ticketing). Loading the row, decrypting the credential, and
    delegating to the same per-provider check unifies both Test buttons.
    """
    # Belt-and-suspenders: the inner handler already has its own
    # try/except, but any unexpected failure here (DB deserialization,
    # missing fields, etc.) used to surface as a bare HTTP 500 in the
    # browser — which the user reasonably mistook for "credentials
    # rejected". Catching everything and returning a structured
    # TestConnectionResponse means the Test chip always shows a
    # specific, actionable message.
    try:
        result = await db.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.id == integration_id,
                IntegrationConfig.tenant_id == user.tenant_id,
            )
        )
        integration = result.scalar_one_or_none()
        if not integration:
            raise HTTPException(status_code=404, detail="Integration not found")

        # Delegate to the same handler as the unsaved Test path. Both
        # buttons then surface identical messages and tone so the user
        # can't get confused by a "different test" returning a
        # different verdict on the same credentials. Decrypt the
        # config first — the inner handler is provider-generic and
        # treats the dict as plaintext credentials.
        config = _decrypted_config(integration)
        fake_body = TestConnectionRequest(provider=integration.provider, config=config)
        return await test_ticketing_connection(fake_body, user)
    except HTTPException:
        raise
    except Exception as e:
        return TestConnectionResponse(
            status="error",
            message=f"Test failed: {str(e)[:200]}",
        )


@router.post("/test-ticketing", response_model=TestConnectionResponse)
async def test_ticketing_connection(
    body: TestConnectionRequest,
    user: User = Depends(get_current_user),
):
    """Test a ticketing provider's credentials WITHOUT persisting them.

    Added 2026-04-26 to support the "Test before Connect" UX on the
    /integrations page. Previously the only way to validate a Jira /
    ServiceNow / Linear config was to save it first and then call
    /integrations/{id}/test — which forced users to commit potentially
    wrong credentials to the encrypted store before they could verify.

    This endpoint dispatches to a provider-specific lightweight check:
      jira         -> GET /rest/api/3/myself  (basic auth: email + api_token)
      servicenow   -> GET /api/now/table/sys_user?sysparm_limit=1
      linear       -> POST /graphql           (Bearer api_key)
      custom       -> reachable HEAD on webhook URL

    Each returns success / auth_failed / connection_failed / error so
    the UI can show a precise red/green chip with a useful message.
    """
    import httpx

    provider = body.provider.lower()
    config = body.config or {}

    async def jira_test() -> TestConnectionResponse:
        # Trim invisible whitespace + trailing slashes — easy to accidentally
        # paste a token with leading/trailing whitespace from a copy that
        # included the email line break, or a site URL with a trailing slash.
        # Strip path/query off the site URL — customers paste from
        # the browser address bar (e.g. `…atlassian.net/jira/for-you`)
        # which would otherwise be appended to /rest/api/3/myself
        # and produce HTTP 200 with HTML (Atlassian routes unknown
        # paths to its UI handler). Same fix as the preview /
        # saved-board / dispatcher paths — bug fix 2026-04-27.
        site = _normalize_atlassian_site_url(config.get("site_url") or config.get("server_url") or "")
        email = (config.get("email") or "").strip()
        token = (config.get("api_token") or "").strip()
        if not (site and email and token):
            return TestConnectionResponse(
                status="error",
                message="Missing site URL, email, or API token.",
            )
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"{site}/rest/api/3/myself",
                    auth=(email, token),
                    headers={"Accept": "application/json"},
                )
            ctype = (r.headers.get("content-type") or "").lower()
            body_preview = (r.text or "").strip()[:200]

            if r.status_code == 200:
                # Defensive parse — Atlassian normally returns JSON on 200,
                # but SSO-protected sites or scoped tokens occasionally
                # return a 200 HTML/text body (login redirect, app-access
                # gate, etc.). Treating that as "success" would be a lie;
                # treat as auth_failed with a useful hint.
                if "json" not in ctype:
                    return TestConnectionResponse(
                        status="auth_failed",
                        message=(
                            "Atlassian returned a non-JSON 200 response (SSO redirect "
                            "or scoped-token gate is most likely). Re-generate the "
                            "token at id.atlassian.com/manage-profile/security/api-tokens "
                            "and confirm your account has API access on this site."
                        ),
                        details={"content_type": ctype, "body_preview": body_preview[:120]},
                    )
                try:
                    me = r.json()
                except Exception:
                    return TestConnectionResponse(
                        status="auth_failed",
                        message="Atlassian returned 200 but body wasn't valid JSON. Check the API token.",
                        details={"body_preview": body_preview[:120]},
                    )
                return TestConnectionResponse(
                    status="success",
                    message=f"Authenticated as {me.get('displayName') or email}",
                    details={"account_id": me.get("accountId", "")},
                )

            if r.status_code in (401, 403):
                return TestConnectionResponse(
                    status="auth_failed",
                    message=(
                        "Atlassian rejected the credentials. Generate an API token at "
                        "id.atlassian.com/manage-profile/security/api-tokens — note that "
                        "account passwords no longer work for the Cloud REST API."
                    ),
                    details={"http_status": r.status_code, "body_preview": body_preview[:120]},
                )

            return TestConnectionResponse(
                status="connection_failed",
                message=f"Jira returned HTTP {r.status_code}: {body_preview[:160]}",
                details={"http_status": r.status_code},
            )
        except httpx.RequestError as e:
            return TestConnectionResponse(
                status="connection_failed",
                message=f"Could not reach {site}: {str(e)[:140]}",
            )

    async def servicenow_test() -> TestConnectionResponse:
        # Same defensive parsing as the Jira test — strip any
        # browser-pasted path off the instance URL.
        instance = _normalize_atlassian_site_url(config.get("instance_url") or "")
        username = (config.get("username") or "").strip()
        password = (config.get("password") or "").strip()
        if not (instance and username and password):
            return TestConnectionResponse(
                status="error",
                message="Missing instance URL, username, or password.",
            )
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"{instance}/api/now/table/sys_user?sysparm_limit=1",
                    auth=(username, password),
                    headers={"Accept": "application/json"},
                )
            if r.status_code == 200:
                return TestConnectionResponse(
                    status="success",
                    message=f"Authenticated to ServiceNow as {username}",
                )
            if r.status_code in (401, 403):
                return TestConnectionResponse(
                    status="auth_failed",
                    message="ServiceNow rejected credentials. Use a service-account password (or OAuth client secret).",
                )
            return TestConnectionResponse(
                status="connection_failed",
                message=f"ServiceNow returned HTTP {r.status_code}",
            )
        except httpx.RequestError as e:
            return TestConnectionResponse(
                status="connection_failed",
                message=f"Could not reach {instance}: {str(e)[:140]}",
            )

    async def linear_test() -> TestConnectionResponse:
        api_key = (config.get("api_key") or "").strip()
        if not api_key:
            return TestConnectionResponse(status="error", message="Missing Linear API key.")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    "https://api.linear.app/graphql",
                    json={"query": "{ viewer { id email name } }"},
                    headers={"Authorization": api_key, "Content-Type": "application/json"},
                )
            if r.status_code == 200:
                try:
                    data = r.json().get("data", {}).get("viewer") or {}
                except Exception:
                    return TestConnectionResponse(
                        status="auth_failed",
                        message="Linear returned 200 but body wasn't valid JSON.",
                    )
                if data:
                    return TestConnectionResponse(
                        status="success",
                        message=f"Authenticated as {data.get('email') or data.get('name') or 'Linear user'}",
                    )
                return TestConnectionResponse(
                    status="auth_failed",
                    message="Linear API responded but didn't return a viewer — check the key.",
                )
            if r.status_code in (401, 403):
                return TestConnectionResponse(
                    status="auth_failed",
                    message="Linear rejected the API key. Generate one at linear.app/settings/api.",
                )
            return TestConnectionResponse(
                status="connection_failed",
                message=f"Linear returned HTTP {r.status_code}",
            )
        except httpx.RequestError as e:
            return TestConnectionResponse(
                status="connection_failed",
                message=f"Could not reach Linear: {str(e)[:140]}",
            )

    async def custom_test() -> TestConnectionResponse:
        url = config.get("webhook_url", "")
        if not url:
            return TestConnectionResponse(status="error", message="Missing webhook URL.")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                # HEAD avoids triggering downstream actions; many webhooks
                # reject HEAD though, so fall back to a no-op POST with an
                # explicit X-Vooda-Test header so receivers can ignore.
                r = await client.head(url, follow_redirects=True)
                if r.status_code == 405:
                    r = await client.post(
                        url,
                        json={"vooda_test": True},
                        headers={"X-Vooda-Test": "1", "Content-Type": "application/json"},
                    )
            if r.status_code < 400:
                return TestConnectionResponse(
                    status="success", message=f"Webhook reachable (HTTP {r.status_code})"
                )
            return TestConnectionResponse(
                status="connection_failed",
                message=f"Webhook returned HTTP {r.status_code}",
            )
        except httpx.RequestError as e:
            return TestConnectionResponse(
                status="connection_failed",
                message=f"Could not reach webhook: {str(e)[:140]}",
            )

    handlers = {
        "jira": jira_test,
        "servicenow": servicenow_test,
        "custom_ticketing": custom_test,
    }
    handler = handlers.get(provider)
    if not handler:
        # This endpoint tests a *saved* integration and grew up around
        # ticketing, so its fallback assumed that was all it would ever
        # see. Vault and notification providers reach it too: a saved
        # HashiCorp Vault answered "No ticketing test implemented for
        # provider: hashicorp_vault" while the same credentials tested
        # fine through /integrations/test. Defer to the shared
        # dispatcher, which knows every provider, before giving up.
        return await _test_provider_connection(provider, config)

    try:
        return await handler()
    except Exception as e:
        return TestConnectionResponse(
            status="error",
            message=f"Test failed: {str(e)[:200]}",
        )




@router.post("", response_model=IntegrationResponse, status_code=201)
async def create_integration(
    body: IntegrationCreateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Save an integration configuration with Org/BU/Project scoping."""
    provider = body.provider.lower()
    if provider not in PROVIDER_SCHEMAS:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    # Validate scoping: BU-scoped needs business_unit_id, project-scoped needs repository_id
    scope = body.scope_level or "organization"
    if scope == "business_unit" and not body.business_unit_id:
        raise HTTPException(status_code=400, detail="business_unit_id required for BU-scoped integration")
    if scope == "project" and not body.repository_id:
        raise HTTPException(status_code=400, detail="repository_id required for project-scoped integration")

    # Check user has access to the requested scope
    await _verify_user_scope_access(db, user, scope, body.business_unit_id, body.repository_id)

    from packages.common.encryption import encrypt_config_dict
    schema = PROVIDER_SCHEMAS[provider]
    encrypted_config = encrypt_config_dict(body.config)
    integration = IntegrationConfig(
        tenant_id=user.tenant_id,
        name=body.name or schema["label"],
        integration_type=schema.get("category", "scanner"),
        provider=provider,
        config=encrypted_config,
        is_active=True,
        repository_id=body.repository_id,
        business_unit_id=body.business_unit_id,
        scope_level=scope,
    )
    db.add(integration)
    await db.flush()
    await db.refresh(integration)

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "integration_created", "integration", integration.id,
                    f"Connected {provider} ({schema.get('category', 'scanner')}) — scope: {scope}")

    return _mask_response(integration)


@router.get("", response_model=list[IntegrationResponse])
async def list_integrations(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List integrations the current user has access to (scoped by Org/BU/Project)."""
    result = await db.execute(
        select(IntegrationConfig)
        .where(IntegrationConfig.tenant_id == user.tenant_id)
        .order_by(IntegrationConfig.created_at.desc())
    )
    all_integrations = result.scalars().all()

    # Filter by user's access grants
    visible = await _filter_by_user_access(db, user, all_integrations)
    return [_mask_response(i) for i in visible]


@router.get("/{integration_id}", response_model=IntegrationResponse)
async def get_integration(
    integration_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == integration_id,
            IntegrationConfig.tenant_id == user.tenant_id,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    return _mask_response(integration)


@router.delete("/{integration_id}", status_code=204)
async def delete_integration(
    integration_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == integration_id,
            IntegrationConfig.tenant_id == user.tenant_id,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "integration_deleted", "integration", integration_id,
                    f"Disconnected {integration.provider} ({integration.integration_type}) — {integration.name}")

    await db.delete(integration)
    await db.flush()


@router.put("/{integration_id}", response_model=IntegrationResponse)
async def update_integration(
    integration_id: UUID,
    body: IntegrationUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update an integration's config, scope, or active status."""
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == integration_id,
            IntegrationConfig.tenant_id == user.tenant_id,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    # If scope is changing, validate access
    new_scope = body.scope_level or integration.scope_level or "organization"
    new_bu_id = body.business_unit_id if body.business_unit_id is not None else integration.business_unit_id
    new_repo_id = body.repository_id if body.repository_id is not None else integration.repository_id

    if new_scope == "business_unit" and not new_bu_id:
        raise HTTPException(status_code=400, detail="business_unit_id required for BU-scoped integration")
    if new_scope == "project" and not new_repo_id:
        raise HTTPException(status_code=400, detail="repository_id required for project-scoped integration")

    await _verify_user_scope_access(db, user, new_scope, new_bu_id, new_repo_id)

    changes = []
    if body.name is not None:
        integration.name = body.name
        changes.append("name")
    if body.config is not None:
        from packages.common.encryption import encrypt_config_dict, decrypt_config_dict
        # Merge: only update keys that are provided (non-masked)
        merged = decrypt_config_dict(dict(integration.config or {}))
        for k, v in body.config.items():
            if v and "•" not in str(v):  # Skip masked values
                merged[k] = v
        integration.config = encrypt_config_dict(merged)
        changes.append("config")
    if body.scope_level is not None:
        integration.scope_level = body.scope_level
        integration.business_unit_id = new_bu_id if new_scope == "business_unit" else None
        integration.repository_id = new_repo_id if new_scope == "project" else None
        changes.append("scope")
    if body.is_active is not None:
        integration.is_active = body.is_active
        changes.append("active" if body.is_active else "inactive")

    await db.flush()
    await db.refresh(integration)

    from apps.api.app.core.audit import log_audit
    await log_audit(db, user, "integration_updated", "integration", integration_id,
                    f"Updated {integration.provider}: {', '.join(changes)}")

    return _mask_response(integration)


# ═══════════════════════════════════════════════════════════════════
#  Connection testers
# ═══════════════════════════════════════════════════════════════════

async def _test_provider_connection(provider: str, config: dict) -> TestConnectionResponse:
    """Route to the correct provider connection tester."""
    testers = {
        # Notification providers
        "slack": _test_slack,
        "teams": _test_teams,
        "email": _test_email,
        "webhook": _test_webhook,
        "pagerduty": _test_pagerduty,
    }
    tester = testers.get(provider)
    if tester:
        return await tester(config)

    # Vault providers all implement the same `test_connection` contract,
    # so they share one tester rather than five near-identical ones.
    from services.vault_integration.factory import VAULT_PROVIDERS
    if provider in VAULT_PROVIDERS:
        return await _test_vault(provider, config)

    return TestConnectionResponse(status="error", message="No test available for this provider")


async def _test_vault(provider: str, config: dict) -> TestConnectionResponse:
    """Authenticate against a vault and confirm its secret list is readable.

    A successful auth alone is not enough to report success: a token can
    authenticate and still lack the list permission this feature needs,
    which would then fail later during a coverage check with no obvious
    cause. Listing here surfaces that at configure time instead.
    """
    from services.vault_integration.factory import create_vault_provider

    def _missing_vault_dependency(p: str) -> str | None:
        """Return the pip name of a required package that is absent.

        Only two providers need anything beyond httpx: AWS uses boto3
        and GCP uses google-auth to mint a token from a service-account
        JWT. HashiCorp, Azure and CyberArk are pure REST.
        """
        needed = {
            "aws_secrets_manager": ("boto3", "boto3"),
            "gcp_secret_manager": ("google.oauth2", "google-auth"),
        }.get(p)
        if not needed:
            return None
        module, pip_name = needed
        try:
            __import__(module)
            return None
        except ImportError:
            return pip_name

    try:
        vault = create_vault_provider(provider, config)
    except ValueError as e:
        return TestConnectionResponse(status="error", message=str(e))

    # A provider whose auth library is absent raises ImportError inside
    # its own broad `except` and returns False, which then surfaced as
    # "check the URL and credentials" — the one message guaranteed to
    # waste the user's time, because their credentials were never the
    # problem. GCP Secret Manager shipped in exactly that state:
    # google-auth was missing from requirements.txt, so every attempt
    # reported bad credentials. Probe the imports first and report a
    # packaging fault as a packaging fault.
    missing = _missing_vault_dependency(provider)
    if missing:
        return TestConnectionResponse(
            status="error",
            message=(
                f"Server is missing the {missing} package needed for this "
                f"provider. Reinstall requirements.txt and restart the API."
            ),
        )

    try:
        if not await vault.test_connection():
            return TestConnectionResponse(
                status="error",
                message="Could not authenticate — check the URL and credentials",
            )
        secrets = await vault.list_secrets()
        return TestConnectionResponse(
            status="success",
            message=f"Connected — {len(secrets)} secret(s) readable",
            details={"provider": provider, "secret_count": len(secrets)},
        )
    except Exception as e:
        return TestConnectionResponse(status="error", message=f"Vault error: {str(e)[:200]}")


async def _test_checkmarx(config: dict) -> TestConnectionResponse:
    import httpx
    url = config["server_url"].rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            # Checkmarx REST API v1 — auth endpoint
            r = await client.post(
                f"{url}/cxrestapi/auth/identity/connect/token",
                data={
                    "username": config["username"],
                    "password": config["password"],
                    "grant_type": "password",
                    "scope": "sast_rest_api",
                    "client_id": "resource_owner_client",
                    "client_secret": "014DF517-39D1-4453-B7B3-9930C563627C",
                },
            )
            if r.status_code == 200 and "access_token" in r.json():
                return TestConnectionResponse(
                    status="success",
                    message="Connected to Checkmarx successfully",
                    details={"server": url},
                )
            elif r.status_code == 401 or r.status_code == 400:
                return TestConnectionResponse(status="auth_failed", message="Invalid credentials")
            else:
                return TestConnectionResponse(status="error", message=f"Checkmarx returned status {r.status_code}")
    except httpx.ConnectError:
        return TestConnectionResponse(status="connection_failed", message=f"Cannot connect to {url}")
    except Exception as e:
        return TestConnectionResponse(status="error", message=str(e)[:200])


async def _test_fortify(config: dict) -> TestConnectionResponse:
    import httpx
    url = config["server_url"].rstrip("/")
    token = config["auth_token"]
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            r = await client.get(
                f"{url}/api/v1/projects?limit=1",
                headers={"Authorization": f"FortifyToken {token}"},
            )
            if r.status_code == 200:
                return TestConnectionResponse(
                    status="success",
                    message="Connected to Fortify SSC successfully",
                    details={"server": url},
                )
            elif r.status_code in (401, 403):
                return TestConnectionResponse(status="auth_failed", message="Invalid or expired authentication token")
            else:
                return TestConnectionResponse(status="error", message=f"Fortify returned status {r.status_code}")
    except httpx.ConnectError:
        return TestConnectionResponse(status="connection_failed", message=f"Cannot connect to {url}")
    except Exception as e:
        return TestConnectionResponse(status="error", message=str(e)[:200])


async def _test_veracode(config: dict) -> TestConnectionResponse:
    import httpx
    import hmac
    import hashlib
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Veracode uses HMAC auth — simplified check against /api/authn/v2/users/self
            r = await client.get(
                "https://api.veracode.com/appsec/v1/applications?size=1",
                headers={
                    "Authorization": f"VERACODE-HMAC-SHA-256 id={config['api_id']},ts=0,nonce=test,sig=test"
                },
            )
            # Even 401 means we reached Veracode
            if r.status_code == 401:
                return TestConnectionResponse(
                    status="auth_failed",
                    message="API credentials rejected. Check your API ID and Secret Key.",
                )
            elif r.status_code == 200:
                return TestConnectionResponse(status="success", message="Connected to Veracode successfully")
            else:
                return TestConnectionResponse(status="success", message="Veracode API reachable (credentials need verification at first scan)")
    except Exception as e:
        return TestConnectionResponse(status="connection_failed", message=str(e)[:200])


async def _test_codeql(config: dict) -> TestConnectionResponse:
    import httpx
    token = config["github_token"]
    repo = config.get("repository", "")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://api.github.com/repos/{repo}/code-scanning/alerts?per_page=1",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"},
            )
            if r.status_code == 200:
                count = len(r.json())
                return TestConnectionResponse(
                    status="success",
                    message=f"Connected to GitHub Code Scanning for {repo}",
                    details={"alerts_available": count > 0},
                )
            elif r.status_code == 404:
                return TestConnectionResponse(
                    status="error",
                    message="Repository not found or Code Scanning not enabled",
                )
            elif r.status_code in (401, 403):
                return TestConnectionResponse(status="auth_failed", message="Invalid token or insufficient permissions")
            else:
                return TestConnectionResponse(status="error", message=f"GitHub returned status {r.status_code}")
    except Exception as e:
        return TestConnectionResponse(status="error", message=str(e)[:200])


async def _test_sonarqube(config: dict) -> TestConnectionResponse:
    import httpx
    url = config["server_url"].rstrip("/")
    token = config["token"]
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            r = await client.get(
                f"{url}/api/system/status",
                auth=(token, ""),  # SonarQube token auth
            )
            if r.status_code == 200:
                data = r.json()
                return TestConnectionResponse(
                    status="success",
                    message=f"Connected to SonarQube ({data.get('status', 'UP')})",
                    details={"version": data.get("version"), "status": data.get("status")},
                )
            elif r.status_code in (401, 403):
                return TestConnectionResponse(status="auth_failed", message="Invalid token")
            else:
                return TestConnectionResponse(status="error", message=f"SonarQube returned status {r.status_code}")
    except httpx.ConnectError:
        return TestConnectionResponse(status="connection_failed", message=f"Cannot connect to {url}")
    except Exception as e:
        return TestConnectionResponse(status="error", message=str(e)[:200])


async def _test_snyk(config: dict) -> TestConnectionResponse:
    import httpx
    token = config["api_token"]
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                "https://api.snyk.io/rest/self?version=2024-04-29",
                headers={"Authorization": f"token {token}"},
            )
            if r.status_code == 200:
                return TestConnectionResponse(
                    status="success",
                    message="Connected to Snyk successfully",
                )
            elif r.status_code in (401, 403):
                return TestConnectionResponse(status="auth_failed", message="Invalid API token")
            else:
                return TestConnectionResponse(status="error", message=f"Snyk returned status {r.status_code}")
    except Exception as e:
        return TestConnectionResponse(status="error", message=str(e)[:200])


async def _test_custom(config: dict) -> TestConnectionResponse:
    """Custom scanners — just validate the config has required fields."""
    if not config.get("scanner_name"):
        return TestConnectionResponse(status="error", message="Scanner name is required")
    return TestConnectionResponse(
        status="success",
        message=f"Custom scanner '{config['scanner_name']}' configured",
        details={"format": config.get("import_format", "json")},
    )


# ── Notification testers ─────────────────────────────────────────


async def _test_slack(config: dict) -> TestConnectionResponse:
    import httpx
    url = config.get("webhook_url", "")
    if not url or "hooks.slack.com" not in url:
        return TestConnectionResponse(status="error", message="Invalid Slack webhook URL")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, json={"text": "✅ Vooda AI connectivity test — this channel will receive security alerts."})
            if r.status_code == 200:
                return TestConnectionResponse(status="success", message="Slack webhook is working — test message sent")
            elif r.status_code in (403, 404):
                return TestConnectionResponse(status="auth_failed", message="Webhook URL is invalid or revoked")
            else:
                return TestConnectionResponse(status="error", message=f"Slack returned status {r.status_code}")
    except httpx.ConnectError:
        return TestConnectionResponse(status="connection_failed", message="Cannot reach Slack — check network")
    except Exception as e:
        return TestConnectionResponse(status="error", message=str(e)[:200])


async def _test_teams(config: dict) -> TestConnectionResponse:
    import httpx
    url = config.get("webhook_url", "")
    if not url:
        return TestConnectionResponse(status="error", message="Webhook URL is required")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, json={
                "@type": "MessageCard",
                "summary": "Vooda AI Test",
                "sections": [{"activityTitle": "✅ Vooda AI Connectivity Test", "text": "This channel will receive security alerts."}],
            })
            body = (r.text or "").strip()
            # Teams delivery CANNOT be confirmed from the HTTP response,
            # and this test must not pretend otherwise:
            #   * A Power Automate Workflow (the current, supported path)
            #     returns 202 Accepted the instant it queues the run.
            #     The run can still fail downstream — a 202 with the
            #     message never arriving is a documented, common case —
            #     and that failure shows only in the workflow run
            #     history, never in this response.
            #   * The legacy outlook.office.com connector is retired by
            #     Microsoft; those URLs return 200 and no longer deliver.
            #     Worse, that host returns 200 with an EMPTY body for any
            #     /webhook/ path, so a bogus URL used to pass as "test
            #     message sent".
            # So: a 2xx means the endpoint ACCEPTED the request, not that
            # a human saw the card. Say exactly that and send the user to
            # the channel to confirm. An empty 200 is the retired-connector
            # / bogus-URL signature and is called out as such.
            if r.status_code in (200, 202) and (body or r.status_code == 202):
                return TestConnectionResponse(
                    status="success",
                    message=(
                        f"Teams accepted the request (HTTP {r.status_code}). Teams does "
                        f"not confirm delivery over HTTP — open the channel to verify the "
                        f"test message arrived."
                    ),
                )
            elif r.status_code == 200 and not body:
                return TestConnectionResponse(
                    status="auth_failed",
                    message=(
                        "Endpoint returned an empty 200 — this is the signature of a "
                        "retired Office 365 connector URL, which no longer delivers. "
                        "Recreate the webhook as a Power Automate Workflow."
                    ),
                )
            elif r.status_code in (400, 403, 404):
                return TestConnectionResponse(status="auth_failed", message="Webhook URL is invalid or expired")
            else:
                return TestConnectionResponse(status="error", message=f"Teams returned status {r.status_code}")
    except httpx.ConnectError:
        return TestConnectionResponse(status="connection_failed", message="Cannot reach Microsoft Teams — check network")
    except Exception as e:
        return TestConnectionResponse(status="error", message=str(e)[:200])


async def _test_email(config: dict) -> TestConnectionResponse:
    """Verify SMTP settings using the same library the dispatcher sends with.

    This used to import aiosmtplib, which is not in requirements.txt, so
    every email Test failed with "No module named 'aiosmtplib'" — while
    the dispatcher (services/notifications/dispatcher.py) sent real mail
    fine via the stdlib smtplib. So the channel worked but could not be
    tested, and the error looked like a platform fault rather than a
    packaging one. Using smtplib here means one SMTP path, no extra
    dependency, and the test exercises what actually sends.

    The blocking smtplib calls run in a thread so the event loop is not
    stalled during connect/login.
    """
    import asyncio
    import smtplib

    host = config.get("smtp_host", "")
    port = int(config.get("smtp_port", "587"))
    user = config.get("smtp_user", "")
    password = config.get("smtp_password", "")
    use_tls = str(config.get("use_tls", "true")).lower() == "true"

    if not host:
        return TestConnectionResponse(status="error", message="SMTP host is required")

    def _probe() -> None:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
        try:
            server.ehlo()
            if use_tls and port != 465:
                server.starttls()
                server.ehlo()
            if user and password:
                server.login(user, password)
        finally:
            try:
                server.quit()
            except Exception:
                pass

    try:
        await asyncio.to_thread(_probe)
        return TestConnectionResponse(
            status="success", message=f"SMTP connection to {host}:{port} successful"
        )
    except smtplib.SMTPAuthenticationError:
        return TestConnectionResponse(
            status="auth_failed",
            message="SMTP authentication failed — check username/password",
        )
    except Exception as e:
        return TestConnectionResponse(
            status="connection_failed", message=f"SMTP error: {str(e)[:200]}"
        )


async def _test_webhook(config: dict) -> TestConnectionResponse:
    import httpx
    url = config.get("endpoint_url", "")
    if not url:
        return TestConnectionResponse(status="error", message="Endpoint URL is required")
    try:
        headers = {"Content-Type": "application/json", "User-Agent": "Vooda-Webhook/1.0"}
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, json={"event": "test", "source": "vooda"}, headers=headers)
            if r.status_code < 400:
                return TestConnectionResponse(status="success", message=f"Webhook endpoint responded with {r.status_code}")
            else:
                return TestConnectionResponse(status="error", message=f"Endpoint returned status {r.status_code}")
    except httpx.ConnectError:
        return TestConnectionResponse(status="connection_failed", message=f"Cannot reach {url}")
    except Exception as e:
        return TestConnectionResponse(status="error", message=str(e)[:200])


async def _test_pagerduty(config: dict) -> TestConnectionResponse:
    import httpx
    routing_key = config.get("routing_key", "")
    if not routing_key:
        return TestConnectionResponse(status="error", message="Routing key is required")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json={
                    "routing_key": routing_key,
                    "event_action": "trigger",
                    "payload": {
                        "summary": "Vooda AI connectivity test — this integration is working",
                        "severity": "info",
                        "source": "Vooda AI SAST Platform",
                    },
                },
            )
            if r.status_code == 202:
                return TestConnectionResponse(status="success", message="PagerDuty integration key is valid — test event sent")
            elif r.status_code == 400:
                return TestConnectionResponse(status="auth_failed", message="Invalid routing key")
            else:
                return TestConnectionResponse(status="error", message=f"PagerDuty returned status {r.status_code}")
    except Exception as e:
        return TestConnectionResponse(status="error", message=str(e)[:200])


# ═══════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════

# Legacy explicit list — kept for backwards compatibility, but the
# real check is via `is_sensitive_key()` which catches suffix
# patterns (`_token`, `_key`, `_secret`, ...) so new provider
# credential fields are automatically masked without a code update.
# Discovered E2E 2026-05-19 that `bot_token` (Slack) was bypassing
# both encryption AND masking because it wasn't in the explicit set.
SENSITIVE_KEYS = {"password", "auth_token", "api_key", "api_secret", "token", "github_token", "api_token", "smtp_password", "secret", "routing_key", "webhook_url"}


def _mask_response(integration: IntegrationConfig) -> dict:
    """Mask sensitive fields in integration config for API responses.

    Previously this function returned ``v[:4] + "•" * (len(v) - 4)`` —
    but ``v`` is the ENCRYPTED ciphertext (starts with ``enc:``).  So
    the "mask" was literally exposing the encryption marker prefix and
    middle-truncating the rest with bullets.  The frontend pre-filled
    form inputs with this garbled string, which (a) looked like real
    config, (b) suppressed the "Leave blank to keep current"
    placeholder, and (c) risked re-encryption corruption if the user
    clicked Save without editing the field.  Bug confirmed E2E on
    2026-05-18 — the Notifications edit flow couldn't reuse stored
    Slack webhooks.

    New contract:
      - sensitive fields → empty string in ``config`` (the form
        placeholder takes over) PLUS a ``secrets_present`` array
        listing the keys that ARE configured.  Frontend can render a
        small "✓ currently set" indicator next to the empty input.
      - non-sensitive fields → returned as-is (plain text — the
        scope, channel name, room id, etc. are not encrypted).

    The update path at ``update_integration`` already correctly skips
    empty values when merging (``if v and "•" not in str(v)``) so an
    untouched empty sensitive field preserves the stored ciphertext.
    """
    from packages.common.encryption import is_sensitive_key
    masked_config: dict = {}
    secrets_present: list[str] = []
    for k, v in (integration.config or {}).items():
        if is_sensitive_key(k):
            if isinstance(v, str) and v:
                secrets_present.append(k)
            masked_config[k] = ""
        else:
            masked_config[k] = v

    return {
        "id": integration.id,
        "name": integration.name,
        "integration_type": integration.integration_type,
        "provider": integration.provider,
        "config": masked_config,
        "secrets_present": secrets_present,
        "is_active": integration.is_active,
        "repository_id": integration.repository_id,
        "business_unit_id": integration.business_unit_id,
        "scope_level": integration.scope_level,
        "created_at": str(integration.created_at),
    }


# ═══════════════════════════════════════════════════════════════════
#  Access control helpers
# ═══════════════════════════════════════════════════════════════════

async def _get_user_access_grants(db: AsyncSession, user: User):
    """Load the user's access grants to determine Org/BU/Project visibility."""
    from apps.api.app.models.access import UserAccessGrant, AccessLevel
    result = await db.execute(
        select(UserAccessGrant).where(UserAccessGrant.user_id == user.id)
    )
    return result.scalars().all()


async def _verify_user_scope_access(
    db: AsyncSession, user: User, scope: str,
    business_unit_id: Optional[UUID], repository_id: Optional[UUID]
):
    """Ensure user has permission to create an integration at the requested scope."""
    from apps.api.app.models.access import UserAccessGrant, AccessLevel

    grants = await _get_user_access_grants(db, user)

    # No grants yet (fresh setup) → allow everything (admin bootstrap)
    if not grants:
        return

    has_org = any(g.access_level == AccessLevel.ORGANIZATION for g in grants)
    if has_org:
        return  # Org-level users can create any scope

    if scope == "organization":
        raise HTTPException(status_code=403, detail="Org-level access required to create org-wide integrations")

    if scope == "business_unit":
        has_bu = any(
            g.access_level == AccessLevel.BUSINESS_UNIT and str(g.business_unit_id) == str(business_unit_id)
            for g in grants
        )
        if not has_bu:
            raise HTTPException(status_code=403, detail="You don't have access to this Business Unit")

    if scope == "project":
        has_proj = any(
            g.access_level == AccessLevel.PROJECT and str(g.repository_id) == str(repository_id)
            for g in grants
        )
        # Also allow if user has BU-level access to the repo's BU
        if not has_proj:
            from apps.api.app.models.repository import Repository
            repo_result = await db.execute(select(Repository.business_unit_id).where(Repository.id == repository_id))
            repo_bu = repo_result.scalar()
            has_bu = repo_bu and any(
                g.access_level == AccessLevel.BUSINESS_UNIT and str(g.business_unit_id) == str(repo_bu)
                for g in grants
            )
            if not has_bu:
                raise HTTPException(status_code=403, detail="You don't have access to this project")


async def _filter_by_user_access(db: AsyncSession, user: User, integrations: list) -> list:
    """Filter integrations list to only those the user has access to."""
    from apps.api.app.models.access import UserAccessGrant, AccessLevel

    grants = await _get_user_access_grants(db, user)

    # No grants yet → show everything (bootstrap / admin)
    if not grants:
        return integrations

    has_org = any(g.access_level == AccessLevel.ORGANIZATION for g in grants)
    if has_org:
        return integrations  # Org-level sees everything

    # Collect accessible BU IDs and project IDs
    accessible_bus = {
        str(g.business_unit_id) for g in grants
        if g.access_level == AccessLevel.BUSINESS_UNIT and g.business_unit_id
    }
    accessible_repos = {
        str(g.repository_id) for g in grants
        if g.access_level == AccessLevel.PROJECT and g.repository_id
    }

    visible = []
    for i in integrations:
        scope = i.scope_level or "organization"

        if scope == "organization":
            # Org-wide integrations: only visible to org-level users (filtered above)
            # BU/project users should NOT see org-wide configs
            continue
        elif scope == "business_unit":
            if i.business_unit_id and str(i.business_unit_id) in accessible_bus:
                visible.append(i)
        elif scope == "project":
            if i.repository_id and str(i.repository_id) in accessible_repos:
                visible.append(i)
            # Also visible if user has BU access to the repo's BU
            elif i.business_unit_id and str(i.business_unit_id) in accessible_bus:
                visible.append(i)
        else:
            # Scanners and other non-scoped types — show if user has any access
            visible.append(i)

    return visible
