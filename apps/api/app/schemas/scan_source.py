# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from typing import Optional


class ScanSourceCreate(BaseModel):
    name: str
    source_type: str  # slack, confluence, jira, s3, docker_image, postman, cicd_logs, ms_teams, etc.
    integration_config_id: UUID
    # Optional — when omitted, the router resolves it to the smart
    # default for the source type (see get_default_schedule below).
    # An explicit "on_demand" still works for callers who really want
    # manual-only scanning; None just means "give me whatever default
    # makes sense for this source category."
    scan_schedule: Optional[str] = None  # on_demand, hourly, daily, weekly
    config: dict = {}
    # Per-source scope: bind this source's findings to a specific
    # repository or business unit. NULL on both = org-wide
    # (current behaviour). Set one or the other; if both are set,
    # repository wins. Bug fix / feature 2026-04-29.
    target_repository_id: Optional[UUID] = None
    target_business_unit_id: Optional[UUID] = None


class ScanSourceUpdate(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None
    scan_schedule: Optional[str] = None
    config: Optional[dict] = None
    target_repository_id: Optional[UUID] = None
    target_business_unit_id: Optional[UUID] = None


class ScanSourceResponse(BaseModel):
    id: UUID
    name: str
    source_type: str
    integration_config_id: UUID
    is_active: bool
    scan_schedule: str
    config: dict
    sync_state: dict
    last_scan_at: Optional[datetime] = None
    # Convenience top-level fields lifted out of stats JSONB so the
    # FE doesn't have to crack the stats blob to render the source
    # card. Set by the worker on every scan attempt — success or
    # failure — so a "Never scanned" card is unambiguous (no recent
    # attempt) vs a "Failed" card (recent attempt that errored).
    last_scan_status: Optional[str] = None  # "success" | "failed" | None
    last_scan_error: Optional[str] = None   # short human-readable error
    stats: dict
    target_repository_id: Optional[UUID] = None
    target_business_unit_id: Optional[UUID] = None
    # Server-computed staleness signal.  True when the source's
    # scan_schedule says it should fire on a cadence (hourly / daily /
    # weekly) but the last successful scan is older than 2× the
    # expected interval — same "silent failure" class of bug that
    # webhook-health badges catch for push-based sources.
    #
    # Derived at response time (see _compute_is_stale in the router)
    # rather than stored on the row, because the schedule itself is
    # editable and we want the answer to reflect the CURRENT schedule
    # without a backfill migration.  on_demand sources are never
    # considered stale — they only run when explicitly triggered.
    is_stale: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Smart scan-schedule defaults per source category ────────────────
# Picked to match what enterprise customers expect from
# configurable-scanner peers (Snyk, Aikido, Sysdig).  The trade-off
# matrix:
#
#   chat          → hourly  (most ephemeral surface; messages get
#                            edited/deleted within minutes — hourly
#                            is the meaningful detection cap before
#                            Slack/Teams rate-limits start biting)
#   docs & wikis  → daily   (persistent content; daily catches it
#                            without burning the upstream API quota)
#   ticketing     → daily   (persistent, high volume per scan;
#                            daily matches Jira/ServiceNow API caps)
#   cloud storage → weekly  (object configs change rarely; full
#                            walks are expensive — weekly is the
#                            sweet spot for S3/GCS/Azure Blob)
#   ci/cd logs    → daily   (logs accumulate fast; daily catches
#                            them before retention rotation)
#   container/image
#                 → weekly  (image configs change rarely; pulling
#                            layers is bandwidth-heavy)
#   crm           → daily   (same persistent-content profile as
#                            ticketing)
#
# These are NEW-source defaults only — the router never modifies an
# existing source's schedule.  Customers always retain full per-source
# control via the Edit form / PUT endpoint.  No alarm-clock surprise
# on the existing fleet.
DEFAULT_SCHEDULE_BY_SOURCE_TYPE: dict[str, str] = {
    # Chat — hourly
    "slack": "hourly",
    "ms_teams": "hourly",
    "mattermost": "hourly",
    # Docs & wikis — daily
    "confluence": "daily",
    "notion": "daily",
    "sharepoint_pages": "daily",
    # Ticketing — daily
    "jira": "daily",
    "servicenow": "daily",
    "azure_devops": "daily",
    # CI/CD logs — daily
    "cicd_logs": "daily",
    # Terraform state — daily (state changes on every apply)
    "terraform_state": "daily",
    # CRM — daily
    "salesforce": "daily",
    # Cloud storage — weekly
    "s3": "weekly",
    "gcs": "weekly",
    "azure_blob": "weekly",
    # Container / image — weekly
    "container_registry": "weekly",
    "docker_image": "weekly",
    "postman": "weekly",
}


def get_default_schedule(source_type: str) -> str:
    """Return the smart default scan_schedule for a source type.

    Falls back to ``"daily"`` for any unknown type so a forgotten
    DEFAULT_SCHEDULE_BY_SOURCE_TYPE entry never lands a new source
    on the prior "on_demand" footgun.  Daily is the safest universal
    default — covers content within 24h without burning API quotas.
    """
    return DEFAULT_SCHEDULE_BY_SOURCE_TYPE.get(source_type, "daily")


# Source type definitions for the frontend
SOURCE_TYPE_SCHEMAS = {
    "slack": {
        "label": "Slack",
        "description": "Scan messages, files, and snippets across Slack channels",
        "icon": "slack",
        "config_fields": [
            {"key": "channels", "label": "Channels to scan", "type": "text", "required": False, "placeholder": "#engineering, #devops",
             "hint": "Comma-separated channel names. Leave blank or enter `*` to scan every channel the bot has been added to."},
            {"key": "include_private", "label": "Include private channels", "type": "boolean", "required": False,
             "hint": "Off by default. Requires the bot to be invited to each private channel — Vooda cannot enumerate them otherwise."},
            {"key": "include_files", "label": "Scan file attachments", "type": "boolean", "required": False,
             "hint": "On scans the text content of uploaded files (snippets, .env, config text). Adds bandwidth cost — leave off for noisy workspaces."},
        ],
    },
    "confluence": {
        "label": "Confluence",
        "description": "Scan pages, attachments, and comments in Confluence spaces",
        "icon": "confluence",
        "config_fields": [
            {"key": "spaces", "label": "Spaces to scan", "type": "text", "required": False, "placeholder": "ENG, DEVOPS",
             "hint": "Comma-separated space keys (the short uppercase identifier in the URL — `/spaces/ENG/`). Leave blank or enter `*` to scan every space the API token can read."},
            {"key": "include_attachments", "label": "Scan file attachments", "type": "boolean", "required": False,
             "hint": "Downloads and scans text-like attachments (.env, .json, .yaml, .log). Adds bandwidth cost; recommended for engineering spaces, optional elsewhere."},
        ],
    },
    "jira": {
        # Always-on surfaces (summary, description, comments, inline
        # link URLs) cover ~90% of real-world Jira secret findings at
        # negligible cost. The opt-in surfaces below cover the
        # remaining ~10% but cost meaningfully more — disabled by
        # default so they don't surprise customers on large tenants.
        # Matches GitGuardian's defaults; one tier safer than
        # TruffleHog Enterprise (which leaves custom-field scanning
        # on by default).
        "label": "Jira",
        "description": "Scan summaries, descriptions, comments, and inline link URLs across all projects. Custom fields and attachments are opt-in.",
        "icon": "jira",
        "config_fields": [
            {"key": "projects", "label": "Projects to scan", "type": "text", "required": False, "placeholder": "SEC, INFRA",
             "hint": "Comma-separated Jira project keys (the uppercase prefix on every issue, e.g. SEC-123). Leave blank or enter `*` to scan every project. On tenants with hundreds of projects, restrict here — full scans can be slow on first sync."},

            # ── Opt-in coverage extensions ──────────────────────────
            {"key": "scan_custom_fields", "label": "Scan custom text fields", "type": "boolean", "required": False, "default": False,
             "hint": (
                 "Off by default. When on, every text/textarea custom field on every issue is scanned "
                 "(Steps to Reproduce, Environment, Build Info, etc.). Catches an extra ~2% of secrets. "
                 "Cost: one extra GET /rest/api/3/field per scan to discover field IDs, plus a larger "
                 "search payload — typically adds 5-15% to scan time on tenants with 30+ custom fields."
             )},

            {"key": "include_attachments", "label": "Scan text-like attachments", "type": "boolean", "required": False, "default": False,
             "hint": (
                 "Off by default. When on, downloads .env, .json, .yaml, .log, .csv, .conf, .properties "
                 "and similar text attachments and scans their contents. Catches an extra ~8% of secrets. "
                 "Cost: bandwidth — each attachment under the size cap is downloaded once per scan. On a "
                 "50K-issue tenant where ~5% of issues have a text attachment, expect ~250 MB of egress "
                 "per full scan. Incremental scans (after the first) only fetch attachments on issues "
                 "updated since the last sync."
             )},
            {"key": "max_attachment_size_mb", "label": "Max attachment size (MB)", "type": "number", "required": False, "placeholder": "10",
             "hint": "Per-file cap. Anything larger is skipped. 10 MB covers env files / config snippets; raise only if you actually have larger text artifacts."},

            # ── Always-recommended toggles ──────────────────────────
            # Self-exclusion is the cross-vendor norm (GitGuardian,
            # Snyk, TruffleHog Enterprise). Default ON — flipping it
            # off is for niche debug scenarios only.
            {"key": "exclude_self_created", "label": "Exclude tickets Vooda created (recommended)", "type": "boolean", "required": False, "default": True,
             "hint": "Skip issues labeled `vooda-ai`. Prevents the feedback loop where every ticket Vooda files (with the masked secret in the body) shows up as a new finding next scan."},
        ],
    },
    "s3": {
        "label": "Amazon S3",
        "description": "Scan objects in S3 buckets for embedded secrets",
        "icon": "s3",
        "config_fields": [
            {"key": "bucket_name", "label": "S3 Bucket Name", "type": "text", "required": True,
             "hint": "Bucket name only — without `s3://` prefix or region suffix."},
            {"key": "prefix", "label": "Object Key Prefix", "type": "text", "required": False, "placeholder": "configs/",
             "hint": "Optional. Restrict the scan to objects whose key begins with this prefix (e.g. `configs/`). Leave blank to scan the entire bucket."},
            {"key": "file_extensions", "label": "File extensions to scan", "type": "text", "required": False, "placeholder": ".json, .yaml, .env, .conf",
             "hint": "Comma-separated extensions. Leave blank to use Vooda's default text-file detection."},
            {"key": "max_object_size_mb", "label": "Max object size (MB)", "type": "number", "required": False, "placeholder": "10",
             "hint": "Per-object cap. Larger objects are skipped to keep scan time and bandwidth predictable."},
        ],
    },
    "docker_image": {
        "label": "Docker Image",
        "description": "Scan Docker image layers, ENV vars, and embedded files",
        "icon": "docker",
        "config_fields": [
            {"key": "image", "label": "Image Reference", "type": "text", "required": True, "placeholder": "myregistry.io/app:latest",
             "hint": "Full image reference as `name:tag` or `name@sha256:digest`. Public Docker Hub images can omit the registry prefix."},
            {"key": "registry_url", "label": "Registry URL (private registries only)", "type": "url", "required": False,
             "hint": "Required only if the image lives in a private registry. Leave blank for Docker Hub or unauthenticated public registries."},
            {"key": "max_layer_size_mb", "label": "Max layer size (MB)", "type": "number", "required": False, "placeholder": "500",
             "hint": "Per-layer cap. Larger layers are skipped to keep scan time bounded."},
        ],
    },
    "postman": {
        "label": "Postman",
        "description": "Scan Postman collections and environments for hardcoded tokens",
        "icon": "postman",
        "config_fields": [
            {"key": "workspace_id", "label": "Workspace ID", "type": "text", "required": False,
             "hint": "Optional. Restrict the scan to a single Postman workspace by ID. Leave blank to scan every workspace the API key can access."},
        ],
    },
    "cicd_logs": {
        "label": "CI/CD Logs",
        "description": "Scan build logs from Jenkins, GitHub Actions, or CircleCI",
        "icon": "cicd",
        "config_fields": [
            {"key": "provider", "label": "CI/CD Provider", "type": "select", "required": True, "options": ["jenkins", "github_actions", "circleci"],
             "hint": "Which CI/CD provider's logs to scan. Determines the API shape and auth header format Vooda uses."},
            {"key": "project", "label": "Project or Repository", "type": "text", "required": False,
             "hint": "Optional. Restrict to a single project (Jenkins job name, GitHub repo `owner/name`, or CircleCI project slug). Leave blank to scan every project the token can read."},
            {"key": "max_builds", "label": "Max builds to scan per run", "type": "number", "required": False, "placeholder": "50",
             "hint": "Most-recent N builds per project. Lower for fast scans; raise to scan deeper history."},
        ],
    },

    "terraform_state": {
        "label": "Terraform State",
        "description": "Scan Terraform / OpenTofu state files — they store secrets as plaintext",
        "icon": "terraform",
        "config_fields": [
            {"key": "state_url", "label": "State URL", "type": "url", "required": True,
             "placeholder": "https://.../terraform.tfstate",
             "hint": "HTTPS URL that returns the raw state JSON — a Terraform HTTP backend address, a Terraform Cloud state-version download URL, or a presigned S3 / GCS / Azure Blob URL."},
            {"key": "auth_token", "label": "Auth token (optional)", "type": "password", "required": False,
             "hint": "Bearer token if the URL requires auth (e.g. a Terraform Cloud API token). Leave blank for presigned / unauthenticated URLs. Encrypted at rest."},
        ],
    },

    # ═══════════════════════════════════════════════════════════════
    #  Enterprise additions (2026-04-30) — closes the M365, Azure,
    #  and modern-DevSecOps gaps that block enterprise procurement.
    # ═══════════════════════════════════════════════════════════════

    "ms_teams": {
        "label": "Microsoft Teams",
        "description": "Scan Teams channel messages and replies for hardcoded secrets",
        "icon": "ms_teams",
        "config_fields": [
            {"key": "teams", "label": "Teams to scan", "type": "text", "required": False, "placeholder": "Engineering, Security",
             "hint": "Comma-separated team display names. Leave blank or enter `*` to scan every team the Microsoft Entra app has been granted access to."},
            {"key": "include_private", "label": "Include private channels", "type": "boolean", "required": False, "default": False,
             "hint": "Off by default. Private channels require an additional `Channel.ReadBasic.All` consent and exposure of these channels' contents to Vooda."},
            {"key": "include_attachment_urls", "label": "Scan attachment URLs", "type": "boolean", "required": False, "default": True,
             "hint": "Adds attachment URLs (not the file content) to the scanned text. Catches SAS tokens / signed URLs in shared-link parameters. Free."},
        ],
    },

    "onedrive_sharepoint": {
        "label": "OneDrive / SharePoint",
        "description": "Scan text-like files in SharePoint sites and document libraries",
        "icon": "onedrive",
        "config_fields": [
            {"key": "sites", "label": "SharePoint sites to scan", "type": "text", "required": False, "placeholder": "Engineering, Operations",
             "hint": "Comma-separated SharePoint site display names. Leave blank or enter `*` to walk every site the Microsoft Entra app can see — slow on tenants with hundreds of sites."},
            {"key": "max_file_size_mb", "label": "Max file size (MB)", "type": "number", "required": False, "placeholder": "10",
             "hint": "Per-file cap. Anything larger is skipped. 10 MB covers env files / config snippets / small CSVs."},
        ],
    },

    "azure_blob": {
        "label": "Azure Blob Storage",
        "description": "Scan text-like blobs in an Azure Storage account",
        "icon": "azure_blob",
        "config_fields": [
            {"key": "container_name", "label": "Container name", "type": "text", "required": False, "placeholder": "configs",
             "hint": "Single Azure Blob container to scan. Leave blank or enter `*` to walk every container in the storage account."},
            {"key": "prefix", "label": "Blob name prefix", "type": "text", "required": False, "placeholder": "configs/",
             "hint": "Optional. Restrict the scan to blobs whose name begins with this prefix. Leave blank to scan the entire container."},
            {"key": "max_blob_size_mb", "label": "Max blob size (MB)", "type": "number", "required": False, "placeholder": "10",
             "hint": "Per-blob cap. Larger blobs are skipped to keep scan time and bandwidth predictable."},
        ],
    },

    "notion": {
        "label": "Notion",
        "description": "Scan pages and code blocks in a Notion workspace",
        "icon": "notion",
        "config_fields": [
            # Notion's permission model is per-page sharing — there
            # are no workspace-level config fields beyond the token
            # itself. Empty config_fields list is intentional.
        ],
    },

    "github_issues": {
        "label": "GitHub Issues",
        "description": "Scan issue + pull request descriptions and comments",
        "icon": "github_issues",
        "config_fields": [
            {"key": "repos", "label": "Repositories to scan", "type": "text", "required": True, "placeholder": "acme/api, acme/web",
             "hint": "Comma-separated repositories in `owner/name` format. Issues and PRs live in GitHub's database (not the repo files), so the regular code scanner misses them — same secret-leak profile as Jira."},
            {"key": "include_pull_requests", "label": "Include pull request bodies + comments", "type": "boolean", "required": False, "default": True,
             "hint": "On by default. Pull requests are issues at the GitHub API level and carry the same risk profile."},
        ],
    },

    "servicenow": {
        "label": "ServiceNow",
        "description": "Scan incident, change request, and service request descriptions / comments",
        "icon": "servicenow",
        "config_fields": [
            {"key": "tables", "label": "ServiceNow tables to scan", "type": "text", "required": False, "placeholder": "incident,change_request,sc_request",
             "hint": "Comma-separated table names. Defaults to the three most common ITIL tables (incident, change_request, sc_request). Add more (e.g. `problem`, `kb_knowledge`) only if your org uses them heavily."},
        ],
    },

    "container_registry": {
        "label": "Container Registry",
        "description": "Enumerate and scan images across an OCI registry (ECR, GCR, Harbor, Quay, Docker Hub, GHCR)",
        "icon": "container_registry",
        "config_fields": [
            {"key": "registry_url", "label": "Registry URL", "type": "url", "required": True, "placeholder": "https://my-registry.example.com",
             "hint": "AWS ECR: https://{acct}.dkr.ecr.{region}.amazonaws.com. Google GCR: https://gcr.io. Docker Hub: https://registry-1.docker.io. Harbor / Quay / GHCR: your full registry hostname."},
            {"key": "repositories", "label": "Repositories to scan", "type": "text", "required": False, "placeholder": "myteam/app, myteam/worker",
             "hint": "Comma-separated repositories within the registry. Leave blank or enter `*` to enumerate every repository the credentials can list."},
            {"key": "max_tags_per_repo", "label": "Max tags per repository", "type": "number", "required": False, "placeholder": "5",
             "hint": "Most-recent N tags per repository. Lower for fast scans; raise to walk deeper history."},
        ],
    },

    # ═══════════════════════════════════════════════════════════════
    #  Top-7-categories expansion (2026-05-01)
    #  Adds CRM & Customer Support (Salesforce) + breadth across
    #  Issue Tracking / Collaboration / Cloud Storage so all 7
    #  enterprise source categories are represented.
    # ═══════════════════════════════════════════════════════════════

    "salesforce": {
        "label": "Salesforce",
        "description": "Scan Cases, Knowledge articles, and Chatter posts for hardcoded secrets",
        "icon": "salesforce",
        "config_fields": [
            {"key": "scan_cases", "label": "Scan Cases (subject + description + comments)", "type": "boolean", "required": False, "default": True,
             "hint": "Customer-support tickets routinely have credentials pasted into descriptions and internal comments."},
            {"key": "scan_knowledge", "label": "Scan Knowledge articles", "type": "boolean", "required": False, "default": True,
             "hint": "Internal Knowledge articles often hold runbook-style instructions with embedded credentials."},
            {"key": "scan_chatter", "label": "Scan Chatter posts (FeedItem)", "type": "boolean", "required": False, "default": True,
             "hint": "Org-internal Chatter posts; treat like a Slack channel for secret-leak risk."},
        ],
    },

    "azure_devops": {
        "label": "Azure DevOps Boards",
        "description": "Scan Azure DevOps work item titles, descriptions, and comments",
        "icon": "azure_devops",
        "config_fields": [],
    },

    "linear": {
        "label": "Linear",
        "description": "Scan Linear issue descriptions and comments",
        "icon": "linear",
        "config_fields": [
            {"key": "teams", "label": "Teams to scan", "type": "text", "required": False, "placeholder": "ENG, SEC",
             "hint": "Comma-separated Linear team keys (the short uppercase identifier in issue IDs — e.g. `ENG-123`). Leave blank or enter `*` to scan every team the API key can access."},
        ],
    },

    "asana": {
        "label": "Asana",
        "description": "Scan Asana task notes and comments across workspaces and projects",
        "icon": "asana",
        "config_fields": [
            {"key": "workspaces", "label": "Workspaces to scan", "type": "text", "required": False,
             "hint": "Comma-separated Asana workspace names. Leave blank or enter `*` to scan every workspace the personal access token can read."},
        ],
    },

    "bitbucket_issues": {
        "label": "Bitbucket Issues / PRs",
        "description": "Scan Bitbucket Cloud issue + pull request descriptions and comments",
        "icon": "bitbucket",
        "config_fields": [
            {"key": "repos", "label": "Repositories to scan", "type": "text", "required": True, "placeholder": "acme/api, acme/web",
             "hint": "Comma-separated repositories in `workspace/repo` format. Bitbucket *code* is scanned via the Repositories page — this adapter covers the discussion surface (issues + PRs) that lives in Bitbucket's database."},
            {"key": "include_pull_requests", "label": "Include pull request descriptions + comments", "type": "boolean", "required": False, "default": True,
             "hint": "On by default. PR descriptions and inline comments carry the same secret-leak risk profile as issues."},
        ],
    },

    "mattermost": {
        "label": "Mattermost",
        "description": "Scan Mattermost channel messages (open-source Slack alternative)",
        "icon": "mattermost",
        "config_fields": [
            {"key": "teams", "label": "Teams to scan", "type": "text", "required": False, "placeholder": "engineering, security",
             "hint": "Comma-separated Mattermost team names (the lowercase URL slug, not display name). Leave blank or enter `*` to scan every team the personal access token can read."},
        ],
    },

    "box": {
        "label": "Box",
        "description": "Scan text-like files in a Box account (env files, config snippets, runbooks)",
        "icon": "box",
        "config_fields": [
            {"key": "root_folder_id", "label": "Starting Folder ID", "type": "text", "required": False, "placeholder": "0",
             "hint": "Folder ID to walk from. Use `0` for the account's root folder, or paste a specific folder ID from its URL (app.box.com/folder/{ID}) to restrict the scan."},
            {"key": "max_file_size_mb", "label": "Max file size (MB)", "type": "number", "required": False, "placeholder": "10",
             "hint": "Per-file cap. Larger files are skipped to keep scan time and bandwidth predictable."},
        ],
    },

    # ═══════════════════════════════════════════════════════════════
    #  2026-05-14 additions
    # ═══════════════════════════════════════════════════════════════

    "sharepoint_pages": {
        # Docs & Wikis #3 alongside Confluence + Notion.  Reuses the
        # same Microsoft Entra app registration as ms_teams +
        # onedrive_sharepoint — customers who've onboarded either of
        # those already have the Sites.Read.All permission granted.
        "label": "SharePoint Pages",
        "description": "Scan SharePoint Pages (wiki content) and List items for hardcoded secrets",
        "icon": "onedrive",
        "config_fields": [
            {"key": "sites", "label": "Sites to scan", "type": "text", "required": False, "placeholder": "Engineering, Operations",
             "hint": "Comma-separated SharePoint site display names. Leave blank or enter `*` to walk every site the Microsoft Entra app can see. On large tenants, list a few sites first — full scans can be slow."},
            {"key": "include_lists", "label": "Include SharePoint Lists", "type": "boolean", "required": False, "default": True,
             "hint": "On scans the text fields of SharePoint List items (FAQ lists, runbook lists, directory lists). Off scans only Pages content. Lists often hold runbook-style entries with embedded credentials."},
        ],
    },

    "gcs": {
        # Cloud Storage #3 — completes the hyperscaler trio (S3 +
        # Azure Blob + GCS).  Auth: S3-compatible HMAC keys generated
        # at console.cloud.google.com/storage/settings → Interoperability.
        # No service-account JSON, no OAuth complexity — same two-field
        # auth shape as AWS S3, just pointed at storage.googleapis.com.
        "label": "Google Cloud Storage",
        "description": "Scan objects in GCS buckets for embedded secrets (backups, deployment artifacts, ML datasets, Terraform state)",
        "icon": "gcs",
        "config_fields": [
            {"key": "bucket_name", "label": "Bucket Name", "type": "text", "required": True, "placeholder": "my-company-data",
             "hint": "GCS bucket to scan. Just the name — no `gs://` prefix or region suffix."},
            {"key": "prefix", "label": "Object Name Prefix", "type": "text", "required": False, "placeholder": "configs/",
             "hint": "Optional. Restrict scanning to objects whose name begins with this prefix (e.g. `configs/`, `backups/`). Leave blank to scan the entire bucket."},
            {"key": "file_extensions", "label": "File extensions to scan", "type": "text", "required": False, "placeholder": ".json, .yaml, .env, .conf",
             "hint": "Comma-separated extensions. Leave blank to use Vooda's default text-file detection."},
            {"key": "max_object_size_mb", "label": "Max object size (MB)", "type": "number", "required": False, "placeholder": "10",
             "hint": "Per-object cap. Larger objects are skipped to keep scan time and bandwidth predictable."},
        ],
    },
}
