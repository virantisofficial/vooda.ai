# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Factory for creating source scanner adapters."""

from services.source_scanners.base import SourceAdapter


def create_source_adapter(source_type: str, config: dict, credentials: dict) -> SourceAdapter:
    """Create the appropriate SourceAdapter for a given source type.

    Args:
        source_type: a key of the ``adapters`` map below (community
            edition: jira, servicenow, azure_devops, s3, gcs, azure_blob,
            onedrive_sharepoint, box, docker_image, cicd_logs,
            container_registry, terraform_state, postman, salesforce)
        config: Source-specific config (channels, bucket name, etc.) from ScanSource.config
        credentials: Provider credentials from IntegrationConfig.config

    Returns:
        An initialized SourceAdapter instance.
    """
    adapters = {
        # ── Issue Tracking ───────────────────────────────────────
        "jira": _create_jira,
        "servicenow": _create_servicenow,
        "azure_devops": _create_azure_devops,
        # ── Cloud Storage ────────────────────────────────────────
        "s3": _create_s3,
        "gcs": _create_gcs,
        "azure_blob": _create_azure_blob,
        # ── DevOps ───────────────────────────────────────────────
        "docker_image": _create_docker_image,
        "cicd_logs": _create_cicd_logs,
        "container_registry": _create_container_registry,
        "terraform_state": _create_terraform_state,
        # ── APIs / SaaS ──────────────────────────────────────────
        "postman": _create_postman,
        "salesforce": _create_salesforce,
        # ── Enterprise-only sources (NOT in the community edition) ──
        # Collaboration (slack, ms_teams, mattermost), Docs & Wikis
        # (confluence, notion, sharepoint_pages), the demoted Issue
        # Tracking sources (github_issues, linear, asana, bitbucket_issues),
        # and the demoted Cloud Storage sources (box, onedrive_sharepoint)
        # are intentionally not wired here. Their adapter code remains
        # in-tree but is unreachable in the community edition.
    }

    factory_fn = adapters.get(source_type)
    if not factory_fn:
        raise ValueError(f"Unknown source type: {source_type}. Supported: {list(adapters.keys())}")

    return factory_fn(config, credentials)


def _create_slack(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.slack import SlackSourceAdapter
    return SlackSourceAdapter(
        bot_token=credentials.get("bot_token") or credentials.get("api_token", ""),
        channels=config.get("channels", "*"),
        include_private=config.get("include_private", False),
        include_files=config.get("include_files", True),
    )


def _create_confluence(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.confluence import ConfluenceSourceAdapter
    return ConfluenceSourceAdapter(
        base_url=credentials.get("site_url", ""),
        email=credentials.get("email", ""),
        api_token=credentials.get("api_token", ""),
        spaces=config.get("spaces", "*"),
        include_attachments=config.get("include_attachments", True),
    )


def _create_jira(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.jira import JiraSourceAdapter

    # Defaults match the schema in apps/api/app/schemas/scan_source.py
    # and the documented behaviour in the connect form. Off-by-default
    # for the opt-in coverage extensions (custom fields, attachments)
    # so the system isn't loaded with high-cost / low-yield work
    # without explicit user consent.
    common_kwargs = dict(
        projects=config.get("projects", "*"),
        scan_custom_fields=bool(config.get("scan_custom_fields", False)),
        include_attachments=bool(config.get("include_attachments", False)),
        exclude_self_created=bool(config.get("exclude_self_created", True)),
        max_attachment_size_mb=int(config.get("max_attachment_size_mb", 10) or 10),
    )

    # Auth-mode dispatch — OAuth credentials live alongside the API
    # token credentials on the same IntegrationConfig.config dict.
    # `auth_type=oauth2` switches the adapter to bearer + cloud_id.
    # The `_token_provider` is wired in by the worker just before
    # building the adapter (it needs DB access to refresh).
    auth_type = (credentials.get("auth_type") or "basic").lower()
    if auth_type == "oauth2":
        return JiraSourceAdapter(
            base_url=credentials.get("site_url", ""),
            auth_mode="oauth2",
            cloud_id=credentials.get("cloud_id", ""),
            token_provider=credentials.get("_token_provider"),
            **common_kwargs,
        )
    return JiraSourceAdapter(
        base_url=credentials.get("site_url", ""),
        email=credentials.get("email", ""),
        api_token=credentials.get("api_token", ""),
        **common_kwargs,
    )


def _create_s3(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.s3 import S3SourceAdapter
    return S3SourceAdapter(
        access_key_id=credentials.get("access_key_id", ""),
        secret_access_key=credentials.get("secret_access_key", ""),
        region=credentials.get("region", "us-east-1"),
        bucket_name=config.get("bucket_name", ""),
        prefix=config.get("prefix", ""),
        file_extensions=config.get("file_extensions", ""),
        max_object_size_mb=int(config.get("max_object_size_mb", 10)),
    )


def _create_docker_image(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.docker_image import DockerImageSourceAdapter
    return DockerImageSourceAdapter(
        image=config.get("image", ""),
        registry_url=config.get("registry_url", ""),
        username=credentials.get("username", ""),
        password=credentials.get("password", ""),
        max_layer_size_mb=int(config.get("max_layer_size_mb", 500)),
    )


def _create_postman(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.postman import PostmanSourceAdapter
    return PostmanSourceAdapter(
        api_key=credentials.get("api_key", ""),
        workspace_id=config.get("workspace_id", ""),
    )


def _create_cicd_logs(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.cicd_logs import CICDLogsSourceAdapter
    return CICDLogsSourceAdapter(
        provider=config.get("provider", "github_actions"),
        base_url=credentials.get("base_url", credentials.get("site_url", "")),
        token=credentials.get("api_token", credentials.get("token", "")),
        project=config.get("project", ""),
        max_builds=int(config.get("max_builds", 50)),
    )


def _create_terraform_state(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.terraform_state import TerraformStateAdapter
    return TerraformStateAdapter(
        state_url=credentials.get("state_url", "") or config.get("state_url", ""),
        auth_token=credentials.get("auth_token", ""),
        max_bytes=int(config.get("max_bytes", 8_000_000)),
    )


# ═══════════════════════════════════════════════════════════════════
#  Enterprise additions — 2026-04-30
#  All seven below were greenlit as the M365 + DevSecOps coverage gaps
#  vs peers. Microsoft Graph adapters share the helper in _msgraph.py;
#  Azure Blob signs requests directly against the storage REST API.
# ═══════════════════════════════════════════════════════════════════


def _create_ms_teams(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.teams import MicrosoftTeamsAdapter
    return MicrosoftTeamsAdapter(
        tenant_id=credentials.get("tenant_id", ""),
        client_id=credentials.get("client_id", ""),
        client_secret=credentials.get("client_secret", ""),
        teams=config.get("teams", "*"),
        include_private=bool(config.get("include_private", False)),
        include_attachment_urls=bool(config.get("include_attachment_urls", True)),
    )


def _create_onedrive_sharepoint(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.onedrive_sharepoint import (
        OneDriveSharePointAdapter,
    )
    return OneDriveSharePointAdapter(
        tenant_id=credentials.get("tenant_id", ""),
        client_id=credentials.get("client_id", ""),
        client_secret=credentials.get("client_secret", ""),
        site_filter=config.get("sites", "*"),
        max_file_size_mb=int(config.get("max_file_size_mb", 10) or 10),
    )


def _create_azure_blob(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.azure_blob import AzureBlobAdapter
    return AzureBlobAdapter(
        account_name=credentials.get("account_name", ""),
        account_key=credentials.get("account_key", ""),
        container_name=config.get("container_name", "*"),
        prefix=config.get("prefix", ""),
        max_blob_size_mb=int(config.get("max_blob_size_mb", 10) or 10),
    )


def _create_notion(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.notion import NotionAdapter
    return NotionAdapter(
        token=credentials.get("token", credentials.get("api_token", "")),
    )


def _create_github_issues(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.github_issues import GitHubIssuesAdapter
    return GitHubIssuesAdapter(
        token=credentials.get("token", credentials.get("github_token", "")),
        repos=config.get("repos", ""),
        api_base=credentials.get("api_base", "https://api.github.com"),
        include_pull_requests=bool(config.get("include_pull_requests", True)),
    )


def _create_servicenow(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.servicenow import ServiceNowAdapter
    return ServiceNowAdapter(
        instance_url=credentials.get("instance_url", credentials.get("site_url", "")),
        username=credentials.get("username", ""),
        password=credentials.get("password", ""),
        tables=config.get("tables", "incident,change_request,sc_request"),
    )


def _create_container_registry(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.container_registry import (
        ContainerRegistryAdapter,
    )
    return ContainerRegistryAdapter(
        registry_url=credentials.get("registry_url", config.get("registry_url", "")),
        username=credentials.get("username", ""),
        password=credentials.get("password", ""),
        repositories=config.get("repositories", "*"),
        max_tags_per_repo=int(config.get("max_tags_per_repo", 5) or 5),
    )


# ═══════════════════════════════════════════════════════════════════
#  2026-05 Top-7-categories expansion
# ═══════════════════════════════════════════════════════════════════


def _create_salesforce(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.salesforce import SalesforceAdapter
    return SalesforceAdapter(
        login_url=credentials.get("login_url", "https://login.salesforce.com"),
        client_id=credentials.get("client_id", ""),
        client_secret=credentials.get("client_secret", ""),
        username=credentials.get("username", ""),
        password=credentials.get("password", ""),
        scan_cases=bool(config.get("scan_cases", True)),
        scan_knowledge=bool(config.get("scan_knowledge", True)),
        scan_chatter=bool(config.get("scan_chatter", True)),
    )


def _create_azure_devops(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.azure_devops import AzureDevOpsBoardsAdapter
    return AzureDevOpsBoardsAdapter(
        organization=credentials.get("organization", ""),
        project=credentials.get("project", ""),
        pat=credentials.get("pat", credentials.get("token", "")),
    )


def _create_linear(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.linear import LinearAdapter
    return LinearAdapter(
        api_key=credentials.get("api_key", credentials.get("token", "")),
        teams=config.get("teams", "*"),
    )


def _create_asana(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.asana import AsanaAdapter
    return AsanaAdapter(
        token=credentials.get("token", credentials.get("pat", "")),
        workspaces=config.get("workspaces", "*"),
    )


def _create_bitbucket_issues(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.bitbucket_issues import BitbucketIssuesAdapter
    return BitbucketIssuesAdapter(
        username=credentials.get("username", ""),
        app_password=credentials.get("app_password", credentials.get("password", "")),
        repos=config.get("repos", ""),
        api_base=credentials.get("api_base", "https://api.bitbucket.org/2.0"),
        include_pull_requests=bool(config.get("include_pull_requests", True)),
    )


def _create_mattermost(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.mattermost import MattermostAdapter
    return MattermostAdapter(
        site_url=credentials.get("site_url", ""),
        token=credentials.get("token", ""),
        teams=config.get("teams", "*"),
    )


def _create_box(config: dict, credentials: dict) -> SourceAdapter:
    from services.source_scanners.adapters.box import BoxAdapter
    return BoxAdapter(
        access_token=credentials.get("access_token", credentials.get("token", "")),
        root_folder_id=config.get("root_folder_id", "0"),
        max_file_size_mb=int(config.get("max_file_size_mb", 10) or 10),
    )


def _create_sharepoint_pages(config: dict, credentials: dict) -> SourceAdapter:
    """SharePoint Pages adapter.  Reuses the M365 Microsoft Entra
    credentials that Teams + OneDrive/SharePoint already use — same
    app registration, same Sites.Read.All permission.
    """
    from services.source_scanners.adapters.sharepoint_pages import SharePointPagesAdapter
    return SharePointPagesAdapter(
        tenant_id=credentials.get("tenant_id", ""),
        client_id=credentials.get("client_id", ""),
        client_secret=credentials.get("client_secret", ""),
        site_filter=config.get("sites", "*"),
        include_lists=bool(config.get("include_lists", True)),
    )


def _create_gcs(config: dict, credentials: dict) -> SourceAdapter:
    """Google Cloud Storage adapter.  Auth: S3-compatible HMAC keys
    (two strings — access_key_id + secret_access_key — generated at
    console.cloud.google.com/storage/settings → Interoperability).
    Same boto3 client shape as the S3 adapter, just pointed at the
    GCS S3-compatible endpoint.
    """
    from services.source_scanners.adapters.gcs import GCSSourceAdapter
    return GCSSourceAdapter(
        access_key_id=credentials.get("access_key_id", ""),
        secret_access_key=credentials.get("secret_access_key", ""),
        bucket_name=config.get("bucket_name", ""),
        prefix=config.get("prefix", ""),
        file_extensions=config.get("file_extensions", ""),
        max_object_size_mb=int(config.get("max_object_size_mb", 10) or 10),
    )
