# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Git provider factory — creates the appropriate provider based on repository URL.
Reuses the URL detection logic from the repositories router.
"""

import re
import structlog
from typing import Optional

from services.git_integration.base import GitProvider
from services.git_integration.github import GitHubProvider
from services.git_integration.gitlab import GitLabProvider
from services.git_integration.bitbucket import BitbucketProvider

logger = structlog.get_logger()


def detect_provider(url: str) -> str:
    """Detect git hosting provider from URL."""
    url_lower = url.lower()
    if "github.com" in url_lower:
        return "github"
    elif "gitlab" in url_lower:
        return "gitlab"
    elif "bitbucket" in url_lower:
        return "bitbucket"
    return "unknown"


def create_git_provider(
    repo_url: str,
    credentials: dict,
) -> Optional[GitProvider]:
    """
    Create a GitProvider instance for the given repository URL.

    Args:
        repo_url: Repository URL (e.g., https://github.com/owner/repo)
        credentials: Dict with provider-specific credentials:
            GitHub: {"token": "ghp_..."}
            GitLab: {"token": "glpat-...", "host": "https://gitlab.com"}
            Bitbucket: {"username": "...", "app_password": "..."}

    Returns:
        GitProvider instance or None if provider not supported
    """
    provider = detect_provider(repo_url)
    url = repo_url.strip().rstrip("/").removesuffix(".git")

    try:
        if provider == "github":
            m = re.search(r"github\.com[:/]([^/]+)/([^/]+)", url)
            if not m:
                logger.error("cannot_parse_github_url", url=url)
                return None
            owner, repo = m.group(1), m.group(2)
            token = credentials.get("token", "")
            if not token:
                logger.error("github_token_missing")
                return None
            return GitHubProvider(owner=owner, repo=repo, token=token)

        elif provider == "gitlab":
            m = re.search(r"gitlab[^/]*[:/](.+)", url)
            if not m:
                logger.error("cannot_parse_gitlab_url", url=url)
                return None
            project_path = m.group(1)
            host_match = re.match(r"(https?://[^/]+)", url)
            host = host_match.group(1) if host_match else "https://gitlab.com"
            token = credentials.get("token", "")
            return GitLabProvider(host=host, project_path=project_path, token=token)

        elif provider == "bitbucket":
            m = re.search(r"bitbucket\.org[:/]([^/]+)/([^/]+)", url)
            if not m:
                logger.error("cannot_parse_bitbucket_url", url=url)
                return None
            workspace, repo_slug = m.group(1), m.group(2)
            return BitbucketProvider(
                workspace=workspace,
                repo_slug=repo_slug,
                username=credentials.get("username", ""),
                app_password=credentials.get("app_password", credentials.get("password", "")),
            )

        else:
            logger.warning("unsupported_git_provider", provider=provider, url=url[:50])
            return None

    except Exception as e:
        logger.error("git_provider_creation_failed", error=str(e)[:200])
        return None
