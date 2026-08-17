# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Webhook Receiver — receives push/PR events from GitHub, GitLab, Bitbucket.

Verifies HMAC signatures, parses events, and dispatches Celery scan tasks
for real-time secret detection on pushed code.
"""

import hashlib
import hmac
import structlog
from dataclasses import dataclass
from typing import Optional

logger = structlog.get_logger()


@dataclass
class WebhookEvent:
    provider: str           # github, gitlab, bitbucket
    event_type: str         # push, pull_request, merge_request
    repo_url: str
    repo_name: str
    branch: str
    base_sha: Optional[str] = None
    head_sha: Optional[str] = None
    author: Optional[str] = None
    pr_number: Optional[int] = None
    pr_title: Optional[str] = None


def verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not signature or not secret:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_gitlab_token(token: str, secret: str) -> bool:
    if not token or not secret:
        return False
    return hmac.compare_digest(token, secret)


def verify_bitbucket_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not signature or not secret:
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_github_event(headers: dict, body: dict) -> Optional[WebhookEvent]:
    event_type = headers.get("x-github-event", "")

    if event_type == "push":
        ref = body.get("ref", "")
        branch = ref.replace("refs/heads/", "")
        repo = body.get("repository", {})
        commits = body.get("commits", [])
        before = body.get("before", "0" * 40)
        after = body.get("after", "")

        return WebhookEvent(
            provider="github",
            event_type="push",
            repo_url=repo.get("clone_url", ""),
            repo_name=repo.get("full_name", ""),
            branch=branch,
            base_sha=before,
            head_sha=after,
            author=body.get("pusher", {}).get("name"),
        )

    elif event_type == "pull_request":
        action = body.get("action", "")
        if action not in ("opened", "synchronize", "reopened"):
            return None

        pr = body.get("pull_request", {})
        repo = body.get("repository", {})

        return WebhookEvent(
            provider="github",
            event_type="pull_request",
            repo_url=repo.get("clone_url", ""),
            repo_name=repo.get("full_name", ""),
            branch=pr.get("head", {}).get("ref", ""),
            base_sha=pr.get("base", {}).get("sha"),
            head_sha=pr.get("head", {}).get("sha"),
            author=pr.get("user", {}).get("login"),
            pr_number=pr.get("number"),
            pr_title=pr.get("title"),
        )

    return None


def parse_gitlab_event(headers: dict, body: dict) -> Optional[WebhookEvent]:
    event_type = body.get("object_kind", "")

    if event_type == "push":
        project = body.get("project", {})
        ref = body.get("ref", "")
        branch = ref.replace("refs/heads/", "")

        return WebhookEvent(
            provider="gitlab",
            event_type="push",
            repo_url=project.get("git_http_url", ""),
            repo_name=project.get("path_with_namespace", ""),
            branch=branch,
            base_sha=body.get("before"),
            head_sha=body.get("after"),
            author=body.get("user_name"),
        )

    elif event_type == "merge_request":
        action = body.get("object_attributes", {}).get("action", "")
        if action not in ("open", "update", "reopen"):
            return None

        attrs = body.get("object_attributes", {})
        project = body.get("project", {})

        return WebhookEvent(
            provider="gitlab",
            event_type="merge_request",
            repo_url=project.get("git_http_url", ""),
            repo_name=project.get("path_with_namespace", ""),
            branch=attrs.get("source_branch", ""),
            base_sha=attrs.get("diff_refs", {}).get("base_sha"),
            head_sha=attrs.get("diff_refs", {}).get("head_sha"),
            author=body.get("user", {}).get("username"),
            pr_number=attrs.get("iid"),
            pr_title=attrs.get("title"),
        )

    return None


def parse_bitbucket_event(headers: dict, body: dict) -> Optional[WebhookEvent]:
    event_type = headers.get("x-event-key", "")

    if event_type == "repo:push":
        repo = body.get("repository", {})
        changes = body.get("push", {}).get("changes", [])
        if not changes:
            return None

        change = changes[0]
        new = change.get("new", {})
        old = change.get("old", {})

        clone_links = repo.get("links", {}).get("html", {}).get("href", "")

        return WebhookEvent(
            provider="bitbucket",
            event_type="push",
            repo_url=clone_links,
            repo_name=repo.get("full_name", ""),
            branch=new.get("name", ""),
            base_sha=old.get("target", {}).get("hash"),
            head_sha=new.get("target", {}).get("hash"),
            author=body.get("actor", {}).get("display_name"),
        )

    elif event_type in ("pullrequest:created", "pullrequest:updated"):
        pr = body.get("pullrequest", {})
        repo = body.get("repository", {})

        return WebhookEvent(
            provider="bitbucket",
            event_type="pull_request",
            repo_url=repo.get("links", {}).get("html", {}).get("href", ""),
            repo_name=repo.get("full_name", ""),
            branch=pr.get("source", {}).get("branch", {}).get("name", ""),
            base_sha=pr.get("destination", {}).get("commit", {}).get("hash"),
            head_sha=pr.get("source", {}).get("commit", {}).get("hash"),
            author=pr.get("author", {}).get("display_name"),
            pr_number=pr.get("id"),
            pr_title=pr.get("title"),
        )

    return None


PARSERS = {
    "github": parse_github_event,
    "gitlab": parse_gitlab_event,
    "bitbucket": parse_bitbucket_event,
}

VERIFIERS = {
    "github": lambda payload, headers, secret: verify_github_signature(payload, headers.get("x-hub-signature-256", ""), secret),
    "gitlab": lambda payload, headers, secret: verify_gitlab_token(headers.get("x-gitlab-token", ""), secret),
    "bitbucket": lambda payload, headers, secret: verify_bitbucket_signature(payload, headers.get("x-hub-signature", ""), secret),
}
