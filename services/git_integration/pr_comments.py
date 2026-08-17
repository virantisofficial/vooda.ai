# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
PR Comment Service — posts scan results back to pull requests.

Supports GitHub, GitLab, and Bitbucket. Uses httpx for async HTTP calls.
Called after webhook scans to give developers immediate feedback on secrets.
"""

import structlog
from typing import Optional
from dataclasses import dataclass

logger = structlog.get_logger()


@dataclass
class PRCommentResult:
    success: bool
    comment_url: Optional[str] = None
    error: Optional[str] = None


# ── Rotation suggestion catalogue ────────────────────────────────────
# Per-secret-type rotation commands surfaced inline in the PR comment.
# This is what turns the PR-comment integration from "here's a list of
# findings" into "here's the list AND the exact command to rotate each
# one" — the Vooda differentiator over plain detection-only comments.
#
# Keys match the `secret_type` field on raw_data (set by the secret
# scanner) OR the branded rule_id (e.g. "AWS-001").  Lookup tries
# secret_type first, then rule_id, then a coarse prefix match on
# rule_id so we cover detector packs we haven't enumerated.
#
# The hints are intentionally short — admins want the COMMAND, not a
# paragraph of context.  Cloud-provider hints assume the standard CLI
# is installed and configured for the right account.  When the
# provider's rotation is fully manual (console-only), the hint points
# at the dashboard URL instead.
_ROTATION_HINTS: dict[str, str] = {
    # AWS
    "aws_access_key": "aws iam create-access-key --user-name <USER> && aws iam delete-access-key --access-key-id <OLD_KEY_ID>",
    "aws_secret_key": "Rotate the parent access key (above) — the secret is one half of the access-key pair.",
    "aws_session_token": "Session tokens auto-expire.  Re-issue via `aws sts get-session-token`.",
    # GCP
    "gcp_service_account_key": "gcloud iam service-accounts keys create new-key.json --iam-account=<SA_EMAIL> && gcloud iam service-accounts keys delete <OLD_KEY_ID> --iam-account=<SA_EMAIL>",
    "gcp_api_key": "Console: APIs & Services → Credentials → regenerate the API key (rotation API not available via gcloud).",
    # Azure
    "azure_storage_key": "az storage account keys renew --account-name <ACCT> --key key1",
    "azure_devops_pat": "Console: dev.azure.com → User settings → Personal access tokens → Revoke + recreate.",
    # GitHub
    "github_pat": "Revoke + recreate at https://github.com/settings/tokens",
    "github_app_token": "Rotate the GitHub App's private key in Settings → Developer settings → GitHub Apps.",
    # Stripe / payment
    "stripe_secret_key": "Console: dashboard.stripe.com/apikeys → Roll secret key (immediately invalidates the leaked one).",
    "stripe_restricted_key": "Console: dashboard.stripe.com/apikeys → Roll the restricted key.",
    # Communication / collaboration
    "slack_bot_token": "Slack admin: api.slack.com/apps → your app → OAuth & Permissions → Reinstall to workspace (regenerates token).",
    "slack_webhook": "Disable the leaked webhook URL and create a new one from the Slack app's Incoming Webhooks page.",
    "twilio_auth_token": "Console: console.twilio.com → Account → API keys & tokens → Rotate auth token.",
    "sendgrid_api_key": "Console: app.sendgrid.com/settings/api_keys → Delete + create.",
    # Generic / catch-all hints
    "private_key": "Generate a new keypair, redeploy public key wherever the old one was authorized, then delete the old private key.",
    "jwt_secret": "Roll the JWT signing secret; all existing tokens will be invalidated on next verification.",
    "database_url": "Rotate the database password in the issuing system and update the connection string in your secret manager.",
    "generic_api_key": "Rotate the API key in the issuing provider's dashboard.",
}


def _rotation_hint_for(finding: dict) -> Optional[str]:
    """Return a rotation-command suggestion for a finding, or None.

    Lookup order: explicit secret_type → exact rule_id → coarse rule_id
    prefix.  Falls back to None for unknown detectors so the comment
    doesn't surface a misleading generic hint when we have no real
    rotation path to suggest.
    """
    st = (finding.get("secret_type") or "").lower()
    if st in _ROTATION_HINTS:
        return _ROTATION_HINTS[st]

    rid = (finding.get("rule_id") or "").upper()
    if not rid:
        return None
    # Direct rule_id match (rare — most rule_ids don't have a hint).
    if rid in _ROTATION_HINTS:
        return _ROTATION_HINTS[rid]
    # Prefix routing — covers detector families we haven't enumerated.
    # Order matters: more specific prefixes first.
    if rid.startswith("AWS-"):
        return _ROTATION_HINTS["aws_access_key"]
    if rid.startswith("GCP-"):
        return _ROTATION_HINTS["gcp_service_account_key"]
    if rid.startswith("AZ-") or rid.startswith("AZURE-"):
        return _ROTATION_HINTS["azure_storage_key"]
    if rid.startswith("GH-") or rid.startswith("GITHUB-"):
        return _ROTATION_HINTS["github_pat"]
    if rid.startswith("STRIPE-"):
        return _ROTATION_HINTS["stripe_secret_key"]
    if rid.startswith("SLACK-"):
        return _ROTATION_HINTS["slack_bot_token"]
    if rid.startswith("DB-") or "DATABASE" in rid:
        return _ROTATION_HINTS["database_url"]
    if "JWT" in rid:
        return _ROTATION_HINTS["jwt_secret"]
    if "PRIVATE-KEY" in rid or "RSA" in rid:
        return _ROTATION_HINTS["private_key"]
    return None


def _format_findings_comment(
    findings: list[dict],
    repo_name: str,
    pr_number: int,
    scan_job_id: str,
    base_sha: str = "",
    head_sha: str = "",
) -> str:
    """Format scan findings into a markdown PR comment."""
    if not findings:
        return (
            "## Vooda Secret Scanner\n\n"
            "No secrets detected in this pull request.\n\n"
            "---\n"
            "*Scanned by [Vooda AI](https://vooda.ai)*"
        )

    # Group by severity
    critical = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    medium = [f for f in findings if f.get("severity") == "medium"]
    low = [f for f in findings if f.get("severity") in ("low", "info")]

    total = len(findings)
    severity_summary = []
    if critical:
        severity_summary.append(f"**{len(critical)} critical**")
    if high:
        severity_summary.append(f"**{len(high)} high**")
    if medium:
        severity_summary.append(f"{len(medium)} medium")
    if low:
        severity_summary.append(f"{len(low)} low")

    header_emoji = "&#x1F6A8;" if critical else "&#x26A0;&#xFE0F;"
    lines = [
        f"## {header_emoji} Vooda Secret Scanner — {total} secret{'s' if total != 1 else ''} found\n",
        f"Found {', '.join(severity_summary)} in this pull request.\n",
        "| Severity | Secret | File | Line |",
        "|:--------:|--------|------|:----:|",
    ]

    for f in findings[:20]:  # Limit to 20 rows
        sev = f.get("severity", "?").upper()
        sev_emoji = {"CRITICAL": "&#x1F534;", "HIGH": "&#x1F7E0;", "MEDIUM": "&#x1F7E1;", "LOW": "&#x1F535;"}.get(sev, "&#x26AA;")
        title = f.get("title", "Secret")[:50]
        file_path = f.get("file_path", "?")
        line = f.get("line_start", "?")
        masked = f.get("masked_value", "****")
        lines.append(f"| {sev_emoji} {sev} | {title} `{masked}` | `{file_path}` | {line} |")

    if len(findings) > 20:
        lines.append(f"\n*... and {len(findings) - 20} more findings*")

    # ── Rotation suggestions ────────────────────────────────────────
    # Per-secret-type rotation commands.  This is what turns the
    # comment from "you have secrets" into "here's exactly how to
    # rotate each one" — the Vooda differentiator over plain
    # detection-only PR comments.
    #
    # Dedupe by suggestion text: if the PR has 5 AWS keys, we only
    # surface the AWS rotation hint once.
    seen_hints: dict[str, list[str]] = {}
    for f in findings:
        hint = _rotation_hint_for(f)
        if not hint:
            continue
        # Track the human label so the bullet says e.g.
        # "AWS Access Key (3 found): ..."
        label = (f.get("secret_type") or "").replace("_", " ").title() or (f.get("title") or "Secret")
        seen_hints.setdefault(hint, []).append(label)

    if seen_hints:
        lines.append("")
        lines.append("### &#x1F511; Suggested rotations")
        for hint, labels in seen_hints.items():
            # Use the most common label for this hint as the bullet
            # heading (e.g. "Aws Access Key" wins over "Aws Secret Key"
            # when both appear).
            from collections import Counter
            label = Counter(labels).most_common(1)[0][0]
            n = len(labels)
            count_suffix = f" ({n} found)" if n > 1 else ""
            lines.append(f"- **{label}**{count_suffix}")
            lines.append(f"  ```\n  {hint}\n  ```")

    lines.extend([
        "",
        "### What to do",
        "1. **Remove** the hardcoded secrets from your code",
        "2. **Rotate** any credentials that may have been exposed (commands above)",
        "3. **Use** environment variables or a secret manager instead",
        "",
        "---",
        "*Scanned by [Vooda AI](https://vooda.ai)*",
    ])

    return "\n".join(lines)


async def post_github_pr_comment(
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    body: str,
) -> PRCommentResult:
    """Post a comment on a GitHub pull request."""
    import httpx
    try:
        url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(url, json={"body": body}, headers=headers)
            r.raise_for_status()
            data = r.json()
            return PRCommentResult(success=True, comment_url=data.get("html_url"))
    except Exception as e:
        logger.warning("github_pr_comment_failed", error=str(e)[:200])
        return PRCommentResult(success=False, error=str(e)[:200])


async def post_gitlab_mr_comment(
    token: str,
    project_id: str,
    mr_iid: int,
    body: str,
    gitlab_url: str = "https://gitlab.com",
) -> PRCommentResult:
    """Post a note on a GitLab merge request."""
    import httpx
    try:
        url = f"{gitlab_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"
        headers = {"PRIVATE-TOKEN": token}
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(url, json={"body": body}, headers=headers)
            r.raise_for_status()
            data = r.json()
            web_url = data.get("web_url") or f"{gitlab_url}/projects/{project_id}/merge_requests/{mr_iid}#note_{data.get('id')}"
            return PRCommentResult(success=True, comment_url=web_url)
    except Exception as e:
        logger.warning("gitlab_mr_comment_failed", error=str(e)[:200])
        return PRCommentResult(success=False, error=str(e)[:200])


async def post_bitbucket_pr_comment(
    username: str,
    app_password: str,
    workspace: str,
    repo_slug: str,
    pr_id: int,
    body: str,
) -> PRCommentResult:
    """Post a comment on a Bitbucket pull request."""
    import httpx
    try:
        url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/pullrequests/{pr_id}/comments"
        auth = (username, app_password)
        async with httpx.AsyncClient(timeout=30, auth=auth) as client:
            r = await client.post(url, json={"content": {"raw": body}})
            r.raise_for_status()
            data = r.json()
            return PRCommentResult(success=True, comment_url=data.get("links", {}).get("html", {}).get("href"))
    except Exception as e:
        logger.warning("bitbucket_pr_comment_failed", error=str(e)[:200])
        return PRCommentResult(success=False, error=str(e)[:200])


async def post_pr_comment(
    provider: str,
    repo_url: str,
    pr_number: int,
    findings: list[dict],
    repo_name: str,
    scan_job_id: str,
    base_sha: str = "",
    head_sha: str = "",
    auth_token: str = "",
) -> PRCommentResult:
    """
    Post scan findings as a comment on a pull request.
    Dispatches to the correct provider based on webhook source.
    """
    body = _format_findings_comment(findings, repo_name, pr_number, scan_job_id, base_sha, head_sha)

    if not auth_token:
        logger.info("pr_comment_skipped_no_token", provider=provider, pr=pr_number)
        return PRCommentResult(success=False, error="No auth token configured for PR comments")

    if provider == "github":
        # Extract owner/repo from URL: https://github.com/owner/repo.git
        parts = repo_url.rstrip("/").rstrip(".git").split("/")
        if len(parts) >= 2:
            owner, repo = parts[-2], parts[-1]
            return await post_github_pr_comment(auth_token, owner, repo, pr_number, body)

    elif provider == "gitlab":
        # Extract project path from URL
        parts = repo_url.rstrip("/").rstrip(".git").split("/")
        if len(parts) >= 2:
            project_path = "/".join(parts[-2:])
            import urllib.parse
            project_id = urllib.parse.quote(project_path, safe="")
            return await post_gitlab_mr_comment(auth_token, project_id, pr_number, body)

    elif provider == "bitbucket":
        parts = repo_url.rstrip("/").rstrip(".git").split("/")
        if len(parts) >= 2:
            workspace, repo_slug = parts[-2], parts[-1]
            return await post_bitbucket_pr_comment("", auth_token, workspace, repo_slug, pr_number, body)

    return PRCommentResult(success=False, error=f"Unsupported provider: {provider}")
