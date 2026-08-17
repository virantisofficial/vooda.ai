# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Blast Radius Analysis — when a credential is verified as active,
enumerate what resources it can access and score the impact.

Runs automatically after verification returns status="active".
Results are stored in finding.source_metadata["blast_radius"].
"""

import structlog
from dataclasses import dataclass, field
from typing import Optional

logger = structlog.get_logger()


@dataclass
class Resource:
    """A single resource accessible by the leaked credential."""
    resource_type: str     # "s3_bucket", "repo", "channel", "database", "iam_policy", etc.
    name: str              # "production-data", "payments-api", "#general"
    access_level: str      # "admin", "write", "read", "list"
    risk: str              # "critical", "high", "medium", "low"
    detail: Optional[str] = None  # Extra context: "Contains PII", "Production environment"


@dataclass
class BlastRadiusResult:
    """Full blast radius analysis for a leaked credential."""
    provider: str
    identity: str           # Who the key belongs to: ARN, username, bot name
    impact_score: int       # 0-100, higher = more dangerous
    impact_level: str       # "critical", "high", "medium", "low"
    resources: list[Resource] = field(default_factory=list)
    summary: str = ""       # Human-readable: "Can access 3 S3 buckets (1 production), 12 repos"
    permissions_count: int = 0
    can_write: bool = False
    can_admin: bool = False

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "identity": self.identity,
            "impact_score": self.impact_score,
            "impact_level": self.impact_level,
            "summary": self.summary,
            "permissions_count": self.permissions_count,
            "can_write": self.can_write,
            "can_admin": self.can_admin,
            "resources": [
                {"type": r.resource_type, "name": r.name, "access": r.access_level, "risk": r.risk, "detail": r.detail}
                for r in self.resources
            ],
        }


def _score_impact(resources: list[Resource], can_write: bool, can_admin: bool) -> tuple[int, str]:
    """Calculate impact score (0-100) from resources and access levels."""
    if not resources:
        return 10, "low"

    score = 0
    risk_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
    for r in resources[:20]:  # Cap at 20 to avoid score explosion
        score += risk_weights.get(r.risk, 5)

    if can_admin:
        score += 30
    elif can_write:
        score += 15

    score = min(score, 100)

    if score >= 80:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    return score, level


# ═══════════════════════════════════════════════════════════════
#  PROVIDER ENUMERATORS
# ═══════════════════════════════════════════════════════════════

async def analyze_aws(source_metadata: dict) -> Optional[BlastRadiusResult]:
    """Enumerate AWS resources accessible by this key."""
    try:
        import httpx

        raw_value = source_metadata.get("_raw_value", "")
        # AWS keys need both access_key_id and secret — we may only have the access key
        # Use the verification details which already called STS GetCallerIdentity
        verification_details = source_metadata.get("verification_details", "")
        identity = verification_details or "Unknown AWS Identity"

        resources = []

        # Parse ARN to determine scope
        arn = ""
        for part in identity.split(","):
            if "ARN:" in part:
                arn = part.split("ARN:")[-1].strip()

        # Determine access level from ARN
        is_root = ":root" in arn
        is_admin = "Admin" in arn or "admin" in arn or is_root
        is_service_role = ":role/" in arn
        is_user = ":user/" in arn

        if is_root:
            resources.append(Resource("aws_account", "Root Account", "admin", "critical", "Full AWS account access"))
            resources.append(Resource("iam", "All IAM Users & Roles", "admin", "critical", "Can create/delete any identity"))
            resources.append(Resource("s3", "All S3 Buckets", "admin", "critical", "Full access to all storage"))
            resources.append(Resource("ec2", "All EC2 Instances", "admin", "critical", "Can start/stop/terminate"))
            resources.append(Resource("rds", "All RDS Databases", "admin", "critical", "Full database access"))
        elif is_admin:
            resources.append(Resource("iam", "IAM Management", "admin", "critical", "Administrator access"))
            resources.append(Resource("s3", "S3 Buckets", "write", "high", "Likely has broad S3 access"))
            resources.append(Resource("ec2", "EC2 Instances", "write", "high", "Likely has compute access"))
        elif is_service_role:
            role_name = arn.split("/")[-1] if "/" in arn else "Unknown Role"
            resources.append(Resource("iam_role", role_name, "assume", "medium", "Service role — scope depends on attached policies"))
        elif is_user:
            user_name = arn.split("/")[-1] if "/" in arn else "Unknown User"
            resources.append(Resource("iam_user", user_name, "read", "medium", "IAM user — check attached policies for scope"))

        can_write = is_root or is_admin
        can_admin = is_root or is_admin
        score, level = _score_impact(resources, can_write, can_admin)

        summary_parts = []
        if is_root:
            summary_parts.append("ROOT account access — full control over all AWS resources")
        elif is_admin:
            summary_parts.append("Administrator access — can manage all resources")
        else:
            summary_parts.append(f"{len(resources)} resource{'s' if len(resources) != 1 else ''} accessible")

        return BlastRadiusResult(
            provider="aws", identity=identity, impact_score=score, impact_level=level,
            resources=resources, summary=". ".join(summary_parts),
            permissions_count=len(resources), can_write=can_write, can_admin=can_admin,
        )
    except Exception as e:
        logger.warning("blast_radius_aws_error", error=str(e)[:200])
        return None


async def analyze_github(source_metadata: dict) -> Optional[BlastRadiusResult]:
    """Enumerate GitHub resources accessible by this token."""
    try:
        import httpx
        token = source_metadata.get("_raw_value", "")
        if not token:
            return None

        resources = []
        identity = ""
        scopes_str = ""
        can_write = False
        can_admin = False

        async with httpx.AsyncClient(timeout=15) as client:
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

            # Get user info + scopes
            r = await client.get("https://api.github.com/user", headers=headers)
            if r.status_code != 200:
                return None
            user = r.json()
            identity = f"{user.get('login', '?')} ({user.get('name', '')})"
            scopes_str = r.headers.get("X-OAuth-Scopes", "")
            scopes = [s.strip() for s in scopes_str.split(",") if s.strip()]

            # Analyze scopes for risk
            if "admin:org" in scopes:
                resources.append(Resource("github_org", "Organization Admin", "admin", "critical", "Can manage org members, teams, settings"))
                can_admin = True
            if "delete_repo" in scopes:
                resources.append(Resource("github_scope", "Delete Repositories", "admin", "critical", "Can permanently delete repos"))
                can_admin = True
            if "repo" in scopes:
                can_write = True
            if "admin:org_hook" in scopes or "admin:repo_hook" in scopes:
                resources.append(Resource("github_webhooks", "Webhook Management", "admin", "high", "Can create/modify webhooks"))

            # List accessible repos (first page only)
            repos_r = await client.get("https://api.github.com/user/repos?per_page=20&sort=updated&affiliation=owner,collaborator,organization_member", headers=headers)
            if repos_r.status_code == 200:
                repos = repos_r.json()
                for repo in repos[:15]:
                    repo_name = repo.get("full_name", "?")
                    is_private = repo.get("private", False)
                    has_push = repo.get("permissions", {}).get("push", False)
                    has_admin = repo.get("permissions", {}).get("admin", False)

                    access = "admin" if has_admin else "write" if has_push else "read"
                    risk = "high" if is_private and has_push else "medium" if is_private else "low"
                    detail = "Private repo" if is_private else "Public repo"
                    if has_admin:
                        detail += " (admin)"
                        can_admin = True

                    resources.append(Resource("repository", repo_name, access, risk, detail))

                total_repos = int(repos_r.headers.get("X-Total-Count", len(repos)))
                if total_repos > 15:
                    resources.append(Resource("repositories", f"+{total_repos - 15} more repos", "varies", "medium", f"Total: {total_repos} accessible repos"))

            # List orgs
            orgs_r = await client.get("https://api.github.com/user/orgs?per_page=10", headers=headers)
            if orgs_r.status_code == 200:
                for org in orgs_r.json():
                    resources.append(Resource("organization", org.get("login", "?"), "member", "medium", "Org membership"))

        score, level = _score_impact(resources, can_write, can_admin)

        repo_count = sum(1 for r in resources if r.resource_type == "repository")
        org_count = sum(1 for r in resources if r.resource_type == "organization")
        summary = f"User: {identity}. {repo_count} repos accessible"
        if org_count > 0:
            summary += f", {org_count} org{'s' if org_count > 1 else ''}"
        if scopes_str:
            summary += f". Scopes: {scopes_str}"

        return BlastRadiusResult(
            provider="github", identity=identity, impact_score=score, impact_level=level,
            resources=resources, summary=summary,
            permissions_count=len(resources), can_write=can_write, can_admin=can_admin,
        )
    except Exception as e:
        logger.warning("blast_radius_github_error", error=str(e)[:200])
        return None


async def analyze_slack(source_metadata: dict) -> Optional[BlastRadiusResult]:
    """Enumerate Slack resources accessible by this token."""
    try:
        import httpx
        token = source_metadata.get("_raw_value", "")
        if not token:
            return None

        resources = []
        identity = ""
        can_write = False
        can_admin = False

        async with httpx.AsyncClient(timeout=15) as client:
            headers = {"Authorization": f"Bearer {token}"}

            # Auth test
            r = await client.post("https://slack.com/api/auth.test", headers=headers)
            data = r.json()
            if not data.get("ok"):
                return None
            identity = f"{data.get('user', '?')} @ {data.get('team', '?')}"
            is_bot = data.get("bot_id") is not None

            # List channels the token can see
            ch_r = await client.get("https://slack.com/api/conversations.list?types=public_channel,private_channel&limit=100&exclude_archived=true", headers=headers)
            if ch_r.status_code == 200 and ch_r.json().get("ok"):
                channels = ch_r.json().get("channels", [])
                public_count = sum(1 for c in channels if not c.get("is_private"))
                private_count = sum(1 for c in channels if c.get("is_private"))

                if private_count > 0:
                    resources.append(Resource("slack_channels", f"{private_count} private channels", "read", "high", "Can read private channel messages"))
                if public_count > 0:
                    resources.append(Resource("slack_channels", f"{public_count} public channels", "read", "medium", "Can read public channel messages"))

                # Check for sensitive channels
                for ch in channels[:50]:
                    name = ch.get("name", "").lower()
                    if any(kw in name for kw in ["secret", "credential", "password", "key", "token", "infra", "prod", "deploy", "admin"]):
                        resources.append(Resource("slack_channel", f"#{ch.get('name', '?')}", "read", "high", "Sensitive channel name"))

            # Check if bot can post messages
            if is_bot:
                can_write = True
                resources.append(Resource("slack_messaging", "Post Messages", "write", "medium", "Bot can post to channels"))

            # List users
            users_r = await client.get("https://slack.com/api/users.list?limit=10", headers=headers)
            if users_r.status_code == 200 and users_r.json().get("ok"):
                members = users_r.json().get("members", [])
                resources.append(Resource("slack_users", f"{len(members)}+ workspace members", "list", "medium", "Can enumerate all workspace members"))

        score, level = _score_impact(resources, can_write, can_admin)
        summary = f"{identity}. Can access {sum(1 for r in resources if 'channel' in r.resource_type)} channels"
        if can_write:
            summary += ", can post messages"

        return BlastRadiusResult(
            provider="slack", identity=identity, impact_score=score, impact_level=level,
            resources=resources, summary=summary,
            permissions_count=len(resources), can_write=can_write, can_admin=can_admin,
        )
    except Exception as e:
        logger.warning("blast_radius_slack_error", error=str(e)[:200])
        return None


async def analyze_stripe(source_metadata: dict) -> Optional[BlastRadiusResult]:
    """Enumerate Stripe resources accessible by this key."""
    try:
        import httpx
        key = source_metadata.get("_raw_value", "")
        if not key:
            return None

        resources = []
        is_live = key.startswith("sk_live") or key.startswith("rk_live")
        is_test = key.startswith("sk_test") or key.startswith("rk_test")
        is_restricted = key.startswith("rk_")
        identity = f"{'Live' if is_live else 'Test'} {'Restricted' if is_restricted else 'Secret'} Key"

        if is_live and not is_restricted:
            resources.append(Resource("stripe_payments", "All Payments", "admin", "critical", "Can create charges, refunds"))
            resources.append(Resource("stripe_customers", "Customer Data", "read", "critical", "Access to all customer records with PII"))
            resources.append(Resource("stripe_payouts", "Payouts", "write", "critical", "Can initiate payouts"))
            resources.append(Resource("stripe_subscriptions", "Subscriptions", "admin", "high", "Can modify subscriptions"))
        elif is_live and is_restricted:
            resources.append(Resource("stripe_restricted", "Restricted Access", "limited", "high", "Live restricted key — limited scope"))
        elif is_test:
            resources.append(Resource("stripe_test", "Test Environment", "admin", "low", "Test mode only — no real money"))

        can_write = is_live
        can_admin = is_live and not is_restricted
        score, level = _score_impact(resources, can_write, can_admin)

        summary = f"{identity}."
        if is_live and not is_restricted:
            summary += " CRITICAL: Full access to live payments, customers, and payouts"
        elif is_live:
            summary += " Live restricted key with limited scope"
        else:
            summary += " Test mode key — no financial risk"

        return BlastRadiusResult(
            provider="stripe", identity=identity, impact_score=score, impact_level=level,
            resources=resources, summary=summary,
            permissions_count=len(resources), can_write=can_write, can_admin=can_admin,
        )
    except Exception as e:
        logger.warning("blast_radius_stripe_error", error=str(e)[:200])
        return None


async def analyze_gitlab(source_metadata: dict) -> Optional[BlastRadiusResult]:
    """Enumerate GitLab resources accessible by this token."""
    try:
        import httpx
        token = source_metadata.get("_raw_value", "")
        if not token:
            return None

        resources = []
        identity = ""
        can_write = False
        can_admin = False

        async with httpx.AsyncClient(timeout=15) as client:
            headers = {"PRIVATE-TOKEN": token}

            r = await client.get("https://gitlab.com/api/v4/user", headers=headers)
            if r.status_code != 200:
                return None
            user = r.json()
            identity = f"{user.get('username', '?')} ({user.get('name', '')})"
            is_admin = user.get("is_admin", False)
            if is_admin:
                resources.append(Resource("gitlab_admin", "GitLab Admin", "admin", "critical", "Full instance admin access"))
                can_admin = True

            # List projects
            proj_r = await client.get("https://gitlab.com/api/v4/projects?membership=true&per_page=20&order_by=updated_at", headers=headers)
            if proj_r.status_code == 200:
                for proj in proj_r.json()[:15]:
                    access = "admin" if proj.get("permissions", {}).get("project_access", {}).get("access_level", 0) >= 40 else "write" if proj.get("permissions", {}).get("project_access", {}).get("access_level", 0) >= 30 else "read"
                    risk = "high" if proj.get("visibility") == "private" and access in ("write", "admin") else "medium"
                    resources.append(Resource("repository", proj.get("path_with_namespace", "?"), access, risk, proj.get("visibility", "?")))
                    if access in ("write", "admin"):
                        can_write = True

        score, level = _score_impact(resources, can_write, can_admin)
        repo_count = sum(1 for r in resources if r.resource_type == "repository")
        summary = f"User: {identity}. {repo_count} projects accessible"

        return BlastRadiusResult(
            provider="gitlab", identity=identity, impact_score=score, impact_level=level,
            resources=resources, summary=summary,
            permissions_count=len(resources), can_write=can_write, can_admin=can_admin,
        )
    except Exception as e:
        logger.warning("blast_radius_gitlab_error", error=str(e)[:200])
        return None


async def analyze_sendgrid(source_metadata: dict) -> Optional[BlastRadiusResult]:
    """Analyze SendGrid API key scope."""
    try:
        import httpx
        key = source_metadata.get("_raw_value", "")
        if not key:
            return None

        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get("https://api.sendgrid.com/v3/scopes", headers={"Authorization": f"Bearer {key}"})
            if r.status_code != 200:
                return None
            scopes = r.json().get("scopes", [])

        resources = []
        can_write = False
        can_admin = False

        # Analyze scopes
        write_scopes = [s for s in scopes if ".create" in s or ".update" in s or ".delete" in s or "send" in s.lower()]
        admin_scopes = [s for s in scopes if "admin" in s.lower() or "api_keys" in s.lower()]

        if any("mail.send" in s for s in scopes):
            resources.append(Resource("sendgrid_mail", "Send Emails", "write", "high", "Can send emails on behalf of your domain"))
            can_write = True
        if admin_scopes:
            resources.append(Resource("sendgrid_admin", "Admin Scopes", "admin", "critical", f"{len(admin_scopes)} admin scopes"))
            can_admin = True
        if any("contacts" in s for s in scopes):
            resources.append(Resource("sendgrid_contacts", "Marketing Contacts", "read", "high", "Access to email contact lists (PII)"))

        resources.append(Resource("sendgrid_scopes", f"{len(scopes)} total scopes", "varies", "medium", f"Write: {len(write_scopes)}, Admin: {len(admin_scopes)}"))

        score, level = _score_impact(resources, can_write, can_admin)
        identity = f"SendGrid API Key ({len(scopes)} scopes)"
        summary = f"{len(scopes)} scopes. {'Can send emails. ' if can_write else ''}{f'{len(admin_scopes)} admin scopes. ' if admin_scopes else ''}"

        return BlastRadiusResult(
            provider="sendgrid", identity=identity, impact_score=score, impact_level=level,
            resources=resources, summary=summary,
            permissions_count=len(scopes), can_write=can_write, can_admin=can_admin,
        )
    except Exception as e:
        logger.warning("blast_radius_sendgrid_error", error=str(e)[:200])
        return None


# ═══════════════════════════════════════════════════════════════
#  DISPATCHER
# ═══════════════════════════════════════════════════════════════

ANALYZERS = {
    "aws": analyze_aws,
    "github": analyze_github,
    "gitlab": analyze_gitlab,
    "slack": analyze_slack,
    "stripe": analyze_stripe,
    "sendgrid": analyze_sendgrid,
}

SUPPORTED_BLAST_RADIUS_PROVIDERS = set(ANALYZERS.keys())


async def analyze_blast_radius(source_metadata: dict) -> Optional[BlastRadiusResult]:
    """
    Run blast radius analysis for a verified-active credential.
    Returns None if provider not supported or analysis fails.
    """
    provider = (source_metadata.get("provider") or "").lower()

    if provider not in ANALYZERS:
        return None

    logger.info("blast_radius_analyzing", provider=provider)
    result = await ANALYZERS[provider](source_metadata)

    if result:
        logger.info(
            "blast_radius_complete",
            provider=provider,
            impact_score=result.impact_score,
            impact_level=result.impact_level,
            resources_count=len(result.resources),
        )

    return result
