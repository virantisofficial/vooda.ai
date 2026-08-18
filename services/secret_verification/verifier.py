# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Secret Verification Service — checks if detected credentials are still active
by making non-destructive API calls to provider endpoints.

This runs AFTER scanning completes, as an async background task.
Only regex-detected findings with known providers are verified.
Entropy-only findings with provider="unknown" are skipped.
"""

import structlog
from typing import Optional
from dataclasses import dataclass

from services.secret_verification.http_client import (
    verification_client,
    is_transient_http_error,
)

logger = structlog.get_logger()


@dataclass
class VerificationResult:
    status: str        # "active", "inactive", "error", "unsupported"
    details: str       # Human-readable explanation
    provider: str      # Which provider was checked
    permissions: Optional[str] = None  # Back-compat free-text summary (UI fallback)
    transient: bool = False  # True when the error is a network blip worth retrying
                             # (DNS, TCP reset, timeout). Only meaningful when status=="error".
    permissions_detail: Optional[dict] = None
    # Structured permission data the UI / Blast Radius panel can render
    # richly. Shape is per-provider but common keys include:
    #   scopes:      list[str]   — OAuth scopes / IAM actions / API scopes
    #   identity:    str         — account name / user / team / ARN
    #   account_id:  str         — account or workspace identifier
    #   risk_level:  str         — "critical" | "high" | "medium" | "low"
    #   is_production: bool      — live vs test key where applicable
    #   extra:       dict        — provider-specific fields
    risk_level: Optional[str] = None
    # Provider-derived risk classification ("critical"/"high"/"medium"/"low").
    # Promoted out of permissions_detail so the worker can use it to drive
    # severity escalation without parsing a dict.
    blast_radius_summary: Optional[str] = None
    # One-sentence human summary of what this credential can do — feeds
    # the Blast Radius UI panel directly. E.g. "GitHub token with repo
    # scope — full read/write access to private repositories."


def summarize_blast_radius(
    provider: str,
    detail: Optional[dict],
) -> Optional[str]:
    """Human-readable one-liner of what a verified credential can do.

    Deliberately short (~120 chars) — the Blast Radius UI panel renders
    this as the headline above any structured scope data. Returns ``None``
    when we have nothing useful to say so the UI can gracefully fall back
    to the plain ``permissions`` string.

    This is purely derivation from ``detail``; it does not call out to
    providers. Riskier scopes bubble up to the front of the summary so
    operators can triage at a glance.
    """
    if not detail:
        return None
    prov = (provider or "").lower()

    # ── GitHub ──
    if prov == "github":
        scopes = detail.get("scopes") or []
        caps = detail.get("capabilities") or {}
        # B4: when live enumeration ran, prefer concrete resource counts
        # to a generic scope-based statement — much more actionable.
        repos = caps.get("repos_accessible")
        orgs = caps.get("orgs_accessible")
        if repos is not None:
            sample = caps.get("sample_repos") or []
            sample_str = f" (including {', '.join(sample[:2])})" if sample else ""
            org_str = f" across {orgs} org(s)" if orgs else ""
            return (
                f"GitHub token for {detail.get('identity', '?')} — "
                f"{repos} repo(s) accessible{org_str}{sample_str}."
            )
        if not scopes:
            return f"GitHub token active (user: {detail.get('identity', '?')})"
        risky = [s for s in scopes if s in ("repo", "admin:org", "admin:enterprise",
                                             "delete_repo", "workflow", "admin:gpg_key")]
        if risky:
            return (
                f"GitHub token with {', '.join(risky[:3])} scope — "
                f"full read/write access to private repos and admin-level actions."
            )
        return f"GitHub token with {len(scopes)} scope(s): {', '.join(scopes[:5])}"

    # ── AWS ──
    if prov == "aws":
        arn = detail.get("arn", "")
        identity = detail.get("identity") or arn or "?"
        caps = detail.get("capabilities") or {}
        # B4: when live enumeration ran, prefer a concrete blast-radius
        # sentence with real resource counts + account alias. Falls back
        # to the ARN-shape-derived sentence when enumeration wasn't run
        # or AccessDenied stopped both sub-calls.
        alias = caps.get("account_alias", "")
        buckets = caps.get("buckets_accessible")
        account_part = f" in account '{alias}'" if alias else ""
        if buckets is not None:
            sample = caps.get("sample_buckets") or []
            sample_str = f" (including {', '.join(sample[:2])})" if sample else ""
            if "Administrator" in arn or "root" in arn.lower():
                role_hint = " with administrative access"
            elif "ReadOnly" in arn:
                role_hint = " with read-only access"
            else:
                role_hint = ""
            return (
                f"AWS credential for {identity}{role_hint}{account_part} "
                f"— {buckets} S3 bucket(s) visible{sample_str}."
            )
        if "Administrator" in arn or "root" in arn.lower():
            return f"AWS credential for {identity}{account_part} — administrative / root-level access."
        if "ReadOnly" in arn:
            return f"AWS credential for {identity}{account_part} — read-only across account."
        return f"AWS credential for {identity}{account_part} — scope depends on attached IAM policy."

    # ── Slack ──
    if prov == "slack":
        team = detail.get("identity") or detail.get("extra", {}).get("team") or "?"
        is_bot = detail.get("extra", {}).get("is_bot", False)
        kind = "Bot" if is_bot else "User"
        return f"Slack {kind} token active in workspace '{team}'."

    # ── Stripe ──
    if prov == "stripe":
        is_prod = detail.get("is_production", False)
        if is_prod:
            return "Stripe LIVE secret key — access to production customer data and payments."
        return "Stripe TEST key — limited to the test-mode sandbox, no production impact."

    # ── Jira ──
    if prov == "jira":
        identity = detail.get("identity") or "?"
        domain = detail.get("extra", {}).get("domain", "")
        return f"Jira API token for {identity} @ {domain} — user-scoped access to projects, issues, and comments."

    # ── GitLab ──
    if prov == "gitlab":
        identity = detail.get("identity") or "?"
        scopes = detail.get("scopes") or []
        caps = detail.get("capabilities") or {}
        projects = caps.get("projects_accessible")
        groups = caps.get("groups_accessible")
        if projects is not None:
            sample = caps.get("sample_projects") or []
            sample_str = f" (including {', '.join(sample[:2])})" if sample else ""
            grp_str = f" across {groups} group(s)" if groups else ""
            return (
                f"GitLab token for {identity} — {projects} project(s) "
                f"accessible{grp_str}{sample_str}."
            )
        if "api" in scopes or "write_repository" in scopes:
            return (
                f"GitLab token for {identity} with api/write_repository — "
                f"full programmatic access to group + project code."
            )
        if scopes:
            return f"GitLab token for {identity} with scopes: {', '.join(scopes[:5])}"
        return f"GitLab token active (user: {identity}) — scope depends on token type."

    # ── Twilio ──
    if prov == "twilio":
        identity = detail.get("identity") or "?"
        return (
            f"Twilio Account SID {identity} — can send SMS / make calls / "
            f"access call logs + billing."
        )

    # ── SendGrid ──
    if prov == "sendgrid":
        scopes = detail.get("scopes") or []
        if "mail.send" in scopes:
            return f"SendGrid key with mail.send scope — can send email as your verified domain ({len(scopes)} scopes total)."
        if scopes:
            return f"SendGrid key with {len(scopes)} scope(s): {', '.join(scopes[:4])}"
        return "SendGrid key active — scope unknown."

    # ── OpenAI ──
    if prov == "openai":
        identity = detail.get("identity") or "?"
        is_prod = detail.get("is_production", False)
        kind = "production project" if is_prod else "account"
        return (
            f"OpenAI API key for {identity} {kind} — billing-linked, can call "
            f"GPT/DALL·E/Whisper/embeddings APIs. Exposed keys accrue real charges."
        )

    # ── Anthropic ──
    if prov == "anthropic":
        identity = detail.get("identity") or "?"
        return (
            f"Anthropic API key for {identity} — billing-linked, can call "
            f"Claude models. Exposed keys accrue real charges."
        )

    # ── Discord ──
    if prov == "discord":
        identity = detail.get("identity") or "?"
        return (
            f"Discord bot token for {identity} — can send messages, "
            f"manage channels, and access guild data wherever this bot "
            f"is invited."
        )

    # ── Notion ──
    if prov == "notion":
        identity = detail.get("identity") or "?"
        kind = detail.get("extra", {}).get("owner_type", "")
        kind_label = "workspace-scoped bot" if kind == "workspace" else "user-scoped integration"
        return (
            f"Notion {kind_label} for {identity} — can read + write pages "
            f"and databases shared with the integration."
        )

    # ── Linear ──
    if prov == "linear":
        identity = detail.get("identity") or "?"
        return (
            f"Linear token for {identity} — full project/issue/comment "
            f"access across their workspace."
        )

    # ── DigitalOcean ──
    if prov == "digitalocean":
        identity = detail.get("identity") or "?"
        dlimit = detail.get("extra", {}).get("droplet_limit")
        limit_suffix = f" (droplet limit: {dlimit})" if dlimit else ""
        return (
            f"DigitalOcean token for {identity}{limit_suffix} — can "
            f"provision / destroy droplets and manage all account resources."
        )

    # ── Datadog ──
    if prov == "datadog":
        kind = detail.get("extra", {}).get("key_type", "API")
        return (
            f"Datadog {kind} key active — can ingest metrics, logs, and "
            f"traces into the account, and (if App key) query them back."
        )

    # ── PagerDuty ──
    if prov == "pagerduty":
        abilities = detail.get("extra", {}).get("abilities_count", 0)
        return (
            f"PagerDuty token active — can trigger / acknowledge / resolve "
            f"incidents and read schedules ({abilities} abilities enabled)."
        )

    # ── Heroku ──
    if prov == "heroku":
        identity = detail.get("identity") or "?"
        mfa = detail.get("extra", {}).get("two_factor", False)
        mfa_note = "" if mfa else " — account lacks 2FA, elevated risk"
        return (
            f"Heroku token for {identity} — full app deploy, config-var, "
            f"and add-on management{mfa_note}."
        )

    # ── Cloudflare ──
    if prov == "cloudflare":
        exp = detail.get("extra", {}).get("expires_on")
        exp_str = f", expires {exp[:10]}" if exp else " (no expiry)"
        return (
            f"Cloudflare token active{exp_str} — scope depends on token "
            f"permissions (DNS / caching / workers / zones)."
        )

    # ── HubSpot ──
    if prov == "hubspot":
        portal = detail.get("account_id") or "?"
        scopes = detail.get("scopes") or []
        scope_str = f" with {len(scopes)} scopes" if scopes else ""
        return (
            f"HubSpot token for portal {portal}{scope_str} — can read/write "
            f"contacts, deals, and marketing content."
        )

    # ── Intercom ──
    if prov == "intercom":
        app = detail.get("extra", {}).get("app_name") or detail.get("identity") or "?"
        return (
            f"Intercom token for workspace '{app}' — can read/write "
            f"conversations and customer profiles."
        )

    # ── Shopify ──
    if prov == "shopify":
        shop = detail.get("extra", {}).get("shop_name") or detail.get("identity") or "?"
        plan = detail.get("extra", {}).get("plan_name", "")
        plan_str = f" ({plan} plan)" if plan else ""
        return (
            f"Shopify token for store '{shop}'{plan_str} — scope depends "
            f"on granted permissions (orders, customers, products, payments)."
        )

    # ── Vercel ──
    if prov == "vercel":
        identity = detail.get("identity") or "?"
        return (
            f"Vercel token for {identity} — can deploy, rollback, and "
            f"modify production environment variables for all projects "
            f"the user owns."
        )

    # ── Netlify ──
    if prov == "netlify":
        identity = detail.get("identity") or "?"
        return (
            f"Netlify token for {identity} — deploy control, DNS, and "
            f"site config across all sites the user owns."
        )

    # ── Asana ──
    if prov == "asana":
        identity = detail.get("identity") or "?"
        ws = detail.get("extra", {}).get("workspace_count", 0)
        return (
            f"Asana token for {identity} across {ws} workspace(s) — "
            f"read/write tasks, projects, and comments."
        )

    # ── Figma ──
    if prov == "figma":
        identity = detail.get("identity") or "?"
        return (
            f"Figma token for {identity} — read files, comments, and "
            f"projects the user has access to; no write without explicit "
            f"file grants."
        )

    # ── DockerHub ──
    if prov == "dockerhub":
        identity = detail.get("identity") or "?"
        return (
            f"DockerHub token for {identity} — can push image tags to "
            f"repositories the user owns. Supply-chain risk if compromised."
        )

    # ── Zoom ──
    if prov == "zoom":
        identity = detail.get("identity") or "?"
        kind = detail.get("extra", {}).get("user_type", "")
        kind_str = f" ({kind})" if kind else ""
        return (
            f"Zoom token for {identity}{kind_str} — can read meetings, "
            f"recordings, and webinar data; create new meetings under this user."
        )

    # ── Bitbucket ──
    if prov == "bitbucket":
        identity = detail.get("identity") or "?"
        return (
            f"Bitbucket token for {identity} — scope depends on app-"
            f"password grants (repo read/write, deployment, pipelines)."
        )

    # ── Airtable ──
    if prov == "airtable":
        bases = detail.get("extra", {}).get("base_count", 0)
        sample = detail.get("extra", {}).get("sample_bases") or []
        sample_str = f" (including {', '.join(sample[:2])})" if sample else ""
        return (
            f"Airtable token — {bases} base(s) accessible{sample_str}. "
            f"Scope depends on per-base permission grants."
        )

    # ── Webflow ──
    if prov == "webflow":
        app = detail.get("extra", {}).get("app_name") or "?"
        scope_count = len(detail.get("scopes") or [])
        return (
            f"Webflow token for app '{app}' with {scope_count} scope(s) — "
            f"can read/write CMS content and publish sites per granted scopes."
        )

    # ── Render ──
    if prov == "render":
        owners = detail.get("extra", {}).get("owner_count", 0)
        sample = detail.get("extra", {}).get("sample_owners") or []
        sample_str = f" (including {sample[0]})" if sample else ""
        return (
            f"Render token — {owners} owner account(s) accessible{sample_str}. "
            f"Can deploy services, modify env-vars, and scale resources."
        )

    return None


def _is_rate_limited(response, provider: str = "") -> bool:
    """Detect provider-specific rate-limit responses.

    Without this, some providers' rate-limit replies masquerade as "bad
    credential" responses — GitHub famously returns ``403`` whether the
    token is invalid OR the account has exhausted its per-hour rate
    budget. Without inspecting the ``X-RateLimit-Remaining`` header we
    would mark a perfectly valid token as ``inactive`` during a rate-
    limit window and lose visibility on a live key.

    Returns True when the response indicates the server refused due to
    rate limiting (so the caller should return a transient error and let
    the finding get re-verified on the next pass) rather than because
    the credential was rejected.

    Provider-specific rules:

    * **GitHub**   — ``403 + X-RateLimit-Remaining: 0``
    * **AWS STS**  — ``400/403`` body contains ``ThrottlingException`` or
                     ``RequestLimitExceeded``
    * **Stripe**   — ``429`` (also the ``stripe-should-retry: true`` header
                     when present, though ``429`` alone is authoritative)
    * **Atlassian**, **Slack**, generic — any ``429`` or ``503`` is
      treated as transient (provider asked us to back off)

    Body inspection is capped at 500 chars to keep this helper cheap
    even for verifiers that return large payloads.
    """
    try:
        status = getattr(response, "status_code", None)
        if status is None:
            return False

        # Universal: 429 Too Many Requests / 503 Service Unavailable
        if status in (429, 503):
            return True

        headers = getattr(response, "headers", {}) or {}

        # GitHub: 403 with X-RateLimit-Remaining: 0
        if status == 403:
            remaining = headers.get("X-RateLimit-Remaining") or headers.get("x-ratelimit-remaining")
            if remaining == "0":
                return True

        # AWS: Throttling / RequestLimitExceeded in body
        if status in (400, 403):
            body = (getattr(response, "text", "") or "")[:500]
            if "ThrottlingException" in body or "RequestLimitExceeded" in body:
                return True

        return False
    except Exception:
        # Never let a helper crash a verifier — fall through to existing behavior
        return False


def _rate_limited_result(provider: str, response) -> VerificationResult:
    """Build a transient VerificationResult for a rate-limit response."""
    try:
        retry_after = (getattr(response, "headers", {}) or {}).get("Retry-After", "")
    except Exception:
        retry_after = ""
    details = f"[transient] {provider} rate-limited"
    if retry_after:
        details += f" (Retry-After: {retry_after})"
    return VerificationResult(
        status="error",
        details=details,
        provider=provider,
        transient=True,
    )


def _error_result(
    exc: BaseException,
    provider: str,
    log_key: Optional[str] = None,
) -> VerificationResult:
    """Build a VerificationResult for an exception, classifying transient vs definitive.

    Transient errors (network blips, timeouts) get ``transient=True`` so the
    worker can distinguish them from hard failures and choose to re-verify
    in a later pass instead of treating the key as permanently unknown.

    ``log_key`` lets multi-cred verifiers keep a more specific log name
    (e.g. ``azure_ad_verification_error``) while returning the canonical
    ``provider`` value (``"azure"``).
    """
    transient = is_transient_http_error(exc)
    details = str(exc)[:200]
    if transient:
        details = f"[transient] {details}"
    logger.warning(
        f"{log_key or provider}_verification_error",
        error=str(exc)[:200],
        transient=transient,
    )
    return VerificationResult(
        status="error",
        details=details,
        provider=provider,
        transient=transient,
    )


# ── Provider Verifiers ────────────────────────────────────────
# Each function makes a SINGLE non-destructive API call to check
# if a credential is valid. Returns VerificationResult.
# We NEVER modify, create, or delete anything — read-only checks only.


def _aws_sigv4_headers(
    *,
    method: str,
    service: str,
    region: str,
    host: str,
    path: str,
    query: str,
    body: str,
    access_key_id: str,
    secret_key: str,
    extra_headers: Optional[dict] = None,
) -> dict:
    """Build SigV4-signed request headers for any AWS service call.

    Factored out of the inline STS signing block so the same code path
    is reusable for the B4 enumeration calls (S3 ListBuckets, IAM
    ListAccountAliases). Returns the complete header dict ready to pass
    to ``httpx``.

    Notes
    -----
    * ``path`` must be canonical (URI-encoded, starts with ``/``).
    * ``query`` must be canonical (sorted, URI-encoded) or empty.
    * ``body`` is the raw request body for POSTs; empty string for GETs.
    * ``extra_headers`` lets callers add content-type etc. — keys are
      lower-cased automatically for the canonical-headers block.
    """
    import hashlib
    import hmac
    import datetime

    now = datetime.datetime.utcnow()
    datestamp = now.strftime("%Y%m%d")
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")

    # Build the header set that we'll include in the signature.
    headers_to_sign = {"host": host, "x-amz-date": amz_date}
    if extra_headers:
        for k, v in extra_headers.items():
            headers_to_sign[k.lower()] = v
    # Canonical headers: sorted, lower-cased, each terminated by \n.
    sorted_keys = sorted(headers_to_sign.keys())
    canonical_headers = "".join(f"{k}:{headers_to_sign[k]}\n" for k in sorted_keys)
    signed_headers = ";".join(sorted_keys)

    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    canonical_request = (
        f"{method}\n{path}\n{query}\n"
        f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )

    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing_key = _sign(_sign(_sign(_sign(
        f"AWS4{secret_key}".encode(), datestamp), region), service), "aws4_request")
    signature = hmac.new(
        signing_key, string_to_sign.encode(), hashlib.sha256
    ).hexdigest()

    auth_header = (
        f"AWS4-HMAC-SHA256 "
        f"Credential={access_key_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    # The final request headers carry the ORIGINAL casing (httpx preserves
    # case); only the signature math used lower-cased names.
    final = {
        "Host": host,
        "X-Amz-Date": amz_date,
        "Authorization": auth_header,
    }
    if extra_headers:
        final.update(extra_headers)
    return final


async def _enumerate_aws_capabilities(
    access_key_id: str,
    secret_key: str,
) -> dict:
    """Non-destructive AWS resource enumeration (B4).

    Called only when ``VOODA_BLAST_RADIUS_ENUMERATE`` is set and STS
    GetCallerIdentity already confirmed the credential is active. Each
    sub-call is wrapped in its own try/except so a 403 AccessDenied on
    one service still lets the others run and contribute data.

    Currently probes:

    * **S3 ListBuckets** (``GET https://s3.amazonaws.com/``) — count of
      buckets and first 5 names. The headline blast-radius signal: "this
      key can see your S3 inventory." Requires ``s3:ListAllMyBuckets``.
    * **IAM ListAccountAliases** (``GET https://iam.amazonaws.com/?Action=…``)
      — customer-friendly account identifier. Requires
      ``iam:ListAccountAliases``.

    Returns a dict shaped like:

        {
          "buckets_accessible": 47,
          "sample_buckets": ["prod-logs", "billing-backups", ...],
          "account_alias": "acme-prod",
        }

    Missing entries mean the call was denied or failed — the caller
    surfaces what we have and stays silent about what we don't.
    """
    import re as _re
    caps: dict = {}

    # ── S3 ListBuckets ──
    try:
        headers = _aws_sigv4_headers(
            method="GET", service="s3", region="us-east-1",
            host="s3.amazonaws.com", path="/", query="", body="",
            access_key_id=access_key_id, secret_key=secret_key,
            extra_headers={"x-amz-content-sha256":
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        )
        async with verification_client(timeout=10) as c:
            r = await c.get("https://s3.amazonaws.com/", headers=headers)
        if r.status_code == 200:
            # Response is XML with <Bucket><Name>…</Name></Bucket> per bucket
            names = _re.findall(r"<Name>([^<]+)</Name>", r.text)
            caps["buckets_accessible"] = len(names)
            if names:
                caps["sample_buckets"] = names[:_ENUMERATION_MAX_SAMPLES]
    except Exception:
        pass  # AccessDenied / network / anything — degrade silently

    # ── IAM ListAccountAliases ──
    try:
        query = "Action=ListAccountAliases&Version=2010-05-08"
        headers = _aws_sigv4_headers(
            method="GET", service="iam", region="us-east-1",
            host="iam.amazonaws.com", path="/", query=query, body="",
            access_key_id=access_key_id, secret_key=secret_key,
            extra_headers={"x-amz-content-sha256":
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        )
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://iam.amazonaws.com/?{query}", headers=headers)
        if r.status_code == 200:
            aliases = _re.findall(r"<member>([^<]+)</member>", r.text)
            if aliases:
                caps["account_alias"] = aliases[0]
    except Exception:
        pass

    return caps


async def verify_aws_access_key(access_key_id: str, secret_key: str) -> VerificationResult:
    """Verify AWS access key by calling STS GetCallerIdentity (read-only, no permissions needed)."""
    try:
        # AWS SigV4 for STS GetCallerIdentity (read-only, zero-permission).
        host = "sts.amazonaws.com"
        body = "Action=GetCallerIdentity&Version=2011-06-15"
        content_type = "application/x-www-form-urlencoded"
        headers = _aws_sigv4_headers(
            method="POST", service="sts", region="us-east-1",
            host=host, path="/", query="", body=body,
            access_key_id=access_key_id, secret_key=secret_key,
            extra_headers={"content-type": content_type},
        )
        async with verification_client(timeout=10) as client:
            r = await client.post(f"https://{host}", content=body, headers=headers)

        if r.status_code == 200:
            # Extract Account and ARN from XML response
            import re
            account_m = re.search(r"<Account>(\d+)</Account>", r.text)
            arn_m = re.search(r"<Arn>([^<]+)</Arn>", r.text)
            account_id = account_m.group(1) if account_m else ""
            arn = arn_m.group(1) if arn_m else ""
            details = f"Account: {account_id or '?'}, ARN: {arn or '?'}"
            # Derive principal type and risk from ARN shape.
            # ARN examples:
            #   arn:aws:iam::123:user/Alice
            #   arn:aws:sts::123:assumed-role/AdminRole/session
            #   arn:aws:iam::123:root
            principal_type = "unknown"
            if "/user/" in arn or ":user/" in arn:
                principal_type = "iam_user"
            elif "assumed-role" in arn:
                principal_type = "assumed_role"
            elif arn.endswith(":root"):
                principal_type = "root"
            # Root account keys are always critical. Administrator in the
            # ARN suggests admin policy attachment; explicit ReadOnly is
            # the only low-risk signal we can be confident about.
            if principal_type == "root" or "Administrator" in arn:
                risk = "critical"
            elif "ReadOnly" in arn:
                risk = "low"
            else:
                risk = "high"  # unknown IAM policy = assume high
            detail = {
                "scopes": [],  # AWS STS doesn't expose attached-policy scopes
                "identity": arn,
                "account_id": account_id,
                "arn": arn,
                "risk_level": risk,
                "is_production": True,
                "extra": {"principal_type": principal_type},
            }

            # B4: opt-in AWS capability enumeration — additional SigV4-
            # signed read calls (S3 ListBuckets, IAM ListAccountAliases)
            # to populate detail.capabilities with concrete resource
            # inventory. Errors (including AccessDenied on any sub-call)
            # are absorbed internally; we surface whatever came back and
            # stay silent about denied calls.
            if _ENUMERATE_ENABLED:
                try:
                    caps = await _enumerate_aws_capabilities(access_key_id, secret_key)
                    if caps:
                        detail["capabilities"] = caps
                except Exception as ee:
                    logger.debug("aws_enumeration_failed", error=str(ee)[:150])

            result = VerificationResult(
                status="active", details=details, provider="aws",
                permissions=details,
                permissions_detail=detail,
                risk_level=risk,
            )
            result.blast_radius_summary = summarize_blast_radius("aws", detail)
            return result
        elif _is_rate_limited(r, "aws"):
            return _rate_limited_result("aws", r)
        elif r.status_code in (403, 401):
            return VerificationResult(status="inactive", details="Credential rejected by AWS STS", provider="aws")
        else:
            return VerificationResult(status="error", details=f"AWS returned HTTP {r.status_code}", provider="aws")

    except Exception as e:
        return _error_result(e, "aws")


# ══════════════════════════════════════════════════════════════
# B4 — Live Blast-Radius Enumeration
# ══════════════════════════════════════════════════════════════
#
# Where B1 surfaces what the *validation* call reveals (scopes from
# response headers, ARN from STS reply), B4 makes *additional*
# read-only enumeration calls to discover what resources the credential
# can actually reach. For the customer's Blast Radius view this turns
# "token has 'repo' scope" into "token can read 47 private repos
# including acme/prod-infra, acme/billing-service".
#
# Gated behind ``VOODA_BLAST_RADIUS_ENUMERATE`` env var. OFF by default
# because:
#
#  1. It multiplies API calls per credential (2-3x per verify).
#  2. It reads tenant-of-customer data (repo names, org names, etc.)
#     which some deployments will want to handle with extra care.
#  3. Not every provider offers truly non-destructive enumeration.
#
# Output caps are conservative (max 5 sample names per resource type)
# and counts come from the GitHub/GitLab ``Link: …; rel="last"`` paging
# header — we never actually paginate through the data.

import os

_ENUMERATE_ENABLED = os.getenv("VOODA_BLAST_RADIUS_ENUMERATE", "").lower() in ("1", "true", "yes")

_ENUMERATION_MAX_SAMPLES = 5


def _parse_last_page_count(link_header: str) -> Optional[int]:
    """Extract the last-page number from a GitHub/GitLab ``Link`` header.

    Both APIs return ``Link: <...page=42>; rel="last"`` on paged
    responses, letting us learn the total without actually paginating.
    """
    if not link_header:
        return None
    import re as _re
    m = _re.search(r'<[^>]*[?&]page=(\d+)[^>]*>;\s*rel="last"', link_header)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


async def _enumerate_github_capabilities(token: str) -> dict:
    """Additional GitHub calls to probe blast radius (best-effort).

    Called only when ``VOODA_BLAST_RADIUS_ENUMERATE`` is set and the
    core verification already succeeded (token is known active). Any
    sub-call failure is absorbed — the field just doesn't get set.

    Makes at most three calls:
      - ``GET /user/repos?per_page=1&visibility=all`` → total repo count
        via ``Link: rel=last``, plus the first 5 full_names.
      - ``GET /user/orgs?per_page=1``                 → org count + names
      - ``GET /user/emails``                          → email count

    Returns a dict like:
      { "repos_accessible": 47, "sample_repos": ["acme/infra", ...],
        "orgs_accessible":  3, "sample_orgs":  ["acme", ...],
        "email_count":      2 }
    """
    caps: dict = {}
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.github+json"}
    try:
        async with verification_client(timeout=10) as c:
            # --- repos ---
            r = await c.get(
                "https://api.github.com/user/repos?per_page=1&visibility=all",
                headers=headers,
            )
            if r.status_code == 200:
                total = _parse_last_page_count(r.headers.get("Link", ""))
                body = r.json() if r.content else []
                # When there's only one page, Link header is absent; one repo visible
                if total is None:
                    total = len(body)
                caps["repos_accessible"] = total
                # Fetch a small sample (first 5) if we saw any
                if total > 0:
                    s = await c.get(
                        f"https://api.github.com/user/repos?per_page={_ENUMERATION_MAX_SAMPLES}&visibility=all",
                        headers=headers,
                    )
                    if s.status_code == 200:
                        caps["sample_repos"] = [
                            repo.get("full_name", "") for repo in s.json()[:_ENUMERATION_MAX_SAMPLES]
                        ]
    except Exception:
        pass  # degrade to what we have so far

    try:
        async with verification_client(timeout=10) as c:
            # --- orgs ---
            r = await c.get("https://api.github.com/user/orgs?per_page=1", headers=headers)
            if r.status_code == 200:
                body = r.json() if r.content else []
                total = _parse_last_page_count(r.headers.get("Link", ""))
                if total is None:
                    total = len(body)
                caps["orgs_accessible"] = total
                if total > 0:
                    s = await c.get(
                        f"https://api.github.com/user/orgs?per_page={_ENUMERATION_MAX_SAMPLES}",
                        headers=headers,
                    )
                    if s.status_code == 200:
                        caps["sample_orgs"] = [
                            o.get("login", "") for o in s.json()[:_ENUMERATION_MAX_SAMPLES]
                        ]
    except Exception:
        pass

    try:
        async with verification_client(timeout=10) as c:
            # --- emails (only available with `user:email` scope) ---
            r = await c.get("https://api.github.com/user/emails", headers=headers)
            if r.status_code == 200:
                emails = r.json() if r.content else []
                caps["email_count"] = len(emails)
    except Exception:
        pass

    return caps


async def _enumerate_gitlab_capabilities(token: str) -> dict:
    """Non-destructive GitLab enumeration.

    ``GET /api/v4/projects?membership=true&per_page=1`` returns an
    ``X-Total`` header with the project count — cheaper than GitHub's
    Link parsing. A ``GET /api/v4/groups?per_page=1`` gives group count
    similarly.
    """
    caps: dict = {}
    headers = {"PRIVATE-TOKEN": token}
    try:
        async with verification_client(timeout=10) as c:
            r = await c.get(
                "https://gitlab.com/api/v4/projects?membership=true&per_page=1",
                headers=headers,
            )
            if r.status_code == 200:
                try:
                    caps["projects_accessible"] = int(r.headers.get("X-Total", "0"))
                except ValueError:
                    pass
                body = r.json() if r.content else []
                if body:
                    # Single sample from this 1-item page; fetch more if multiple
                    if caps.get("projects_accessible", 0) > 1:
                        s = await c.get(
                            f"https://gitlab.com/api/v4/projects?membership=true&per_page={_ENUMERATION_MAX_SAMPLES}",
                            headers=headers,
                        )
                        if s.status_code == 200:
                            caps["sample_projects"] = [
                                p.get("path_with_namespace", "") for p in s.json()[:_ENUMERATION_MAX_SAMPLES]
                            ]
                    else:
                        caps["sample_projects"] = [body[0].get("path_with_namespace", "")]
    except Exception:
        pass

    try:
        async with verification_client(timeout=10) as c:
            r = await c.get("https://gitlab.com/api/v4/groups?per_page=1", headers=headers)
            if r.status_code == 200:
                try:
                    caps["groups_accessible"] = int(r.headers.get("X-Total", "0"))
                except ValueError:
                    pass
    except Exception:
        pass

    return caps


async def verify_github_token(token: str) -> VerificationResult:
    """Verify GitHub token by calling /user endpoint (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.get("https://api.github.com/user", headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            })

        if r.status_code == 200:
            data = r.json()
            user = data.get("login", "?")
            scopes_raw = r.headers.get("X-OAuth-Scopes", "")
            scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()]
            # Risk classification: repo / admin:* / delete_repo / workflow
            # are all blast-radius critical. Fine-grained tokens return no
            # classic scopes but are still real credentials (medium).
            risky_scopes = {"repo", "admin:org", "admin:enterprise",
                            "delete_repo", "workflow", "admin:gpg_key",
                            "admin:public_key", "admin:repo_hook"}
            has_risky = any(s in risky_scopes for s in scopes)
            risk = "critical" if has_risky else ("medium" if scopes else "medium")
            detail = {
                "scopes": scopes,
                "identity": user,
                "account_id": str(data.get("id", "")),
                "risk_level": risk,
                "is_production": True,  # GitHub tokens are always live
                "extra": {
                    "name": data.get("name") or "",
                    "email": data.get("email") or "",
                    "type": data.get("type") or "User",
                },
            }

            # B4: opt-in capability enumeration — additional read-only
            # calls to discover concrete blast-radius (repo / org counts
            # and sample names). Errors are absorbed internally; degrades
            # to scopes-only B1 output.
            if _ENUMERATE_ENABLED:
                try:
                    caps = await _enumerate_github_capabilities(token)
                    if caps:
                        detail["capabilities"] = caps
                except Exception as ee:
                    logger.debug("github_enumeration_failed", error=str(ee)[:150])

            result = VerificationResult(
                status="active",
                details=f"Authenticated as: {user}",
                provider="github",
                permissions=f"Scopes: {scopes_raw or 'fine-grained or none'}",
                permissions_detail=detail,
                risk_level=risk,
            )
            result.blast_radius_summary = summarize_blast_radius("github", detail)
            return result
        elif _is_rate_limited(r, "github"):
            # GitHub returns 403 for both rate-limit and bad-token; the
            # X-RateLimit-Remaining header disambiguates. _is_rate_limited
            # handles that so we never mark a live token inactive during
            # a rate-limit window.
            return _rate_limited_result("github", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Token rejected by GitHub", provider="github")
        else:
            return VerificationResult(status="error", details=f"GitHub returned HTTP {r.status_code}", provider="github")

    except Exception as e:
        return _error_result(e, "github")


async def verify_gitlab_token(token: str) -> VerificationResult:
    """Verify GitLab token by calling /api/v4/user (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.get("https://gitlab.com/api/v4/user", headers={
                "PRIVATE-TOKEN": token,
            })

        if r.status_code == 200:
            data = r.json()
            user = data.get("username", "?")
            # GitLab /user response includes bot flag + admin flag. Scope
            # list is only returned on /personal_access_tokens/self which
            # requires a separate call; we gather what /user provides.
            is_admin = bool(data.get("is_admin", False))
            is_bot = bool(data.get("bot", False))
            # Without a scope call we classify by identity role: admin
            # tokens are critical, bot tokens are usually high (full API
            # where granted), regular users are medium.
            risk = "critical" if is_admin else ("high" if not is_bot else "medium")
            detail = {
                "scopes": [],  # not available from /user endpoint
                "identity": user,
                "account_id": str(data.get("id", "")),
                "risk_level": risk,
                "is_production": True,
                "extra": {
                    "name": data.get("name") or "",
                    "email": data.get("email") or "",
                    "is_admin": is_admin,
                    "is_bot": is_bot,
                    "state": data.get("state") or "",
                },
            }

            # B4: opt-in GitLab capability enumeration.
            if _ENUMERATE_ENABLED:
                try:
                    caps = await _enumerate_gitlab_capabilities(token)
                    if caps:
                        detail["capabilities"] = caps
                except Exception as ee:
                    logger.debug("gitlab_enumeration_failed", error=str(ee)[:150])

            result = VerificationResult(
                status="active", details=f"Authenticated as: {user}", provider="gitlab",
                permissions=f"User: {user}" + (" (admin)" if is_admin else ""),
                permissions_detail=detail, risk_level=risk,
            )
            result.blast_radius_summary = summarize_blast_radius("gitlab", detail)
            return result
        elif _is_rate_limited(r, "gitlab"):
            return _rate_limited_result("gitlab", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Token rejected by GitLab", provider="gitlab")
        else:
            return VerificationResult(status="error", details=f"GitLab returned HTTP {r.status_code}", provider="gitlab")

    except Exception as e:
        return _error_result(e, "gitlab")


async def verify_slack_token(token: str) -> VerificationResult:
    """Verify Slack token by calling auth.test (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.post("https://slack.com/api/auth.test", headers={
                "Authorization": f"Bearer {token}",
            })

        if _is_rate_limited(r, "slack"):
            # Slack returns 429 with Retry-After during burst windows;
            # don't mark the token inactive.
            return _rate_limited_result("slack", r)
        data = r.json()
        if data.get("ok"):
            team = data.get("team", "?")
            user = data.get("user", "?")
            # Slack tokens starting with xoxb- are bots (limited); xoxp-
            # are user tokens (broad). Capture both signals.
            is_bot = bool(data.get("bot_id"))
            detail = {
                "scopes": [],  # auth.test doesn't return scopes
                "identity": team,
                "account_id": data.get("team_id", ""),
                "risk_level": "high" if not is_bot else "medium",
                "is_production": True,
                "extra": {
                    "team": team,
                    "user": user,
                    "user_id": data.get("user_id", ""),
                    "is_bot": is_bot,
                    "url": data.get("url", ""),
                },
            }
            result = VerificationResult(
                status="active",
                details=f"Workspace: {team}, User: {user}",
                provider="slack",
                permissions=f"Team: {team}",
                permissions_detail=detail,
                risk_level=detail["risk_level"],
            )
            result.blast_radius_summary = summarize_blast_radius("slack", detail)
            return result
        else:
            error = data.get("error", "unknown")
            # Slack also communicates rate-limit via `error` field rather
            # than HTTP status on some endpoints.
            if error in ("ratelimited", "rate_limited"):
                return VerificationResult(
                    status="error",
                    details=f"[transient] Slack rate-limited ({error})",
                    provider="slack",
                    transient=True,
                )
            if error in ("invalid_auth", "account_inactive", "token_revoked"):
                return VerificationResult(status="inactive", details=f"Slack auth failed: {error}", provider="slack")
            return VerificationResult(status="error", details=f"Slack error: {error}", provider="slack")

    except Exception as e:
        return _error_result(e, "slack")


async def verify_stripe_key(key: str) -> VerificationResult:
    """Verify Stripe key by calling /v1/charges?limit=1 (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.get("https://api.stripe.com/v1/charges?limit=1", headers={
                "Authorization": f"Bearer {key}",
            })

        if r.status_code == 200:
            key_type = "live" if key.startswith("sk_live") else "test"
            is_production = key_type == "live"
            # Live secret keys = customer data + payments = critical.
            # Test keys are sandboxed and pose no production risk.
            risk = "critical" if is_production else "low"
            detail = {
                "scopes": ["full_access"],  # Stripe sk_ keys are all-or-nothing
                "identity": "stripe_account",
                "risk_level": risk,
                "is_production": is_production,
                "extra": {"key_type": key_type, "prefix": key[:8]},
            }
            result = VerificationResult(
                status="active",
                details=f"Stripe {key_type} key is active",
                provider="stripe",
                permissions=f"Key type: {key_type}",
                permissions_detail=detail,
                risk_level=risk,
            )
            result.blast_radius_summary = summarize_blast_radius("stripe", detail)
            return result
        elif _is_rate_limited(r, "stripe"):
            return _rate_limited_result("stripe", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Stripe key rejected", provider="stripe")
        else:
            return VerificationResult(status="error", details=f"Stripe returned HTTP {r.status_code}", provider="stripe")

    except Exception as e:
        return _error_result(e, "stripe")


async def verify_sendgrid_key(key: str) -> VerificationResult:
    """Verify SendGrid key by calling /v3/scopes (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.get("https://api.sendgrid.com/v3/scopes", headers={
                "Authorization": f"Bearer {key}",
            })

        if r.status_code == 200:
            scopes = r.json().get("scopes", [])
            # mail.send is the highest-value scope (can send email from the
            # verified domain). admin scopes are critical (can modify other
            # API keys). Template scopes are lower risk.
            has_mail_send = "mail.send" in scopes
            has_admin = any(s.startswith("admin.") or s == "user.api_keys.update" for s in scopes)
            if has_admin:
                risk = "critical"
            elif has_mail_send:
                risk = "high"
            elif scopes:
                risk = "medium"
            else:
                risk = "low"
            detail = {
                "scopes": scopes,
                "identity": "sendgrid_account",
                "risk_level": risk,
                "is_production": True,
                "extra": {"scope_count": len(scopes)},
            }
            result = VerificationResult(
                status="active",
                details=f"SendGrid key active with {len(scopes)} scopes",
                provider="sendgrid",
                permissions=f"{len(scopes)} scopes",
                permissions_detail=detail, risk_level=risk,
            )
            result.blast_radius_summary = summarize_blast_radius("sendgrid", detail)
            return result
        elif _is_rate_limited(r, "sendgrid"):
            return _rate_limited_result("sendgrid", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="SendGrid key rejected", provider="sendgrid")
        else:
            return VerificationResult(status="error", details=f"SendGrid returned HTTP {r.status_code}", provider="sendgrid")

    except Exception as e:
        return _error_result(e, "sendgrid")


async def verify_twilio_key(account_sid: str, auth_token: str) -> VerificationResult:
    """Verify Twilio credentials by calling /Accounts (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.get(
                f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json",
                auth=(account_sid, auth_token),
            )

        if r.status_code == 200:
            data = r.json()
            name = data.get("friendly_name", "?")
            account_type = data.get("type", "")  # "Trial" or "Full"
            status_val = data.get("status", "")  # "active" / "suspended" / "closed"
            # Twilio master auth_token has full account access: send SMS,
            # make calls, access logs, billing. Always high risk. Trial
            # accounts are bounded by trial credit (still high, not
            # critical — capped blast radius).
            risk = "high"
            detail = {
                "scopes": [],
                "identity": account_sid,
                "account_id": account_sid,
                "risk_level": risk,
                "is_production": account_type != "Trial",
                "extra": {
                    "friendly_name": name,
                    "type": account_type,
                    "status": status_val,
                },
            }
            result = VerificationResult(
                status="active", details=f"Account: {name}", provider="twilio",
                permissions=f"Account: {account_sid}",
                permissions_detail=detail, risk_level=risk,
            )
            result.blast_radius_summary = summarize_blast_radius("twilio", detail)
            return result
        elif _is_rate_limited(r, "twilio"):
            return _rate_limited_result("twilio", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Twilio credentials rejected", provider="twilio")
        else:
            return VerificationResult(status="error", details=f"Twilio returned HTTP {r.status_code}", provider="twilio")

    except Exception as e:
        return _error_result(e, "twilio")


async def verify_anthropic_key(key: str) -> VerificationResult:
    """Verify Anthropic API key by calling /v1/models (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.get("https://api.anthropic.com/v1/models", headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
            })

        if r.status_code == 200:
            model_count = len(r.json().get("data", []))
            # Anthropic keys are billing-attached. sk-ant-admin01-* are
            # admin keys with API-key management rights — upgrade risk.
            is_admin = key.startswith("sk-ant-admin01-")
            risk = "critical" if is_admin else "high"
            detail = {
                "scopes": ["admin"] if is_admin else ["inference"],
                "identity": "anthropic_account",
                "risk_level": risk,
                "is_production": True,  # Anthropic has no test-mode keys
                "extra": {
                    "model_count": model_count,
                    "is_admin_key": is_admin,
                    "key_prefix": key[:16],
                },
            }
            result = VerificationResult(
                status="active",
                details=f"Anthropic API key active, {model_count} models accessible",
                provider="anthropic",
                permissions=f"{model_count} models" + (" (admin key)" if is_admin else ""),
                permissions_detail=detail, risk_level=risk,
            )
            result.blast_radius_summary = summarize_blast_radius("anthropic", detail)
            return result
        elif _is_rate_limited(r, "anthropic"):
            return _rate_limited_result("anthropic", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Anthropic key rejected", provider="anthropic")
        else:
            return VerificationResult(status="error", details=f"Anthropic returned HTTP {r.status_code}", provider="anthropic")

    except Exception as e:
        return _error_result(e, "anthropic")


async def verify_openai_key(key: str) -> VerificationResult:
    """Verify OpenAI API key by calling /v1/models (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.get("https://api.openai.com/v1/models", headers={
                "Authorization": f"Bearer {key}",
            })

        if r.status_code == 200:
            model_count = len(r.json().get("data", []))
            # OpenAI key prefixes:
            #   sk-svcacct-*  service-account key (bound to project)
            #   sk-proj-*     project-scoped user key
            #   sk-admin-*    organization admin key (manages keys + billing)
            #   sk-*          classic user key
            if key.startswith("sk-admin-"):
                key_type, risk = "admin", "critical"
            elif key.startswith("sk-proj-"):
                key_type, risk = "project", "high"
            elif key.startswith("sk-svcacct-"):
                key_type, risk = "service_account", "high"
            else:
                key_type, risk = "user", "high"
            detail = {
                "scopes": ["admin"] if key_type == "admin" else ["inference"],
                "identity": "openai_account",
                "risk_level": risk,
                "is_production": True,  # OpenAI has no test-mode sandbox
                "extra": {
                    "key_type": key_type,
                    "model_count": model_count,
                    "key_prefix": key[:13],
                },
            }
            result = VerificationResult(
                status="active",
                details=f"OpenAI {key_type} key active, {model_count} models accessible",
                provider="openai",
                permissions=f"{key_type} scope, {model_count} models",
                permissions_detail=detail, risk_level=risk,
            )
            result.blast_radius_summary = summarize_blast_radius("openai", detail)
            return result
        elif _is_rate_limited(r, "openai"):
            return _rate_limited_result("openai", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="OpenAI key rejected", provider="openai")
        else:
            return VerificationResult(status="error", details=f"OpenAI returned HTTP {r.status_code}", provider="openai")

    except Exception as e:
        return _error_result(e, "openai")


async def verify_cloudflare_token(token: str) -> VerificationResult:
    """Verify Cloudflare API token by calling /user/tokens/verify (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.get("https://api.cloudflare.com/client/v4/user/tokens/verify", headers={
                "Authorization": f"Bearer {token}",
            })

        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                result_data = data.get("result", {})
                token_status = result_data.get("status", "unknown")
                token_id = result_data.get("id", "")
                expires_on = result_data.get("expires_on")  # ISO timestamp or None
                not_before = result_data.get("not_before")
                detail = {
                    "scopes": [],  # granular policy not exposed at /verify;
                                    # would need /user/tokens/{id} for that
                    "identity": token_id,
                    "account_id": token_id,
                    # Cloudflare tokens can range from read-only (low) to
                    # full zone-edit (critical). Without /user/tokens/{id}
                    # we can't distinguish — default to high.
                    "risk_level": "high",
                    "is_production": True,
                    "extra": {
                        "token_status": token_status,
                        "expires_on": expires_on,
                        "not_before": not_before,
                    },
                }
                result = VerificationResult(
                    status="active",
                    details=f"Cloudflare token active (status: {token_status})",
                    provider="cloudflare",
                    permissions=f"Token id: {token_id[:12]}",
                    permissions_detail=detail,
                    risk_level="high",
                )
                result.blast_radius_summary = summarize_blast_radius("cloudflare", detail)
                return result
            return VerificationResult(status="inactive", details="Cloudflare token not valid", provider="cloudflare")
        if _is_rate_limited(r, "cloudflare"):
            return _rate_limited_result("cloudflare", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Cloudflare token rejected", provider="cloudflare")
        else:
            return VerificationResult(status="error", details=f"Cloudflare returned HTTP {r.status_code}", provider="cloudflare")

    except Exception as e:
        return _error_result(e, "cloudflare")


async def verify_datadog_key(api_key: str) -> VerificationResult:
    """Verify Datadog API key by calling /api/v1/validate (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.get("https://api.datadoghq.com/api/v1/validate", headers={
                "DD-API-KEY": api_key,
            })

        if r.status_code == 200:
            valid = r.json().get("valid", False)
            if valid:
                # The /validate endpoint accepts both API keys (32 hex
                # chars) and App keys (40 chars). We get the length from
                # the caller so surface it in extra.
                key_type = "App" if len(api_key) >= 40 else "API"
                detail = {
                    "scopes": ["metrics.ingest"] if key_type == "API" else ["metrics.ingest", "metrics.query", "logs.query", "dashboards.read"],
                    "identity": "datadog_account",
                    "risk_level": "high" if key_type == "App" else "medium",
                    "is_production": True,
                    "extra": {"key_type": key_type},
                }
                result = VerificationResult(
                    status="active",
                    details=f"Datadog {key_type} key valid",
                    provider="datadog",
                    permissions=f"{key_type} key scope",
                    permissions_detail=detail,
                    risk_level=detail["risk_level"],
                )
                result.blast_radius_summary = summarize_blast_radius("datadog", detail)
                return result
            return VerificationResult(status="inactive", details="Datadog key not valid", provider="datadog")
        if _is_rate_limited(r, "datadog"):
            return _rate_limited_result("datadog", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Datadog key rejected", provider="datadog")
        else:
            return VerificationResult(status="error", details=f"Datadog returned HTTP {r.status_code}", provider="datadog")

    except Exception as e:
        return _error_result(e, "datadog")


async def verify_pagerduty_token(token: str) -> VerificationResult:
    """Verify PagerDuty API token by calling /abilities (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.get("https://api.pagerduty.com/abilities", headers={
                "Authorization": f"Token token={token}",
                "Accept": "application/vnd.pagerduty+json;version=2",
            })

        if r.status_code == 200:
            abilities = r.json().get("abilities", [])
            detail = {
                "scopes": abilities[:20],  # cap for storage
                "identity": "pagerduty_account",
                "risk_level": "high",  # can trigger/ack/resolve incidents
                "is_production": True,
                "extra": {
                    "abilities_count": len(abilities),
                    "has_teams": "teams" in abilities,
                    "has_oncall_management": "urgency_management" in abilities,
                },
            }
            result = VerificationResult(
                status="active",
                details=f"PagerDuty token active, {len(abilities)} abilities",
                provider="pagerduty",
                permissions=f"{len(abilities)} abilities",
                permissions_detail=detail,
                risk_level="high",
            )
            result.blast_radius_summary = summarize_blast_radius("pagerduty", detail)
            return result
        if _is_rate_limited(r, "pagerduty"):
            return _rate_limited_result("pagerduty", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="PagerDuty token rejected", provider="pagerduty")
        else:
            return VerificationResult(status="error", details=f"PagerDuty returned HTTP {r.status_code}", provider="pagerduty")

    except Exception as e:
        return _error_result(e, "pagerduty")


async def verify_npm_token(token: str) -> VerificationResult:
    """Verify NPM access token by calling /-/whoami (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.get("https://registry.npmjs.org/-/whoami", headers={
                "Authorization": f"Bearer {token}",
            })

        if r.status_code == 200:
            username = r.json().get("username", "?")
            return VerificationResult(
                status="active",
                details=f"NPM token active, user: {username}",
                provider="npm",
                permissions=f"user: {username}",
            )
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="NPM token rejected", provider="npm")
        else:
            return VerificationResult(status="error", details=f"NPM returned HTTP {r.status_code}", provider="npm")

    except Exception as e:
        return _error_result(e, "npm")


async def verify_dockerhub_token(token: str) -> VerificationResult:
    """Verify DockerHub access token by calling /v2/user (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            # DockerHub personal access tokens use JWT header with the raw token as bearer
            r = await client.get("https://hub.docker.com/v2/user/", headers={
                "Authorization": f"Bearer {token}",
            })

        if r.status_code == 200:
            body = r.json()
            username = body.get("username", "?")
            detail = {
                "scopes": [],
                "identity": username,
                "account_id": str(body.get("id", "")),
                # Image-publish access is supply-chain-critical: a leaked
                # token can push a malicious tag that a downstream pull
                # inherits automatically.
                "risk_level": "critical",
                "is_production": True,
                "extra": {
                    "full_name": body.get("full_name", ""),
                    "type": body.get("type", ""),
                    "verified": body.get("is_admin", False),
                },
            }
            result = VerificationResult(
                status="active",
                details=f"DockerHub token active, user: {username}",
                provider="dockerhub",
                permissions=f"user: {username}",
                permissions_detail=detail,
                risk_level="critical",
            )
            result.blast_radius_summary = summarize_blast_radius("dockerhub", detail)
            return result
        if _is_rate_limited(r, "dockerhub"):
            return _rate_limited_result("dockerhub", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="DockerHub token rejected", provider="dockerhub")
        else:
            return VerificationResult(status="error", details=f"DockerHub returned HTTP {r.status_code}", provider="dockerhub")

    except Exception as e:
        return _error_result(e, "dockerhub")


async def verify_heroku_token(token: str) -> VerificationResult:
    """Verify Heroku API key by calling /account (read-only)."""
    try:
        import httpx
        async with verification_client(timeout=10) as client:
            r = await client.get("https://api.heroku.com/account", headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.heroku+json; version=3",
            })

        if r.status_code == 200:
            data = r.json()
            email = data.get("email", "?")
            mfa = bool(data.get("two_factor_authentication", False))
            detail = {
                "scopes": [],  # Heroku API keys are all-or-nothing
                "identity": email,
                "account_id": str(data.get("id", "")),
                "risk_level": "critical",  # full app deploy + config access
                "is_production": True,
                "extra": {
                    "two_factor": mfa,
                    "verified": data.get("verified", False),
                    "suspended_at": data.get("suspended_at"),
                },
            }
            result = VerificationResult(
                status="active",
                details=f"Heroku token active, account: {email}",
                provider="heroku",
                permissions=f"account: {email}",
                permissions_detail=detail,
                risk_level="critical",
            )
            result.blast_radius_summary = summarize_blast_radius("heroku", detail)
            return result
        if _is_rate_limited(r, "heroku"):
            return _rate_limited_result("heroku", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Heroku token rejected", provider="heroku")
        else:
            return VerificationResult(status="error", details=f"Heroku returned HTTP {r.status_code}", provider="heroku")

    except Exception as e:
        return _error_result(e, "heroku")


async def verify_okta_token(token: str, domain: str = "") -> VerificationResult:
    """Verify Okta API token by calling /api/v1/users/me (read-only).

    Okta domain is tenant-specific — if not provided, we can't verify.
    domain should be like 'yourcompany.okta.com' (without scheme).
    """
    try:
        if not domain:
            # Can't verify without tenant domain — Okta tokens are tenant-scoped
            return VerificationResult(
                status="unsupported",
                details="Okta verification requires tenant domain (not extracted)",
                provider="okta",
            )
        import httpx
        url = f"https://{domain}/api/v1/users/me"
        async with verification_client(timeout=10) as client:
            r = await client.get(url, headers={
                "Authorization": f"SSWS {token}",
                "Accept": "application/json",
            })

        if r.status_code == 200:
            profile = r.json().get("profile", {})
            login = profile.get("login", "?")
            return VerificationResult(
                status="active",
                details=f"Okta token active, user: {login} @ {domain}",
                provider="okta",
                permissions=f"user: {login}",
            )
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Okta token rejected", provider="okta")
        else:
            return VerificationResult(status="error", details=f"Okta returned HTTP {r.status_code}", provider="okta")

    except Exception as e:
        return _error_result(e, "okta")


async def verify_auth0_token(token: str, domain: str = "") -> VerificationResult:
    """Verify Auth0 Management API token by calling /api/v2/users (read-only).

    Like Okta, Auth0 is tenant-scoped — needs the tenant domain.
    domain should be like 'yourtenant.auth0.com'.
    """
    try:
        if not domain:
            return VerificationResult(
                status="unsupported",
                details="Auth0 verification requires tenant domain (not extracted)",
                provider="auth0",
            )
        import httpx
        url = f"https://{domain}/api/v2/users?per_page=1"
        async with verification_client(timeout=10) as client:
            r = await client.get(url, headers={
                "Authorization": f"Bearer {token}",
            })

        if r.status_code == 200:
            return VerificationResult(
                status="active",
                details=f"Auth0 Management API token active @ {domain}",
                provider="auth0",
                permissions=f"tenant: {domain}",
            )
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Auth0 token rejected", provider="auth0")
        else:
            return VerificationResult(status="error", details=f"Auth0 returned HTTP {r.status_code}", provider="auth0")

    except Exception as e:
        return _error_result(e, "auth0")


# ── Stage 2: Additional SaaS / Dev-tool verifiers ─────────────
# Each follows the same read-only single-call pattern.


async def verify_vercel_token(token: str) -> VerificationResult:
    """GET /v2/user — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.vercel.com/v2/user", headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json().get("user", {})
            username = data.get("username", "?")
            email = data.get("email", "?")
            detail = {
                "scopes": [],  # Vercel PATs inherit the user's org membership
                "identity": username,
                "account_id": str(data.get("id", "")),
                "risk_level": "critical",  # deploy + env-var control
                "is_production": True,
                "extra": {
                    "email": email,
                    "name": data.get("name", ""),
                    "username": username,
                },
            }
            result = VerificationResult(status="active",
                details=f"Vercel token active, user: {username}",
                provider="vercel",
                permissions=f"email: {email}",
                permissions_detail=detail, risk_level="critical")
            result.blast_radius_summary = summarize_blast_radius("vercel", detail)
            return result
        if _is_rate_limited(r, "vercel"):
            return _rate_limited_result("vercel", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Vercel token rejected", provider="vercel")
        return VerificationResult(status="error", details=f"Vercel HTTP {r.status_code}", provider="vercel")
    except Exception as e:
        return _error_result(e, "vercel")


async def verify_netlify_token(token: str) -> VerificationResult:
    """GET /api/v1/user — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.netlify.com/api/v1/user", headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Netlify token active, user: {data.get('email', '?')}",
                provider="netlify", permissions=f"id: {data.get('id', '')[:12]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Netlify token rejected", provider="netlify")
        return VerificationResult(status="error", details=f"Netlify HTTP {r.status_code}", provider="netlify")
    except Exception as e:
        return _error_result(e, "netlify")


async def verify_linear_token(token: str) -> VerificationResult:
    """POST /graphql { viewer { id, email } } — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.post("https://api.linear.app/graphql",
                headers={"Authorization": token, "Content-Type": "application/json"},
                json={"query": "{ viewer { id email name } }"})
        if r.status_code == 200:
            data = r.json().get("data", {}).get("viewer", {})
            if data.get("id"):
                email = data.get("email", "?")
                name = data.get("name", "")
                detail = {
                    "scopes": [],
                    "identity": email,
                    "account_id": str(data.get("id", "")),
                    "risk_level": "high",
                    "is_production": True,
                    "extra": {"name": name},
                }
                result = VerificationResult(status="active",
                    details=f"Linear token active, user: {email}",
                    provider="linear", permissions=f"user id: {data.get('id', '')[:12]}",
                    permissions_detail=detail, risk_level="high")
                result.blast_radius_summary = summarize_blast_radius("linear", detail)
                return result
            return VerificationResult(status="inactive", details="Linear: no viewer in response", provider="linear")
        if _is_rate_limited(r, "linear"):
            return _rate_limited_result("linear", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Linear token rejected", provider="linear")
        return VerificationResult(status="error", details=f"Linear HTTP {r.status_code}", provider="linear")
    except Exception as e:
        return _error_result(e, "linear")


async def verify_notion_token(token: str) -> VerificationResult:
    """GET /v1/users/me — Bearer + Notion-Version header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.notion.com/v1/users/me", headers={
                "Authorization": f"Bearer {token}",
                "Notion-Version": "2022-06-28",
            })
        if r.status_code == 200:
            data = r.json()
            name = data.get("name", "?")
            user_type = data.get("type", "")  # "person" or "bot"
            bot = data.get("bot", {}) if isinstance(data.get("bot"), dict) else {}
            owner = bot.get("owner", {}) if isinstance(bot.get("owner"), dict) else {}
            owner_type = owner.get("type", "")  # "workspace" or "user"
            workspace_name = bot.get("workspace_name", "")
            # Workspace-scoped integrations have wider blast radius than
            # user-scoped — critical vs high.
            risk = "critical" if owner_type == "workspace" else "high"
            detail = {
                "scopes": [],
                "identity": name,
                "account_id": str(data.get("id", "")),
                "risk_level": risk,
                "is_production": True,
                "extra": {
                    "user_type": user_type,
                    "owner_type": owner_type,
                    "workspace_name": workspace_name,
                },
            }
            result = VerificationResult(status="active",
                details=f"Notion token active, user: {name}",
                provider="notion", permissions=f"bot id: {data.get('id', '')[:12]}",
                permissions_detail=detail, risk_level=risk)
            result.blast_radius_summary = summarize_blast_radius("notion", detail)
            return result
        if _is_rate_limited(r, "notion"):
            return _rate_limited_result("notion", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Notion token rejected", provider="notion")
        return VerificationResult(status="error", details=f"Notion HTTP {r.status_code}", provider="notion")
    except Exception as e:
        return _error_result(e, "notion")


async def verify_asana_token(token: str) -> VerificationResult:
    """GET /api/1.0/users/me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://app.asana.com/api/1.0/users/me", headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json().get("data", {})
            email = data.get("email", "?")
            workspaces = data.get("workspaces", []) or []
            detail = {
                "scopes": [],
                "identity": email,
                "account_id": str(data.get("gid", "")),
                "risk_level": "medium",  # project/task access, no billing
                "is_production": True,
                "extra": {
                    "name": data.get("name", ""),
                    "workspace_count": len(workspaces),
                    "sample_workspaces": [w.get("name", "") for w in workspaces[:3]],
                },
            }
            result = VerificationResult(status="active",
                details=f"Asana token active, user: {email}",
                provider="asana",
                permissions=f"workspaces: {len(workspaces)}",
                permissions_detail=detail, risk_level="medium")
            result.blast_radius_summary = summarize_blast_radius("asana", detail)
            return result
        if _is_rate_limited(r, "asana"):
            return _rate_limited_result("asana", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Asana token rejected", provider="asana")
        return VerificationResult(status="error", details=f"Asana HTTP {r.status_code}", provider="asana")
    except Exception as e:
        return _error_result(e, "asana")


async def verify_circleci_token(token: str) -> VerificationResult:
    """GET /api/v2/me — Circle-Token header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://circleci.com/api/v2/me", headers={"Circle-Token": token})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"CircleCI token active, user: {data.get('login', '?')}",
                provider="circleci", permissions=f"id: {data.get('id', '')[:12]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="CircleCI token rejected", provider="circleci")
        return VerificationResult(status="error", details=f"CircleCI HTTP {r.status_code}", provider="circleci")
    except Exception as e:
        return _error_result(e, "circleci")


async def verify_figma_token(token: str) -> VerificationResult:
    """GET /v1/me — X-Figma-Token header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.figma.com/v1/me", headers={"X-Figma-Token": token})
        if r.status_code == 200:
            data = r.json()
            email = data.get("email", "?")
            handle = data.get("handle", "?")
            detail = {
                "scopes": [],
                "identity": email,
                "account_id": str(data.get("id", "")),
                # Figma tokens are read-heavy (files + comments) — design
                # data is sensitive but lower blast radius than infra or
                # billing-linked keys.
                "risk_level": "medium",
                "is_production": True,
                "extra": {"handle": handle, "img_url": data.get("img_url", "")},
            }
            result = VerificationResult(status="active",
                details=f"Figma token active, user: {email}",
                provider="figma",
                permissions=f"handle: {handle}",
                permissions_detail=detail, risk_level="medium")
            result.blast_radius_summary = summarize_blast_radius("figma", detail)
            return result
        if _is_rate_limited(r, "figma"):
            return _rate_limited_result("figma", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Figma token rejected", provider="figma")
        return VerificationResult(status="error", details=f"Figma HTTP {r.status_code}", provider="figma")
    except Exception as e:
        return _error_result(e, "figma")


async def verify_clickup_token(token: str) -> VerificationResult:
    """GET /api/v2/user — raw token in Authorization header (no Bearer prefix)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.clickup.com/api/v2/user", headers={"Authorization": token})
        if r.status_code == 200:
            data = r.json().get("user", {})
            return VerificationResult(status="active",
                details=f"ClickUp token active, user: {data.get('username', '?')}",
                provider="clickup", permissions=f"email: {data.get('email', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="ClickUp token rejected", provider="clickup")
        return VerificationResult(status="error", details=f"ClickUp HTTP {r.status_code}", provider="clickup")
    except Exception as e:
        return _error_result(e, "clickup")


async def verify_discord_bot_token(token: str) -> VerificationResult:
    """GET /users/@me — Bot {token}."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://discord.com/api/v10/users/@me", headers={"Authorization": f"Bot {token}"})
        if r.status_code == 200:
            data = r.json()
            username = data.get("username", "?")
            discrim = data.get("discriminator", "0000")
            identity = f"{username}#{discrim}" if discrim != "0" else username
            # Discord bot flags (raw bitfield). Presence = privileged bot.
            flags = data.get("flags", 0)
            is_verified = bool(flags & (1 << 16))  # VERIFIED_BOT flag
            detail = {
                "scopes": [],  # Discord gates via OAuth2 scopes at invite
                "identity": identity,
                "account_id": str(data.get("id", "")),
                "risk_level": "high",
                "is_production": True,
                "extra": {
                    "username": username,
                    "bot_verified": is_verified,
                    "flags": flags,
                },
            }
            result = VerificationResult(status="active",
                details=f"Discord bot active: {identity}",
                provider="discord", permissions=f"bot id: {data.get('id', '')[:18]}",
                permissions_detail=detail, risk_level="high")
            result.blast_radius_summary = summarize_blast_radius("discord", detail)
            return result
        if _is_rate_limited(r, "discord"):
            return _rate_limited_result("discord", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Discord bot token rejected", provider="discord")
        return VerificationResult(status="error", details=f"Discord HTTP {r.status_code}", provider="discord")
    except Exception as e:
        return _error_result(e, "discord")


async def verify_telegram_bot_token(token: str) -> VerificationResult:
    """GET /bot{token}/getMe."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.telegram.org/bot{token}/getMe")
        if r.status_code == 200:
            data = r.json()
            if data.get("ok"):
                u = data.get("result", {})
                return VerificationResult(status="active",
                    details=f"Telegram bot active: @{u.get('username', '?')}",
                    provider="telegram", permissions=f"bot name: {u.get('first_name', '?')}")
            return VerificationResult(status="inactive", details=f"Telegram: {data.get('description','?')}", provider="telegram")
        elif r.status_code in (401, 403, 404):
            return VerificationResult(status="inactive", details="Telegram bot token rejected", provider="telegram")
        return VerificationResult(status="error", details=f"Telegram HTTP {r.status_code}", provider="telegram")
    except Exception as e:
        return _error_result(e, "telegram")


async def verify_bitbucket_token(token: str) -> VerificationResult:
    """GET /2.0/user — Bearer (app password format: user:token, but bearer works too)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.bitbucket.org/2.0/user", headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            username = data.get("username", "?")
            detail = {
                "scopes": [],  # app-password scopes aren't exposed via /user
                "identity": username,
                "account_id": str(data.get("uuid", "")),
                # Similar blast radius to GitHub/GitLab tokens: repo-scoped
                # access including private code. High (not critical because
                # it can't self-escalate billing).
                "risk_level": "high",
                "is_production": True,
                "extra": {
                    "display_name": data.get("display_name", ""),
                    "type": data.get("type", ""),
                    "nickname": data.get("nickname", ""),
                    "account_status": data.get("account_status", ""),
                },
            }
            result = VerificationResult(status="active",
                details=f"Bitbucket token active, user: {username}",
                provider="bitbucket",
                permissions=f"id: {data.get('uuid', '')[:18]}",
                permissions_detail=detail, risk_level="high")
            result.blast_radius_summary = summarize_blast_radius("bitbucket", detail)
            return result
        if _is_rate_limited(r, "bitbucket"):
            return _rate_limited_result("bitbucket", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Bitbucket token rejected", provider="bitbucket")
        return VerificationResult(status="error", details=f"Bitbucket HTTP {r.status_code}", provider="bitbucket")
    except Exception as e:
        return _error_result(e, "bitbucket")


async def verify_mailgun_key(key: str) -> VerificationResult:
    """GET /v3/domains — HTTP Basic auth (api:key)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.mailgun.net/v3/domains?limit=1", auth=("api", key))
        if r.status_code == 200:
            items = r.json().get("items", [])
            return VerificationResult(status="active",
                details=f"Mailgun key active, {len(items)} domain(s) visible",
                provider="mailgun", permissions=f"domains: {len(items)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Mailgun key rejected", provider="mailgun")
        return VerificationResult(status="error", details=f"Mailgun HTTP {r.status_code}", provider="mailgun")
    except Exception as e:
        return _error_result(e, "mailgun")


async def verify_mailchimp_key(key: str) -> VerificationResult:
    """GET /3.0/ping — Basic auth (anystring:key), DC from key suffix."""
    try:
        if "-" not in key:
            return VerificationResult(status="error", details="Mailchimp key missing -<dc> suffix", provider="mailchimp")
        dc = key.rsplit("-", 1)[-1]
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://{dc}.api.mailchimp.com/3.0/ping", auth=("anystring", key))
        if r.status_code == 200:
            return VerificationResult(status="active",
                details=f"Mailchimp key active (datacenter {dc})",
                provider="mailchimp", permissions=f"dc: {dc}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Mailchimp key rejected", provider="mailchimp")
        return VerificationResult(status="error", details=f"Mailchimp HTTP {r.status_code}", provider="mailchimp")
    except Exception as e:
        return _error_result(e, "mailchimp")


async def verify_cohere_key(key: str) -> VerificationResult:
    """POST /v1/check-api-key — Bearer. Cohere returns 200 with {valid:false} for bad keys.

    POST is correct and non-destructive here: Cohere ships a dedicated
    /v1/check-api-key endpoint whose *sole documented purpose* is
    "checks that the api key in the Authorization header is valid and
    active." It performs no inference, mutates no state, returns only
    ``{valid, organization_name}``. Allowlisted in D1 accordingly.
    (Credit-burn audit, 2026-04-18 — every other AI verifier in this
    module uses GET; Cohere is the single POST intentionally because
    it's cheaper than listing models.)
    """
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.post("https://api.cohere.ai/v1/check-api-key", headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json()
            # Cohere returns 200 even for bad keys — inspect the `valid` field.
            if data.get("valid") is True:
                return VerificationResult(status="active",
                    details=f"Cohere key active, org: {data.get('organization_name', '?')}",
                    provider="cohere", permissions=f"valid=True")
            return VerificationResult(status="inactive",
                details="Cohere reports key is invalid", provider="cohere")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Cohere key rejected", provider="cohere")
        return VerificationResult(status="error", details=f"Cohere HTTP {r.status_code}", provider="cohere")
    except Exception as e:
        return _error_result(e, "cohere")


async def verify_replicate_token(token: str) -> VerificationResult:
    """GET /v1/account — Token {key} (not Bearer)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.replicate.com/v1/account", headers={"Authorization": f"Token {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Replicate token active, user: {data.get('username', '?')}",
                provider="replicate", permissions=f"type: {data.get('type', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Replicate token rejected", provider="replicate")
        return VerificationResult(status="error", details=f"Replicate HTTP {r.status_code}", provider="replicate")
    except Exception as e:
        return _error_result(e, "replicate")


async def verify_pinecone_key(key: str) -> VerificationResult:
    """GET /projects — Api-Key header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.pinecone.io/projects", headers={"Api-Key": key})
        if r.status_code == 200:
            projects = r.json().get("projects", [])
            return VerificationResult(status="active",
                details=f"Pinecone key active, {len(projects)} project(s)",
                provider="pinecone", permissions=f"projects: {len(projects)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Pinecone key rejected", provider="pinecone")
        return VerificationResult(status="error", details=f"Pinecone HTTP {r.status_code}", provider="pinecone")
    except Exception as e:
        return _error_result(e, "pinecone")


async def verify_coinbase_token(token: str) -> VerificationResult:
    """GET /v2/user — Bearer (modern) or CB-ACCESS-KEY (legacy). We try Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.coinbase.com/v2/user", headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json().get("data", {})
            return VerificationResult(status="active",
                details=f"Coinbase token active, user: {data.get('email', '?')}",
                provider="coinbase", permissions=f"id: {data.get('id', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Coinbase token rejected", provider="coinbase")
        return VerificationResult(status="error", details=f"Coinbase HTTP {r.status_code}", provider="coinbase")
    except Exception as e:
        return _error_result(e, "coinbase")


async def verify_clerk_key(key: str) -> VerificationResult:
    """GET /v1/users?limit=1 — Bearer sk_live_/sk_test_."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.clerk.com/v1/users?limit=1", headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            key_type = "live" if "sk_live" in key else "test"
            return VerificationResult(status="active",
                details=f"Clerk {key_type} secret key active",
                provider="clerk", permissions=f"key type: {key_type}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Clerk key rejected", provider="clerk")
        return VerificationResult(status="error", details=f"Clerk HTTP {r.status_code}", provider="clerk")
    except Exception as e:
        return _error_result(e, "clerk")


async def verify_digitalocean_token(token: str) -> VerificationResult:
    """GET /v2/account — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.digitalocean.com/v2/account", headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json().get("account", {})
            email = data.get("email", "?")
            detail = {
                "scopes": [],
                "identity": email,
                "account_id": str(data.get("uuid", "")),
                # DO personal-access tokens give full account access:
                # droplet provisioning, domain DNS, load balancers, spaces.
                # "critical" given billing + infra impact.
                "risk_level": "critical",
                "is_production": True,
                "extra": {
                    "status": data.get("status", ""),
                    "email_verified": data.get("email_verified", False),
                    "droplet_limit": data.get("droplet_limit"),
                    "volume_limit": data.get("volume_limit"),
                },
            }
            result = VerificationResult(status="active",
                details=f"DigitalOcean token active, email: {email}",
                provider="digitalocean",
                permissions=f"uuid: {data.get('uuid', '')[:18]}",
                permissions_detail=detail, risk_level="critical")
            result.blast_radius_summary = summarize_blast_radius("digitalocean", detail)
            return result
        if _is_rate_limited(r, "digitalocean"):
            return _rate_limited_result("digitalocean", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="DigitalOcean token rejected", provider="digitalocean")
        return VerificationResult(status="error", details=f"DigitalOcean HTTP {r.status_code}", provider="digitalocean")
    except Exception as e:
        return _error_result(e, "digitalocean")


async def verify_flyio_token(token: str) -> VerificationResult:
    """GET machines.dev/v1/apps — Bearer (api.fly.io returns 404 now; the modern
    Machines API host is api.machines.dev)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.machines.dev/v1/apps?org_slug=personal",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code in (200, 201):
            return VerificationResult(status="active",
                details="Fly.io token active",
                provider="flyio", permissions="apps list accessible")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Fly.io token rejected", provider="flyio")
        return VerificationResult(status="error", details=f"Fly.io HTTP {r.status_code}", provider="flyio")
    except Exception as e:
        return _error_result(e, "flyio")


async def verify_resend_key(key: str) -> VerificationResult:
    """GET /domains — Bearer. Resend returns 400 'API key is invalid' for bad keys."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.resend.com/domains", headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            doms = r.json().get("data", [])
            return VerificationResult(status="active",
                details=f"Resend key active, {len(doms)} domain(s) visible",
                provider="resend", permissions=f"domains: {len(doms)}")
        elif r.status_code in (401, 403) or (r.status_code == 400 and "invalid" in r.text.lower()):
            return VerificationResult(status="inactive", details="Resend key rejected", provider="resend")
        return VerificationResult(status="error", details=f"Resend HTTP {r.status_code}", provider="resend")
    except Exception as e:
        return _error_result(e, "resend")


async def verify_posthog_key(key: str) -> VerificationResult:
    """GET /api/users/@me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://app.posthog.com/api/users/@me/", headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"PostHog key active, user: {data.get('email', '?')}",
                provider="posthog", permissions=f"org: {data.get('organization', {}).get('name', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="PostHog key rejected", provider="posthog")
        return VerificationResult(status="error", details=f"PostHog HTTP {r.status_code}", provider="posthog")
    except Exception as e:
        return _error_result(e, "posthog")


async def verify_sentry_token(token: str) -> VerificationResult:
    """GET /api/0/ (lightweight ping) — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://sentry.io/api/0/organizations/", headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            orgs = r.json() if isinstance(r.json(), list) else []
            return VerificationResult(status="active",
                details=f"Sentry token active, {len(orgs)} org(s) visible",
                provider="sentry", permissions=f"orgs: {len(orgs)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Sentry token rejected", provider="sentry")
        return VerificationResult(status="error", details=f"Sentry HTTP {r.status_code}", provider="sentry")
    except Exception as e:
        return _error_result(e, "sentry")


async def verify_grafana_cloud_token(token: str) -> VerificationResult:
    """GET /api/orgs — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://grafana.com/api/orgs", headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            items = r.json().get("items", r.json() if isinstance(r.json(), list) else [])
            return VerificationResult(status="active",
                details=f"Grafana Cloud token active, {len(items)} org(s)",
                provider="grafana", permissions=f"orgs: {len(items)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Grafana token rejected", provider="grafana")
        return VerificationResult(status="error", details=f"Grafana HTTP {r.status_code}", provider="grafana")
    except Exception as e:
        return _error_result(e, "grafana")


async def verify_hubspot_token(token: str) -> VerificationResult:
    """GET /integrations/v1/me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.hubapi.com/integrations/v1/me", headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            portal_id = data.get("portalId", "")
            scopes = data.get("scopes", []) or []
            # HubSpot private apps list their scopes in the /me response;
            # OAuth tokens don't — absence does not imply "no scopes".
            has_write = any("write" in s for s in scopes)
            risk = "critical" if has_write else "high" if scopes else "high"
            detail = {
                "scopes": scopes[:30],  # cap for storage
                "identity": str(portal_id),
                "account_id": str(portal_id),
                "risk_level": risk,
                "is_production": True,
                "extra": {
                    "app_id": data.get("appId"),
                    "user": data.get("user"),
                    "user_id": data.get("userId"),
                    "scope_count": len(scopes),
                },
            }
            result = VerificationResult(status="active",
                details=f"HubSpot token active, portal: {portal_id}",
                provider="hubspot",
                permissions=f"hub id: {portal_id}" + (f" ({len(scopes)} scopes)" if scopes else ""),
                permissions_detail=detail, risk_level=risk)
            result.blast_radius_summary = summarize_blast_radius("hubspot", detail)
            return result
        if _is_rate_limited(r, "hubspot"):
            return _rate_limited_result("hubspot", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="HubSpot token rejected", provider="hubspot")
        return VerificationResult(status="error", details=f"HubSpot HTTP {r.status_code}", provider="hubspot")
    except Exception as e:
        return _error_result(e, "hubspot")


async def verify_intercom_token(token: str) -> VerificationResult:
    """GET /me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.intercom.io/me", headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            })
        if r.status_code == 200:
            data = r.json()
            app = data.get("app", {}) if isinstance(data.get("app"), dict) else {}
            app_name = app.get("name", "?")
            app_id = app.get("id_code", "")
            email = data.get("email", "")
            detail = {
                "scopes": [],
                "identity": email or app_name,
                "account_id": str(app_id),
                "risk_level": "high",  # full conversation + customer data access
                "is_production": True,
                "extra": {
                    "app_name": app_name,
                    "app_id_code": app_id,
                    "email": email,
                    "email_verified": data.get("email_verified", False),
                    "avatar": data.get("avatar", {}).get("image_url") if isinstance(data.get("avatar"), dict) else None,
                },
            }
            result = VerificationResult(status="active",
                details=f"Intercom token active, app: {app_name}",
                provider="intercom",
                permissions=f"id: {data.get('id', '')[:18]}",
                permissions_detail=detail, risk_level="high")
            result.blast_radius_summary = summarize_blast_radius("intercom", detail)
            return result
        if _is_rate_limited(r, "intercom"):
            return _rate_limited_result("intercom", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Intercom token rejected", provider="intercom")
        return VerificationResult(status="error", details=f"Intercom HTTP {r.status_code}", provider="intercom")
    except Exception as e:
        return _error_result(e, "intercom")


async def verify_zoom_token(token: str) -> VerificationResult:
    """GET /v2/users/me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.zoom.us/v2/users/me", headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            email = data.get("email", "?")
            user_type = data.get("type", "")  # integer type; map to label
            user_type_label = {1: "Basic", 2: "Licensed", 3: "On-Prem"}.get(user_type, str(user_type))
            detail = {
                "scopes": [],
                "identity": email,
                "account_id": str(data.get("account_id", "")),
                # Meeting + recording data is customer-sensitive; can
                # also create meetings under this user. High.
                "risk_level": "high",
                "is_production": True,
                "extra": {
                    "first_name": data.get("first_name", ""),
                    "last_name": data.get("last_name", ""),
                    "user_type": user_type_label,
                    "role_name": data.get("role_name", ""),
                    "verified": data.get("verified", 0),
                },
            }
            result = VerificationResult(status="active",
                details=f"Zoom token active, user: {email}",
                provider="zoom",
                permissions=f"account: {data.get('account_id', '')[:18]}",
                permissions_detail=detail, risk_level="high")
            result.blast_radius_summary = summarize_blast_radius("zoom", detail)
            return result
        if _is_rate_limited(r, "zoom"):
            return _rate_limited_result("zoom", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Zoom token rejected", provider="zoom")
        return VerificationResult(status="error", details=f"Zoom HTTP {r.status_code}", provider="zoom")
    except Exception as e:
        return _error_result(e, "zoom")


async def verify_zendesk_token(token: str, subdomain: str = "") -> VerificationResult:
    """GET /api/v2/users/me.json — Bearer. Tenant-scoped on subdomain."""
    try:
        if not subdomain:
            return VerificationResult(status="unsupported",
                details="Zendesk verification requires subdomain", provider="zendesk")
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://{subdomain}.zendesk.com/api/v2/users/me.json",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            user = r.json().get("user", {})
            return VerificationResult(status="active",
                details=f"Zendesk token active @ {subdomain}, user: {user.get('email', '?')}",
                provider="zendesk", permissions=f"role: {user.get('role', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Zendesk token rejected", provider="zendesk")
        return VerificationResult(status="error", details=f"Zendesk HTTP {r.status_code}", provider="zendesk")
    except Exception as e:
        return _error_result(e, "zendesk")


async def verify_shopify_token(token: str, shop_domain: str = "") -> VerificationResult:
    """GET /admin/api/2024-01/shop.json — X-Shopify-Access-Token. Tenant-scoped."""
    try:
        if not shop_domain:
            return VerificationResult(status="unsupported",
                details="Shopify verification requires shop domain (myshopify.com)", provider="shopify")
        import httpx
        async with verification_client(timeout=10, provider="shopify") as c:
            r = await c.get(f"https://{shop_domain}/admin/api/2024-01/shop.json",
                headers={"X-Shopify-Access-Token": token})
        if r.status_code == 200:
            shop = r.json().get("shop", {})
            shop_name = shop.get("name", "?")
            shop_domain_field = shop.get("domain", "?")
            plan = shop.get("plan_name", "") or shop.get("plan_display_name", "")
            detail = {
                "scopes": [],  # actual granted scopes require /admin/oauth/access_scopes
                "identity": shop_name,
                "account_id": str(shop.get("id", "")),
                # Shopify admin tokens typically carry broad scopes
                # (orders, products, customers). Critical because leaked
                # token exposes buyer PII + ability to issue refunds.
                "risk_level": "critical",
                "is_production": True,
                "extra": {
                    "shop_name": shop_name,
                    "shop_domain": shop_domain_field,
                    "myshopify_domain": shop.get("myshopify_domain", ""),
                    "plan_name": plan,
                    "country": shop.get("country_code", ""),
                    "email": shop.get("email", ""),
                },
            }
            result = VerificationResult(status="active",
                details=f"Shopify token active, shop: {shop_name}",
                provider="shopify",
                permissions=f"domain: {shop_domain_field}",
                permissions_detail=detail, risk_level="critical")
            result.blast_radius_summary = summarize_blast_radius("shopify", detail)
            return result
        if _is_rate_limited(r, "shopify"):
            return _rate_limited_result("shopify", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Shopify token rejected", provider="shopify")
        return VerificationResult(status="error", details=f"Shopify HTTP {r.status_code}", provider="shopify")
    except Exception as e:
        return _error_result(e, "shopify")


async def verify_algolia_key(key: str, app_id: str = "") -> VerificationResult:
    """GET /1/keys/{key} — X-Algolia-API-Key + X-Algolia-Application-Id. Tenant-scoped on app_id."""
    try:
        if not app_id:
            return VerificationResult(status="unsupported",
                details="Algolia verification requires application ID", provider="algolia")
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://{app_id}-dsn.algolia.net/1/keys/{key}",
                headers={"X-Algolia-API-Key": key, "X-Algolia-Application-Id": app_id})
        if r.status_code == 200:
            data = r.json()
            acl = data.get("acl", [])
            return VerificationResult(status="active",
                details=f"Algolia key active @ {app_id}",
                provider="algolia", permissions=f"acls: {','.join(acl[:5])}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Algolia key rejected", provider="algolia")
        return VerificationResult(status="error", details=f"Algolia HTTP {r.status_code}", provider="algolia")
    except Exception as e:
        return _error_result(e, "algolia")


async def verify_supabase_service_key(key: str, project_url: str = "") -> VerificationResult:
    """GET /rest/v1/ — apikey header. Tenant-scoped on project URL."""
    try:
        if not project_url:
            return VerificationResult(status="unsupported",
                details="Supabase verification requires project URL (xxx.supabase.co)", provider="supabase")
        import httpx
        async with verification_client(timeout=10, provider="supabase") as c:
            r = await c.get(f"https://{project_url}/rest/v1/", headers={"apikey": key, "Authorization": f"Bearer {key}"})
        if r.status_code in (200, 400):  # 400 is "swagger list" response — still valid auth
            return VerificationResult(status="active",
                details=f"Supabase service key active @ {project_url}",
                provider="supabase", permissions="bypasses RLS")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Supabase key rejected", provider="supabase")
        return VerificationResult(status="error", details=f"Supabase HTTP {r.status_code}", provider="supabase")
    except Exception as e:
        return _error_result(e, "supabase")


# ── Stage 2 Tier 2: AI/LLM, dev tools, observability, email ──


async def verify_huggingface_token(token: str) -> VerificationResult:
    """GET /api/whoami-v2 — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://huggingface.co/api/whoami-v2",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"HuggingFace token active, user: {data.get('name', '?')}",
                provider="huggingface", permissions=f"type: {data.get('type', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="HuggingFace token rejected", provider="huggingface")
        return VerificationResult(status="error", details=f"HuggingFace HTTP {r.status_code}", provider="huggingface")
    except Exception as e:
        return _error_result(e, "huggingface")


async def verify_mistral_key(key: str) -> VerificationResult:
    """GET /v1/models — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.mistral.ai/v1/models",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            count = len(r.json().get("data", []))
            return VerificationResult(status="active",
                details=f"Mistral key active, {count} models accessible",
                provider="mistral", permissions=f"{count} models")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Mistral key rejected", provider="mistral")
        return VerificationResult(status="error", details=f"Mistral HTTP {r.status_code}", provider="mistral")
    except Exception as e:
        return _error_result(e, "mistral")


async def verify_deepseek_key(key: str) -> VerificationResult:
    """GET /v1/user/balance — Bearer (DeepSeek's cheap no-charge endpoint)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.deepseek.com/user/balance",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"DeepSeek key active, available: {data.get('is_available', '?')}",
                provider="deepseek", permissions="account billing access")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="DeepSeek key rejected", provider="deepseek")
        return VerificationResult(status="error", details=f"DeepSeek HTTP {r.status_code}", provider="deepseek")
    except Exception as e:
        return _error_result(e, "deepseek")


async def verify_groq_key(key: str) -> VerificationResult:
    """GET /openai/v1/models — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            count = len(r.json().get("data", []))
            return VerificationResult(status="active",
                details=f"Groq key active, {count} models accessible",
                provider="groq", permissions=f"{count} models")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Groq key rejected", provider="groq")
        return VerificationResult(status="error", details=f"Groq HTTP {r.status_code}", provider="groq")
    except Exception as e:
        return _error_result(e, "groq")


async def verify_perplexity_key(key: str) -> VerificationResult:
    """POST /chat/completions (minimal probe) — Bearer.

    Earlier attempt used ``GET /v1/models`` thinking it was an auth-
    check endpoint per the docs. B3 validation (2026-04-19) proved
    it's actually **fully public** — returns the same model list for
    no auth, wrong key, right key. Could not distinguish valid from
    invalid tokens. That was a false-active bug.

    Reverted to the original inference probe: POST /chat/completions
    with ``max_tokens=1`` and a one-char prompt. Costs ~$0.0001 per
    verify (negligible compared to misclassifying a live key). 400
    with "model not found" still proves auth was accepted, so treat
    that as active too — saves the re-verify churn when model names
    change.
    """
    try:
        async with verification_client(timeout=12) as c:
            r = await c.post(
                "https://api.perplexity.ai/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": "sonar", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1},
            )
        if r.status_code == 200:
            return VerificationResult(
                status="active",
                details="Perplexity key active",
                provider="perplexity",
                permissions="chat + search",
                risk_level="high",
            )
        if _is_rate_limited(r, "perplexity"):
            return _rate_limited_result("perplexity", r)
        if r.status_code == 400:
            # Bad model name but auth was accepted — still a valid key.
            return VerificationResult(
                status="active",
                details="Perplexity key accepted (auth OK; model param rejected)",
                provider="perplexity",
                permissions="chat + search",
                risk_level="high",
            )
        if r.status_code in (401, 403):
            return VerificationResult(
                status="inactive",
                details="Perplexity key rejected",
                provider="perplexity",
            )
        return VerificationResult(
            status="error",
            details=f"Perplexity HTTP {r.status_code}",
            provider="perplexity",
        )
    except Exception as e:
        return _error_result(e, "perplexity")


async def verify_postmark_token(token: str) -> VerificationResult:
    """GET /server — X-Postmark-Server-Token header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.postmarkapp.com/server",
                headers={"X-Postmark-Server-Token": token, "Accept": "application/json"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Postmark token active, server: {data.get('Name', '?')}",
                provider="postmark", permissions=f"id: {data.get('ID', '?')}")
        elif r.status_code in (401, 403, 422):
            return VerificationResult(status="inactive", details="Postmark token rejected", provider="postmark")
        return VerificationResult(status="error", details=f"Postmark HTTP {r.status_code}", provider="postmark")
    except Exception as e:
        return _error_result(e, "postmark")


async def verify_typeform_token(token: str) -> VerificationResult:
    """GET /me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.typeform.com/me",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Typeform token active, user: {data.get('email', '?')}",
                provider="typeform", permissions=f"alias: {data.get('alias', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Typeform token rejected", provider="typeform")
        return VerificationResult(status="error", details=f"Typeform HTTP {r.status_code}", provider="typeform")
    except Exception as e:
        return _error_result(e, "typeform")


async def verify_contentful_management_token(token: str) -> VerificationResult:
    """GET /spaces — Bearer (Contentful Management API)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.contentful.com/spaces?limit=1",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            items = r.json().get("items", [])
            return VerificationResult(status="active",
                details=f"Contentful CMA token active, {len(items)} space(s) visible",
                provider="contentful", permissions="content write")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Contentful token rejected", provider="contentful")
        return VerificationResult(status="error", details=f"Contentful HTTP {r.status_code}", provider="contentful")
    except Exception as e:
        return _error_result(e, "contentful")


async def verify_doppler_token(token: str) -> VerificationResult:
    """GET /v3/me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.doppler.com/v3/me",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            # Service tokens return 'type': 'service', PATs return 'type': 'user'
            return VerificationResult(status="active",
                details=f"Doppler token active, type: {data.get('type', '?')}",
                provider="doppler", permissions=f"slug: {data.get('slug', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Doppler token rejected", provider="doppler")
        return VerificationResult(status="error", details=f"Doppler HTTP {r.status_code}", provider="doppler")
    except Exception as e:
        return _error_result(e, "doppler")


async def verify_postman_api_key(key: str) -> VerificationResult:
    """GET /me — X-Api-Key header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.getpostman.com/me", headers={"X-Api-Key": key})
        if r.status_code == 200:
            data = r.json().get("user", {})
            return VerificationResult(status="active",
                details=f"Postman key active, user: {data.get('username', '?')}",
                provider="postman", permissions=f"email: {data.get('email', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Postman key rejected", provider="postman")
        return VerificationResult(status="error", details=f"Postman HTTP {r.status_code}", provider="postman")
    except Exception as e:
        return _error_result(e, "postman")


async def verify_airtable_token(token: str) -> VerificationResult:
    """GET /v0/meta/bases — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.airtable.com/v0/meta/bases",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            bases = r.json().get("bases", []) or []
            sample_bases = [b.get("name", "") for b in bases[:3]]
            detail = {
                "scopes": [],  # PAT scopes not returned by /v0/meta/bases
                "identity": "airtable_account",
                "risk_level": "high",  # customer/record data
                "is_production": True,
                "extra": {
                    "base_count": len(bases),
                    "sample_bases": sample_bases,
                },
            }
            result = VerificationResult(status="active",
                details=f"Airtable token active, {len(bases)} base(s) visible",
                provider="airtable",
                permissions=f"bases: {len(bases)}",
                permissions_detail=detail, risk_level="high")
            result.blast_radius_summary = summarize_blast_radius("airtable", detail)
            return result
        if _is_rate_limited(r, "airtable"):
            return _rate_limited_result("airtable", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Airtable token rejected", provider="airtable")
        return VerificationResult(status="error", details=f"Airtable HTTP {r.status_code}", provider="airtable")
    except Exception as e:
        return _error_result(e, "airtable")


async def verify_twitch_token(token: str) -> VerificationResult:
    """GET /oauth2/validate — OAuth {token} (non-Bearer form)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://id.twitch.tv/oauth2/validate",
                headers={"Authorization": f"OAuth {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Twitch token active, client_id: {data.get('client_id', '?')[:12]}",
                provider="twitch", permissions=f"scopes: {len(data.get('scopes', []))}")
        elif r.status_code == 401:
            return VerificationResult(status="inactive", details="Twitch token rejected", provider="twitch")
        return VerificationResult(status="error", details=f"Twitch HTTP {r.status_code}", provider="twitch")
    except Exception as e:
        return _error_result(e, "twitch")


async def verify_newrelic_key(key: str) -> VerificationResult:
    """GET /v2/users.json — Api-Key header (user key)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.newrelic.com/v2/users.json",
                headers={"Api-Key": key})
        if r.status_code == 200:
            users = r.json().get("users", [])
            return VerificationResult(status="active",
                details=f"New Relic key active, {len(users)} user(s) visible",
                provider="newrelic", permissions="user listing access")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="New Relic key rejected", provider="newrelic")
        return VerificationResult(status="error", details=f"New Relic HTTP {r.status_code}", provider="newrelic")
    except Exception as e:
        return _error_result(e, "newrelic")


async def verify_launchdarkly_key(key: str) -> VerificationResult:
    """GET /api/v2/caller-identity — Authorization header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://app.launchdarkly.com/api/v2/caller-identity",
                headers={"Authorization": key})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"LaunchDarkly key active, account: {data.get('accountId', '')[:12]}",
                provider="launchdarkly", permissions=f"type: {data.get('tokenKind', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="LaunchDarkly key rejected", provider="launchdarkly")
        return VerificationResult(status="error", details=f"LaunchDarkly HTTP {r.status_code}", provider="launchdarkly")
    except Exception as e:
        return _error_result(e, "launchdarkly")


async def verify_terraform_cloud_token(token: str) -> VerificationResult:
    """GET /api/v2/account/details — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://app.terraform.io/api/v2/account/details",
                headers={"Authorization": f"Bearer {token}",
                         "Content-Type": "application/vnd.api+json"})
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            return VerificationResult(status="active",
                details=f"Terraform Cloud token active, user: {data.get('username', '?')}",
                provider="terraform", permissions=f"email: {data.get('email', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Terraform Cloud token rejected", provider="terraform")
        return VerificationResult(status="error", details=f"Terraform HTTP {r.status_code}", provider="terraform")
    except Exception as e:
        return _error_result(e, "terraform")


async def verify_sonarcloud_token(token: str) -> VerificationResult:
    """GET /api/authentication/validate — HTTP Basic with token:empty."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://sonarcloud.io/api/authentication/validate",
                auth=(token, ""))
        if r.status_code == 200:
            data = r.json()
            if data.get("valid"):
                return VerificationResult(status="active",
                    details="SonarCloud token active", provider="sonarcloud", permissions="valid=true")
            return VerificationResult(status="inactive",
                details="SonarCloud reports token invalid", provider="sonarcloud")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="SonarCloud token rejected", provider="sonarcloud")
        return VerificationResult(status="error", details=f"SonarCloud HTTP {r.status_code}", provider="sonarcloud")
    except Exception as e:
        return _error_result(e, "sonarcloud")


async def verify_snyk_token(token: str) -> VerificationResult:
    """GET /v1/user/me — token {key} (not Bearer)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.snyk.io/v1/user/me",
                headers={"Authorization": f"token {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Snyk token active, user: {data.get('username', '?')}",
                provider="snyk", permissions=f"id: {data.get('id', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Snyk token rejected", provider="snyk")
        return VerificationResult(status="error", details=f"Snyk HTTP {r.status_code}", provider="snyk")
    except Exception as e:
        return _error_result(e, "snyk")


async def verify_buildkite_token(token: str) -> VerificationResult:
    """GET /v2/user — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.buildkite.com/v2/user",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Buildkite token active, user: {data.get('email', '?')}",
                provider="buildkite", permissions=f"name: {data.get('name', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Buildkite token rejected", provider="buildkite")
        return VerificationResult(status="error", details=f"Buildkite HTTP {r.status_code}", provider="buildkite")
    except Exception as e:
        return _error_result(e, "buildkite")


async def verify_bitrise_token(token: str) -> VerificationResult:
    """GET /v0.1/me — raw token in Authorization header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.bitrise.io/v0.1/me",
                headers={"Authorization": token})
        if r.status_code == 200:
            data = r.json().get("data", {})
            return VerificationResult(status="active",
                details=f"Bitrise token active, user: {data.get('username', '?')}",
                provider="bitrise", permissions=f"slug: {data.get('slug', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Bitrise token rejected", provider="bitrise")
        return VerificationResult(status="error", details=f"Bitrise HTTP {r.status_code}", provider="bitrise")
    except Exception as e:
        return _error_result(e, "bitrise")


async def verify_linode_token(token: str) -> VerificationResult:
    """GET /v4/profile — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.linode.com/v4/profile",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Linode token active, user: {data.get('username', '?')}",
                provider="linode", permissions=f"email: {data.get('email', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Linode token rejected", provider="linode")
        return VerificationResult(status="error", details=f"Linode HTTP {r.status_code}", provider="linode")
    except Exception as e:
        return _error_result(e, "linode")


async def verify_vultr_key(key: str) -> VerificationResult:
    """GET /v2/account — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.vultr.com/v2/account",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json().get("account", {})
            return VerificationResult(status="active",
                details=f"Vultr key active, email: {data.get('email', '?')}",
                provider="vultr", permissions=f"name: {data.get('name', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Vultr key rejected", provider="vultr")
        return VerificationResult(status="error", details=f"Vultr HTTP {r.status_code}", provider="vultr")
    except Exception as e:
        return _error_result(e, "vultr")


async def verify_hetzner_token(token: str) -> VerificationResult:
    """GET /v1/locations — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.hetzner.cloud/v1/locations",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            locs = r.json().get("locations", [])
            return VerificationResult(status="active",
                details=f"Hetzner token active, {len(locs)} location(s) visible",
                provider="hetzner", permissions=f"locations: {len(locs)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Hetzner token rejected", provider="hetzner")
        return VerificationResult(status="error", details=f"Hetzner HTTP {r.status_code}", provider="hetzner")
    except Exception as e:
        return _error_result(e, "hetzner")


async def verify_paystack_key(key: str) -> VerificationResult:
    """GET /transaction — Bearer. Must be an auth-required endpoint — /bank is
    public and returns 200 even for invalid keys, which would produce false
    positives."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.paystack.co/transaction?perPage=1",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json()
            if data.get("status"):
                return VerificationResult(status="active",
                    details="Paystack key active", provider="paystack", permissions="transaction read")
            return VerificationResult(status="inactive",
                details=f"Paystack: {data.get('message','?')}", provider="paystack")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Paystack key rejected", provider="paystack")
        return VerificationResult(status="error", details=f"Paystack HTTP {r.status_code}", provider="paystack")
    except Exception as e:
        return _error_result(e, "paystack")


async def verify_square_token(token: str) -> VerificationResult:
    """GET /v2/locations — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://connect.squareup.com/v2/locations",
                headers={"Authorization": f"Bearer {token}",
                         "Square-Version": "2024-01-18"})
        if r.status_code == 200:
            locs = r.json().get("locations", [])
            return VerificationResult(status="active",
                details=f"Square token active, {len(locs)} location(s)",
                provider="square", permissions=f"locations: {len(locs)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Square token rejected", provider="square")
        return VerificationResult(status="error", details=f"Square HTTP {r.status_code}", provider="square")
    except Exception as e:
        return _error_result(e, "square")


async def verify_dropbox_token(token: str) -> VerificationResult:
    """POST /2/users/get_current_account — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.post("https://api.dropboxapi.com/2/users/get_current_account",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Dropbox token active, email: {data.get('email', '?')}",
                provider="dropbox", permissions=f"acct id: {data.get('account_id', '')[:18]}")
        elif r.status_code in (401, 403, 400):
            return VerificationResult(status="inactive", details="Dropbox token rejected", provider="dropbox")
        return VerificationResult(status="error", details=f"Dropbox HTTP {r.status_code}", provider="dropbox")
    except Exception as e:
        return _error_result(e, "dropbox")


async def verify_jumpcloud_key(key: str) -> VerificationResult:
    """GET /api/systems — x-api-key header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://console.jumpcloud.com/api/systems?limit=1",
                headers={"x-api-key": key, "Content-Type": "application/json"})
        if r.status_code == 200:
            total = r.json().get("totalCount", 0)
            return VerificationResult(status="active",
                details=f"JumpCloud key active, {total} system(s) in tenant",
                provider="jumpcloud", permissions=f"systems: {total}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="JumpCloud key rejected", provider="jumpcloud")
        return VerificationResult(status="error", details=f"JumpCloud HTTP {r.status_code}", provider="jumpcloud")
    except Exception as e:
        return _error_result(e, "jumpcloud")


async def verify_opsgenie_key(key: str) -> VerificationResult:
    """GET /v2/account — GenieKey {key}. Opsgenie returns 422 for invalid keys
    (with message 'Key format is not valid!'), not the standard 401."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.opsgenie.com/v2/account",
                headers={"Authorization": f"GenieKey {key}"})
        if r.status_code == 200:
            data = r.json().get("data", {})
            return VerificationResult(status="active",
                details=f"Opsgenie key active, name: {data.get('name', '?')}",
                provider="opsgenie", permissions=f"user count: {data.get('userCount', '?')}")
        elif r.status_code in (401, 403, 422):
            return VerificationResult(status="inactive", details="Opsgenie key rejected", provider="opsgenie")
        return VerificationResult(status="error", details=f"Opsgenie HTTP {r.status_code}", provider="opsgenie")
    except Exception as e:
        return _error_result(e, "opsgenie")


async def verify_mapbox_secret(token: str) -> VerificationResult:
    """GET /tokens/v2 — Bearer. Mapbox secret tokens (sk.) can list all tokens."""
    try:
        import httpx
        # Extract username from JWT payload (Mapbox encodes user in the middle segment)
        import base64, json
        try:
            parts = token.split(".")
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload).decode())
            username = claims.get("u", "")
        except Exception:
            username = ""
        if not username:
            return VerificationResult(status="unsupported",
                details="Mapbox verification needs username from JWT claims", provider="mapbox")
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.mapbox.com/tokens/v2/{username}",
                params={"access_token": token})
        if r.status_code == 200:
            tokens = r.json() if isinstance(r.json(), list) else []
            return VerificationResult(status="active",
                details=f"Mapbox secret token active, user: {username}",
                provider="mapbox", permissions=f"can see {len(tokens)} tokens")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Mapbox token rejected", provider="mapbox")
        return VerificationResult(status="error", details=f"Mapbox HTTP {r.status_code}", provider="mapbox")
    except Exception as e:
        return _error_result(e, "mapbox")


async def verify_trello_key_token(key: str, token: str = "") -> VerificationResult:
    """GET /1/members/me — key + token as query params."""
    try:
        if not token:
            return VerificationResult(status="unsupported",
                details="Trello verification needs both API key and user token", provider="trello")
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.trello.com/1/members/me",
                params={"key": key, "token": token})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Trello creds active, user: {data.get('username', '?')}",
                provider="trello", permissions=f"id: {data.get('id', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Trello creds rejected", provider="trello")
        return VerificationResult(status="error", details=f"Trello HTTP {r.status_code}", provider="trello")
    except Exception as e:
        return _error_result(e, "trello")


async def verify_klaviyo_key(key: str) -> VerificationResult:
    """GET /api/accounts — Klaviyo-API-Key Klaviyo-API-Key {key} (with version header)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://a.klaviyo.com/api/accounts",
                headers={"Authorization": f"Klaviyo-API-Key {key}",
                         "revision": "2024-02-15"})
        if r.status_code == 200:
            data = r.json().get("data", [])
            return VerificationResult(status="active",
                details=f"Klaviyo key active, {len(data)} account(s) visible",
                provider="klaviyo", permissions=f"accounts: {len(data)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Klaviyo key rejected", provider="klaviyo")
        return VerificationResult(status="error", details=f"Klaviyo HTTP {r.status_code}", provider="klaviyo")
    except Exception as e:
        return _error_result(e, "klaviyo")


async def verify_basecamp_token(token: str) -> VerificationResult:
    """GET /authorization — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://launchpad.37signals.com/authorization.json",
                headers={"Authorization": f"Bearer {token}",
                         "User-Agent": "Vooda (verification)"})
        if r.status_code == 200:
            data = r.json()
            accts = data.get("accounts", [])
            return VerificationResult(status="active",
                details=f"Basecamp token active, {len(accts)} account(s)",
                provider="basecamp", permissions=f"accounts: {len(accts)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Basecamp token rejected", provider="basecamp")
        return VerificationResult(status="error", details=f"Basecamp HTTP {r.status_code}", provider="basecamp")
    except Exception as e:
        return _error_result(e, "basecamp")


# ── Stage 2 Tier 3: long-tail SaaS / dev / media ─────────────


async def verify_fastly_key(key: str) -> VerificationResult:
    """GET /current_customer — Fastly-Key header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.fastly.com/current_customer",
                headers={"Fastly-Key": key, "Accept": "application/json"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Fastly key active, customer: {data.get('name', '?')}",
                provider="fastly", permissions=f"id: {data.get('id', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Fastly key rejected", provider="fastly")
        return VerificationResult(status="error", details=f"Fastly HTTP {r.status_code}", provider="fastly")
    except Exception as e:
        return _error_result(e, "fastly")


async def verify_ngrok_key(key: str) -> VerificationResult:
    """GET /api/credentials — Bearer + Ngrok-Version header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.ngrok.com/credentials",
                headers={"Authorization": f"Bearer {key}", "Ngrok-Version": "2"})
        if r.status_code == 200:
            items = r.json().get("credentials", [])
            return VerificationResult(status="active",
                details=f"ngrok key active, {len(items)} credential(s) visible",
                provider="ngrok", permissions=f"creds: {len(items)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="ngrok key rejected", provider="ngrok")
        return VerificationResult(status="error", details=f"ngrok HTTP {r.status_code}", provider="ngrok")
    except Exception as e:
        return _error_result(e, "ngrok")


async def verify_browserstack_creds(username: str, key: str = "") -> VerificationResult:
    """GET /automate/browsers.json — HTTP Basic (username + key). Needs both."""
    try:
        if not key:
            return VerificationResult(status="unsupported",
                details="BrowserStack verification needs username + access key pair", provider="browserstack")
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.browserstack.com/automate/browsers.json", auth=(username, key))
        if r.status_code == 200:
            browsers = r.json()
            return VerificationResult(status="active",
                details=f"BrowserStack creds active, {len(browsers)} browser configs",
                provider="browserstack", permissions=f"user: {username}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="BrowserStack creds rejected", provider="browserstack")
        return VerificationResult(status="error", details=f"BrowserStack HTTP {r.status_code}", provider="browserstack")
    except Exception as e:
        return _error_result(e, "browserstack")


async def verify_iterable_key(key: str) -> VerificationResult:
    """GET /api/lists — Api-Key header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.iterable.com/api/lists",
                headers={"Api-Key": key})
        if r.status_code == 200:
            lists = r.json().get("lists", [])
            return VerificationResult(status="active",
                details=f"Iterable key active, {len(lists)} list(s) visible",
                provider="iterable", permissions=f"lists: {len(lists)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Iterable key rejected", provider="iterable")
        return VerificationResult(status="error", details=f"Iterable HTTP {r.status_code}", provider="iterable")
    except Exception as e:
        return _error_result(e, "iterable")


async def verify_honeybadger_token(token: str) -> VerificationResult:
    """GET /v2/projects — X-Api-Token header (correct path is /v2, not /v1)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://app.honeybadger.io/v2/projects",
                headers={"X-Api-Token": token})
        if r.status_code == 200:
            projs = r.json().get("results", [])
            return VerificationResult(status="active",
                details=f"Honeybadger token active, {len(projs)} project(s)",
                provider="honeybadger", permissions=f"projects: {len(projs)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Honeybadger token rejected", provider="honeybadger")
        return VerificationResult(status="error", details=f"Honeybadger HTTP {r.status_code}", provider="honeybadger")
    except Exception as e:
        return _error_result(e, "honeybadger")


async def verify_unsplash_key(key: str) -> VerificationResult:
    """GET /photos — Client-ID {key}. /photos accepts Client-ID auth (whereas
    /me requires a user OAuth token that we don't have)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.unsplash.com/photos?per_page=1",
                headers={"Authorization": f"Client-ID {key}"})
        if r.status_code == 200:
            photos = r.json() if isinstance(r.json(), list) else []
            return VerificationResult(status="active",
                details=f"Unsplash access key valid, {len(photos)} photo(s) returned",
                provider="unsplash", permissions="read Unsplash photos")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Unsplash key rejected", provider="unsplash")
        return VerificationResult(status="error", details=f"Unsplash HTTP {r.status_code}", provider="unsplash")
    except Exception as e:
        return _error_result(e, "unsplash")


async def verify_pexels_key(key: str) -> VerificationResult:
    """Pexels' public API does not validate Authorization headers — all
    endpoints respond with 200 + data regardless of whether a key is
    supplied. There is no reliable way to verify a Pexels key without a
    billing-level check we can't perform. Marked unsupported."""
    return VerificationResult(status="unsupported",
        details="Pexels API does not validate keys on public endpoints",
        provider="pexels")


async def verify_yelp_key(key: str) -> VerificationResult:
    """GET /v3/autocomplete — Bearer. Yelp requires a 128-char API key and
    returns 400 with VALIDATION_ERROR for keys in the wrong format — treat
    that as inactive since it's still a rejection."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.yelp.com/v3/autocomplete?text=a&latitude=37.7749&longitude=-122.4194",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Yelp Fusion key active",
                provider="yelp", permissions="read Fusion data")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Yelp key rejected", provider="yelp")
        elif r.status_code == 400 and ("VALIDATION_ERROR" in r.text or "format" in r.text.lower()):
            return VerificationResult(status="inactive", details="Yelp key format invalid", provider="yelp")
        return VerificationResult(status="error", details=f"Yelp HTTP {r.status_code}", provider="yelp")
    except Exception as e:
        return _error_result(e, "yelp")


async def verify_wakatime_key(key: str) -> VerificationResult:
    """GET /api/v1/users/current — Basic auth (api_key:empty)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://wakatime.com/api/v1/users/current",
                auth=(key, ""))
        if r.status_code == 200:
            data = r.json().get("data", {})
            return VerificationResult(status="active",
                details=f"WakaTime key active, user: {data.get('email', '?')}",
                provider="wakatime", permissions=f"id: {data.get('id', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="WakaTime key rejected", provider="wakatime")
        return VerificationResult(status="error", details=f"WakaTime HTTP {r.status_code}", provider="wakatime")
    except Exception as e:
        return _error_result(e, "wakatime")


async def verify_ipinfo_token(token: str) -> VerificationResult:
    """GET /?token=X — token as query param."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://ipinfo.io/8.8.8.8?token={token}")
        if r.status_code == 200:
            data = r.json()
            # ipinfo returns IP info even without auth, but token info shows up
            return VerificationResult(status="active",
                details=f"ipinfo token accepted",
                provider="ipinfo", permissions=f"querying for: {data.get('ip', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="ipinfo token rejected", provider="ipinfo")
        return VerificationResult(status="error", details=f"ipinfo HTTP {r.status_code}", provider="ipinfo")
    except Exception as e:
        return _error_result(e, "ipinfo")


async def verify_gitbook_token(token: str) -> VerificationResult:
    """GET /v1/user — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.gitbook.com/v1/user",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"GitBook token active, user: {data.get('email', '?')}",
                provider="gitbook", permissions=f"id: {data.get('id', '')[:12]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="GitBook token rejected", provider="gitbook")
        return VerificationResult(status="error", details=f"GitBook HTTP {r.status_code}", provider="gitbook")
    except Exception as e:
        return _error_result(e, "gitbook")


async def verify_smartsheet_token(token: str) -> VerificationResult:
    """GET /2.0/users/me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.smartsheet.com/2.0/users/me",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Smartsheet token active, user: {data.get('email', '?')}",
                provider="smartsheet", permissions=f"id: {data.get('id', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Smartsheet token rejected", provider="smartsheet")
        return VerificationResult(status="error", details=f"Smartsheet HTTP {r.status_code}", provider="smartsheet")
    except Exception as e:
        return _error_result(e, "smartsheet")


async def verify_wrike_token(token: str) -> VerificationResult:
    """GET /api/v4/contacts — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://www.wrike.com/api/v4/contacts?me=true",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json().get("data", [])
            return VerificationResult(status="active",
                details="Wrike token active",
                provider="wrike", permissions=f"contacts visible: {len(data)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Wrike token rejected", provider="wrike")
        return VerificationResult(status="error", details=f"Wrike HTTP {r.status_code}", provider="wrike")
    except Exception as e:
        return _error_result(e, "wrike")


async def verify_monday_com_token(token: str) -> VerificationResult:
    """POST /v2 — GraphQL { me { name } } — Authorization."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.post("https://api.monday.com/v2",
                headers={"Authorization": token, "Content-Type": "application/json"},
                json={"query": "{ me { name email } }"})
        if r.status_code == 200:
            me = r.json().get("data", {}).get("me")
            if me:
                return VerificationResult(status="active",
                    details=f"Monday.com token active, user: {me.get('email', '?')}",
                    provider="monday", permissions=f"name: {me.get('name', '?')}")
            errs = r.json().get("errors", [])
            if errs:
                return VerificationResult(status="inactive",
                    details=f"Monday.com: {errs[0].get('message','?')[:80]}", provider="monday")
            return VerificationResult(status="inactive", details="Monday.com: empty me", provider="monday")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Monday.com token rejected", provider="monday")
        return VerificationResult(status="error", details=f"Monday.com HTTP {r.status_code}", provider="monday")
    except Exception as e:
        return _error_result(e, "monday")


async def verify_frontapp_token(token: str) -> VerificationResult:
    """GET /me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api2.frontapp.com/me",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Front token active, user: {data.get('email', '?')}",
                provider="front", permissions=f"id: {data.get('id', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Front token rejected", provider="front")
        return VerificationResult(status="error", details=f"Front HTTP {r.status_code}", provider="front")
    except Exception as e:
        return _error_result(e, "front")


async def verify_salesloft_token(token: str) -> VerificationResult:
    """GET /v2/me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.salesloft.com/v2/me.json",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json().get("data", {})
            return VerificationResult(status="active",
                details=f"Salesloft token active, user: {data.get('email', '?')}",
                provider="salesloft", permissions=f"id: {data.get('id', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Salesloft token rejected", provider="salesloft")
        return VerificationResult(status="error", details=f"Salesloft HTTP {r.status_code}", provider="salesloft")
    except Exception as e:
        return _error_result(e, "salesloft")


async def verify_lever_token(token: str) -> VerificationResult:
    """GET /v1/postings — Basic auth (token:empty)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.lever.co/v1/postings?limit=1", auth=(token, ""))
        if r.status_code == 200:
            data = r.json().get("data", [])
            return VerificationResult(status="active",
                details=f"Lever token active",
                provider="lever", permissions=f"postings visible: {len(data)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Lever token rejected", provider="lever")
        return VerificationResult(status="error", details=f"Lever HTTP {r.status_code}", provider="lever")
    except Exception as e:
        return _error_result(e, "lever")


async def verify_greenhouse_token(token: str) -> VerificationResult:
    """GET /v1/users — Basic auth (token:empty)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://harvest.greenhouse.io/v1/users?per_page=1", auth=(token, ""))
        if r.status_code == 200:
            users = r.json() if isinstance(r.json(), list) else []
            return VerificationResult(status="active",
                details=f"Greenhouse token active, {len(users)} user(s) visible",
                provider="greenhouse", permissions=f"users: {len(users)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Greenhouse token rejected", provider="greenhouse")
        return VerificationResult(status="error", details=f"Greenhouse HTTP {r.status_code}", provider="greenhouse")
    except Exception as e:
        return _error_result(e, "greenhouse")


async def verify_workable_token(token: str) -> VerificationResult:
    """GET /spi/v3/accounts — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://www.workable.com/spi/v3/accounts",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            accts = r.json().get("accounts", [])
            return VerificationResult(status="active",
                details=f"Workable token active, {len(accts)} account(s)",
                provider="workable", permissions=f"accounts: {len(accts)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Workable token rejected", provider="workable")
        return VerificationResult(status="error", details=f"Workable HTTP {r.status_code}", provider="workable")
    except Exception as e:
        return _error_result(e, "workable")


async def verify_helpscout_key(key: str) -> VerificationResult:
    """GET /v2/users/me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.helpscout.net/v2/users/me",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Help Scout key active, user: {data.get('email', '?')}",
                provider="helpscout", permissions=f"id: {data.get('id', '')[:12]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Help Scout key rejected", provider="helpscout")
        return VerificationResult(status="error", details=f"Help Scout HTTP {r.status_code}", provider="helpscout")
    except Exception as e:
        return _error_result(e, "helpscout")


async def verify_ashby_key(key: str) -> VerificationResult:
    """POST /apiKey.info — Basic auth (key:empty)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.post("https://api.ashbyhq.com/apiKey.info", auth=(key, ""))
        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                return VerificationResult(status="active",
                    details=f"Ashby key active, scopes: {len(data.get('results', {}).get('scopes', []))}",
                    provider="ashby", permissions="ATS access")
            return VerificationResult(status="inactive", details="Ashby key invalid", provider="ashby")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Ashby key rejected", provider="ashby")
        return VerificationResult(status="error", details=f"Ashby HTTP {r.status_code}", provider="ashby")
    except Exception as e:
        return _error_result(e, "ashby")


async def verify_buffer_token(token: str) -> VerificationResult:
    """GET /1/user — access_token query param."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.bufferapp.com/1/user.json?access_token={token}")
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Buffer token active, user: {data.get('email', '?')}",
                provider="buffer", permissions=f"id: {data.get('id', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Buffer token rejected", provider="buffer")
        return VerificationResult(status="error", details=f"Buffer HTTP {r.status_code}", provider="buffer")
    except Exception as e:
        return _error_result(e, "buffer")


async def verify_pipedrive_key(key: str) -> VerificationResult:
    """GET /v1/users/me — api_token query param (Pipedrive hosts on subdomain,
    but /users/me works on api.pipedrive.com directly for token validation)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.pipedrive.com/v1/users/me?api_token={key}")
        if r.status_code == 200:
            data = r.json().get("data", {})
            return VerificationResult(status="active",
                details=f"Pipedrive key active, user: {data.get('email', '?')}",
                provider="pipedrive", permissions=f"company: {data.get('company_name', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Pipedrive key rejected", provider="pipedrive")
        return VerificationResult(status="error", details=f"Pipedrive HTTP {r.status_code}", provider="pipedrive")
    except Exception as e:
        return _error_result(e, "pipedrive")


async def verify_airbyte_cloud_token(token: str) -> VerificationResult:
    """GET /v1/workspaces — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.airbyte.com/v1/workspaces",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            ws = r.json().get("data", [])
            return VerificationResult(status="active",
                details=f"Airbyte Cloud token active, {len(ws)} workspace(s)",
                provider="airbyte", permissions=f"workspaces: {len(ws)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Airbyte token rejected", provider="airbyte")
        return VerificationResult(status="error", details=f"Airbyte HTTP {r.status_code}", provider="airbyte")
    except Exception as e:
        return _error_result(e, "airbyte")


async def verify_bunny_net_key(key: str) -> VerificationResult:
    """GET /apikey — AccessKey header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.bunny.net/apikey",
                headers={"AccessKey": key, "Accept": "application/json"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Bunny.net key active",
                provider="bunny", permissions=f"roles: {len(data.get('Roles', []))}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Bunny.net key rejected", provider="bunny")
        return VerificationResult(status="error", details=f"Bunny.net HTTP {r.status_code}", provider="bunny")
    except Exception as e:
        return _error_result(e, "bunny")


async def verify_mixpanel_secret(secret: str) -> VerificationResult:
    """GET /api/app/me — Basic auth (service_account:secret). Without project
    we use the /api/app/me endpoint which reports owner info."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            # Mixpanel's Service Accounts: probe the query API with basic auth
            r = await c.get("https://mixpanel.com/api/app/me",
                headers={"Authorization": f"Basic {secret}"} if ":" in secret else {"Authorization": f"Bearer {secret}"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Mixpanel service account accepted",
                provider="mixpanel", permissions="project query access")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Mixpanel secret rejected", provider="mixpanel")
        return VerificationResult(status="error", details=f"Mixpanel HTTP {r.status_code}", provider="mixpanel")
    except Exception as e:
        return _error_result(e, "mixpanel")


async def verify_chatwork_token(token: str) -> VerificationResult:
    """GET /v2/me — X-ChatWorkToken header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.chatwork.com/v2/me",
                headers={"X-ChatWorkToken": token})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"ChatWork token active, user: {data.get('name', '?')}",
                provider="chatwork", permissions=f"login id: {data.get('login_name', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="ChatWork token rejected", provider="chatwork")
        return VerificationResult(status="error", details=f"ChatWork HTTP {r.status_code}", provider="chatwork")
    except Exception as e:
        return _error_result(e, "chatwork")


# verify_fauna_key removed 2026-05-19 — Fauna (db.fauna.com) was
# acquired and shut down its hosted DB product; the endpoint no
# longer resolves.  Detection rule for fauna_secret is kept so we
# still flag legacy tokens in code, but live verification is now
# permanently unavailable (status="unsupported" returned by the
# default dispatcher path).


async def verify_storyblok_token(token: str) -> VerificationResult:
    """GET /v2/cdn/spaces/me — token query param."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.storyblok.com/v2/cdn/spaces/me?token={token}")
        if r.status_code == 200:
            data = r.json().get("space", {})
            return VerificationResult(status="active",
                details=f"Storyblok token active, space: {data.get('name', '?')}",
                provider="storyblok", permissions=f"domain: {data.get('domain', '?')}")
        elif r.status_code in (401, 403, 422):
            return VerificationResult(status="inactive", details="Storyblok token rejected", provider="storyblok")
        return VerificationResult(status="error", details=f"Storyblok HTTP {r.status_code}", provider="storyblok")
    except Exception as e:
        return _error_result(e, "storyblok")


async def verify_jira_cloud_creds(email: str, token: str = "", domain: str = "") -> VerificationResult:
    """GET /rest/api/3/myself — Basic auth (email:token). Tenant-scoped."""
    try:
        if not token or not domain:
            return VerificationResult(status="unsupported",
                details="Jira verification needs email + API token + cloud domain", provider="jira")
        import httpx
        async with verification_client(timeout=10, provider="jira") as c:
            r = await c.get(f"https://{domain}/rest/api/3/myself", auth=(email, token))
        if r.status_code == 200:
            data = r.json()
            email_addr = data.get("emailAddress", "?")
            account_id = data.get("accountId", "")
            # Jira Cloud API tokens inherit the user's permissions. Without
            # a separate permissions endpoint call we can't enumerate exact
            # project access, but user-scoped tokens are consistently
            # medium risk (project read/write, comment, transition issues).
            detail = {
                "scopes": [],
                "identity": email_addr,
                "account_id": account_id,
                "risk_level": "medium",
                "is_production": True,
                "extra": {
                    "domain": domain,
                    "email": email_addr,
                    "display_name": data.get("displayName", ""),
                    "active": data.get("active", True),
                },
            }
            result = VerificationResult(status="active",
                details=f"Jira token active @ {domain}, user: {email_addr}",
                provider="jira", permissions=f"accountId: {account_id[:18]}",
                permissions_detail=detail, risk_level="medium")
            result.blast_radius_summary = summarize_blast_radius("jira", detail)
            return result
        elif _is_rate_limited(r, "jira"):
            # Atlassian returns 429 with Retry-After during burst windows.
            return _rate_limited_result("jira", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Jira creds rejected", provider="jira")
        return VerificationResult(status="error", details=f"Jira HTTP {r.status_code}", provider="jira")
    except Exception as e:
        return _error_result(e, "jira")


async def verify_zoho_token(token: str, region: str = "com") -> VerificationResult:
    """GET /oauth/v2/userinfo — Zoho-oauthtoken {token}. Region-scoped (com/eu/in/au)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://accounts.zoho.{region}/oauth/user/info",
                headers={"Authorization": f"Zoho-oauthtoken {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Zoho token active, user: {data.get('Email', '?')}",
                provider="zoho", permissions=f"region: {region}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Zoho token rejected", provider="zoho")
        return VerificationResult(status="error", details=f"Zoho HTTP {r.status_code}", provider="zoho")
    except Exception as e:
        return _error_result(e, "zoho")


async def verify_render_token(token: str) -> VerificationResult:
    """GET /v1/owners — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.render.com/v1/owners",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            body = r.json()
            owners = body if isinstance(body, list) else []
            # Response is a list of {owner: {id, name, email, type}, cursor}
            sample_owners = []
            for entry in owners[:3]:
                o = entry.get("owner", {}) if isinstance(entry, dict) else {}
                if o.get("name"):
                    sample_owners.append(o.get("name"))
            detail = {
                "scopes": [],  # Render tokens are full-account
                "identity": "render_account",
                # Deploy control + env-var access + scale → critical
                "risk_level": "critical",
                "is_production": True,
                "extra": {
                    "owner_count": len(owners),
                    "sample_owners": sample_owners,
                },
            }
            result = VerificationResult(status="active",
                details=f"Render token active, {len(owners)} owner(s) visible",
                provider="render",
                permissions=f"owners: {len(owners)}",
                permissions_detail=detail, risk_level="critical")
            result.blast_radius_summary = summarize_blast_radius("render", detail)
            return result
        if _is_rate_limited(r, "render"):
            return _rate_limited_result("render", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Render token rejected", provider="render")
        return VerificationResult(status="error", details=f"Render HTTP {r.status_code}", provider="render")
    except Exception as e:
        return _error_result(e, "render")


# ── Stage 3: Multi-credential verifiers ───────────────────────


async def verify_azure_ad(client_id: str, client_secret: str, tenant_id: str) -> VerificationResult:
    """POST /{tenant}/oauth2/v2.0/token — client credentials grant.
    Azure AD verifies by requesting an access token for Microsoft Graph."""
    try:
        if not (client_id and client_secret and tenant_id):
            return VerificationResult(status="unsupported",
                details="Azure AD needs client_id + client_secret + tenant_id",
                provider="azure")
        import httpx
        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }
        async with verification_client(timeout=12) as c:
            r = await c.post(url, data=data)
        if r.status_code == 200:
            body = r.json()
            return VerificationResult(status="active",
                details=f"Azure AD client active in tenant {tenant_id[:8]}...",
                provider="azure",
                permissions=f"scope: {body.get('scope','')[:40]}, exp={body.get('expires_in','?')}s")
        elif r.status_code in (400, 401, 403):
            detail = r.json().get("error_description", "")[:120] if r.headers.get("content-type","").startswith("application/json") else "auth rejected"
            return VerificationResult(status="inactive",
                details=f"Azure AD: {detail}", provider="azure")
        return VerificationResult(status="error",
            details=f"Azure AD HTTP {r.status_code}", provider="azure")
    except Exception as e:
        return _error_result(e, "azure", log_key="azure_ad")


async def verify_gcp_service_account(key_json: str) -> VerificationResult:
    """Verify a GCP Service Account by signing a JWT with its private key and
    exchanging it for an access token at oauth2.googleapis.com.

    key_json is the full JSON key file content (as a string) — or a dict.
    """
    try:
        import json, time, base64, hashlib
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        import httpx

        if isinstance(key_json, str):
            try:
                key_dict = json.loads(key_json)
            except json.JSONDecodeError:
                return VerificationResult(status="error",
                    details="GCP SA key is not valid JSON", provider="gcp")
        else:
            key_dict = key_json

        required = ("client_email", "private_key", "token_uri")
        if not all(key_dict.get(k) for k in required):
            return VerificationResult(status="unsupported",
                details="GCP SA JSON missing required fields", provider="gcp")

        client_email = key_dict["client_email"]
        private_key_pem = key_dict["private_key"]
        token_uri = key_dict.get("token_uri", "https://oauth2.googleapis.com/token")

        # Build JWT
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": key_dict.get("private_key_id", "")}
        claims = {
            "iss": client_email,
            "scope": "https://www.googleapis.com/auth/cloud-platform.read-only",
            "aud": token_uri,
            "iat": now,
            "exp": now + 300,
        }

        def _b64(obj):
            return base64.urlsafe_b64encode(
                json.dumps(obj, separators=(",", ":")).encode()
            ).decode().rstrip("=")

        signing_input = f"{_b64(header)}.{_b64(claims)}".encode()
        priv_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        sig = priv_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jwt = signing_input.decode() + "." + base64.urlsafe_b64encode(sig).decode().rstrip("=")

        async with verification_client(timeout=10) as c:
            r = await c.post(token_uri, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jwt,
            })
        if r.status_code == 200:
            body = r.json()
            return VerificationResult(status="active",
                details=f"GCP SA active: {client_email}",
                provider="gcp",
                permissions=f"project: {key_dict.get('project_id', '?')}, exp: {body.get('expires_in','?')}s")
        elif r.status_code in (400, 401, 403):
            return VerificationResult(status="inactive",
                details=f"GCP SA rejected: {r.text[:120]}", provider="gcp")
        return VerificationResult(status="error",
            details=f"GCP HTTP {r.status_code}", provider="gcp")
    except Exception as e:
        return _error_result(e, "gcp", log_key="gcp_sa")


async def verify_paypal_oauth(client_id: str, client_secret: str, live: bool = False) -> VerificationResult:
    """POST /v1/oauth2/token — Basic auth with client_id:secret. Verifies by
    requesting an access token. live=True uses api-m.paypal.com,
    False uses api-m.sandbox.paypal.com."""
    try:
        if not (client_id and client_secret):
            return VerificationResult(status="unsupported",
                details="PayPal needs both client_id and client_secret",
                provider="paypal")
        import httpx
        host = "api-m.paypal.com" if live else "api-m.sandbox.paypal.com"
        async with verification_client(timeout=10) as c:
            r = await c.post(f"https://{host}/v1/oauth2/token",
                auth=(client_id, client_secret),
                data={"grant_type": "client_credentials"},
                headers={"Accept": "application/json"})
        if r.status_code == 200:
            body = r.json()
            return VerificationResult(status="active",
                details=f"PayPal {'LIVE' if live else 'sandbox'} OAuth active",
                provider="paypal",
                permissions=f"scope: {body.get('scope', '')[:40]}...")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive",
                details="PayPal credentials rejected", provider="paypal")
        return VerificationResult(status="error",
            details=f"PayPal HTTP {r.status_code}", provider="paypal")
    except Exception as e:
        return _error_result(e, "paypal")


async def verify_mongodb_atlas_paired(public_key: str, private_key: str, group_id: str = "") -> VerificationResult:
    """GET /api/atlas/v2/orgs — HTTP Digest auth with public:private."""
    try:
        if not (public_key and private_key):
            return VerificationResult(status="unsupported",
                details="MongoDB Atlas needs public + private key pair",
                provider="mongodb")
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://cloud.mongodb.com/api/atlas/v2/orgs?pageNum=1&itemsPerPage=1",
                auth=httpx.DigestAuth(public_key, private_key),
                headers={"Accept": "application/vnd.atlas.2023-01-01+json"})
        if r.status_code == 200:
            orgs = r.json().get("results", [])
            return VerificationResult(status="active",
                details=f"MongoDB Atlas keys active, {len(orgs)} org(s) visible",
                provider="mongodb",
                permissions=f"orgs: {len(orgs)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive",
                details="MongoDB Atlas keys rejected", provider="mongodb")
        return VerificationResult(status="error",
            details=f"MongoDB Atlas HTTP {r.status_code}", provider="mongodb")
    except Exception as e:
        return _error_result(e, "mongodb", log_key="mongodb_atlas")


async def verify_snowflake_paired(account: str, user: str, password: str) -> VerificationResult:
    """POST /session/v1/login-request — Snowflake password auth. Verifies
    by completing a login flow. Account format: orgname-accountname."""
    try:
        if not (account and user and password):
            return VerificationResult(status="unsupported",
                details="Snowflake needs account + user + password",
                provider="snowflake")
        import httpx
        url = f"https://{account}.snowflakecomputing.com/session/v1/login-request"
        async with verification_client(timeout=12) as c:
            r = await c.post(url, json={
                "data": {
                    "LOGIN_NAME": user,
                    "PASSWORD": password,
                    "CLIENT_APP_ID": "VoodaVerifier",
                    "CLIENT_APP_VERSION": "1.0",
                }
            })
        if r.status_code == 200:
            body = r.json()
            if body.get("success"):
                return VerificationResult(status="active",
                    details=f"Snowflake login active: {user}@{account}",
                    provider="snowflake",
                    permissions=f"session token issued")
            msg = body.get("message", "?")[:100]
            return VerificationResult(status="inactive",
                details=f"Snowflake rejected: {msg}", provider="snowflake")
        elif r.status_code in (401, 403, 400, 404):
            # 404 = account subdomain doesn't exist (equivalent to creds invalid)
            return VerificationResult(status="inactive",
                details="Snowflake creds rejected or account not found", provider="snowflake")
        return VerificationResult(status="error",
            details=f"Snowflake HTTP {r.status_code}", provider="snowflake")
    except Exception as e:
        return _error_result(e, "snowflake")


async def verify_stripe_connect_paired(secret_key: str, account_id: str = "") -> VerificationResult:
    """GET /v1/accounts/{id} with Stripe-Account header — Bearer + connected
    account. Verifies the secret key works + the Connect account is
    accessible."""
    try:
        if not secret_key:
            return VerificationResult(status="unsupported",
                details="Stripe Connect needs a secret key",
                provider="stripe")
        import httpx
        headers = {"Authorization": f"Bearer {secret_key}"}
        if account_id:
            headers["Stripe-Account"] = account_id
        async with verification_client(timeout=10) as c:
            # If we have an account ID, hit that account; otherwise /v1/account (self)
            if account_id:
                r = await c.get(f"https://api.stripe.com/v1/accounts/{account_id}", headers=headers)
            else:
                r = await c.get("https://api.stripe.com/v1/account", headers=headers)
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Stripe secret key active, account: {data.get('id', '?')}",
                provider="stripe",
                permissions=f"country: {data.get('country','?')}, charges: {data.get('charges_enabled', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive",
                details="Stripe key rejected", provider="stripe")
        return VerificationResult(status="error",
            details=f"Stripe HTTP {r.status_code}", provider="stripe")
    except Exception as e:
        return _error_result(e, "stripe", log_key="stripe_connect")


async def verify_mailjet_paired(public_key: str, private_key: str) -> VerificationResult:
    """GET /v3/REST/user — Basic auth with public:private."""
    try:
        if not (public_key and private_key):
            return VerificationResult(status="unsupported",
                details="Mailjet needs public + private key pair",
                provider="mailjet")
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.mailjet.com/v3/REST/user",
                auth=(public_key, private_key))
        if r.status_code == 200:
            data = r.json().get("Data", [])
            return VerificationResult(status="active",
                details=f"Mailjet keys active, {len(data)} user(s) visible",
                provider="mailjet",
                permissions=f"users: {len(data)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive",
                details="Mailjet keys rejected", provider="mailjet")
        return VerificationResult(status="error",
            details=f"Mailjet HTTP {r.status_code}", provider="mailjet")
    except Exception as e:
        return _error_result(e, "mailjet")


# ── Stage 2 Tier 4 — verifiers for Wave 2 ported rules ───────


async def _simple_get(url: str, headers: dict, provider: str, timeout: int = 10,
                      expect_200_only: bool = True) -> VerificationResult:
    """Shared helper: single GET, status→active/inactive based on response.

    expect_200_only=True treats non-200/401/403 as error.
    """
    try:
        async with verification_client(timeout=timeout) as c:
            r = await c.get(url, headers=headers)
        if r.status_code == 200:
            return VerificationResult(status="active",
                details=f"{provider} key active",
                provider=provider, permissions="read access")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive",
                details=f"{provider} key rejected", provider=provider)
        return VerificationResult(status="error",
            details=f"{provider} HTTP {r.status_code}", provider=provider)
    except Exception as e:
        logger.warning(f"{provider}_verification_error", error=str(e)[:200])
        return VerificationResult(status="error", details=str(e)[:200], provider=provider)


async def verify_gemini_key(key: str) -> VerificationResult:
    """GET /v1beta/models?key={key}."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={key}")
        if r.status_code == 200:
            count = len(r.json().get("models", []))
            return VerificationResult(status="active",
                details=f"Gemini key active, {count} models accessible",
                provider="gemini", permissions=f"{count} models")
        elif r.status_code in (400, 401, 403):
            return VerificationResult(status="inactive", details="Gemini key rejected", provider="gemini")
        return VerificationResult(status="error", details=f"Gemini HTTP {r.status_code}", provider="gemini")
    except Exception as e:
        return _error_result(e, "gemini")


async def verify_fireworks_key(key: str) -> VerificationResult:
    """GET /inference/v1/models — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.fireworks.ai/inference/v1/models",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Fireworks AI key active",
                provider="fireworks", permissions="inference API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Fireworks key rejected", provider="fireworks")
        return VerificationResult(status="error", details=f"Fireworks HTTP {r.status_code}", provider="fireworks")
    except Exception as e:
        return _error_result(e, "fireworks")


async def verify_novita_key(key: str) -> VerificationResult:
    """GET /v3/model (singular) — Bearer. /v3/models (plural) returns 404."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.novita.ai/v3/model",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Novita AI key active",
                provider="novita", permissions="inference API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Novita key rejected", provider="novita")
        return VerificationResult(status="error", details=f"Novita HTTP {r.status_code}", provider="novita")
    except Exception as e:
        return _error_result(e, "novita")


async def verify_deepl_key(key: str) -> VerificationResult:
    """POST /v2/usage — Authorization: DeepL-Auth-Key {key}. Free keys end
    with :fx, pro keys don't — we pick the host accordingly."""
    try:
        import httpx
        host = "api-free.deepl.com" if key.endswith(":fx") else "api.deepl.com"
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://{host}/v2/usage",
                headers={"Authorization": f"DeepL-Auth-Key {key}"})
        if r.status_code == 200:
            data = r.json()
            tier = "free" if ":fx" in key else "pro"
            return VerificationResult(status="active",
                details=f"DeepL {tier} key active, chars: {data.get('character_count', '?')}/{data.get('character_limit', '?')}",
                provider="deepl", permissions=f"tier: {tier}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="DeepL key rejected", provider="deepl")
        return VerificationResult(status="error", details=f"DeepL HTTP {r.status_code}", provider="deepl")
    except Exception as e:
        return _error_result(e, "deepl")


async def verify_elevenlabs_key(key: str) -> VerificationResult:
    """GET /v1/user — xi-api-key header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.elevenlabs.io/v1/user",
                headers={"xi-api-key": key})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"ElevenLabs key active, user: {data.get('xi_api_key', '?')}",
                provider="elevenlabs",
                permissions=f"tier: {data.get('subscription', {}).get('tier', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="ElevenLabs key rejected", provider="elevenlabs")
        return VerificationResult(status="error", details=f"ElevenLabs HTTP {r.status_code}", provider="elevenlabs")
    except Exception as e:
        return _error_result(e, "elevenlabs")


async def verify_polygon_io_key(key: str) -> VerificationResult:
    """GET /v3/reference/tickers?apiKey=X&limit=1."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.polygon.io/v3/reference/tickers?apiKey={key}&limit=1")
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details="Polygon.io key active",
                provider="polygon", permissions=f"req: {data.get('request_id', '')[:12]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Polygon.io key rejected", provider="polygon")
        return VerificationResult(status="error", details=f"Polygon HTTP {r.status_code}", provider="polygon")
    except Exception as e:
        return _error_result(e, "polygon")


async def verify_alphavantage_key(key: str) -> VerificationResult:
    """Alpha Vantage does not validate API keys at the request layer —
    any arbitrary string returns real data (keys are only used for billing
    rate-limits, enforced async). Marked unsupported."""
    return VerificationResult(status="unsupported",
        details="Alpha Vantage does not enforce auth at request time",
        provider="alphavantage")


async def verify_finnhub_key(key: str) -> VerificationResult:
    """GET /api/v1/quote?symbol=AAPL&token=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://finnhub.io/api/v1/quote?symbol=AAPL&token={key}")
        if r.status_code == 200:
            data = r.json()
            if "c" in data:  # "c" is current price
                return VerificationResult(status="active",
                    details="Finnhub key active",
                    provider="finnhub", permissions="stock quotes")
            if data.get("error"):
                return VerificationResult(status="inactive", details=f"Finnhub: {data['error']}", provider="finnhub")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Finnhub rejected", provider="finnhub")
        return VerificationResult(status="error", details=f"Finnhub HTTP {r.status_code}", provider="finnhub")
    except Exception as e:
        return _error_result(e, "finnhub")


async def verify_openexchangerates_key(key: str) -> VerificationResult:
    """GET /api/usage.json?app_id=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://openexchangerates.org/api/usage.json?app_id={key}")
        if r.status_code == 200:
            data = r.json().get("data", {})
            return VerificationResult(status="active",
                details=f"OpenExchangeRates key active, plan: {data.get('plan', {}).get('name', '?')}",
                provider="openexchangerates",
                permissions=f"requests: {data.get('usage', {}).get('requests', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="OpenExchangeRates rejected", provider="openexchangerates")
        return VerificationResult(status="error", details=f"OpenExchangeRates HTTP {r.status_code}", provider="openexchangerates")
    except Exception as e:
        return _error_result(e, "openexchangerates")


async def verify_fixer_key(key: str) -> VerificationResult:
    """GET /latest?access_key=X. Fixer returns HTTP 401 on bad keys; treat as
    inactive (not error)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"http://data.fixer.io/api/latest?access_key={key}&symbols=USD")
        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                return VerificationResult(status="active",
                    details="Fixer.io key active",
                    provider="fixer", permissions="FX data")
            err = data.get("error", {})
            return VerificationResult(status="inactive",
                details=f"Fixer.io: {err.get('info', '?')[:80]}", provider="fixer")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Fixer.io rejected", provider="fixer")
        return VerificationResult(status="error", details=f"Fixer HTTP {r.status_code}", provider="fixer")
    except Exception as e:
        return _error_result(e, "fixer")


async def verify_coinmarketcap_key(key: str) -> VerificationResult:
    """GET /v1/key/info — X-CMC_PRO_API_KEY header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://pro-api.coinmarketcap.com/v1/key/info",
                headers={"X-CMC_PRO_API_KEY": key, "Accept": "application/json"})
        if r.status_code == 200:
            data = r.json().get("data", {})
            return VerificationResult(status="active",
                details=f"CoinMarketCap key active, plan: {data.get('plan', {}).get('credit_limit_monthly', '?')} credits/mo",
                provider="coinmarketcap", permissions=f"id: {data.get('user_id', '')[:12]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="CoinMarketCap rejected", provider="coinmarketcap")
        return VerificationResult(status="error", details=f"CMC HTTP {r.status_code}", provider="coinmarketcap")
    except Exception as e:
        return _error_result(e, "coinmarketcap")


async def verify_etherscan_key(key: str) -> VerificationResult:
    """GET ?module=stats&action=ethsupply&apikey=X. Etherscan always returns
    HTTP 200 — the JSON body's status field and result indicate rejection."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.etherscan.io/api?module=stats&action=ethsupply&apikey={key}")
        if r.status_code == 200:
            data = r.json()
            status = data.get("status")
            result = str(data.get("result", ""))
            if status == "1":
                return VerificationResult(status="active",
                    details="Etherscan key active",
                    provider="etherscan", permissions="blockchain data")
            # status == "0" with "Invalid API Key" or similar rejection message
            if status == "0" or "invalid" in result.lower() or "NOTOK" in str(data.get("message", "")):
                return VerificationResult(status="inactive",
                    details=f"Etherscan: {result[:80]}", provider="etherscan")
        return VerificationResult(status="error", details=f"Etherscan HTTP {r.status_code}", provider="etherscan")
    except Exception as e:
        return _error_result(e, "etherscan")


async def verify_openweather_key(key: str) -> VerificationResult:
    """GET /data/2.5/weather?q=London&appid=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.openweathermap.org/data/2.5/weather?q=London&appid={key}")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="OpenWeather key active",
                provider="openweather", permissions="weather data")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="OpenWeather rejected", provider="openweather")
        return VerificationResult(status="error", details=f"OpenWeather HTTP {r.status_code}", provider="openweather")
    except Exception as e:
        return _error_result(e, "openweather")


async def verify_weatherapi_key(key: str) -> VerificationResult:
    """GET /v1/current.json?key=X&q=London."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.weatherapi.com/v1/current.json?key={key}&q=London")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="WeatherAPI key active",
                provider="weatherapi", permissions="current weather")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="WeatherAPI rejected", provider="weatherapi")
        return VerificationResult(status="error", details=f"WeatherAPI HTTP {r.status_code}", provider="weatherapi")
    except Exception as e:
        return _error_result(e, "weatherapi")


async def verify_tomorrow_io_key(key: str) -> VerificationResult:
    """GET /v4/weather/realtime?location=London&apikey=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.tomorrow.io/v4/weather/realtime?location=London&apikey={key}")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Tomorrow.io key active",
                provider="tomorrow_io", permissions="realtime weather")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Tomorrow.io rejected", provider="tomorrow_io")
        return VerificationResult(status="error", details=f"Tomorrow.io HTTP {r.status_code}", provider="tomorrow_io")
    except Exception as e:
        return _error_result(e, "tomorrow_io")


async def verify_here_maps_key(key: str) -> VerificationResult:
    """GET /v1/geocode?apikey=X&q=London."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://geocode.search.hereapi.com/v1/geocode?apikey={key}&q=London")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="HERE Maps key active",
                provider="here", permissions="geocoding")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="HERE Maps rejected", provider="here")
        return VerificationResult(status="error", details=f"HERE HTTP {r.status_code}", provider="here")
    except Exception as e:
        return _error_result(e, "here")


async def verify_tomtom_key(key: str) -> VerificationResult:
    """GET /search/2/geocode/London.json?key=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.tomtom.com/search/2/geocode/London.json?key={key}")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="TomTom key active",
                provider="tomtom", permissions="maps+geocoding")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="TomTom rejected", provider="tomtom")
        return VerificationResult(status="error", details=f"TomTom HTTP {r.status_code}", provider="tomtom")
    except Exception as e:
        return _error_result(e, "tomtom")


async def verify_opencage_key(key: str) -> VerificationResult:
    """GET /geocode/v1/json?q=London&key=X&limit=1."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.opencagedata.com/geocode/v1/json?q=London&key={key}&limit=1")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="OpenCage key active",
                provider="opencage", permissions="geocoding")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="OpenCage rejected", provider="opencage")
        return VerificationResult(status="error", details=f"OpenCage HTTP {r.status_code}", provider="opencage")
    except Exception as e:
        return _error_result(e, "opencage")


async def verify_locationiq_key(key: str) -> VerificationResult:
    """GET /v1/search.php?key=X&q=London&format=json."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://us1.locationiq.com/v1/search.php?key={key}&q=London&format=json")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="LocationIQ key active",
                provider="locationiq", permissions="geocoding")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="LocationIQ rejected", provider="locationiq")
        return VerificationResult(status="error", details=f"LocationIQ HTTP {r.status_code}", provider="locationiq")
    except Exception as e:
        return _error_result(e, "locationiq")


async def verify_positionstack_key(key: str) -> VerificationResult:
    """GET /v1/forward?access_key=X&query=London. Returns HTTP 401 on bad keys."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"http://api.positionstack.com/v1/forward?access_key={key}&query=London")
        if r.status_code == 200:
            data = r.json()
            if data.get("error"):
                return VerificationResult(status="inactive",
                    details=f"Positionstack: {data['error'].get('message', '?')[:80]}", provider="positionstack")
            return VerificationResult(status="active",
                details="Positionstack key active",
                provider="positionstack", permissions="geocoding")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Positionstack rejected", provider="positionstack")
        return VerificationResult(status="error", details=f"Positionstack HTTP {r.status_code}", provider="positionstack")
    except Exception as e:
        return _error_result(e, "positionstack")


async def verify_ipstack_key(key: str) -> VerificationResult:
    """GET /8.8.8.8?access_key=X. Returns HTTP 401 on bad keys."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"http://api.ipstack.com/8.8.8.8?access_key={key}")
        if r.status_code == 200:
            data = r.json()
            if data.get("success") is False:
                return VerificationResult(status="inactive",
                    details=f"IPStack: {data.get('error', {}).get('info', '?')[:80]}",
                    provider="ipstack")
            return VerificationResult(status="active",
                details="IPStack key active",
                provider="ipstack", permissions="IP geolocation")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="IPStack rejected", provider="ipstack")
        return VerificationResult(status="error", details=f"IPStack HTTP {r.status_code}", provider="ipstack")
    except Exception as e:
        return _error_result(e, "ipstack")


async def verify_ipgeolocation_key(key: str) -> VerificationResult:
    """GET /ipgeo?apiKey=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.ipgeolocation.io/ipgeo?apiKey={key}&ip=8.8.8.8")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="IPGeolocation key active",
                provider="ipgeolocation", permissions="IP geolocation")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="IPGeolocation rejected", provider="ipgeolocation")
        return VerificationResult(status="error", details=f"IPGeolocation HTTP {r.status_code}", provider="ipgeolocation")
    except Exception as e:
        return _error_result(e, "ipgeolocation")


async def verify_virustotal_key(key: str) -> VerificationResult:
    """GET /api/v3/ip_addresses/8.8.8.8 — X-Apikey header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                headers={"x-apikey": key})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="VirusTotal key active",
                provider="virustotal", permissions="threat intel")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="VirusTotal rejected", provider="virustotal")
        return VerificationResult(status="error", details=f"VirusTotal HTTP {r.status_code}", provider="virustotal")
    except Exception as e:
        return _error_result(e, "virustotal")


async def verify_abuseipdb_key(key: str) -> VerificationResult:
    """GET /api/v2/check?ipAddress=8.8.8.8 — Key header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8",
                headers={"Key": key, "Accept": "application/json"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="AbuseIPDB key active",
                provider="abuseipdb", permissions="IP reputation")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="AbuseIPDB rejected", provider="abuseipdb")
        return VerificationResult(status="error", details=f"AbuseIPDB HTTP {r.status_code}", provider="abuseipdb")
    except Exception as e:
        return _error_result(e, "abuseipdb")


async def verify_hibp_key(key: str) -> VerificationResult:
    """GET /api/v3/breachedaccount/{test} — hibp-api-key. /breaches is public;
    /breachedaccount strictly requires auth and returns 401 for bogus keys."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com?truncateResponse=true",
                headers={"hibp-api-key": key, "User-Agent": "Vooda/1.0"})
        # 200 = breaches found, 404 = no breaches (still valid auth)
        if r.status_code in (200, 404):
            return VerificationResult(status="active",
                details="HIBP key active",
                provider="hibp", permissions="breach lookup")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="HIBP rejected", provider="hibp")
        return VerificationResult(status="error", details=f"HIBP HTTP {r.status_code}", provider="hibp")
    except Exception as e:
        return _error_result(e, "hibp")


async def verify_greynoise_key(key: str) -> VerificationResult:
    """GET /v2/noise/context/8.8.8.8 — key header. v2/context requires auth
    (returns 401 for bogus); v3/community is unauthenticated and returns 200."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.greynoise.io/v2/noise/context/8.8.8.8",
                headers={"key": key, "Accept": "application/json"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="GreyNoise key active",
                provider="greynoise", permissions="IP intel")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="GreyNoise rejected", provider="greynoise")
        return VerificationResult(status="error", details=f"GreyNoise HTTP {r.status_code}", provider="greynoise")
    except Exception as e:
        return _error_result(e, "greynoise")


async def verify_persona_key(key: str) -> VerificationResult:
    """GET /api/v1/inquiries — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://withpersona.com/api/v1/inquiries?page[size]=1",
                headers={"Authorization": f"Bearer {key}", "Persona-Version": "2023-01-05"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Persona key active",
                provider="persona", permissions="inquiries read")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Persona rejected", provider="persona")
        return VerificationResult(status="error", details=f"Persona HTTP {r.status_code}", provider="persona")
    except Exception as e:
        return _error_result(e, "persona")


async def verify_onfido_token(token: str) -> VerificationResult:
    """GET /v3.5/applicants — Token {token}."""
    try:
        import httpx
        region_host = "api.us.onfido.com" if "api_live_us." in token or "api_sandbox_us." in token else "api.eu.onfido.com"
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://{region_host}/v3.5/applicants",
                headers={"Authorization": f"Token token={token}"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details=f"Onfido token active @ {region_host}",
                provider="onfido", permissions="KYC applicants")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Onfido rejected", provider="onfido")
        return VerificationResult(status="error", details=f"Onfido HTTP {r.status_code}", provider="onfido")
    except Exception as e:
        return _error_result(e, "onfido")


async def verify_datocms_token(token: str) -> VerificationResult:
    """GET /site — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://site-api.datocms.com/site",
                headers={"Authorization": f"Bearer {token}",
                         "Accept": "application/json",
                         "X-Api-Version": "3"})
        if r.status_code == 200:
            site = r.json().get("data", {}).get("attributes", {})
            return VerificationResult(status="active",
                details=f"DatoCMS token active, site: {site.get('name', '?')}",
                provider="datocms", permissions=f"domain: {site.get('domain', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="DatoCMS rejected", provider="datocms")
        return VerificationResult(status="error", details=f"DatoCMS HTTP {r.status_code}", provider="datocms")
    except Exception as e:
        return _error_result(e, "datocms")


async def verify_pingdom_token(token: str) -> VerificationResult:
    """GET /api/3.1/checks — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.pingdom.com/api/3.1/checks?limit=1",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            checks = r.json().get("checks", [])
            return VerificationResult(status="active",
                details=f"Pingdom token active, {len(checks)} check(s)",
                provider="pingdom", permissions=f"checks: {len(checks)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Pingdom rejected", provider="pingdom")
        return VerificationResult(status="error", details=f"Pingdom HTTP {r.status_code}", provider="pingdom")
    except Exception as e:
        return _error_result(e, "pingdom")


async def verify_uptimerobot_key(key: str) -> VerificationResult:
    """POST /v2/getAccountDetails — form-urlencoded api_key."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.post("https://api.uptimerobot.com/v2/getAccountDetails",
                data={"api_key": key, "format": "json"},
                headers={"Content-Type": "application/x-www-form-urlencoded"})
        if r.status_code == 200:
            data = r.json()
            if data.get("stat") == "ok":
                return VerificationResult(status="active",
                    details=f"UptimeRobot key active, email: {data.get('account', {}).get('email', '?')}",
                    provider="uptimerobot", permissions="monitor management")
            return VerificationResult(status="inactive",
                details=f"UptimeRobot: {data.get('error', {}).get('message', '?')[:80]}",
                provider="uptimerobot")
        return VerificationResult(status="error", details=f"UptimeRobot HTTP {r.status_code}", provider="uptimerobot")
    except Exception as e:
        return _error_result(e, "uptimerobot")


async def verify_koyeb_token(token: str) -> VerificationResult:
    """GET /v1/apps — Bearer. Returns 401 for bad token, 200 for valid (even
    if the account has no apps)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://app.koyeb.com/v1/apps?limit=1",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            apps = r.json().get("apps", [])
            return VerificationResult(status="active",
                details=f"Koyeb token active, {len(apps)} app(s) visible",
                provider="koyeb", permissions=f"apps: {len(apps)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Koyeb rejected", provider="koyeb")
        return VerificationResult(status="error", details=f"Koyeb HTTP {r.status_code}", provider="koyeb")
    except Exception as e:
        return _error_result(e, "koyeb")


async def verify_wistia_token(token: str) -> VerificationResult:
    """GET /v1/account — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.wistia.com/v1/account.json",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Wistia token active, name: {data.get('name', '?')}",
                provider="wistia", permissions=f"plan: {data.get('plan', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Wistia rejected", provider="wistia")
        return VerificationResult(status="error", details=f"Wistia HTTP {r.status_code}", provider="wistia")
    except Exception as e:
        return _error_result(e, "wistia")


async def verify_dbt_cloud_token(token: str) -> VerificationResult:
    """GET /api/v3/accounts — Authorization: Token."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://cloud.getdbt.com/api/v3/accounts",
                headers={"Authorization": f"Token {token}"})
        if r.status_code == 200:
            accts = r.json().get("data", [])
            return VerificationResult(status="active",
                details=f"dbt Cloud token active, {len(accts)} account(s)",
                provider="dbt", permissions=f"accounts: {len(accts)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="dbt Cloud rejected", provider="dbt")
        return VerificationResult(status="error", details=f"dbt Cloud HTTP {r.status_code}", provider="dbt")
    except Exception as e:
        return _error_result(e, "dbt")


async def verify_betterstack_token(token: str) -> VerificationResult:
    """GET /api/v2/monitors — Bearer (Better Uptime / Better Stack)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://uptime.betterstack.com/api/v2/monitors?per_page=1",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json().get("data", [])
            return VerificationResult(status="active",
                details=f"Better Stack token active, {len(data)} monitor(s)",
                provider="betterstack", permissions=f"monitors: {len(data)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Better Stack rejected", provider="betterstack")
        return VerificationResult(status="error", details=f"Better Stack HTTP {r.status_code}", provider="betterstack")
    except Exception as e:
        return _error_result(e, "betterstack")


async def verify_hightouch_token(token: str) -> VerificationResult:
    """GET /api/v1/workspaces — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.hightouch.com/api/v1/workspaces",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            ws = r.json().get("data", [])
            return VerificationResult(status="active",
                details=f"Hightouch token active, {len(ws)} workspace(s)",
                provider="hightouch", permissions=f"workspaces: {len(ws)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Hightouch rejected", provider="hightouch")
        return VerificationResult(status="error", details=f"Hightouch HTTP {r.status_code}", provider="hightouch")
    except Exception as e:
        return _error_result(e, "hightouch")


async def verify_railway_token(token: str) -> VerificationResult:
    """POST /graphql/v2 — { me { id } } — Bearer. Railway returns 200 with a
    GraphQL errors array when auth fails — treat "Not Authorized" as inactive."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.post("https://backboard.railway.app/graphql/v2",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={"query": "{ me { id email } }"})
        if r.status_code == 200:
            body = r.json()
            errors = body.get("errors") or []
            if errors:
                msg = errors[0].get("message", "")
                if "Not Authorized" in msg or "unauthorized" in msg.lower() or "invalid" in msg.lower():
                    return VerificationResult(status="inactive",
                        details=f"Railway: {msg[:80]}", provider="railway")
                return VerificationResult(status="error",
                    details=f"Railway GraphQL error: {msg[:80]}", provider="railway")
            me = (body.get("data") or {}).get("me")
            if me:
                return VerificationResult(status="active",
                    details=f"Railway token active, user: {me.get('email', '?')}",
                    provider="railway", permissions=f"id: {me.get('id', '')[:18]}")
            return VerificationResult(status="inactive", details="Railway: no viewer", provider="railway")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Railway rejected", provider="railway")
        return VerificationResult(status="error", details=f"Railway HTTP {r.status_code}", provider="railway")
    except Exception as e:
        return _error_result(e, "railway")


async def verify_runway_key(key: str) -> VerificationResult:
    """GET /v1/tasks — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.runwayml.com/v1/tasks?limit=1",
                headers={"Authorization": f"Bearer {key}",
                         "X-Runway-Version": "2024-11-06"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="RunwayML key active",
                provider="runway", permissions="video generation API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="RunwayML rejected", provider="runway")
        return VerificationResult(status="error", details=f"RunwayML HTTP {r.status_code}", provider="runway")
    except Exception as e:
        return _error_result(e, "runway")


async def verify_tiingo_key(key: str) -> VerificationResult:
    """GET /api/test/ — Authorization: Token {key} header. Query-param
    ?token=X doesn't actually authenticate on the /api/test endpoint
    (returns 200 for anyone). Use the auth header + proper content-type."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.tiingo.com/api/test/",
                headers={"Authorization": f"Token {key}",
                         "Content-Type": "application/json"})
        if r.status_code == 200:
            data = r.json()
            # With a valid token, Tiingo returns {"message": "You successfully sent..."}
            # With no token, returns {"message": "You did not set..."}
            if "successfully" in str(data.get("message", "")).lower():
                return VerificationResult(status="active",
                    details="Tiingo key active", provider="tiingo", permissions="market data")
            return VerificationResult(status="inactive",
                details=f"Tiingo: {data.get('message', 'rejected')[:80]}", provider="tiingo")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Tiingo rejected", provider="tiingo")
        return VerificationResult(status="error", details=f"Tiingo HTTP {r.status_code}", provider="tiingo")
    except Exception as e:
        return _error_result(e, "tiingo")


async def verify_octopus_deploy_key(key: str, server_url: str = "") -> VerificationResult:
    """GET /api/users/me — X-Octopus-ApiKey header. Octopus is tenant-scoped;
    without a server URL we can't verify (on-prem each customer has their own
    server host). Returns unsupported unless server_url is supplied."""
    try:
        if not server_url:
            return VerificationResult(status="unsupported",
                details="Octopus Deploy verification needs server URL (e.g. https://company.octopus.app)",
                provider="octopus")
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"{server_url.rstrip('/')}/api/users/me",
                headers={"X-Octopus-ApiKey": key})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Octopus Deploy key active, user: {data.get('Username', '?')}",
                provider="octopus", permissions=f"id: {data.get('Id', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Octopus key rejected", provider="octopus")
        return VerificationResult(status="error", details=f"Octopus HTTP {r.status_code}", provider="octopus")
    except Exception as e:
        return _error_result(e, "octopus")


async def verify_dropbox_sign_key(key: str) -> VerificationResult:
    """GET /v3/account — Basic auth with key:empty (HelloSign/Dropbox Sign)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.hellosign.com/v3/account",
                auth=(key, ""))
        if r.status_code == 200:
            data = r.json().get("account", {})
            return VerificationResult(status="active",
                details=f"Dropbox Sign key active, email: {data.get('email_address', '?')}",
                provider="dropbox_sign", permissions=f"role: {data.get('role_code', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Dropbox Sign rejected", provider="dropbox_sign")
        return VerificationResult(status="error", details=f"Dropbox Sign HTTP {r.status_code}", provider="dropbox_sign")
    except Exception as e:
        return _error_result(e, "dropbox_sign")


async def verify_pandadoc_key(key: str) -> VerificationResult:
    """GET /public/v1/documents?count=1 — API-Key header (prefix 'API-Key')."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.pandadoc.com/public/v1/documents?count=1",
                headers={"Authorization": f"API-Key {key}"})
        if r.status_code == 200:
            docs = r.json().get("results", [])
            return VerificationResult(status="active",
                details=f"PandaDoc key active, {len(docs)} doc(s) visible",
                provider="pandadoc", permissions=f"docs: {len(docs)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="PandaDoc rejected", provider="pandadoc")
        return VerificationResult(status="error", details=f"PandaDoc HTTP {r.status_code}", provider="pandadoc")
    except Exception as e:
        return _error_result(e, "pandadoc")


async def verify_zerobounce_key(key: str) -> VerificationResult:
    """GET /v2/getcredits?api_key=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.zerobounce.net/v2/getcredits?api_key={key}")
        if r.status_code == 200:
            data = r.json()
            credits = data.get("Credits", -999)
            if str(credits).lstrip("-").isdigit() and int(credits) >= 0:
                return VerificationResult(status="active",
                    details=f"ZeroBounce key active, {credits} credits",
                    provider="zerobounce", permissions=f"credits: {credits}")
            return VerificationResult(status="inactive",
                details="ZeroBounce: no credits / invalid", provider="zerobounce")
        return VerificationResult(status="error", details=f"ZeroBounce HTTP {r.status_code}", provider="zerobounce")
    except Exception as e:
        return _error_result(e, "zerobounce")


async def verify_neverbounce_key(key: str) -> VerificationResult:
    """GET /v4/account/info?key=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.neverbounce.com/v4/account/info?key={key}")
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                credits = data.get("credits_info", {})
                return VerificationResult(status="active",
                    details=f"NeverBounce key active",
                    provider="neverbounce",
                    permissions=f"paid credits: {credits.get('paid_credits_remaining', '?')}")
            return VerificationResult(status="inactive",
                details=f"NeverBounce: {data.get('message', '?')[:80]}", provider="neverbounce")
        return VerificationResult(status="error", details=f"NeverBounce HTTP {r.status_code}", provider="neverbounce")
    except Exception as e:
        return _error_result(e, "neverbounce")


async def verify_kickbox_key(key: str) -> VerificationResult:
    """GET /v2/verify?email=test@example.com&apikey=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.kickbox.com/v2/verify?email=test@example.com&apikey={key}")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Kickbox key active",
                provider="kickbox", permissions="email verification")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Kickbox rejected", provider="kickbox")
        return VerificationResult(status="error", details=f"Kickbox HTTP {r.status_code}", provider="kickbox")
    except Exception as e:
        return _error_result(e, "kickbox")


async def verify_emailable_key(key: str) -> VerificationResult:
    """GET /v1/account?api_key=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.emailable.com/v1/account?api_key={key}")
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Emailable key active, plan: {data.get('plan_name', '?')}",
                provider="emailable", permissions=f"credits: {data.get('credits', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Emailable rejected", provider="emailable")
        return VerificationResult(status="error", details=f"Emailable HTTP {r.status_code}", provider="emailable")
    except Exception as e:
        return _error_result(e, "emailable")


async def verify_lokalise_token(token: str) -> VerificationResult:
    """GET /api2/teams — X-Api-Token header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.lokalise.com/api2/teams",
                headers={"X-Api-Token": token})
        if r.status_code == 200:
            teams = r.json().get("teams", [])
            return VerificationResult(status="active",
                details=f"Lokalise token active, {len(teams)} team(s)",
                provider="lokalise", permissions=f"teams: {len(teams)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Lokalise rejected", provider="lokalise")
        return VerificationResult(status="error", details=f"Lokalise HTTP {r.status_code}", provider="lokalise")
    except Exception as e:
        return _error_result(e, "lokalise")


async def verify_crowdin_token(token: str) -> VerificationResult:
    """GET /api/v2/user — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.crowdin.com/api/v2/user",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json().get("data", {})
            return VerificationResult(status="active",
                details=f"Crowdin token active, user: {data.get('username', '?')}",
                provider="crowdin", permissions=f"email: {data.get('email', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Crowdin rejected", provider="crowdin")
        return VerificationResult(status="error", details=f"Crowdin HTTP {r.status_code}", provider="crowdin")
    except Exception as e:
        return _error_result(e, "crowdin")


async def verify_phrase_token(token: str) -> VerificationResult:
    """GET /api/v2/user — Authorization: token t_{key}."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.phrase.com/api/v2/user",
                headers={"Authorization": f"token {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Phrase token active, user: {data.get('email', '?')}",
                provider="phrase", permissions=f"name: {data.get('name', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Phrase rejected", provider="phrase")
        return VerificationResult(status="error", details=f"Phrase HTTP {r.status_code}", provider="phrase")
    except Exception as e:
        return _error_result(e, "phrase")


async def verify_papertrail_token(token: str) -> VerificationResult:
    """GET /api/v1/users/show.json — X-Papertrail-Token header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://papertrailapp.com/api/v1/users/show.json",
                headers={"X-Papertrail-Token": token})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Papertrail token active",
                provider="papertrail", permissions="log management")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Papertrail rejected", provider="papertrail")
        return VerificationResult(status="error", details=f"Papertrail HTTP {r.status_code}", provider="papertrail")
    except Exception as e:
        return _error_result(e, "papertrail")


async def verify_axiom_pat(token: str) -> VerificationResult:
    """GET /v1/user — Bearer (Axiom PAT)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.axiom.co/v1/user",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Axiom token active, user: {data.get('email', '?')}",
                provider="axiom", permissions=f"id: {data.get('id', '')[:12]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Axiom rejected", provider="axiom")
        return VerificationResult(status="error", details=f"Axiom HTTP {r.status_code}", provider="axiom")
    except Exception as e:
        return _error_result(e, "axiom")


async def verify_flagsmith_env_key(key: str) -> VerificationResult:
    """GET /api/v1/flags/ — X-Environment-Key header. Use api.flagsmith.com
    (edge.api.flagsmith.com returns 404 for this endpoint)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.flagsmith.com/api/v1/flags/",
                headers={"X-Environment-Key": key})
        if r.status_code == 200:
            flags = r.json() if isinstance(r.json(), list) else []
            return VerificationResult(status="active",
                details=f"Flagsmith key active, {len(flags)} flag(s)",
                provider="flagsmith", permissions=f"flags: {len(flags)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Flagsmith rejected", provider="flagsmith")
        return VerificationResult(status="error", details=f"Flagsmith HTTP {r.status_code}", provider="flagsmith")
    except Exception as e:
        return _error_result(e, "flagsmith")


async def verify_airbrake_key(key: str) -> VerificationResult:
    """GET /api/v4/projects — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.airbrake.io/api/v4/projects",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            projects = r.json() if isinstance(r.json(), list) else r.json().get("projects", [])
            return VerificationResult(status="active",
                details=f"Airbrake key active, {len(projects)} project(s)",
                provider="airbrake", permissions=f"projects: {len(projects)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Airbrake rejected", provider="airbrake")
        return VerificationResult(status="error", details=f"Airbrake HTTP {r.status_code}", provider="airbrake")
    except Exception as e:
        return _error_result(e, "airbrake")


async def verify_hunter_key(key: str) -> VerificationResult:
    """GET /v2/account?api_key=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.hunter.io/v2/account?api_key={key}")
        if r.status_code == 200:
            data = r.json().get("data", {})
            return VerificationResult(status="active",
                details=f"Hunter.io key active, plan: {data.get('plan_name', '?')}",
                provider="hunter", permissions=f"email: {data.get('email', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Hunter.io rejected", provider="hunter")
        return VerificationResult(status="error", details=f"Hunter HTTP {r.status_code}", provider="hunter")
    except Exception as e:
        return _error_result(e, "hunter")


async def verify_apollo_io_key(key: str) -> VerificationResult:
    """GET /api/v1/email_accounts?api_key=X. Returns 401 for bad keys."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.apollo.io/api/v1/email_accounts?api_key={key}")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Apollo.io key active",
                provider="apollo", permissions="sales intel")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Apollo.io rejected", provider="apollo")
        return VerificationResult(status="error", details=f"Apollo HTTP {r.status_code}", provider="apollo")
    except Exception as e:
        return _error_result(e, "apollo")


async def verify_drift_token(token: str) -> VerificationResult:
    """GET /contacts?limit=1 — Bearer (OAuth JWT)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://driftapi.com/contacts?limit=1",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Drift token active",
                provider="drift", permissions="conversations API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Drift rejected", provider="drift")
        return VerificationResult(status="error", details=f"Drift HTTP {r.status_code}", provider="drift")
    except Exception as e:
        return _error_result(e, "drift")


async def verify_close_io_key(key: str) -> VerificationResult:
    """GET /api/v1/me — Basic auth (key:empty)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.close.com/api/v1/me/", auth=(key, ""))
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Close.com key active, user: {data.get('email', '?')}",
                provider="close", permissions=f"id: {data.get('id', '')[:18]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Close.com rejected", provider="close")
        return VerificationResult(status="error", details=f"Close HTTP {r.status_code}", provider="close")
    except Exception as e:
        return _error_result(e, "close", log_key="close_io")


async def verify_lemonsqueezy_key(key: str) -> VerificationResult:
    """GET /v1/users/me — Bearer (JWT)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.lemonsqueezy.com/v1/users/me",
                headers={"Authorization": f"Bearer {key}", "Accept": "application/vnd.api+json"})
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            return VerificationResult(status="active",
                details=f"Lemon Squeezy key active, email: {data.get('email', '?')}",
                provider="lemonsqueezy", permissions=f"name: {data.get('name', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Lemon Squeezy rejected", provider="lemonsqueezy")
        return VerificationResult(status="error", details=f"Lemon Squeezy HTTP {r.status_code}", provider="lemonsqueezy")
    except Exception as e:
        return _error_result(e, "lemonsqueezy")


async def verify_gumroad_token(token: str) -> VerificationResult:
    """GET /v2/user?access_token=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.gumroad.com/v2/user?access_token={token}")
        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                user = data.get("user", {})
                return VerificationResult(status="active",
                    details=f"Gumroad token active, user: {user.get('email', '?')}",
                    provider="gumroad", permissions=f"id: {user.get('user_id', '')[:18]}")
            return VerificationResult(status="inactive", details="Gumroad: not successful", provider="gumroad")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Gumroad rejected", provider="gumroad")
        return VerificationResult(status="error", details=f"Gumroad HTTP {r.status_code}", provider="gumroad")
    except Exception as e:
        return _error_result(e, "gumroad")


async def verify_jotform_key(key: str) -> VerificationResult:
    """GET /user?apiKey=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.jotform.com/user?apiKey={key}")
        if r.status_code == 200:
            data = r.json()
            if data.get("responseCode") == 200:
                return VerificationResult(status="active",
                    details=f"Jotform key active, user: {data.get('content', {}).get('email', '?')}",
                    provider="jotform", permissions="forms API")
            return VerificationResult(status="inactive",
                details=f"Jotform: {data.get('message', '?')[:80]}", provider="jotform")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Jotform rejected", provider="jotform")
        return VerificationResult(status="error", details=f"Jotform HTTP {r.status_code}", provider="jotform")
    except Exception as e:
        return _error_result(e, "jotform")


async def verify_riot_games_key(key: str) -> VerificationResult:
    """GET /lol/status/v4/platform-data — X-Riot-Token header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://na1.api.riotgames.com/lol/status/v4/platform-data",
                headers={"X-Riot-Token": key})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Riot Games key active",
                provider="riot", permissions="game data API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Riot key rejected", provider="riot")
        return VerificationResult(status="error", details=f"Riot HTTP {r.status_code}", provider="riot")
    except Exception as e:
        return _error_result(e, "riot")


async def verify_steam_key(key: str) -> VerificationResult:
    """GET /ISteamWebAPIUtil/GetServerInfo/v1/?key=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key={key}&steamids=76561197960435530")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Steam Web API key active",
                provider="steam", permissions="Steam API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Steam rejected", provider="steam")
        return VerificationResult(status="error", details=f"Steam HTTP {r.status_code}", provider="steam")
    except Exception as e:
        return _error_result(e, "steam")


async def verify_giphy_key(key: str) -> VerificationResult:
    """GET /v1/gifs/trending?api_key=X&limit=1."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.giphy.com/v1/gifs/trending?api_key={key}&limit=1")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Giphy key active",
                provider="giphy", permissions="GIF API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Giphy rejected", provider="giphy")
        return VerificationResult(status="error", details=f"Giphy HTTP {r.status_code}", provider="giphy")
    except Exception as e:
        return _error_result(e, "giphy")


async def verify_tenor_key(key: str) -> VerificationResult:
    """GET /v2/search — Google Tenor API returns 400 API_KEY_INVALID for bad keys."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://tenor.googleapis.com/v2/search?q=test&key={key}&limit=1")
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Tenor key active",
                provider="tenor", permissions="GIF API")
        elif r.status_code in (400, 401, 403) and "API_KEY_INVALID" in r.text:
            return VerificationResult(status="inactive", details="Tenor key rejected", provider="tenor")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Tenor rejected", provider="tenor")
        return VerificationResult(status="error", details=f"Tenor HTTP {r.status_code}", provider="tenor")
    except Exception as e:
        return _error_result(e, "tenor")


async def verify_amadeus_oauth(client_id: str, client_secret: str) -> VerificationResult:
    """POST /v1/security/oauth2/token — client credentials grant."""
    try:
        if not (client_id and client_secret):
            return VerificationResult(status="unsupported",
                details="Amadeus needs client_id + client_secret pair", provider="amadeus")
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.post("https://test.travel.api.amadeus.com/v1/security/oauth2/token",
                data={"grant_type": "client_credentials",
                      "client_id": client_id,
                      "client_secret": client_secret})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Amadeus OAuth active (test env)",
                provider="amadeus", permissions="travel search")
        elif r.status_code in (401, 403, 400):
            return VerificationResult(status="inactive", details="Amadeus rejected", provider="amadeus")
        return VerificationResult(status="error", details=f"Amadeus HTTP {r.status_code}", provider="amadeus")
    except Exception as e:
        return _error_result(e, "amadeus")


async def verify_webflow_token(token: str) -> VerificationResult:
    """GET /v2/token/introspect — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.webflow.com/v2/token/introspect",
                headers={"Authorization": f"Bearer {token}",
                         "accept-version": "2.0.0"})
        if r.status_code == 200:
            data = r.json()
            app = data.get("application", {}) if isinstance(data.get("application"), dict) else {}
            app_name = app.get("displayName", "?")
            auth = data.get("authorization", {}) if isinstance(data.get("authorization"), dict) else {}
            scopes = auth.get("scope", []) or []
            has_write = any("write" in s or "publish" in s for s in scopes)
            risk = "critical" if has_write else "high" if scopes else "high"
            detail = {
                "scopes": scopes[:30],
                "identity": app_name,
                "account_id": str(app.get("id", "")),
                "risk_level": risk,
                "is_production": True,
                "extra": {
                    "app_name": app_name,
                    "app_description": app.get("description", "")[:120],
                    "scope_count": len(scopes),
                },
            }
            result = VerificationResult(status="active",
                details=f"Webflow token active, app: {app_name}",
                provider="webflow",
                permissions=f"scopes: {len(scopes)}",
                permissions_detail=detail, risk_level=risk)
            result.blast_radius_summary = summarize_blast_radius("webflow", detail)
            return result
        if _is_rate_limited(r, "webflow"):
            return _rate_limited_result("webflow", r)
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Webflow rejected", provider="webflow")
        return VerificationResult(status="error", details=f"Webflow HTTP {r.status_code}", provider="webflow")
    except Exception as e:
        return _error_result(e, "webflow")


async def verify_moralis_key(key: str) -> VerificationResult:
    """GET /v2.2/info/endpointWeights — X-API-Key header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://deep-index.moralis.io/api/v2.2/info/endpointWeights",
                headers={"X-API-Key": key, "accept": "application/json"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Moralis key active",
                provider="moralis", permissions="Web3 infra API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Moralis rejected", provider="moralis")
        return VerificationResult(status="error", details=f"Moralis HTTP {r.status_code}", provider="moralis")
    except Exception as e:
        return _error_result(e, "moralis")


async def verify_xai_grok_key(key: str) -> VerificationResult:
    """GET /v1/api-key — Bearer. xAI returns HTTP 400 with 'Incorrect API key'
    message for invalid keys (rather than 401)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.x.ai/v1/api-key",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"xAI Grok key active, name: {data.get('name', '?')}",
                provider="xai", permissions=f"redacted: {data.get('redacted_api_key', '?')[:20]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="xAI rejected", provider="xai")
        elif r.status_code == 400 and "Incorrect API key" in r.text:
            return VerificationResult(status="inactive", details="xAI key rejected", provider="xai")
        return VerificationResult(status="error", details=f"xAI HTTP {r.status_code}", provider="xai")
    except Exception as e:
        return _error_result(e, "xai")


async def verify_copper_crm_key(key: str, email: str = "") -> VerificationResult:
    """GET /developer_api/v1/users — X-PW-AccessToken + X-PW-Application + X-PW-UserEmail.
    Tenant-scoped (needs email to auth)."""
    try:
        if not email:
            return VerificationResult(status="unsupported",
                details="Copper CRM needs user email to verify", provider="copper")
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.copper.com/developer_api/v1/users/me",
                headers={"X-PW-AccessToken": key,
                         "X-PW-Application": "developer_api",
                         "X-PW-UserEmail": email,
                         "Content-Type": "application/json"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Copper CRM key active, user: {data.get('email', '?')}",
                provider="copper", permissions=f"id: {data.get('id', '')[:12]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Copper rejected", provider="copper")
        return VerificationResult(status="error", details=f"Copper HTTP {r.status_code}", provider="copper")
    except Exception as e:
        return _error_result(e, "copper")


async def verify_surveymonkey_token(token: str) -> VerificationResult:
    """GET /v3/users/me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.surveymonkey.com/v3/users/me",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"SurveyMonkey token active, username: {data.get('username', '?')}",
                provider="surveymonkey", permissions=f"email: {data.get('email', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="SurveyMonkey rejected", provider="surveymonkey")
        return VerificationResult(status="error", details=f"SurveyMonkey HTTP {r.status_code}", provider="surveymonkey")
    except Exception as e:
        return _error_result(e, "surveymonkey")


async def verify_loops_key(key: str) -> VerificationResult:
    """GET /v1/api-key — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://app.loops.so/api/v1/api-key",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                return VerificationResult(status="active",
                    details=f"Loops.so key active, team: {data.get('teamName', '?')}",
                    provider="loops", permissions=f"team: {data.get('teamName', '?')}")
            return VerificationResult(status="inactive", details="Loops.so invalid", provider="loops")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Loops.so rejected", provider="loops")
        return VerificationResult(status="error", details=f"Loops.so HTTP {r.status_code}", provider="loops")
    except Exception as e:
        return _error_result(e, "loops")


async def verify_convertkit_secret(secret: str) -> VerificationResult:
    """GET /v3/account?api_secret=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.convertkit.com/v3/account?api_secret={secret}")
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"ConvertKit secret active, name: {data.get('name', '?')}",
                provider="convertkit", permissions=f"email: {data.get('primary_email_address', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="ConvertKit rejected", provider="convertkit")
        return VerificationResult(status="error", details=f"ConvertKit HTTP {r.status_code}", provider="convertkit")
    except Exception as e:
        return _error_result(e, "convertkit")


async def verify_deputy_token(token: str, subdomain: str = "") -> VerificationResult:
    """GET /api/v1/me — Bearer. Tenant-scoped on subdomain."""
    try:
        if not subdomain:
            return VerificationResult(status="unsupported",
                details="Deputy needs tenant subdomain", provider="deputy")
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://{subdomain}.deputy.com/api/v1/me",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details=f"Deputy token active @ {subdomain}",
                provider="deputy", permissions="workforce API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Deputy rejected", provider="deputy")
        return VerificationResult(status="error", details=f"Deputy HTTP {r.status_code}", provider="deputy")
    except Exception as e:
        return _error_result(e, "deputy")


async def verify_bamboohr_key(key: str, subdomain: str = "") -> VerificationResult:
    """GET /v1/meta/users — Basic auth (key:x). Tenant-scoped on subdomain."""
    try:
        if not subdomain:
            return VerificationResult(status="unsupported",
                details="BambooHR needs tenant subdomain", provider="bamboohr")
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.bamboohr.com/api/gateway.php/{subdomain}/v1/meta/users",
                auth=(key, "x"), headers={"Accept": "application/json"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details=f"BambooHR key active @ {subdomain}",
                provider="bamboohr", permissions="HR data")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="BambooHR rejected", provider="bamboohr")
        return VerificationResult(status="error", details=f"BambooHR HTTP {r.status_code}", provider="bamboohr")
    except Exception as e:
        return _error_result(e, "bamboohr")


async def verify_assemblyai_key(key: str) -> VerificationResult:
    """GET /v2/transcript?limit=1 — Authorization header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.assemblyai.com/v2/transcript?limit=1",
                headers={"Authorization": key})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="AssemblyAI key active",
                provider="assemblyai", permissions="transcription API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="AssemblyAI rejected", provider="assemblyai")
        return VerificationResult(status="error", details=f"AssemblyAI HTTP {r.status_code}", provider="assemblyai")
    except Exception as e:
        return _error_result(e, "assemblyai")


async def verify_stability_ai_key(key: str) -> VerificationResult:
    """GET /v1/user/account — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.stability.ai/v1/user/account",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Stability AI key active, email: {data.get('email', '?')}",
                provider="stability", permissions=f"id: {data.get('id', '')[:12]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Stability AI rejected", provider="stability")
        return VerificationResult(status="error", details=f"Stability HTTP {r.status_code}", provider="stability")
    except Exception as e:
        return _error_result(e, "stability")


async def verify_openrouter_key(key: str) -> VerificationResult:
    """GET /api/v1/auth/key — Bearer. Returns usage info for valid keys."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://openrouter.ai/api/v1/auth/key",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json().get("data", {})
            return VerificationResult(status="active",
                details=f"OpenRouter key active, usage: ${data.get('usage', 0):.2f}",
                provider="openrouter", permissions=f"label: {data.get('label', '?')[:40]}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="OpenRouter rejected", provider="openrouter")
        return VerificationResult(status="error", details=f"OpenRouter HTTP {r.status_code}", provider="openrouter")
    except Exception as e:
        return _error_result(e, "openrouter")


async def verify_gitguardian_token(token: str) -> VerificationResult:
    """GET /v1/health — Authorization: Token."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.gitguardian.com/v1/health",
                headers={"Authorization": f"Token {token}"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="GitGuardian token active",
                provider="gitguardian", permissions="scanner API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="GitGuardian rejected", provider="gitguardian")
        return VerificationResult(status="error", details=f"GitGuardian HTTP {r.status_code}", provider="gitguardian")
    except Exception as e:
        return _error_result(e, "gitguardian")


async def verify_magic_link_secret(key: str) -> VerificationResult:
    """GET /v1/admin/auth/user/get — X-Magic-Secret-Key header."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.magic.link/v1/admin/auth/user/get?issuer=none",
                headers={"X-Magic-Secret-Key": key})
        if r.status_code in (200, 400):
            # 400 with "no user found" still means auth succeeded
            return VerificationResult(status="active",
                details="Magic.link secret key active",
                provider="magic", permissions="admin user API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Magic.link rejected", provider="magic")
        return VerificationResult(status="error", details=f"Magic HTTP {r.status_code}", provider="magic")
    except Exception as e:
        return _error_result(e, "magic")


async def verify_thirdweb_secret(key: str) -> VerificationResult:
    """GET /v1/wallets/user — x-secret-key. /v1/chains is public, so use
    /v1/wallets/user which returns 401 for bad keys."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.thirdweb.com/v1/wallets/user",
                headers={"x-secret-key": key})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Thirdweb secret key active",
                provider="thirdweb", permissions="Web3 SDK backend")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Thirdweb rejected", provider="thirdweb")
        return VerificationResult(status="error", details=f"Thirdweb HTTP {r.status_code}", provider="thirdweb")
    except Exception as e:
        return _error_result(e, "thirdweb")


async def verify_outreach_token(token: str) -> VerificationResult:
    """GET /api/v2/users — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.outreach.io/api/v2/users?page[limit]=1",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            users = r.json().get("data", [])
            return VerificationResult(status="active",
                details=f"Outreach token active, {len(users)} user(s) visible",
                provider="outreach", permissions="sales engagement API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Outreach rejected", provider="outreach")
        return VerificationResult(status="error", details=f"Outreach HTTP {r.status_code}", provider="outreach")
    except Exception as e:
        return _error_result(e, "outreach")


async def verify_shodan_key(key: str) -> VerificationResult:
    """GET /account/profile?key=X."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"https://api.shodan.io/account/profile?key={key}")
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Shodan key active, member: {data.get('member', False)}",
                provider="shodan", permissions=f"credits: {data.get('credits', '?')}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Shodan rejected", provider="shodan")
        return VerificationResult(status="error", details=f"Shodan HTTP {r.status_code}", provider="shodan")
    except Exception as e:
        return _error_result(e, "shodan")


async def verify_urlscan_key(key: str) -> VerificationResult:
    """GET /user/quotas/ — API-Key header. urlscan returns HTTP 400 "Invalid
    API key format" for malformed keys and 401 for valid-format-but-bad keys."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://urlscan.io/user/quotas/",
                headers={"API-Key": key})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"urlscan.io key active",
                provider="urlscan", permissions=f"limits: {data.get('limits', {}).get('public', {}).get('day', '?')}/day")
        elif r.status_code in (400, 401, 403) and ("Invalid" in r.text or "unauthorized" in r.text.lower()):
            return VerificationResult(status="inactive", details="urlscan rejected", provider="urlscan")
        return VerificationResult(status="error", details=f"urlscan HTTP {r.status_code}", provider="urlscan")
    except Exception as e:
        return _error_result(e, "urlscan")


async def verify_mailersend_token(token: str) -> VerificationResult:
    """GET /v1/domains — Bearer. /v1/api-keys returns 404; use /v1/domains
    which returns 401 Unauthenticated for bad tokens."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.mailersend.com/v1/domains",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            domains = r.json().get("data", [])
            return VerificationResult(status="active",
                details=f"MailerSend token active, {len(domains)} domain(s)",
                provider="mailersend", permissions=f"domains: {len(domains)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="MailerSend rejected", provider="mailersend")
        return VerificationResult(status="error", details=f"MailerSend HTTP {r.status_code}", provider="mailersend")
    except Exception as e:
        return _error_result(e, "mailersend")


async def verify_infobip_key(key: str) -> VerificationResult:
    """GET /account/1/balance — App prefix header. Returns 401 for bad keys."""
    try:
        import httpx
        auth_header = key if key.startswith("App ") else f"App {key}"
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.infobip.com/account/1/balance",
                headers={"Authorization": auth_header, "Accept": "application/json"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Infobip key active",
                provider="infobip", permissions="CPaaS API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Infobip rejected", provider="infobip")
        return VerificationResult(status="error", details=f"Infobip HTTP {r.status_code}", provider="infobip")
    except Exception as e:
        return _error_result(e, "infobip")


async def verify_courier_key(key: str) -> VerificationResult:
    """GET /profiles/test — Bearer (will 404 but confirms auth)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.courier.com/profiles/__nonexistent__",
                headers={"Authorization": f"Bearer {key}"})
        # 404 with valid auth means key worked but profile doesn't exist
        # 401/403 with invalid auth
        if r.status_code in (200, 404):
            return VerificationResult(status="active",
                details="Courier key active",
                provider="courier", permissions="notification API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Courier rejected", provider="courier")
        return VerificationResult(status="error", details=f"Courier HTTP {r.status_code}", provider="courier")
    except Exception as e:
        return _error_result(e, "courier")


async def verify_rippling_token(token: str) -> VerificationResult:
    """GET /platform/api/me — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.rippling.com/platform/api/me",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Rippling token active",
                provider="rippling", permissions="HR/payroll API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Rippling rejected", provider="rippling")
        return VerificationResult(status="error", details=f"Rippling HTTP {r.status_code}", provider="rippling")
    except Exception as e:
        return _error_result(e, "rippling")


async def verify_deel_token(token: str) -> VerificationResult:
    """GET /rest/v2/organizations — Bearer."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.letsdeel.com/rest/v2/organizations",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Deel token active",
                provider="deel", permissions="global payroll API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Deel rejected", provider="deel")
        return VerificationResult(status="error", details=f"Deel HTTP {r.status_code}", provider="deel")
    except Exception as e:
        return _error_result(e, "deel")


async def verify_adyen_key(key: str) -> VerificationResult:
    """GET /checkout/v70/paymentMethods — X-API-Key. Adyen returns 403 for
    bad API keys with clear error body."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.post("https://checkout-test.adyen.com/v70/paymentMethods",
                headers={"X-API-Key": key, "Content-Type": "application/json"},
                json={"merchantAccount": "TestMerchant"})
        if r.status_code in (200, 422):
            # 422 = merchant account invalid but auth OK
            return VerificationResult(status="active",
                details="Adyen API key active",
                provider="adyen", permissions="payment API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Adyen rejected", provider="adyen")
        return VerificationResult(status="error", details=f"Adyen HTTP {r.status_code}", provider="adyen")
    except Exception as e:
        return _error_result(e, "adyen")


async def verify_paystack_secret(key: str) -> VerificationResult:
    """GET /bank — Bearer (Paystack public-list endpoint requires auth)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.paystack.co/balance",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json()
            return VerificationResult(status="active",
                details=f"Paystack key active, status: {data.get('status', '?')}",
                provider="paystack", permissions="payment gateway")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Paystack rejected", provider="paystack")
        return VerificationResult(status="error", details=f"Paystack HTTP {r.status_code}", provider="paystack")
    except Exception as e:
        return _error_result(e, "paystack")


async def verify_cockroach_cloud_key(key: str) -> VerificationResult:
    """GET /api/v1/clusters — Bearer. CockroachDB Cloud API."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://cockroachlabs.cloud/api/v1/clusters",
                headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json().get("clusters", [])
            return VerificationResult(status="active",
                details=f"CockroachDB Cloud key active, {len(data)} cluster(s)",
                provider="cockroachdb", permissions=f"clusters: {len(data)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="CockroachDB rejected", provider="cockroachdb")
        return VerificationResult(status="error", details=f"CockroachDB HTTP {r.status_code}", provider="cockroachdb")
    except Exception as e:
        return _error_result(e, "cockroachdb")


async def verify_gong_key(key: str, access_key_secret: str = "") -> VerificationResult:
    """GET /v2/users — Basic auth with access_key:secret. Tenant-scoped."""
    try:
        if not access_key_secret:
            return VerificationResult(status="unsupported",
                details="Gong needs access_key + secret pair", provider="gong")
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.gong.io/v2/users?limit=1",
                auth=(key, access_key_secret))
        if r.status_code == 200:
            return VerificationResult(status="active",
                details="Gong key active",
                provider="gong", permissions="revenue intelligence API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Gong rejected", provider="gong")
        return VerificationResult(status="error", details=f"Gong HTTP {r.status_code}", provider="gong")
    except Exception as e:
        return _error_result(e, "gong")


async def verify_chronosphere_token(token: str, domain: str = "") -> VerificationResult:
    """GET /api/v1/config/services — Bearer. Tenant-scoped on domain."""
    try:
        if not domain:
            return VerificationResult(status="unsupported",
                details="Chronosphere needs tenant domain (e.g., company.chronosphere.io)",
                provider="chronosphere")
        import httpx
        async with verification_client(timeout=10, provider="chronosphere") as c:
            r = await c.get(f"https://{domain}/api/v1/config/services",
                headers={"API-Token": token})
        if r.status_code == 200:
            return VerificationResult(status="active",
                details=f"Chronosphere token active @ {domain}",
                provider="chronosphere", permissions="observability API")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Chronosphere rejected", provider="chronosphere")
        return VerificationResult(status="error", details=f"Chronosphere HTTP {r.status_code}", provider="chronosphere")
    except Exception as e:
        return _error_result(e, "chronosphere")


async def verify_sentry_auth_token(token: str) -> VerificationResult:
    """GET /api/0/organizations/ — Bearer (sentry sntrys_ or sntryu_)."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get("https://sentry.io/api/0/organizations/",
                headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            orgs = r.json() if isinstance(r.json(), list) else []
            return VerificationResult(status="active",
                details=f"Sentry auth token active, {len(orgs)} org(s)",
                provider="sentry", permissions=f"orgs: {len(orgs)}")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="Sentry rejected", provider="sentry")
        return VerificationResult(status="error", details=f"Sentry HTTP {r.status_code}", provider="sentry")
    except Exception as e:
        return _error_result(e, "sentry", log_key="sentry_auth")


async def verify_currencylayer_key(key: str) -> VerificationResult:
    """GET /live?access_key=X. Returns HTTP 401 on bad keys — treat as inactive."""
    try:
        import httpx
        async with verification_client(timeout=10) as c:
            r = await c.get(f"http://api.currencylayer.com/live?access_key={key}")
        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                return VerificationResult(status="active",
                    details="CurrencyLayer key active",
                    provider="currencylayer", permissions="FX rates")
            err = data.get("error", {})
            return VerificationResult(status="inactive",
                details=f"CurrencyLayer: {err.get('info', '?')[:80]}", provider="currencylayer")
        elif r.status_code in (401, 403):
            return VerificationResult(status="inactive", details="CurrencyLayer rejected", provider="currencylayer")
        return VerificationResult(status="error", details=f"CurrencyLayer HTTP {r.status_code}", provider="currencylayer")
    except Exception as e:
        return _error_result(e, "currencylayer")


# ══════════════════════════════════════════════════════════════
# B2 Wave — +40 verifiers (AI / ops / CRM / payments / cloud / dev)
# ══════════════════════════════════════════════════════════════
#
# Shared concise helper so each new verifier stays ~5 lines. It wires
# rate-limit detection, _error_result transient classification, and a
# consistent inactive/error split so every new provider inherits the
# correctness fixes from A1/A3 for free.


async def _verify_bearer(
    provider: str,
    url: str,
    key: str,
    *,
    header_name: str = "Authorization",
    header_fmt: str = "Bearer {}",
    extra_headers: Optional[dict] = None,
    risk: str = "medium",
    active_details: str = "",
    permissions: str = "read access",
    timeout: int = 10,
    inactive_codes: tuple = (401, 403),
) -> VerificationResult:
    """Generic keyed-GET verifier. Returns a VerificationResult.

    Defaults mirror the majority pattern: Bearer token in Authorization
    header, 200 → active, 401/403 → inactive, 429/503 / provider-specific
    rate-limit → transient error, anything else → error.
    """
    try:
        headers = {header_name: header_fmt.format(key)}
        if extra_headers:
            headers.update(extra_headers)
        async with verification_client(timeout=timeout) as c:
            r = await c.get(url, headers=headers)
        if r.status_code == 200:
            return VerificationResult(
                status="active",
                details=active_details or f"{provider} key active",
                provider=provider,
                permissions=permissions,
                risk_level=risk,
            )
        if _is_rate_limited(r, provider):
            return _rate_limited_result(provider, r)
        if r.status_code in inactive_codes:
            return VerificationResult(
                status="inactive",
                details=f"{provider} key rejected",
                provider=provider,
            )
        return VerificationResult(
            status="error",
            details=f"{provider} HTTP {r.status_code}",
            provider=provider,
        )
    except Exception as e:
        return _error_result(e, provider)


# ── AI / LLM (5) ─────────────────────────────────────────────

async def verify_together_key(key: str) -> VerificationResult:
    """Together AI — GET /v1/models. Bearer."""
    return await _verify_bearer(
        "together", "https://api.together.xyz/v1/models", key,
        risk="high", permissions="inference",
        active_details="Together AI key active — billing-linked inference access",
    )


async def verify_deepinfra_key(key: str) -> VerificationResult:
    """DeepInfra — GET /v1/openai/models. Bearer."""
    return await _verify_bearer(
        "deepinfra", "https://api.deepinfra.com/v1/openai/models", key,
        risk="high", permissions="inference",
        active_details="DeepInfra key active — billing-linked inference access",
    )


async def verify_ai21_key(key: str) -> VerificationResult:
    """AI21 — GET /studio/v1/paraphrase/versions (list-only, no inference)."""
    return await _verify_bearer(
        "ai21", "https://api.ai21.com/studio/v1/paraphrase/versions", key,
        risk="high", permissions="inference",
        active_details="AI21 key active — billing-linked Jurassic-2 access",
    )


async def verify_nvidia_key(key: str) -> VerificationResult:
    """POST /v1/chat/completions (minimal probe) — Bearer.

    NVIDIA's ``/v1/models`` catalog endpoint returns 200 with a model
    list for fake tokens too (B3 validation 2026-04-19) — so we can't
    use it as an auth check. Using a tiny inference POST instead:
    1-token output against a small model. Real cost is fraction of a
    cent per verify; verified-correctly beats false-active.
    """
    try:
        async with verification_client(timeout=12) as c:
            r = await c.post(
                "https://integrate.api.nvidia.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": "meta/llama-3.1-8b-instruct",
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 1,
                },
            )
        if r.status_code == 200:
            return VerificationResult(
                status="active",
                details="NVIDIA API key active — catalog inference access",
                provider="nvidia",
                permissions="inference",
                risk_level="high",
            )
        if _is_rate_limited(r, "nvidia"):
            return _rate_limited_result("nvidia", r)
        if r.status_code == 400:
            # Bad model name but auth was accepted.
            return VerificationResult(
                status="active",
                details="NVIDIA key accepted (auth OK; model param rejected)",
                provider="nvidia",
                permissions="inference",
                risk_level="high",
            )
        if r.status_code in (401, 403):
            return VerificationResult(
                status="inactive",
                details="NVIDIA key rejected",
                provider="nvidia",
            )
        return VerificationResult(
            status="error",
            details=f"nvidia HTTP {r.status_code}",
            provider="nvidia",
        )
    except Exception as e:
        return _error_result(e, "nvidia")


async def verify_anyscale_key(key: str) -> VerificationResult:
    """Anyscale — GET /v1/models. Bearer."""
    return await _verify_bearer(
        "anyscale", "https://api.endpoints.anyscale.com/v1/models", key,
        risk="high", permissions="inference",
        active_details="Anyscale key active — hosted OSS-LLM inference",
    )


# ── Observability / Monitoring (5) ───────────────────────────

async def verify_rollbar_token(key: str) -> VerificationResult:
    """Rollbar — GET /api/1/me. X-Rollbar-Access-Token header."""
    return await _verify_bearer(
        "rollbar", "https://api.rollbar.com/api/1/me", key,
        header_name="X-Rollbar-Access-Token", header_fmt="{}",
        risk="medium", permissions="read error events",
    )


async def verify_checkly_key(key: str) -> VerificationResult:
    """Checkly — GET /v1/accounts. Authorization: Bearer."""
    return await _verify_bearer(
        "checkly", "https://api.checklyhq.com/v1/accounts", key,
        risk="medium", permissions="synthetic monitoring",
    )


async def verify_cronitor_key(key: str) -> VerificationResult:
    """Cronitor — GET /api/monitors. Authorization: Bearer."""
    return await _verify_bearer(
        "cronitor", "https://cronitor.io/api/monitors", key,
        risk="low", permissions="read cron status",
    )


async def verify_healthchecks_key(key: str) -> VerificationResult:
    """Healthchecks.io — GET /api/v3/checks/. X-Api-Key header."""
    return await _verify_bearer(
        "healthchecks", "https://healthchecks.io/api/v3/checks/", key,
        header_name="X-Api-Key", header_fmt="{}",
        risk="low", permissions="read checks",
    )


async def verify_statuspage_key(key: str) -> VerificationResult:
    """Statuspage (Atlassian) — GET /v1/pages. Authorization: OAuth <token>."""
    return await _verify_bearer(
        "statuspage", "https://api.statuspage.io/v1/pages", key,
        header_fmt="OAuth {}",
        risk="high", permissions="status-page admin",
        active_details="Statuspage token active — can post/update incidents",
    )


# ── CI/CD / Dev infra (3) ────────────────────────────────────

async def verify_harness_key(key: str) -> VerificationResult:
    """Harness — GET /ng/api/accounts. x-api-key."""
    return await _verify_bearer(
        "harness", "https://app.harness.io/ng/api/accounts", key,
        header_name="x-api-key", header_fmt="{}",
        risk="critical", permissions="pipeline control",
        active_details="Harness key active — CI/CD pipeline access",
    )


async def verify_codecov_token(key: str) -> VerificationResult:
    """Codecov — GET /api/v2/users/current. Authorization: Bearer."""
    return await _verify_bearer(
        "codecov", "https://api.codecov.io/api/v2/users/current", key,
        risk="medium", permissions="coverage reports",
    )


async def verify_pulumi_token(key: str) -> VerificationResult:
    """Pulumi Cloud — GET /api/user. Authorization: token <key>."""
    return await _verify_bearer(
        "pulumi", "https://api.pulumi.com/api/user", key,
        header_fmt="token {}",
        risk="critical", permissions="infrastructure state",
        active_details="Pulumi token active — infra state + stack control",
    )


# ── CRM / Marketing (3) ──────────────────────────────────────

async def verify_customerio_token(key: str) -> VerificationResult:
    """Customer.io App API — GET /v1/api/segments. Authorization: Bearer."""
    return await _verify_bearer(
        "customerio", "https://api.customer.io/v1/api/segments", key,
        risk="high", permissions="customer-data read/write",
    )


async def verify_calendly_token(key: str) -> VerificationResult:
    """Calendly — GET /users/me. Authorization: Bearer."""
    return await _verify_bearer(
        "calendly", "https://api.calendly.com/users/me", key,
        risk="medium", permissions="scheduling",
    )


# verify_loops_key already exists upstream — don't redefine


# ── Payments (2) ─────────────────────────────────────────────

async def verify_wise_token(key: str) -> VerificationResult:
    """Wise — GET /v1/profiles. Authorization: Bearer."""
    return await _verify_bearer(
        "wise", "https://api.transferwise.com/v1/profiles", key,
        risk="critical", permissions="payments + banking",
        active_details="Wise token active — access to profiles and transfers",
    )


async def verify_gocardless_token(key: str) -> VerificationResult:
    """GoCardless — GET /customers?limit=1. Authorization: Bearer + version header."""
    return await _verify_bearer(
        "gocardless", "https://api.gocardless.com/customers?limit=1", key,
        extra_headers={"GoCardless-Version": "2015-07-06"},
        risk="critical", permissions="direct-debit payments",
    )


# ── Comms (2) ────────────────────────────────────────────────

async def verify_messagebird_key(key: str) -> VerificationResult:
    """MessageBird / Bird — GET /balance. Authorization: AccessKey <key>."""
    return await _verify_bearer(
        "messagebird", "https://rest.messagebird.com/balance", key,
        header_fmt="AccessKey {}",
        risk="high", permissions="SMS + voice",
        active_details="MessageBird key active — can send SMS / calls",
    )


async def verify_pushbullet_token(key: str) -> VerificationResult:
    """Pushbullet — GET /v2/users/me. Access-Token header."""
    return await _verify_bearer(
        "pushbullet", "https://api.pushbullet.com/v2/users/me", key,
        header_name="Access-Token", header_fmt="{}",
        risk="medium", permissions="device push",
    )


# ── Cloud (1) ────────────────────────────────────────────────

async def verify_scaleway_token(key: str) -> VerificationResult:
    """Scaleway — GET /account/v2/projects. X-Auth-Token."""
    return await _verify_bearer(
        "scaleway", "https://api.scaleway.com/account/v2/projects?per_page=1", key,
        header_name="X-Auth-Token", header_fmt="{}",
        risk="critical", permissions="cloud compute",
        active_details="Scaleway token active — cloud infra provisioning",
    )


# ── Dev-tool / Package registry (2) ──────────────────────────

async def verify_rubygems_token(key: str) -> VerificationResult:
    """RubyGems.org — GET /api/v1/profile/me.json. Authorization: {token}."""
    return await _verify_bearer(
        "rubygems", "https://rubygems.org/api/v1/profile/me.json", key,
        header_fmt="{}",
        risk="high", permissions="gem publish",
        active_details="RubyGems API key active — can publish gems",
    )


async def verify_crates_token(key: str) -> VerificationResult:
    """crates.io — GET /api/v1/me. Authorization: {token}."""
    return await _verify_bearer(
        "cratesio", "https://crates.io/api/v1/me", key,
        header_fmt="{}",
        risk="high", permissions="crate publish",
        active_details="crates.io token active — can publish crates",
    )


# ── Email infra (1) ──────────────────────────────────────────

async def verify_elasticemail_key(key: str) -> VerificationResult:
    """Elastic Email — GET /v2/account/profileoverview. X-ElasticEmail-ApiKey.

    ElasticEmail quirk: every response is HTTP 200 with a ``success``
    field in the body. For invalid or expired keys it returns
    ``{"success": false, "error": "..."}`` — so we can't rely on
    status code alone. The generic ``_verify_bearer`` helper was
    misclassifying invalid keys as active (caught by B3 validation
    2026-04-19).
    """
    try:
        async with verification_client(timeout=10) as c:
            r = await c.get(
                "https://api.elasticemail.com/v2/account/profileoverview",
                headers={"X-ElasticEmail-ApiKey": key},
            )
        if r.status_code == 200:
            try:
                body = r.json()
            except Exception:
                body = {}
            if body.get("success") is False:
                return VerificationResult(
                    status="inactive",
                    details=f"ElasticEmail: {body.get('error', 'key invalid')[:80]}",
                    provider="elasticemail",
                )
            return VerificationResult(
                status="active",
                details="ElasticEmail key active",
                provider="elasticemail",
                permissions="email-send",
                risk_level="high",
            )
        if _is_rate_limited(r, "elasticemail"):
            return _rate_limited_result("elasticemail", r)
        if r.status_code in (401, 403):
            return VerificationResult(
                status="inactive",
                details="ElasticEmail key rejected",
                provider="elasticemail",
            )
        return VerificationResult(
            status="error",
            details=f"elasticemail HTTP {r.status_code}",
            provider="elasticemail",
        )
    except Exception as e:
        return _error_result(e, "elasticemail")


# ── Scraping / Utility APIs (4) ──────────────────────────────

async def verify_scrapingbee_key(key: str) -> VerificationResult:
    """ScrapingBee — GET /api/v1/usage?api_key=<key>. Key in query string."""
    return await _verify_bearer(
        "scrapingbee", f"https://app.scrapingbee.com/api/v1/usage?api_key={key}", key,
        header_name="X-Unused", header_fmt="{}",
        extra_headers={},  # auth is in the query string
        risk="low", permissions="web scraping",
    )


async def verify_scraperapi_key(key: str) -> VerificationResult:
    """ScraperAPI — GET /account?api_key=<key>. Key in query string."""
    return await _verify_bearer(
        "scraperapi", f"http://api.scraperapi.com/account?api_key={key}", key,
        header_name="X-Unused", header_fmt="{}",
        risk="low", permissions="web scraping",
    )


async def verify_zenrows_key(key: str) -> VerificationResult:
    """ZenRows — GET /usage?apikey=<key>. Key in query string."""
    return await _verify_bearer(
        "zenrows", f"https://app.zenrows.com/api/usage?apikey={key}", key,
        header_name="X-Unused", header_fmt="{}",
        risk="low", permissions="web scraping",
    )


async def verify_proxycurl_key(key: str) -> VerificationResult:
    """Proxycurl — GET /credit-balance. Authorization: Bearer."""
    return await _verify_bearer(
        "proxycurl", "https://nubela.co/proxycurl/api/credit-balance", key,
        risk="low", permissions="LinkedIn scraping",
    )


# ── Geo / data utility (3) ───────────────────────────────────

async def verify_exchangerate_key(key: str) -> VerificationResult:
    """ExchangeRate-API — GET /v6/<key>/latest/USD. Key path-scoped."""
    return await _verify_bearer(
        "exchangerate", f"https://v6.exchangerate-api.com/v6/{key}/latest/USD", key,
        header_name="X-Unused", header_fmt="{}",
        risk="low", permissions="FX rates",
    )


# verify_ipinfo_token already exists upstream — don't redefine
# verify_ipstack_key already exists upstream — don't redefine


# ── Security / OSINT (2) ─────────────────────────────────────

async def verify_securitytrails_key(key: str) -> VerificationResult:
    """SecurityTrails — GET /v1/ping. APIKEY header."""
    return await _verify_bearer(
        "securitytrails", "https://api.securitytrails.com/v1/ping", key,
        header_name="APIKEY", header_fmt="{}",
        risk="low", permissions="DNS / cert history",
    )


# verify_hunter_key already exists upstream — don't redefine


# ── Push (1) ─────────────────────────────────────────────────

async def verify_onesignal_key(key: str) -> VerificationResult:
    """OneSignal — GET /apps. Authorization: Basic <key>."""
    return await _verify_bearer(
        "onesignal", "https://api.onesignal.com/apps", key,
        header_fmt="Basic {}",
        risk="high", permissions="push notifications",
        active_details="OneSignal key active — can send pushes to any app",
    )


# ── DB-as-a-Service (3) ──────────────────────────────────────

async def verify_neon_key(key: str) -> VerificationResult:
    """Neon — GET /api/v2/users/me. Authorization: Bearer."""
    return await _verify_bearer(
        "neon", "https://console.neon.tech/api/v2/users/me", key,
        risk="critical", permissions="Postgres databases",
        active_details="Neon API key active — can manage Postgres projects",
    )


async def verify_planetscale_token(key: str) -> VerificationResult:
    """PlanetScale — GET /v1/organizations. Authorization: Bearer."""
    return await _verify_bearer(
        "planetscale", "https://api.planetscale.com/v1/organizations", key,
        risk="critical", permissions="MySQL branches",
        active_details="PlanetScale key active — branch + schema access",
    )


# verify_xata_key removed 2026-05-19 — Xata sunset its hosted
# serverless-DB product in April 2025; api.xata.io no longer
# resolves.  Detection rules are kept (legacy keys may still
# appear in old repos) but live verification is permanently
# unavailable.


# ── Compute / PaaS (2) ───────────────────────────────────────

async def verify_apify_token(key: str) -> VerificationResult:
    """Apify — GET /v2/users/me. Authorization: Bearer."""
    return await _verify_bearer(
        "apify", "https://api.apify.com/v2/users/me", key,
        risk="medium", permissions="actor runs",
    )


# verify_mailchimp_key already exists upstream — don't redefine


async def verify_heremaps_key(key: str) -> VerificationResult:
    """HERE Maps — GET /v1/geocode?q=Berlin&apiKey=<key>."""
    return await _verify_bearer(
        "heremaps",
        f"https://geocode.search.hereapi.com/v1/geocode?q=Berlin&apiKey={key}",
        key,
        header_name="X-Unused", header_fmt="{}",
        risk="low", permissions="geocoding",
    )


# ── Enterprise source-tier verifiers (2026-05-03) ─────────────
# Six verifiers added to close the loop on the 22-source enterprise
# scan catalog: each was a SOURCE we could already scan FROM but had
# no validator FOR if the same provider's credentials showed up in
# another scan. All five business-app verifiers are tenant-scoped
# (need both the secret and the instance URL). The webhook verifier
# is non-destructive — issues a GET that confirms the URL exists
# without ever sending payload data to the receiving channel.


async def verify_salesforce_token(token: str, instance_url: str = "") -> VerificationResult:
    """Salesforce — GET /services/data/v60.0/limits — Bearer.

    Tenant-scoped: needs the customer's instance URL (e.g.
    `https://acme.my.salesforce.com`). The /limits endpoint is the
    cheapest authenticated read — no record access required, just a
    valid session token. 200 → active session; 401 → expired or
    revoked; 403 → IP restriction or refresh required.
    """
    try:
        if not token or not instance_url:
            return VerificationResult(
                status="unsupported",
                details="Salesforce verification needs token + instance URL",
                provider="salesforce",
            )
        # Normalize URL — accept bare host or full URL
        base = instance_url.rstrip("/")
        if not base.startswith("http"):
            base = f"https://{base}"
        async with verification_client(timeout=10) as c:
            r = await c.get(f"{base}/services/data/v60.0/limits",
                            headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            api_remaining = ""
            if isinstance(data, dict):
                daily = data.get("DailyApiRequests", {})
                if isinstance(daily, dict) and daily.get("Remaining") is not None:
                    api_remaining = f" — {daily['Remaining']}/{daily.get('Max', '?')} API calls left today"
            detail = {
                "scopes": [],
                "identity": base,
                "account_id": base,
                "risk_level": "high",
                "is_production": "sandbox" not in base.lower() and "test." not in base.lower(),
                "extra": {"instance_url": base, "limits": api_remaining.strip(" —") if api_remaining else ""},
            }
            result = VerificationResult(
                status="active",
                details=f"Salesforce token active @ {base}{api_remaining}",
                provider="salesforce",
                permissions=f"instance: {base}",
                permissions_detail=detail,
                risk_level="high",
            )
            result.blast_radius_summary = summarize_blast_radius("salesforce", detail)
            return result
        if _is_rate_limited(r, "salesforce"):
            return _rate_limited_result("salesforce", r)
        if r.status_code in (401, 403):
            return VerificationResult(
                status="inactive",
                details=f"Salesforce token rejected (HTTP {r.status_code})",
                provider="salesforce",
            )
        return VerificationResult(
            status="error",
            details=f"Salesforce HTTP {r.status_code}",
            provider="salesforce",
        )
    except Exception as e:
        return _error_result(e, "salesforce")


async def verify_box_token(token: str) -> VerificationResult:
    """Box — GET /2.0/users/me — Bearer.

    Box developer / OAuth tokens are not tenant-scoped (a token IS
    the identity). The /users/me endpoint returns the authenticated
    user with no side effects. Box developer tokens expire in 60
    minutes by default — `inactive` result here often means the
    token simply expired, not that it was revoked.
    """
    try:
        async with verification_client(timeout=10) as c:
            r = await c.get("https://api.box.com/2.0/users/me",
                            headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            login = data.get("login", "?")
            name = data.get("name", "")
            user_id = data.get("id", "")
            enterprise = data.get("enterprise", {}) or {}
            ent_name = enterprise.get("name", "")
            # Enterprise-scoped tokens are critical — they can read every
            # file the user has access to across the org.
            risk = "critical" if ent_name else "high"
            detail = {
                "scopes": [],
                "identity": login,
                "account_id": str(user_id),
                "risk_level": risk,
                "is_production": True,
                "extra": {"name": name, "enterprise": ent_name},
            }
            result = VerificationResult(
                status="active",
                details=f"Box token active, user: {login}" + (f" (enterprise: {ent_name})" if ent_name else ""),
                provider="box",
                permissions=f"user id: {user_id}",
                permissions_detail=detail,
                risk_level=risk,
            )
            result.blast_radius_summary = summarize_blast_radius("box", detail)
            return result
        if _is_rate_limited(r, "box"):
            return _rate_limited_result("box", r)
        if r.status_code in (401, 403):
            return VerificationResult(
                status="inactive",
                details=f"Box token rejected (HTTP {r.status_code} — may be expired developer token)",
                provider="box",
            )
        return VerificationResult(
            status="error",
            details=f"Box HTTP {r.status_code}",
            provider="box",
        )
    except Exception as e:
        return _error_result(e, "box")


async def verify_mattermost_token(token: str, server_url: str = "") -> VerificationResult:
    """Mattermost — GET /api/v4/users/me — Bearer. Tenant-scoped.

    Mattermost is self-hosted; the customer's server URL is required
    (e.g. `https://chat.acme.com`). The /users/me endpoint returns
    the authenticated user with no side effects.
    """
    try:
        if not token or not server_url:
            return VerificationResult(
                status="unsupported",
                details="Mattermost verification needs token + server URL",
                provider="mattermost",
            )
        base = server_url.rstrip("/")
        if not base.startswith("http"):
            base = f"https://{base}"
        async with verification_client(timeout=10) as c:
            r = await c.get(f"{base}/api/v4/users/me",
                            headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            email = data.get("email", "?")
            username = data.get("username", "")
            user_id = data.get("id", "")
            roles = data.get("roles", "")  # space-separated; "system_admin" is the dangerous one
            is_admin = "system_admin" in roles
            risk = "critical" if is_admin else "high"
            detail = {
                "scopes": roles.split() if roles else [],
                "identity": email or username,
                "account_id": user_id,
                "risk_level": risk,
                "is_production": True,
                "extra": {
                    "server_url": base,
                    "username": username,
                    "is_system_admin": is_admin,
                },
            }
            result = VerificationResult(
                status="active",
                details=f"Mattermost token active @ {base}, user: {email or username}" + (" (system admin)" if is_admin else ""),
                provider="mattermost",
                permissions=f"roles: {roles}" if roles else "user",
                permissions_detail=detail,
                risk_level=risk,
            )
            result.blast_radius_summary = summarize_blast_radius("mattermost", detail)
            return result
        if _is_rate_limited(r, "mattermost"):
            return _rate_limited_result("mattermost", r)
        if r.status_code in (401, 403):
            return VerificationResult(
                status="inactive",
                details=f"Mattermost token rejected (HTTP {r.status_code})",
                provider="mattermost",
            )
        return VerificationResult(
            status="error",
            details=f"Mattermost HTTP {r.status_code}",
            provider="mattermost",
        )
    except Exception as e:
        return _error_result(e, "mattermost")


async def verify_azure_devops_pat(pat: str, org_url: str = "") -> VerificationResult:
    """Azure DevOps — GET /_apis/connectionData?api-version=7.0 — Basic auth.

    Tenant-scoped: needs the org URL (e.g. `https://dev.azure.com/acme`
    or just `acme` for the org slug). PAT auth is HTTP Basic with empty
    username + PAT as password. /connectionData returns the auth user
    plus the org's instance ID without enumerating any work items.
    """
    try:
        if not pat:
            return VerificationResult(
                status="unsupported",
                details="Azure DevOps verification needs PAT + org URL",
                provider="azure_devops",
            )
        # Normalize: accept org name, host, or full URL
        if not org_url:
            return VerificationResult(
                status="unsupported",
                details="Azure DevOps verification needs PAT + org URL",
                provider="azure_devops",
            )
        org = org_url.strip().rstrip("/")
        if org.startswith("http"):
            base = org
        elif "/" in org or "." in org:
            base = f"https://{org}"
        else:
            # Bare org slug
            base = f"https://dev.azure.com/{org}"
        async with verification_client(timeout=10) as c:
            r = await c.get(
                f"{base}/_apis/connectionData?api-version=7.0",
                auth=("", pat),
            )
        if r.status_code == 200:
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            auth_user = data.get("authenticatedUser", {}) or {}
            email = auth_user.get("properties", {}).get("Account", {}).get("$value", "") if isinstance(auth_user.get("properties"), dict) else ""
            display = auth_user.get("providerDisplayName") or auth_user.get("customDisplayName") or "?"
            instance_id = data.get("instanceId", "")
            detail = {
                "scopes": [],
                "identity": email or display,
                "account_id": instance_id,
                "risk_level": "high",
                "is_production": True,
                "extra": {
                    "org_url": base,
                    "display_name": display,
                    "email": email,
                    "instance_id": instance_id,
                },
            }
            result = VerificationResult(
                status="active",
                details=f"Azure DevOps PAT active @ {base}, user: {display}",
                provider="azure_devops",
                permissions=f"org: {base.rsplit('/', 1)[-1]}",
                permissions_detail=detail,
                risk_level="high",
            )
            result.blast_radius_summary = summarize_blast_radius("azure_devops", detail)
            return result
        if _is_rate_limited(r, "azure_devops"):
            return _rate_limited_result("azure_devops", r)
        if r.status_code in (401, 203):
            # Azure DevOps quirk: returns 203 + sign-in HTML on bad PAT
            return VerificationResult(
                status="inactive",
                details=f"Azure DevOps PAT rejected (HTTP {r.status_code})",
                provider="azure_devops",
            )
        if r.status_code == 404:
            return VerificationResult(
                status="inactive",
                details=f"Azure DevOps org {base} not found",
                provider="azure_devops",
            )
        return VerificationResult(
            status="error",
            details=f"Azure DevOps HTTP {r.status_code}",
            provider="azure_devops",
        )
    except Exception as e:
        return _error_result(e, "azure_devops")


async def verify_servicenow_creds(
    user_or_token: str,
    password: str = "",
    instance_url: str = "",
) -> VerificationResult:
    """ServiceNow — GET /api/now/table/sys_user?sysparm_limit=1 — Basic auth.

    Tenant-scoped: needs the instance URL (e.g.
    `https://acme.service-now.com`). ServiceNow uses Basic auth with
    `username:password` — both required. Returns 200 + 1 user record
    on success. We use sysparm_limit=1 to keep the response trivial.

    Note: oauth bearer token verification path can be added later if
    a customer uses ServiceNow OAuth. For now the Basic-auth flow is
    the dominant integration shape we see.
    """
    try:
        if not user_or_token or not password or not instance_url:
            return VerificationResult(
                status="unsupported",
                details="ServiceNow verification needs username + password + instance URL",
                provider="servicenow",
            )
        base = instance_url.rstrip("/")
        if not base.startswith("http"):
            base = f"https://{base}"
        async with verification_client(timeout=10) as c:
            r = await c.get(
                f"{base}/api/now/table/sys_user?sysparm_limit=1&sysparm_fields=user_name,email",
                auth=(user_or_token, password),
                headers={"Accept": "application/json"},
            )
        if r.status_code == 200:
            detail = {
                "scopes": [],
                "identity": user_or_token,
                "account_id": base,
                "risk_level": "high",
                "is_production": "test" not in base.lower() and "dev" not in base.lower(),
                "extra": {"instance_url": base, "username": user_or_token},
            }
            result = VerificationResult(
                status="active",
                details=f"ServiceNow creds active @ {base}, user: {user_or_token}",
                provider="servicenow",
                permissions=f"instance: {base}",
                permissions_detail=detail,
                risk_level="high",
            )
            result.blast_radius_summary = summarize_blast_radius("servicenow", detail)
            return result
        if _is_rate_limited(r, "servicenow"):
            return _rate_limited_result("servicenow", r)
        if r.status_code in (401, 403):
            return VerificationResult(
                status="inactive",
                details=f"ServiceNow creds rejected (HTTP {r.status_code})",
                provider="servicenow",
            )
        if r.status_code == 404:
            return VerificationResult(
                status="inactive",
                details=f"ServiceNow instance {base} not found",
                provider="servicenow",
            )
        return VerificationResult(
            status="error",
            details=f"ServiceNow HTTP {r.status_code}",
            provider="servicenow",
        )
    except Exception as e:
        return _error_result(e, "servicenow")


async def verify_webhook_url(url: str) -> VerificationResult:
    """Webhook URL liveness check — GET request, never POST.

    Used by GEN-010-COLLAB findings (Slack/Discord/Teams/PagerDuty
    webhook URLs with embedded secrets in the path). The URL itself
    IS the credential — anyone with it can post to the channel.

    Verification is non-destructive: a GET request returns:
      - Slack: 200 OK + `no_payload` JSON when the webhook is live;
        404 / "no_service" when the webhook was deleted.
      - Discord: 200 OK + webhook metadata when live; 404 when deleted.
      - Teams: 405 Method Not Allowed when live (POST-only); 404 when
        the connector was removed.
      - PagerDuty / Opsgenie: 200 or 405 when live; 401/404 when revoked.

    We DO NOT POST under any circumstances — that would deliver junk
    to the customer's channel. A response code of 2xx, 405, or 410
    indicates the URL was accepted by the server (live or recently-
    revoked endpoint that's still reachable). 404 / connection
    refused → revoked / never existed.
    """
    try:
        if not url or not url.startswith("https://"):
            return VerificationResult(
                status="unsupported",
                details="Webhook URL must be a fully-qualified https:// URL",
                provider="webhook",
            )
        async with verification_client(timeout=8) as c:
            r = await c.get(url)
        # Slack returns 200 with `{"ok":false,"error":"no_payload"}` on GET
        # of a live webhook. Discord returns 200 with webhook JSON. Teams
        # returns 405 Method Not Allowed. PagerDuty returns 200 or 405.
        body_lower = (r.text or "")[:200].lower()
        looks_live = (
            r.status_code in (200, 405)
            or "no_payload" in body_lower
            or "method not allowed" in body_lower
        )
        revoked = (
            r.status_code in (404, 410)
            or "no_service" in body_lower
            or "no_team" in body_lower
            or "invalid_token" in body_lower
        )
        # Identify webhook flavor for the blast-radius summary
        flavor = "generic"
        if "hooks.slack.com" in url:
            flavor = "slack"
        elif "discord" in url and "webhooks" in url:
            flavor = "discord"
        elif "webhook.office.com" in url:
            flavor = "teams"
        elif "pagerduty.com" in url:
            flavor = "pagerduty"
        elif "opsgenie.com" in url:
            flavor = "opsgenie"
        if looks_live:
            detail = {
                "scopes": ["post_to_channel"],
                "identity": url[:80] + ("…" if len(url) > 80 else ""),
                "account_id": url.split("/")[-1][:24],
                "risk_level": "high",
                "is_production": True,
                "extra": {"flavor": flavor, "endpoint_status": r.status_code},
            }
            result = VerificationResult(
                status="active",
                details=f"{flavor.capitalize()} webhook URL is live (HTTP {r.status_code}) — anyone with this URL can post to the receiving channel",
                provider="webhook",
                permissions="post to receiving channel",
                permissions_detail=detail,
                risk_level="high",
            )
            result.blast_radius_summary = (
                f"Live {flavor} webhook — full post access to the receiving channel/incident queue."
            )
            return result
        if revoked:
            return VerificationResult(
                status="inactive",
                details=f"{flavor.capitalize()} webhook URL revoked / not found (HTTP {r.status_code})",
                provider="webhook",
            )
        return VerificationResult(
            status="error",
            details=f"Webhook check returned HTTP {r.status_code} — could not determine live status",
            provider="webhook",
        )
    except Exception as e:
        return _error_result(e, "webhook")


# ── Verification Dispatcher ───────────────────────────────────

# Map provider names to verification functions
# Each entry: (function, how to extract credentials from source_metadata)
VERIFIERS = {
    # Tier 0 — original verifiers
    "github": lambda sm: verify_github_token(sm.get("_raw_value", "")),
    "gitlab": lambda sm: verify_gitlab_token(sm.get("_raw_value", "")),
    "slack": lambda sm: verify_slack_token(sm.get("_raw_value", "")),
    "stripe": lambda sm: verify_stripe_key(sm.get("_raw_value", "")),
    "sendgrid": lambda sm: verify_sendgrid_key(sm.get("_raw_value", "")),
    # Tier 1 — added in the Oct verifier expansion batch
    "anthropic": lambda sm: verify_anthropic_key(sm.get("_raw_value", "")),
    "openai": lambda sm: verify_openai_key(sm.get("_raw_value", "")),
    "cloudflare": lambda sm: verify_cloudflare_token(sm.get("_raw_value", "")),
    "datadog": lambda sm: verify_datadog_key(sm.get("_raw_value", "")),
    "pagerduty": lambda sm: verify_pagerduty_token(sm.get("_raw_value", "")),
    "npm": lambda sm: verify_npm_token(sm.get("_raw_value", "")),
    "dockerhub": lambda sm: verify_dockerhub_token(sm.get("_raw_value", "")),
    "heroku": lambda sm: verify_heroku_token(sm.get("_raw_value", "")),
    # Tier 1 — tenant-scoped (domain from source_metadata if available)
    "okta": lambda sm: verify_okta_token(sm.get("_raw_value", ""), sm.get("tenant_domain", "")),
    "auth0": lambda sm: verify_auth0_token(sm.get("_raw_value", ""), sm.get("tenant_domain", "")),
    # Tier 2 — Stage 2 SaaS/dev-tool expansion (stateless Bearer/custom-header)
    "vercel": lambda sm: verify_vercel_token(sm.get("_raw_value", "")),
    "netlify": lambda sm: verify_netlify_token(sm.get("_raw_value", "")),
    "linear": lambda sm: verify_linear_token(sm.get("_raw_value", "")),
    "notion": lambda sm: verify_notion_token(sm.get("_raw_value", "")),
    "asana": lambda sm: verify_asana_token(sm.get("_raw_value", "")),
    "circleci": lambda sm: verify_circleci_token(sm.get("_raw_value", "")),
    "figma": lambda sm: verify_figma_token(sm.get("_raw_value", "")),
    "clickup": lambda sm: verify_clickup_token(sm.get("_raw_value", "")),
    "discord": lambda sm: verify_discord_bot_token(sm.get("_raw_value", "")),
    "telegram": lambda sm: verify_telegram_bot_token(sm.get("_raw_value", "")),
    "bitbucket": lambda sm: verify_bitbucket_token(sm.get("_raw_value", "")),
    "mailgun": lambda sm: verify_mailgun_key(sm.get("_raw_value", "")),
    "mailchimp": lambda sm: verify_mailchimp_key(sm.get("_raw_value", "")),
    "cohere": lambda sm: verify_cohere_key(sm.get("_raw_value", "")),
    "replicate": lambda sm: verify_replicate_token(sm.get("_raw_value", "")),
    "pinecone": lambda sm: verify_pinecone_key(sm.get("_raw_value", "")),
    "coinbase": lambda sm: verify_coinbase_token(sm.get("_raw_value", "")),
    "clerk": lambda sm: verify_clerk_key(sm.get("_raw_value", "")),
    "digitalocean": lambda sm: verify_digitalocean_token(sm.get("_raw_value", "")),
    "flyio": lambda sm: verify_flyio_token(sm.get("_raw_value", "")),
    "resend": lambda sm: verify_resend_key(sm.get("_raw_value", "")),
    "posthog": lambda sm: verify_posthog_key(sm.get("_raw_value", "")),
    "sentry": lambda sm: verify_sentry_token(sm.get("_raw_value", "")),
    "grafana": lambda sm: verify_grafana_cloud_token(sm.get("_raw_value", "")),
    "hubspot": lambda sm: verify_hubspot_token(sm.get("_raw_value", "")),
    "intercom": lambda sm: verify_intercom_token(sm.get("_raw_value", "")),
    "zoom": lambda sm: verify_zoom_token(sm.get("_raw_value", "")),
    # Tenant-scoped Stage 2 — require subdomain / shop / app_id / project_url
    "zendesk": lambda sm: verify_zendesk_token(sm.get("_raw_value", ""), sm.get("tenant_domain", "")),
    "shopify": lambda sm: verify_shopify_token(sm.get("_raw_value", ""), sm.get("tenant_domain", "")),
    "algolia": lambda sm: verify_algolia_key(sm.get("_raw_value", ""), sm.get("app_id", "")),
    "supabase": lambda sm: verify_supabase_service_key(sm.get("_raw_value", ""), sm.get("project_url", "")),
    # Tier 2 Wave 2 — AI/LLM, CI, observability, productivity
    "huggingface": lambda sm: verify_huggingface_token(sm.get("_raw_value", "")),
    "mistral": lambda sm: verify_mistral_key(sm.get("_raw_value", "")),
    "deepseek": lambda sm: verify_deepseek_key(sm.get("_raw_value", "")),
    "groq": lambda sm: verify_groq_key(sm.get("_raw_value", "")),
    "perplexity": lambda sm: verify_perplexity_key(sm.get("_raw_value", "")),
    "postmark": lambda sm: verify_postmark_token(sm.get("_raw_value", "")),
    "typeform": lambda sm: verify_typeform_token(sm.get("_raw_value", "")),
    "contentful": lambda sm: verify_contentful_management_token(sm.get("_raw_value", "")),
    "doppler": lambda sm: verify_doppler_token(sm.get("_raw_value", "")),
    "postman": lambda sm: verify_postman_api_key(sm.get("_raw_value", "")),
    "airtable": lambda sm: verify_airtable_token(sm.get("_raw_value", "")),
    "twitch": lambda sm: verify_twitch_token(sm.get("_raw_value", "")),
    "newrelic": lambda sm: verify_newrelic_key(sm.get("_raw_value", "")),
    "launchdarkly": lambda sm: verify_launchdarkly_key(sm.get("_raw_value", "")),
    "terraform": lambda sm: verify_terraform_cloud_token(sm.get("_raw_value", "")),
    "sonarcloud": lambda sm: verify_sonarcloud_token(sm.get("_raw_value", "")),
    "snyk": lambda sm: verify_snyk_token(sm.get("_raw_value", "")),
    "buildkite": lambda sm: verify_buildkite_token(sm.get("_raw_value", "")),
    "bitrise": lambda sm: verify_bitrise_token(sm.get("_raw_value", "")),
    "linode": lambda sm: verify_linode_token(sm.get("_raw_value", "")),
    "vultr": lambda sm: verify_vultr_key(sm.get("_raw_value", "")),
    "hetzner": lambda sm: verify_hetzner_token(sm.get("_raw_value", "")),
    "paystack": lambda sm: verify_paystack_key(sm.get("_raw_value", "")),
    "square": lambda sm: verify_square_token(sm.get("_raw_value", "")),
    "dropbox": lambda sm: verify_dropbox_token(sm.get("_raw_value", "")),
    "jumpcloud": lambda sm: verify_jumpcloud_key(sm.get("_raw_value", "")),
    "opsgenie": lambda sm: verify_opsgenie_key(sm.get("_raw_value", "")),
    "klaviyo": lambda sm: verify_klaviyo_key(sm.get("_raw_value", "")),
    "basecamp": lambda sm: verify_basecamp_token(sm.get("_raw_value", "")),
    # Tenant-scoped Tier 2 Wave 2
    "mapbox": lambda sm: verify_mapbox_secret(sm.get("_raw_value", "")),    # username in JWT claims
    "trello": lambda sm: verify_trello_key_token(sm.get("_raw_value", ""), sm.get("user_token", "")),
    # Tier 3 — long-tail SaaS / dev / media
    "fastly": lambda sm: verify_fastly_key(sm.get("_raw_value", "")),
    "ngrok": lambda sm: verify_ngrok_key(sm.get("_raw_value", "")),
    "iterable": lambda sm: verify_iterable_key(sm.get("_raw_value", "")),
    "honeybadger": lambda sm: verify_honeybadger_token(sm.get("_raw_value", "")),
    "unsplash": lambda sm: verify_unsplash_key(sm.get("_raw_value", "")),
    "pexels": lambda sm: verify_pexels_key(sm.get("_raw_value", "")),
    "yelp": lambda sm: verify_yelp_key(sm.get("_raw_value", "")),
    "wakatime": lambda sm: verify_wakatime_key(sm.get("_raw_value", "")),
    "ipinfo": lambda sm: verify_ipinfo_token(sm.get("_raw_value", "")),
    "gitbook": lambda sm: verify_gitbook_token(sm.get("_raw_value", "")),
    "smartsheet": lambda sm: verify_smartsheet_token(sm.get("_raw_value", "")),
    "wrike": lambda sm: verify_wrike_token(sm.get("_raw_value", "")),
    "monday": lambda sm: verify_monday_com_token(sm.get("_raw_value", "")),
    "front": lambda sm: verify_frontapp_token(sm.get("_raw_value", "")),
    "salesloft": lambda sm: verify_salesloft_token(sm.get("_raw_value", "")),
    "lever": lambda sm: verify_lever_token(sm.get("_raw_value", "")),
    "greenhouse": lambda sm: verify_greenhouse_token(sm.get("_raw_value", "")),
    "workable": lambda sm: verify_workable_token(sm.get("_raw_value", "")),
    "helpscout": lambda sm: verify_helpscout_key(sm.get("_raw_value", "")),
    "ashby": lambda sm: verify_ashby_key(sm.get("_raw_value", "")),
    "buffer": lambda sm: verify_buffer_token(sm.get("_raw_value", "")),
    "pipedrive": lambda sm: verify_pipedrive_key(sm.get("_raw_value", "")),
    "airbyte": lambda sm: verify_airbyte_cloud_token(sm.get("_raw_value", "")),
    "bunny": lambda sm: verify_bunny_net_key(sm.get("_raw_value", "")),
    "mixpanel": lambda sm: verify_mixpanel_secret(sm.get("_raw_value", "")),
    "chatwork": lambda sm: verify_chatwork_token(sm.get("_raw_value", "")),
    # "fauna" verifier removed 2026-05-19 — provider sunset (see verify_fauna_key comment).
    "storyblok": lambda sm: verify_storyblok_token(sm.get("_raw_value", "")),
    "render": lambda sm: verify_render_token(sm.get("_raw_value", "")),
    # Tier 3 tenant-scoped
    "browserstack": lambda sm: verify_browserstack_creds(sm.get("_raw_value", ""), sm.get("access_key", "")),
    "jira": lambda sm: verify_jira_cloud_creds(sm.get("email", ""), sm.get("_raw_value", ""), sm.get("tenant_domain", "")),
    "zoho": lambda sm: verify_zoho_token(sm.get("_raw_value", ""), sm.get("region", "com")),
    # Stage 3 — multi-credential verifiers. Called by the worker when the
    # credential_pairing module successfully pairs complementary values
    # from the same file. Each lambda reads paired values from enriched
    # source_metadata populated by credential_pairing.
    "aws_paired": lambda sm: verify_aws_access_key(
        sm.get("_raw_value", ""),                      # access_key_id
        sm.get("aws_secret") or sm.get("aws_secret_access_key", ""),
    ),
    "twilio_paired": lambda sm: verify_twilio_key(
        sm.get("_raw_value", ""),                      # account_sid
        sm.get("twilio_auth_token", ""),
    ),
    "azure_ad_paired": lambda sm: verify_azure_ad(
        sm.get("_raw_value", ""),                      # client_id
        sm.get("azure_client_secret", ""),
        sm.get("azure_tenant_id", ""),
    ),
    "paypal_paired": lambda sm: verify_paypal_oauth(
        sm.get("_raw_value", ""),                      # client_id
        sm.get("paypal_client_secret", ""),
        live=bool(sm.get("paypal_live", False)),
    ),
    "mongodb_atlas_paired": lambda sm: verify_mongodb_atlas_paired(
        sm.get("_raw_value", ""),                      # public_key
        sm.get("mongodb_atlas_private_key", ""),
        sm.get("mongodb_group_id", ""),
    ),
    "snowflake_paired": lambda sm: verify_snowflake_paired(
        sm.get("_raw_value", ""),                      # account
        sm.get("snowflake_user", ""),
        sm.get("snowflake_password", ""),
    ),
    "stripe_connect_paired": lambda sm: verify_stripe_connect_paired(
        sm.get("stripe_secret_key") or sm.get("_raw_value", ""),
        sm.get("stripe_account_id", ""),
    ),
    "mailjet_paired": lambda sm: verify_mailjet_paired(
        sm.get("_raw_value", ""),                      # public_key
        sm.get("mailjet_private_key", ""),
    ),
    # GCP service account — special path: the whole JSON is the "credential"
    "gcp": lambda sm: verify_gcp_service_account(sm.get("_raw_value", "")),
    # Tier 4 — AI/LLM, financial, weather, geo, threat intel, misc
    "gemini": lambda sm: verify_gemini_key(sm.get("_raw_value", "")),
    "fireworks": lambda sm: verify_fireworks_key(sm.get("_raw_value", "")),
    "novita": lambda sm: verify_novita_key(sm.get("_raw_value", "")),
    "deepl": lambda sm: verify_deepl_key(sm.get("_raw_value", "")),
    "elevenlabs": lambda sm: verify_elevenlabs_key(sm.get("_raw_value", "")),
    "runway": lambda sm: verify_runway_key(sm.get("_raw_value", "")),
    "polygon": lambda sm: verify_polygon_io_key(sm.get("_raw_value", "")),
    "alphavantage": lambda sm: verify_alphavantage_key(sm.get("_raw_value", "")),
    "finnhub": lambda sm: verify_finnhub_key(sm.get("_raw_value", "")),
    "tiingo": lambda sm: verify_tiingo_key(sm.get("_raw_value", "")),
    "openexchangerates": lambda sm: verify_openexchangerates_key(sm.get("_raw_value", "")),
    "fixer": lambda sm: verify_fixer_key(sm.get("_raw_value", "")),
    "currencylayer": lambda sm: verify_currencylayer_key(sm.get("_raw_value", "")),
    "coinmarketcap": lambda sm: verify_coinmarketcap_key(sm.get("_raw_value", "")),
    "etherscan": lambda sm: verify_etherscan_key(sm.get("_raw_value", "")),
    "openweather": lambda sm: verify_openweather_key(sm.get("_raw_value", "")),
    "weatherapi": lambda sm: verify_weatherapi_key(sm.get("_raw_value", "")),
    "tomorrow_io": lambda sm: verify_tomorrow_io_key(sm.get("_raw_value", "")),
    "here": lambda sm: verify_here_maps_key(sm.get("_raw_value", "")),
    "tomtom": lambda sm: verify_tomtom_key(sm.get("_raw_value", "")),
    "opencage": lambda sm: verify_opencage_key(sm.get("_raw_value", "")),
    "locationiq": lambda sm: verify_locationiq_key(sm.get("_raw_value", "")),
    "positionstack": lambda sm: verify_positionstack_key(sm.get("_raw_value", "")),
    "ipstack": lambda sm: verify_ipstack_key(sm.get("_raw_value", "")),
    "ipgeolocation": lambda sm: verify_ipgeolocation_key(sm.get("_raw_value", "")),
    "virustotal": lambda sm: verify_virustotal_key(sm.get("_raw_value", "")),
    "abuseipdb": lambda sm: verify_abuseipdb_key(sm.get("_raw_value", "")),
    "hibp": lambda sm: verify_hibp_key(sm.get("_raw_value", "")),
    "greynoise": lambda sm: verify_greynoise_key(sm.get("_raw_value", "")),
    "persona": lambda sm: verify_persona_key(sm.get("_raw_value", "")),
    "onfido": lambda sm: verify_onfido_token(sm.get("_raw_value", "")),
    "datocms": lambda sm: verify_datocms_token(sm.get("_raw_value", "")),
    "pingdom": lambda sm: verify_pingdom_token(sm.get("_raw_value", "")),
    "uptimerobot": lambda sm: verify_uptimerobot_key(sm.get("_raw_value", "")),
    "koyeb": lambda sm: verify_koyeb_token(sm.get("_raw_value", "")),
    "wistia": lambda sm: verify_wistia_token(sm.get("_raw_value", "")),
    "dbt": lambda sm: verify_dbt_cloud_token(sm.get("_raw_value", "")),
    "betterstack": lambda sm: verify_betterstack_token(sm.get("_raw_value", "")),
    "hightouch": lambda sm: verify_hightouch_token(sm.get("_raw_value", "")),
    "railway": lambda sm: verify_railway_token(sm.get("_raw_value", "")),
    # Tier 5 — Stage 1 Wave 2+3 providers (closes the verifier gap for new rules)
    "octopus": lambda sm: verify_octopus_deploy_key(sm.get("_raw_value", ""), sm.get("tenant_domain", "")),
    "dropbox_sign": lambda sm: verify_dropbox_sign_key(sm.get("_raw_value", "")),
    "pandadoc": lambda sm: verify_pandadoc_key(sm.get("_raw_value", "")),
    "zerobounce": lambda sm: verify_zerobounce_key(sm.get("_raw_value", "")),
    "neverbounce": lambda sm: verify_neverbounce_key(sm.get("_raw_value", "")),
    "kickbox": lambda sm: verify_kickbox_key(sm.get("_raw_value", "")),
    "emailable": lambda sm: verify_emailable_key(sm.get("_raw_value", "")),
    "lokalise": lambda sm: verify_lokalise_token(sm.get("_raw_value", "")),
    "crowdin": lambda sm: verify_crowdin_token(sm.get("_raw_value", "")),
    "phrase": lambda sm: verify_phrase_token(sm.get("_raw_value", "")),
    "papertrail": lambda sm: verify_papertrail_token(sm.get("_raw_value", "")),
    "axiom": lambda sm: verify_axiom_pat(sm.get("_raw_value", "")),
    "flagsmith": lambda sm: verify_flagsmith_env_key(sm.get("_raw_value", "")),
    "airbrake": lambda sm: verify_airbrake_key(sm.get("_raw_value", "")),
    "hunter": lambda sm: verify_hunter_key(sm.get("_raw_value", "")),
    "apollo": lambda sm: verify_apollo_io_key(sm.get("_raw_value", "")),
    "drift": lambda sm: verify_drift_token(sm.get("_raw_value", "")),
    "close": lambda sm: verify_close_io_key(sm.get("_raw_value", "")),
    "lemonsqueezy": lambda sm: verify_lemonsqueezy_key(sm.get("_raw_value", "")),
    "gumroad": lambda sm: verify_gumroad_token(sm.get("_raw_value", "")),
    "jotform": lambda sm: verify_jotform_key(sm.get("_raw_value", "")),
    "riot": lambda sm: verify_riot_games_key(sm.get("_raw_value", "")),
    "steam": lambda sm: verify_steam_key(sm.get("_raw_value", "")),
    "giphy": lambda sm: verify_giphy_key(sm.get("_raw_value", "")),
    "tenor": lambda sm: verify_tenor_key(sm.get("_raw_value", "")),
    "webflow": lambda sm: verify_webflow_token(sm.get("_raw_value", "")),
    "moralis": lambda sm: verify_moralis_key(sm.get("_raw_value", "")),
    "xai": lambda sm: verify_xai_grok_key(sm.get("_raw_value", "")),
    "surveymonkey": lambda sm: verify_surveymonkey_token(sm.get("_raw_value", "")),
    "loops": lambda sm: verify_loops_key(sm.get("_raw_value", "")),
    "convertkit": lambda sm: verify_convertkit_secret(sm.get("_raw_value", "")),
    # Tier 5 paired verifiers (need client_secret / email / subdomain context)
    "amadeus": lambda sm: verify_amadeus_oauth(sm.get("_raw_value", ""), sm.get("amadeus_client_secret", "")),
    "copper": lambda sm: verify_copper_crm_key(sm.get("_raw_value", ""), sm.get("email", "")),
    "deputy": lambda sm: verify_deputy_token(sm.get("_raw_value", ""), sm.get("tenant_domain", "")),
    "bamboohr": lambda sm: verify_bamboohr_key(sm.get("_raw_value", ""), sm.get("tenant_domain", "")),
    # Tier 6 — AI/security/dev/sales/ops additional
    "assemblyai": lambda sm: verify_assemblyai_key(sm.get("_raw_value", "")),
    "stability": lambda sm: verify_stability_ai_key(sm.get("_raw_value", "")),
    "openrouter": lambda sm: verify_openrouter_key(sm.get("_raw_value", "")),
    "gitguardian": lambda sm: verify_gitguardian_token(sm.get("_raw_value", "")),
    "magic": lambda sm: verify_magic_link_secret(sm.get("_raw_value", "")),
    "thirdweb": lambda sm: verify_thirdweb_secret(sm.get("_raw_value", "")),
    "outreach": lambda sm: verify_outreach_token(sm.get("_raw_value", "")),
    "shodan": lambda sm: verify_shodan_key(sm.get("_raw_value", "")),
    "urlscan": lambda sm: verify_urlscan_key(sm.get("_raw_value", "")),
    "mailersend": lambda sm: verify_mailersend_token(sm.get("_raw_value", "")),
    "infobip": lambda sm: verify_infobip_key(sm.get("_raw_value", "")),
    "courier": lambda sm: verify_courier_key(sm.get("_raw_value", "")),
    "rippling": lambda sm: verify_rippling_token(sm.get("_raw_value", "")),
    "deel": lambda sm: verify_deel_token(sm.get("_raw_value", "")),
    "adyen": lambda sm: verify_adyen_key(sm.get("_raw_value", "")),
    "cockroachdb": lambda sm: verify_cockroach_cloud_key(sm.get("_raw_value", "")),
    # Tier 6 tenant-scoped / paired
    "gong": lambda sm: verify_gong_key(sm.get("_raw_value", ""), sm.get("gong_secret", "")),
    "chronosphere": lambda sm: verify_chronosphere_token(sm.get("_raw_value", ""), sm.get("tenant_domain", "")),
    # ── B2 Wave (+40) ───────────────────────────────────────
    # AI / LLM
    "together": lambda sm: verify_together_key(sm.get("_raw_value", "")),
    "deepinfra": lambda sm: verify_deepinfra_key(sm.get("_raw_value", "")),
    "ai21": lambda sm: verify_ai21_key(sm.get("_raw_value", "")),
    "nvidia": lambda sm: verify_nvidia_key(sm.get("_raw_value", "")),
    "anyscale": lambda sm: verify_anyscale_key(sm.get("_raw_value", "")),
    # Observability / monitoring
    "rollbar": lambda sm: verify_rollbar_token(sm.get("_raw_value", "")),
    "checkly": lambda sm: verify_checkly_key(sm.get("_raw_value", "")),
    "cronitor": lambda sm: verify_cronitor_key(sm.get("_raw_value", "")),
    "healthchecks": lambda sm: verify_healthchecks_key(sm.get("_raw_value", "")),
    "statuspage": lambda sm: verify_statuspage_key(sm.get("_raw_value", "")),
    # CI/CD / Dev infra
    "harness": lambda sm: verify_harness_key(sm.get("_raw_value", "")),
    "codecov": lambda sm: verify_codecov_token(sm.get("_raw_value", "")),
    "pulumi": lambda sm: verify_pulumi_token(sm.get("_raw_value", "")),
    # CRM / Marketing
    "customerio": lambda sm: verify_customerio_token(sm.get("_raw_value", "")),
    "calendly": lambda sm: verify_calendly_token(sm.get("_raw_value", "")),
    # "loops" already registered upstream — skipped here to avoid overwrite
    # Payments
    "wise": lambda sm: verify_wise_token(sm.get("_raw_value", "")),
    "gocardless": lambda sm: verify_gocardless_token(sm.get("_raw_value", "")),
    # Comms
    "messagebird": lambda sm: verify_messagebird_key(sm.get("_raw_value", "")),
    "pushbullet": lambda sm: verify_pushbullet_token(sm.get("_raw_value", "")),
    # Cloud
    "scaleway": lambda sm: verify_scaleway_token(sm.get("_raw_value", "")),
    # Package registries
    "rubygems": lambda sm: verify_rubygems_token(sm.get("_raw_value", "")),
    "cratesio": lambda sm: verify_crates_token(sm.get("_raw_value", "")),
    # Email infra
    "elasticemail": lambda sm: verify_elasticemail_key(sm.get("_raw_value", "")),
    # Scraping / web-utility APIs
    "scrapingbee": lambda sm: verify_scrapingbee_key(sm.get("_raw_value", "")),
    "scraperapi": lambda sm: verify_scraperapi_key(sm.get("_raw_value", "")),
    "zenrows": lambda sm: verify_zenrows_key(sm.get("_raw_value", "")),
    "proxycurl": lambda sm: verify_proxycurl_key(sm.get("_raw_value", "")),
    # Geo / data utility
    "exchangerate": lambda sm: verify_exchangerate_key(sm.get("_raw_value", "")),
    # "ipinfo", "ipstack" already registered upstream — skipped
    "heremaps": lambda sm: verify_heremaps_key(sm.get("_raw_value", "")),
    # Security / OSINT
    "securitytrails": lambda sm: verify_securitytrails_key(sm.get("_raw_value", "")),
    # "hunter" already registered upstream — skipped
    # Push
    "onesignal": lambda sm: verify_onesignal_key(sm.get("_raw_value", "")),
    # DB-as-a-Service
    "neon": lambda sm: verify_neon_key(sm.get("_raw_value", "")),
    "planetscale": lambda sm: verify_planetscale_token(sm.get("_raw_value", "")),
    # "xata" verifier removed 2026-05-19 — provider sunset (see verify_xata_key comment).
    # Compute / PaaS / email marketing
    "apify": lambda sm: verify_apify_token(sm.get("_raw_value", "")),
    # "mailchimp" already registered upstream — skipped

    # ── Enterprise source-tier verifiers (2026-05-03) ────────
    # All five are tenant-scoped — they expect both the secret and
    # the customer's instance URL in source_metadata. The webhook
    # verifier is global (URL contains its own path-secret).
    "salesforce": lambda sm: verify_salesforce_token(
        sm.get("_raw_value", ""),
        sm.get("instance_url") or sm.get("tenant_domain", ""),
    ),
    "box": lambda sm: verify_box_token(sm.get("_raw_value", "")),
    "mattermost": lambda sm: verify_mattermost_token(
        sm.get("_raw_value", ""),
        sm.get("server_url") or sm.get("tenant_domain", ""),
    ),
    "azure_devops": lambda sm: verify_azure_devops_pat(
        sm.get("_raw_value", ""),
        sm.get("org_url") or sm.get("tenant_domain", ""),
    ),
    "servicenow": lambda sm: verify_servicenow_creds(
        sm.get("username") or sm.get("_raw_value", ""),
        sm.get("password", ""),
        sm.get("instance_url") or sm.get("tenant_domain", ""),
    ),
    # Webhook URL liveness check — used by GEN-010-COLLAB findings.
    # The whole URL IS the credential, so we just pass it through.
    "webhook": lambda sm: verify_webhook_url(sm.get("_raw_value", "")),
}

# Providers that need special handling (multiple values)
# AWS needs both access_key_id and secret_key — can only verify if both found in same file
# Twilio needs account_sid and auth_token

SUPPORTED_PROVIDERS = set(VERIFIERS.keys())


def _verification_enabled() -> bool:
    """Global kill-switch (``settings.VERIFICATION_ENABLED``).

    Lazily imports settings so this module stays importable in the trimmed
    CLI image (which ships no ``apps`` package and never calls a verifier).
    Defaults to enabled when settings are unavailable.
    """
    try:
        from apps.api.app.core.config import settings
        return bool(getattr(settings, "VERIFICATION_ENABLED", True))
    except Exception:
        return True


async def verify_finding(source_metadata: dict) -> Optional[VerificationResult]:
    """
    Verify a single finding based on its source_metadata.

    Args:
        source_metadata: Must contain 'provider' and '_raw_value' keys.

    Returns:
        VerificationResult or None if provider not supported.
    """
    # Global kill-switch — air-gapped / regulated deployments set
    # VERIFICATION_ENABLED=false to forbid ALL outbound verification. Returns
    # None (treated as "not validated") so scans complete normally and nothing
    # is ever suppressed on a deployment that cannot reach providers.
    if not _verification_enabled():
        return None

    provider = (source_metadata.get("provider") or "").lower()
    detection_method = source_metadata.get("detection_method", "")

    # Verify findings from all detection methods that have a known provider
    # (regex, regex_base64, config_key always; entropy and structured_parse
    # when the provider is identified — e.g., a GitHub token caught by entropy)
    if detection_method not in ("regex", "regex_base64", "config_key", "entropy", "structured_parse"):
        return None

    # Only verify if we have a verifier for this provider
    if provider not in VERIFIERS:
        return VerificationResult(
            status="unsupported",
            details=f"No verifier available for provider: {provider}",
            provider=provider,
        )

    # Must have the raw secret value to verify
    raw_value = source_metadata.get("_raw_value", "")
    if not raw_value or len(raw_value) < 8:
        return VerificationResult(
            status="error",
            details="Raw secret value not available for verification",
            provider=provider,
        )

    verifier_fn = VERIFIERS[provider]
    result = await verifier_fn(source_metadata)

    logger.info(
        "secret_verified",
        provider=provider,
        status=result.status,
        details=result.details[:100],
    )

    return result


async def verify_findings_batch(findings: list[dict]) -> list[dict]:
    """
    Verify a batch of findings. Returns list of {finding_id, verification_result}.
    Only processes regex-detected findings with supported providers.
    """
    results = []

    for finding in findings:
        sm = finding.get("source_metadata") or finding.get("raw_data") or {}
        finding_id = finding.get("id")

        result = await verify_finding(sm)
        if result and result.status != "unsupported":
            results.append({
                "finding_id": finding_id,
                "status": result.status,
                "details": result.details,
                "provider": result.provider,
                "permissions": result.permissions,
            })

    logger.info("batch_verification_complete", total=len(findings), verified=len(results))
    return results
