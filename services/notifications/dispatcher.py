# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Notification Dispatcher — sends alerts through configured channels.

Supports: Slack, Microsoft Teams, Email (SMTP), generic Webhook.
Called after scan completion, critical finding detection, or approval events.

SCOPING RULES:
- scope_level=NULL / "organization"  → fires for ALL repos in the tenant
- scope_level="business_unit"        → fires ONLY for repos in that BU
- scope_level="project"              → fires ONLY for that specific repo (repository_id)

In-app notifications are delivered ONLY to users whose UserAccessGrant
permits access to the affected BU / project.
"""

import structlog
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from dataclasses import dataclass, field, asdict
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_

logger = structlog.get_logger()


# ── Retry-eligibility classifier ─────────────────────────────────
#
# Decides whether a failed DispatchResult is worth persisting for
# async retry vs. logged-and-forgotten.  Transient errors → retry.
# Permanent errors (auth, malformed config) → no retry; the row is
# either skipped (not persisted) or marked permanent_failure for
# audit.
#
# Heuristic: HTTP status text in the error string.  We can't see the
# raw httpx response from this layer, but every channel handler
# already includes the status code in its error string when it
# constructs the failing DispatchResult.
def _is_retryable_error(error_text: Optional[str]) -> bool:
    """Return True when the error string looks like a transient
    failure (network blip, rate limit, provider outage).  Returns
    False for permanent failures (auth rejected, malformed payload)
    that wouldn't succeed on retry.

    Conservative on the True side: when uncertain, retry — it costs
    little to attempt again, and silent loss is the worse failure mode.
    """
    if not error_text:
        # No error string means caller didn't tell us — assume
        # transient and retry.
        return True
    err = error_text.lower()
    # Permanent: 4xx auth / bad config / malformed payload.
    permanent_markers = (
        "401", "403", "unauthorized", "forbidden", "invalid_auth",
        "authentication", "not_authed", "invalid token", "invalid api key",
        "404", "not found", "no such",
        "400", "bad request", "malformed", "invalid payload",
        "unsupported", "unknown channel",
        # Malformed destination — the config is wrong, not the network,
        # so every retry fails identically. Dead-letter instead of
        # burning the retry budget.
        "invalid port", "invalid url", "no host", "missing url", "no url",
        "invalid ipv6", "unsupported protocol", "relative url",
    )
    if any(m in err for m in permanent_markers):
        return False
    return True


@dataclass
class NotificationPayload:
    """Notification content to dispatch."""
    title: str
    body: str
    severity: str = "info"  # info, warning, critical
    event_type: str = "scan_complete"  # scan_complete, critical_finding, remediation, approval
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    url: Optional[str] = None  # deep link to the resource
    metadata: dict = field(default_factory=dict)
    # Scoping context — set by the caller (worker)
    business_unit_id: Optional[str] = None
    repository_id: Optional[str] = None


@dataclass
class DispatchResult:
    channel: str
    success: bool
    error: Optional[str] = None
    # Provider-supplied success metadata (Jira issue_key, ServiceNow
    # incident sys_id, Linear issue id, etc). Several provider handlers
    # were already passing details=... at construction time but the
    # dataclass didn't accept the kwarg — caller would crash with
    # `unexpected keyword argument 'details'` and the whole channel
    # dispatch would fail. Bug-fix 2026-04-27.
    details: Optional[dict] = None


class NotificationDispatcher:
    """Routes notifications to configured channels with Org/BU/Project scoping."""

    async def dispatch(
        self,
        db: AsyncSession,
        tenant_id: UUID,
        payload: NotificationPayload,
    ) -> list[DispatchResult]:
        """Send notification to scoped channels only, gated by notification rules."""
        results = []

        # ── 0. Check notification rules — is this event enabled? ──
        rule = await self._get_notification_rule(db, tenant_id, payload.event_type)
        if rule is not None and not rule.is_enabled:
            logger.info("notification_rule_disabled", event_type=payload.event_type, tenant=str(tenant_id))
            return results
        if rule is not None and not self._severity_passes_threshold(payload.severity, rule.severity_threshold):
            logger.info("notification_below_threshold", event_type=payload.event_type,
                        severity=payload.severity, threshold=rule.severity_threshold)
            return results

        # ── 1. Find matching notification configs (scoped) ──────
        channels = await self._get_scoped_channels(db, tenant_id, payload)

        for channel in channels:
            try:
                result = await self._send_to_channel(channel, payload)
                results.append(result)
            except Exception as e:
                results.append(DispatchResult(
                    channel=channel.provider,
                    success=False,
                    error=str(e)[:200],
                ))

        # ── 2. Create in-app notifications for scoped users ─────
        await self._create_inapp_notifications(db, tenant_id, payload)

        # ── 3. Persist failed transient deliveries for retry ─────
        # Track-A P1.5 (2026-05-22): every failed external-channel
        # dispatch with a transient-looking error becomes a row in
        # notification_deliveries.  The Celery beat task
        # process_notification_retries_task picks them up and re-
        # attempts with exponential backoff.  Permanent failures
        # (auth / 4xx) are NOT persisted — they wouldn't succeed
        # on retry and would just clutter the queue.
        try:
            await self._persist_failed_dispatches_for_retry(db, tenant_id, payload, channels, results)
        except Exception as e:
            # Persistence MUST NOT fail the original dispatch — the
            # notification's primary mission is to fire, and the retry
            # queue is a backstop.  Log and move on.
            logger.warning("retry_queue_persist_failed", error=str(e)[:200])

        return results

    async def _persist_failed_dispatches_for_retry(
        self,
        db: AsyncSession,
        tenant_id: UUID,
        payload: "NotificationPayload",
        channels: list,
        results: list["DispatchResult"],
    ) -> int:
        """Create NotificationDelivery rows for transient failures.

        ``channels`` and ``results`` are in matching order (one result
        per channel attempted, in dispatch order).  We zip them so
        each persisted row knows which IntegrationConfig produced the
        failure — required for the retry task to look up credentials.

        Permanent-classification failures get a single row at
        status=permanent_failure for audit visibility (so reviewers
        can answer "why did Slack stop working for this tenant?")
        but never get re-attempted.

        Returns the number of rows created (for observability).
        """
        from apps.api.app.models.notification_delivery import (
            NotificationDelivery, RETRY_BACKOFF_SECONDS,
        )

        # Defensive: if results and channels are out of sync due to a
        # caller bug, fall back to "no retry persistence" rather than
        # write incorrect channel-to-config mappings.
        if len(results) != len(channels):
            return 0

        # Serialise the payload once — used identically for every
        # row.  asdict() handles the dataclass; UUIDs stringified for
        # JSONB.
        payload_dump = asdict(payload)
        for k, v in list(payload_dump.items()):
            if isinstance(v, UUID):
                payload_dump[k] = str(v)

        created = 0
        for channel, result in zip(channels, results):
            if result.success:
                continue
            retryable = _is_retryable_error(result.error)
            row = NotificationDelivery(
                tenant_id=tenant_id,
                channel=result.channel,
                event_type=payload.event_type,
                severity=payload.severity,
                resource_type=payload.resource_type,
                resource_id=payload.resource_id,
                payload=payload_dump,
                integration_config_id=channel.id,
                last_attempted_at=datetime.now(timezone.utc),
                last_error=(result.error or "")[:2000],
                attempt_count=1,
            )
            if retryable:
                row.status = "pending_retry"
                row.next_retry_at = datetime.now(timezone.utc) + timedelta(seconds=RETRY_BACKOFF_SECONDS[0])
            else:
                # Permanent failures land in the table at terminal
                # state so they're visible in audit / observability
                # without ever consuming retry budget.
                row.status = "permanent_failure"
                row.dead_lettered_at = datetime.now(timezone.utc)
                row.next_retry_at = None
            db.add(row)
            created += 1
        return created

    async def _get_notification_rule(self, db: AsyncSession, tenant_id: UUID, event_type: str):
        """
        Fetch the notification rule for this event type.
        Returns None if no rule exists (treat as enabled with threshold 'all' for backward compat).
        """
        from apps.api.app.models.notification_rule import NotificationRule

        stmt = select(NotificationRule).where(
            NotificationRule.tenant_id == tenant_id,
            NotificationRule.event_type == event_type,
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    def _severity_passes_threshold(severity: str, threshold: str) -> bool:
        """Check if a notification severity meets the configured threshold."""
        if threshold == "all":
            return True

        severity_levels = {
            "info": 1, "low": 2, "medium": 3, "warning": 3, "high": 4, "critical": 5,
        }
        threshold_minimums = {
            "all": 0,
            "high_and_above": 4,
            "critical": 5,
        }

        sev_val = severity_levels.get(severity, 1)
        min_val = threshold_minimums.get(threshold, 0)
        return sev_val >= min_val

    async def _get_scoped_channels(self, db: AsyncSession, tenant_id: UUID, payload: NotificationPayload):
        """
        Return only notification configs that match the scope of this event.

        Matching rules:
        - org-level configs (scope_level IS NULL or 'organization') → always match
        - BU-level configs → match if payload.business_unit_id == config.business_unit_id
        - project-level configs → match if payload.repository_id == config.repository_id
        """
        from apps.api.app.models.integration import IntegrationConfig

        # NOTIFICATION channels only — slack / teams / email /
        # pagerduty / generic webhook. These are human-facing summary
        # destinations ("Scan complete: foo, 12 findings, 3 critical").
        #
        # Ticketing channels (jira / servicenow / linear / custom) are
        # NOT included here — they're reserved for per-finding fan-out
        # via `dispatch_finding_tickets`, which produces one work
        # item per finding with full defect details. Filing the
        # scan-complete summary as a Jira ticket pollutes the dev
        # board with a "Scan complete: foo" item that has no
        # actionable defect content. User report 2026-04-27:
        # "we don't need this only for findings [Vooda AI] Scan
        # complete: TruffleSecurity".
        #
        # (Earlier in this session we briefly included "ticketing"
        # here as a fix for a different bug — silent ticketing
        # failures because the dispatch path never saw those rows.
        # That root cause is now solved by `dispatch_finding_tickets`
        # owning the per-finding fan-out, so we can revert to the
        # cleaner separation: dispatch() = humans on chat/email,
        # dispatch_finding_tickets() = work items on dev boards.)
        stmt = (
            select(IntegrationConfig)
            .where(
                IntegrationConfig.tenant_id == tenant_id,
                IntegrationConfig.integration_type == "notification",
                IntegrationConfig.is_active == True,
            )
        )
        result = await db.execute(stmt)
        all_channels = result.scalars().all()

        matched = []
        for ch in all_channels:
            scope = ch.scope_level or "organization"

            if scope == "organization":
                # Org-wide → always fires
                matched.append(ch)
            elif scope == "business_unit":
                # BU-scoped → only if the repo belongs to this BU
                if payload.business_unit_id and ch.business_unit_id:
                    if str(ch.business_unit_id) == str(payload.business_unit_id):
                        matched.append(ch)
            elif scope == "project":
                # Project-scoped → only if it's this exact repo
                if payload.repository_id and ch.repository_id:
                    if str(ch.repository_id) == str(payload.repository_id):
                        matched.append(ch)

        logger.info(
            "notification_scope_resolved",
            tenant=str(tenant_id),
            total_channels=len(all_channels),
            matched_channels=len(matched),
            bu_id=payload.business_unit_id,
            repo_id=payload.repository_id,
        )
        return matched

    async def _create_inapp_notifications(self, db: AsyncSession, tenant_id: UUID, payload: NotificationPayload):
        """
        Create in-app notifications ONLY for users with access to the affected scope.

        - Org-level access → always receive
        - BU-level access → receive if their BU matches
        - Project-level access → receive if their repo matches
        """
        from apps.api.app.models.notification import Notification
        from apps.api.app.models.access import UserAccessGrant, AccessLevel
        from apps.api.app.models.user import User

        # Find users who should receive this notification
        recipient_ids = set()

        # 1) Org-level users always get notifications
        org_grants = await db.execute(
            select(UserAccessGrant.user_id).where(
                UserAccessGrant.tenant_id == tenant_id,
                UserAccessGrant.access_level == AccessLevel.ORGANIZATION,
            )
        )
        for row in org_grants.scalars().all():
            recipient_ids.add(row)

        # 2) BU-level users — only if their BU matches
        if payload.business_unit_id:
            bu_grants = await db.execute(
                select(UserAccessGrant.user_id).where(
                    UserAccessGrant.tenant_id == tenant_id,
                    UserAccessGrant.access_level == AccessLevel.BUSINESS_UNIT,
                    UserAccessGrant.business_unit_id == UUID(str(payload.business_unit_id)),
                )
            )
            for row in bu_grants.scalars().all():
                recipient_ids.add(row)

        # 3) Project-level users — only if their repo matches
        if payload.repository_id:
            proj_grants = await db.execute(
                select(UserAccessGrant.user_id).where(
                    UserAccessGrant.tenant_id == tenant_id,
                    UserAccessGrant.access_level == AccessLevel.PROJECT,
                    UserAccessGrant.repository_id == UUID(str(payload.repository_id)),
                )
            )
            for row in proj_grants.scalars().all():
                recipient_ids.add(row)

        # Fallback: if no access grants exist yet (fresh setup), notify all active users
        if not recipient_ids:
            all_users = await db.execute(
                select(User.id).where(User.tenant_id == tenant_id, User.is_active == True)
            )
            recipient_ids = {row for row in all_users.scalars().all()}

        # Create one in-app notification per recipient
        for user_id in recipient_ids:
            notification = Notification(
                tenant_id=tenant_id,
                user_id=user_id,
                title=payload.title,
                body=payload.body,
                notification_type=payload.event_type,
                resource_type=payload.resource_type,
                resource_id=payload.resource_id,
                metadata_={
                    "severity": payload.severity,
                    "url": payload.url,
                    "business_unit_id": payload.business_unit_id,
                    "repository_id": payload.repository_id,
                },
            )
            db.add(notification)

        await db.flush()
        logger.info(
            "inapp_notifications_created",
            tenant=str(tenant_id),
            recipient_count=len(recipient_ids),
            event_type=payload.event_type,
        )

    async def _send_to_channel(
        self,
        channel,
        payload: NotificationPayload,
    ) -> DispatchResult:
        """Route to the appropriate channel handler."""
        provider = channel.provider
        # Decrypt sensitive fields (api_token, password, secret, etc.)
        # before forwarding to the provider handler. The PUT
        # integrations endpoint stores these as `enc:<base64>` and the
        # handlers below assume plaintext — without this step Jira /
        # ServiceNow / Splunk / etc. all received ciphertext as the
        # credential and rejected it. Bug fix 2026-04-27.
        from packages.common.encryption import decrypt_config_dict
        config = decrypt_config_dict(dict(channel.config or {}))

        if provider == "slack":
            return await self._send_slack(config, payload)
        elif provider == "teams":
            return await self._send_teams(config, payload)
        elif provider == "email":
            return await self._send_email(config, payload)
        elif provider == "webhook":
            return await self._send_webhook(config, payload)
        elif provider == "pagerduty":
            return await self._send_pagerduty(config, payload)
        elif provider == "jira":
            return await self._send_jira(config, payload)
        elif provider == "splunk":
            return await self._send_splunk(config, payload)
        elif provider == "sentinel":
            return await self._send_sentinel(config, payload)
        elif provider == "datadog":
            return await self._send_datadog(config, payload)
        elif provider == "servicenow":
            return await self._send_servicenow(config, payload)
        elif provider == "linear":
            return await self._send_linear(config, payload)
        elif provider == "custom_ticketing":
            return await self._send_custom_ticketing(config, payload)
        else:
            return DispatchResult(channel=provider, success=False, error=f"Unknown channel: {provider}")

    async def _send_slack(self, config: dict, payload: NotificationPayload) -> DispatchResult:
        """Send notification via Slack webhook."""
        import httpx

        webhook_url = config.get("webhook_url")
        if not webhook_url:
            return DispatchResult(channel="slack", success=False, error="No webhook URL")

        color_map = {"critical": "#e74c3c", "warning": "#f39c12", "info": "#3498db"}
        color = color_map.get(payload.severity, "#3498db")

        slack_payload = {
            "attachments": [{
                "color": color,
                "title": payload.title,
                "text": payload.body,
                "fields": [
                    {"title": "Event", "value": payload.event_type, "short": True},
                    {"title": "Severity", "value": payload.severity.upper(), "short": True},
                ],
                "footer": "Vooda AI Security Engine",
            }],
        }
        if payload.url:
            slack_payload["attachments"][0]["title_link"] = payload.url

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(webhook_url, json=slack_payload)
                return DispatchResult(channel="slack", success=r.status_code == 200)
        except Exception as e:
            return DispatchResult(channel="slack", success=False, error=str(e)[:200])

    async def _send_teams(self, config: dict, payload: NotificationPayload) -> DispatchResult:
        """Send notification via Microsoft Teams webhook."""
        import httpx

        webhook_url = config.get("webhook_url")
        if not webhook_url:
            return DispatchResult(channel="teams", success=False, error="No webhook URL")

        color_map = {"critical": "FF0000", "warning": "FFA500", "info": "0078D7"}

        teams_payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color_map.get(payload.severity, "0078D7"),
            "summary": payload.title,
            "sections": [{
                "activityTitle": payload.title,
                "activitySubtitle": f"Vooda AI — {payload.event_type}",
                "text": payload.body,
                "facts": [
                    {"name": "Severity", "value": payload.severity.upper()},
                    {"name": "Event", "value": payload.event_type},
                ],
            }],
        }
        if payload.url:
            teams_payload["potentialAction"] = [{
                "@type": "OpenUri",
                "name": "View in Vooda AI",
                "targets": [{"os": "default", "uri": payload.url}],
            }]

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(webhook_url, json=teams_payload)
                return DispatchResult(channel="teams", success=r.status_code == 200)
        except Exception as e:
            return DispatchResult(channel="teams", success=False, error=str(e)[:200])

    async def _send_email(self, config: dict, payload: NotificationPayload) -> DispatchResult:
        """Send notification via SMTP email."""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        smtp_host = config.get("smtp_host")
        smtp_port = int(config.get("smtp_port", 587))
        smtp_user = config.get("smtp_user")
        smtp_password = config.get("smtp_password")
        use_tls = config.get("use_tls", "true").lower() == "true"
        from_email = config.get("from_address") or config.get("from_email") or smtp_user
        to_raw = config.get("to_addresses") or config.get("to_emails") or ""
        to_emails = [e.strip() for e in to_raw.split(",") if e.strip()]

        if not smtp_host or not to_emails:
            return DispatchResult(channel="email", success=False, error="SMTP not configured")

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[Vooda AI] {payload.title}"
            msg["From"] = from_email
            msg["To"] = ", ".join(to_emails)

            html = f"""
            <div style="font-family: sans-serif; max-width: 600px;">
                <h2 style="color: #1a2138;">{payload.title}</h2>
                <p>{payload.body}</p>
                <p><strong>Severity:</strong> {payload.severity.upper()}</p>
                <p><strong>Event:</strong> {payload.event_type}</p>
                {"<p><a href='" + payload.url + "'>View in Vooda AI</a></p>" if payload.url else ""}
                <hr>
                <p style="color: #666; font-size: 12px;">Vooda AI Security Engine</p>
            </div>
            """
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if use_tls:
                    server.starttls()
                if smtp_user and smtp_password and use_tls:
                    server.login(smtp_user, smtp_password)
                server.sendmail(from_email, to_emails, msg.as_string())

            return DispatchResult(channel="email", success=True)
        except Exception as e:
            return DispatchResult(channel="email", success=False, error=str(e)[:200])

    async def _send_webhook(self, config: dict, payload: NotificationPayload) -> DispatchResult:
        """Send notification via generic webhook (POST JSON)."""
        import hashlib
        import hmac
        import json

        import httpx

        url = config.get("url") or config.get("endpoint_url")
        if not url:
            return DispatchResult(channel="webhook", success=False, error="No URL")

        # Build the body ONCE and send exactly these bytes. The signature
        # used to be computed over `payload.__dict__` while a separately
        # constructed dict was posted — different keys, different ordering,
        # so the digest never matched the delivered body and any receiver
        # verifying it rejected every notification.
        body = {
            "title": payload.title,
            "body": payload.body,
            "severity": payload.severity,
            "event_type": payload.event_type,
            "resource_type": payload.resource_type,
            "resource_id": payload.resource_id,
            "url": payload.url,
            "business_unit_id": payload.business_unit_id,
            "repository_id": payload.repository_id,
            "metadata": payload.metadata,
            "source": "vooda_ai",
        }
        raw = json.dumps(body, default=str).encode()

        headers = {"Content-Type": "application/json", "User-Agent": "Vooda-Webhook/1.0"}
        # Operator-supplied headers, applied first so the values below always
        # win — a custom header must never be able to overwrite the signature
        # or replace the content type. Accepts a JSON object (what the UI
        # field collects) or an already-parsed dict.
        extra = config.get("headers")
        if extra:
            if isinstance(extra, str):
                try:
                    extra = json.loads(extra)
                except ValueError:
                    extra = None
            if isinstance(extra, dict):
                for k, v in extra.items():
                    if isinstance(k, str) and k.strip():
                        headers[k.strip()] = str(v)
        headers["Content-Type"] = "application/json"
        headers["User-Agent"] = "Vooda-Webhook/1.0"

        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]
        if config.get("secret"):
            # `sha256=` prefix matches the ticketing webhook and the common
            # GitHub/Stripe convention, so one verification routine works
            # against every webhook Vooda sends.
            sig = hmac.new(config["secret"].encode(), raw, hashlib.sha256).hexdigest()
            headers["X-Vooda-Signature"] = "sha256=" + sig

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(url, content=raw, headers=headers)
                if 200 <= r.status_code < 300:
                    return DispatchResult(channel="webhook", success=True)
                return DispatchResult(
                    channel="webhook", success=False,
                    error=f"Webhook returned {r.status_code}",
                )
        except Exception as e:
            return DispatchResult(channel="webhook", success=False, error=str(e)[:200])

    async def _send_pagerduty(self, config: dict, payload: NotificationPayload) -> DispatchResult:
        """Send notification via PagerDuty Events API v2."""
        import httpx

        routing_key = config.get("routing_key")
        if not routing_key:
            return DispatchResult(channel="pagerduty", success=False, error="No routing key")

        # Map Vooda AI severity to PagerDuty severity
        severity_map = {
            "critical": "critical",
            "high": "error",
            "warning": "warning",
            "medium": "warning",
            "low": "info",
            "info": "info",
        }
        pd_severity = severity_map.get(payload.severity, "info")

        pd_payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"[Vooda AI] {payload.title}",
                "severity": pd_severity,
                "source": "Vooda AI Security Engine",
                "component": payload.resource_type or "unknown",
                "group": payload.event_type,
                "class": payload.severity,
                "custom_details": {
                    "body": payload.body,
                    "event_type": payload.event_type,
                    "severity": payload.severity,
                    "resource_type": payload.resource_type,
                    "resource_id": payload.resource_id,
                    "business_unit_id": payload.business_unit_id,
                    "repository_id": payload.repository_id,
                    "metadata": payload.metadata,
                },
            },
        }

        if payload.url:
            pd_payload["links"] = [{"href": payload.url, "text": "View in Vooda AI"}]

        # Use dedup_key to allow PagerDuty to group related events
        if payload.resource_id:
            pd_payload["dedup_key"] = f"vooda-{payload.event_type}-{payload.resource_id}"

        pagerduty_url = config.get("api_url", "https://events.pagerduty.com/v2/enqueue")

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(pagerduty_url, json=pd_payload)
                if r.status_code == 202:
                    return DispatchResult(channel="pagerduty", success=True)
                else:
                    return DispatchResult(
                        channel="pagerduty", success=False,
                        error=f"PagerDuty returned {r.status_code}: {r.text[:100]}",
                    )
        except Exception as e:
            return DispatchResult(channel="pagerduty", success=False, error=str(e)[:200])

    async def _send_jira(self, config: dict, payload: NotificationPayload) -> DispatchResult:
        """Create a Jira issue for a finding."""
        import httpx

        # Accept either field name. The integrations UI writes
        # `site_url` (which matches Atlassian's Cloud terminology),
        # older configs use `server_url`. Without this fallback the
        # ticketing dispatch silently failed for every config saved
        # via the new UI.
        #
        # Strip everything after the hostname — customers often paste
        # the URL straight from their browser address bar (e.g.
        # `…atlassian.net/jira/for-you`), which would otherwise be
        # appended to our REST path and produce 200-with-HTML
        # responses (Atlassian routes unknown paths to its UI). Bug
        # fix 2026-04-27, mirrors the normalization in
        # apps/api/app/routers/integrations.py:_normalize_atlassian_site_url.
        raw_url = (config.get("site_url") or config.get("server_url") or "").strip()
        try:
            from urllib.parse import urlparse
            _p = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
            server_url = (f"{_p.scheme or 'https'}://{_p.netloc}".rstrip("/")) if _p.netloc else raw_url.rstrip("/")
        except Exception:
            server_url = raw_url.rstrip("/")
        email = config.get("email")
        api_token = config.get("api_token")
        project_key = config.get("project_key", "SEC")
        issue_type = config.get("issue_type", "Task")

        if not server_url or not email or not api_token:
            return DispatchResult(channel="jira", success=False, error="Missing Jira config (site_url/server_url, email, api_token)")

        severity_priority = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}.get(
            payload.severity or "medium", "Medium"
        )

        issue_data = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[Vooda AI] {payload.title}"[:255],
                "description": f"{payload.body}\n\n---\nDetected by Vooda AI Secret Scanner",
                "issuetype": {"name": issue_type},
                "priority": {"name": severity_priority},
                "labels": ["vooda-ai", "secret-detection", payload.severity or "medium"],
            }
        }

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(
                    f"{server_url}/rest/api/2/issue",
                    json=issue_data,
                    auth=(email, api_token),
                    headers={"Content-Type": "application/json"},
                )
                if r.status_code in (200, 201):
                    data = r.json()
                    return DispatchResult(channel="jira", success=True, details={"issue_key": data.get("key")})
                else:
                    return DispatchResult(channel="jira", success=False, error=f"Jira returned {r.status_code}: {r.text[:100]}")
        except Exception as e:
            return DispatchResult(channel="jira", success=False, error=str(e)[:200])

    async def _send_splunk(self, config: dict, payload: NotificationPayload) -> DispatchResult:
        """Forward finding to Splunk via HTTP Event Collector (HEC)."""
        import httpx

        hec_url = config.get("hec_url", "").rstrip("/")
        hec_token = config.get("hec_token")
        source = config.get("source", "vooda-ai")
        sourcetype = config.get("sourcetype", "_json")
        index = config.get("index", "main")

        if not hec_url or not hec_token:
            return DispatchResult(channel="splunk", success=False, error="Missing Splunk HEC config")

        event_data = {
            "event": {
                "title": payload.title,
                "severity": payload.severity,
                "event_type": payload.event_type,
                "body": payload.body,
                "resource_type": payload.resource_type,
                "resource_id": payload.resource_id,
                "url": payload.url,
                "metadata": payload.metadata,
            },
            "source": source,
            "sourcetype": sourcetype,
            "index": index,
        }

        try:
            async with httpx.AsyncClient(timeout=10, verify=config.get("verify_ssl", True)) as client:
                r = await client.post(
                    f"{hec_url}/services/collector/event",
                    json=event_data,
                    headers={"Authorization": f"Splunk {hec_token}"},
                )
                if r.status_code == 200:
                    return DispatchResult(channel="splunk", success=True)
                else:
                    return DispatchResult(channel="splunk", success=False, error=f"Splunk HEC returned {r.status_code}")
        except Exception as e:
            return DispatchResult(channel="splunk", success=False, error=str(e)[:200])

    async def _send_sentinel(self, config: dict, payload: NotificationPayload) -> DispatchResult:
        """Forward finding to Azure Sentinel via Log Analytics Data Collector API."""
        import httpx
        import hashlib
        import hmac
        import base64
        import datetime

        workspace_id = config.get("workspace_id")
        shared_key = config.get("shared_key")
        log_type = config.get("log_type", "VoodaAISecretFinding")

        if not workspace_id or not shared_key:
            return DispatchResult(channel="sentinel", success=False, error="Missing Azure Sentinel config")

        body_str = str([{
            "Title": payload.title,
            "Severity": payload.severity,
            "EventType": payload.event_type,
            "Description": payload.body[:1000],
            "ResourceType": payload.resource_type,
            "ResourceId": payload.resource_id,
            "URL": payload.url,
            "Source": "VoodaAI",
        }])

        rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_length = len(body_str)
        string_to_sign = f"POST\n{content_length}\napplication/json\nx-ms-date:{rfc1123date}\n/api/logs"

        try:
            decoded_key = base64.b64decode(shared_key)
            encoded_hash = base64.b64encode(
                hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
            ).decode("utf-8")
            authorization = f"SharedKey {workspace_id}:{encoded_hash}"

            url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(
                    url,
                    content=body_str,
                    headers={
                        "Content-Type": "application/json",
                        "Log-Type": log_type,
                        "Authorization": authorization,
                        "x-ms-date": rfc1123date,
                    },
                )
                if r.status_code in (200, 202):
                    return DispatchResult(channel="sentinel", success=True)
                else:
                    return DispatchResult(channel="sentinel", success=False, error=f"Sentinel returned {r.status_code}")
        except Exception as e:
            return DispatchResult(channel="sentinel", success=False, error=str(e)[:200])

    async def _send_datadog(self, config: dict, payload: NotificationPayload) -> DispatchResult:
        """Send security signal to Datadog."""
        import httpx

        api_key = config.get("api_key")
        site = config.get("site", "datadoghq.com")

        if not api_key:
            return DispatchResult(channel="datadog", success=False, error="Missing Datadog API key")

        event_data = {
            "title": f"[Vooda AI] {payload.title}",
            "text": payload.body[:4000],
            "priority": "normal" if payload.severity in ("low", "medium") else "high",
            "tags": [f"source:vooda-ai", f"severity:{payload.severity}", f"event:{payload.event_type}"],
            "alert_type": {"critical": "error", "high": "warning", "medium": "info", "low": "info"}.get(payload.severity or "medium", "info"),
            "source_type_name": "vooda_ai",
        }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    f"https://api.{site}/api/v1/events",
                    json=event_data,
                    headers={"DD-API-KEY": api_key, "Content-Type": "application/json"},
                )
                if r.status_code in (200, 202):
                    return DispatchResult(channel="datadog", success=True)
                else:
                    return DispatchResult(channel="datadog", success=False, error=f"Datadog returned {r.status_code}")
        except Exception as e:
            return DispatchResult(channel="datadog", success=False, error=str(e)[:200])

    async def _send_servicenow(self, config: dict, payload: NotificationPayload) -> DispatchResult:
        """Create a ServiceNow incident."""
        import httpx

        # Strip path/query off the instance URL — same defensive parse
        # the Jira dispatcher does. Customers paste the URL straight
        # from the ServiceNow UI ("/now/nav/ui/...") which would
        # otherwise be appended to /api/now/table/incident and land
        # on a 404 / SSO HTML page. Bug fix 2026-04-27, mirrors the
        # _send_jira path.
        raw_url = (config.get("instance_url") or "").strip()
        try:
            from urllib.parse import urlparse
            _p = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
            instance_url = (f"{_p.scheme or 'https'}://{_p.netloc}".rstrip("/")) if _p.netloc else raw_url.rstrip("/")
        except Exception:
            instance_url = raw_url.rstrip("/")
        username = config.get("username")
        password = config.get("password")
        assignment_group = config.get("assignment_group", "Security Operations")

        if not instance_url or not username or not password:
            return DispatchResult(channel="servicenow", success=False, error="Missing ServiceNow config")

        urgency_map = {"critical": "1", "high": "2", "medium": "3", "low": "3"}
        impact_map = {"critical": "1", "high": "2", "medium": "2", "low": "3"}

        incident_data = {
            "short_description": f"[Vooda AI] {payload.title}"[:160],
            "description": f"{payload.body}\n\nDetected by Vooda AI Secret Scanner\n{payload.url or ''}",
            "urgency": urgency_map.get(payload.severity or "medium", "3"),
            "impact": impact_map.get(payload.severity or "medium", "2"),
            "assignment_group": assignment_group,
            "category": "Security",
            "subcategory": "Secret Exposure",
        }

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(
                    f"{instance_url}/api/now/table/incident",
                    json=incident_data,
                    auth=(username, password),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                )
                if r.status_code in (200, 201):
                    data = r.json()
                    number = data.get("result", {}).get("number", "")
                    return DispatchResult(channel="servicenow", success=True, details={"incident_number": number})
                else:
                    return DispatchResult(channel="servicenow", success=False, error=f"ServiceNow returned {r.status_code}")
        except Exception as e:
            return DispatchResult(channel="servicenow", success=False, error=str(e)[:200])

    async def _send_linear(self, config: dict, payload: NotificationPayload) -> DispatchResult:
        """Create a Linear issue for a finding.

        Linear's issueCreate mutation requires a team. The ticketing
        config collects an api_key and an optional team_key; if the key
        is omitted and the workspace has exactly one team, that team is
        used. Auth is the raw API key in the Authorization header (no
        "Bearer"), matching Linear's personal-key convention and the
        connection test.

        Before this existed, Linear was an advertised, configurable,
        test-passing ticketing provider whose findings never produced a
        ticket — _send_to_channel had no case for it and fell through to
        "Unknown channel: linear".
        """
        import httpx

        api_key = (config.get("api_key") or "").strip()
        if not api_key:
            return DispatchResult(channel="linear", success=False, error="Missing Linear api_key")

        team_key = (config.get("team_key") or config.get("team_id") or "").strip()
        headers = {"Authorization": api_key, "Content-Type": "application/json"}
        # Linear priority: 1 Urgent, 2 High, 3 Normal, 4 Low (0 = none).
        priority = {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(payload.severity or "medium", 3)

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                teams_q = await client.post(
                    "https://api.linear.app/graphql",
                    json={"query": "{ teams { nodes { id key } } }"},
                    headers=headers,
                )
                if teams_q.status_code == 401:
                    return DispatchResult(channel="linear", success=False, error="Linear rejected the API key")
                if teams_q.status_code != 200:
                    return DispatchResult(channel="linear", success=False, error=f"Linear returned {teams_q.status_code}")

                teams = (teams_q.json().get("data") or {}).get("teams", {}).get("nodes", [])
                if not teams:
                    return DispatchResult(channel="linear", success=False, error="No Linear teams visible to this API key")

                if team_key:
                    match = [t for t in teams if t.get("key") == team_key or t.get("id") == team_key]
                    if not match:
                        return DispatchResult(channel="linear", success=False,
                                              error=f"Linear team '{team_key}' not found for this key")
                    team_id = match[0]["id"]
                elif len(teams) == 1:
                    team_id = teams[0]["id"]
                else:
                    keys = ", ".join(t.get("key", "?") for t in teams[:6])
                    return DispatchResult(channel="linear", success=False,
                                          error=f"Multiple Linear teams ({keys}); set team_key in the config")

                mutation = (
                    "mutation($teamId:String!,$title:String!,$description:String,$priority:Int){"
                    "  issueCreate(input:{teamId:$teamId,title:$title,description:$description,priority:$priority}){"
                    "    success issue { identifier url }"
                    "  }"
                    "}"
                )
                variables = {
                    "teamId": team_id,
                    "title": f"[Vooda AI] {payload.title}"[:255],
                    "description": f"{payload.body}\n\n---\nDetected by Vooda AI Secret Scanner",
                    "priority": priority,
                }
                r = await client.post(
                    "https://api.linear.app/graphql",
                    json={"query": mutation, "variables": variables},
                    headers=headers,
                )
                if r.status_code != 200:
                    return DispatchResult(channel="linear", success=False, error=f"Linear returned {r.status_code}: {r.text[:100]}")
                data = r.json()
                if data.get("errors"):
                    import json as _json
                    return DispatchResult(channel="linear", success=False, error=f"Linear: {_json.dumps(data['errors'])[:150]}")
                created = (data.get("data") or {}).get("issueCreate") or {}
                if created.get("success"):
                    issue = created.get("issue") or {}
                    return DispatchResult(channel="linear", success=True,
                                          details={"identifier": issue.get("identifier"), "url": issue.get("url")})
                return DispatchResult(channel="linear", success=False, error="Linear issueCreate returned success=false")
        except Exception as e:
            return DispatchResult(channel="linear", success=False, error=str(e)[:200])

    async def _send_custom_ticketing(self, config: dict, payload: NotificationPayload) -> DispatchResult:
        """POST a finding to a customer-defined ticketing webhook.

        Same shape as _send_webhook, but keyed on the `webhook_url`
        field the custom-ticketing config uses, with optional HMAC
        signing. Without this handler, custom_ticketing fell through to
        "Unknown channel" — configurable and test-passing but silently
        creating nothing.
        """
        import httpx

        url = (config.get("webhook_url") or config.get("url") or config.get("endpoint_url") or "").strip()
        if not url:
            return DispatchResult(channel="custom_ticketing", success=False, error="Missing webhook_url")

        body = {
            "title": payload.title,
            "body": payload.body,
            "severity": payload.severity,
            "event_type": payload.event_type,
            "resource_type": payload.resource_type,
            "resource_id": payload.resource_id,
            "url": payload.url,
            "repository_id": payload.repository_id,
            "metadata": payload.metadata,
            "source": "vooda_ai",
        }
        headers = {"Content-Type": "application/json", "User-Agent": "Vooda-Ticketing/1.0"}
        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]
        if config.get("secret"):
            import hmac, hashlib, json as _json
            raw = _json.dumps(body, default=str).encode()
            headers["X-Vooda-Signature"] = "sha256=" + hmac.new(config["secret"].encode(), raw, hashlib.sha256).hexdigest()

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(url, json=body, headers=headers)
                if 200 <= r.status_code < 300:
                    return DispatchResult(channel="custom_ticketing", success=True, details={"http_status": r.status_code})
                return DispatchResult(channel="custom_ticketing", success=False, error=f"Webhook returned {r.status_code}")
        except Exception as e:
            return DispatchResult(channel="custom_ticketing", success=False, error=str(e)[:200])

    # ────────────────────────────────────────────────────────────────
    #  PER-FINDING TICKET DISPATCH (Jira / ServiceNow / Linear / etc.)
    # ────────────────────────────────────────────────────────────────
    #
    # Why this is separate from `dispatch()`:
    #
    #   `dispatch()` sends ONE summary payload to every active channel
    #   (notification + ticketing). It works for "scan complete" alerts
    #   to humans on Slack/Teams/email but is wrong for ticketing —
    #   the dev team wants ONE ticket per finding with the full defect
    #   details (file path, line, masked value, AI verdict, snippet,
    #   remediation hint). A 27-finding scan should create 27 Jira
    #   tickets, not one ticket that says "27 findings found".
    #
    #   This method loops the findings and dispatches a rich, per-
    #   finding payload to TICKETING channels only. It honors the push
    #   rules saved by the integrations UI: minimum severity, the
    #   four exclusion checkboxes (false_positive / test_credential /
    #   accepted_risk / rotated), the trigger gate (on_true_positive
    #   vs on_detection vs manual), and per-channel dedup so re-running
    #   a scan doesn't fire duplicate tickets for findings that were
    #   already pushed.
    #
    # Dedup strategy: after a successful ticket creation, we append a
    #   marker tag to the finding's `tags` list — e.g. `"jira:VOOD-42"`.
    #   The next dispatch checks for that prefix per provider and
    #   skips the finding if it already has one. No new column needed.

    async def dispatch_finding_tickets(
        self,
        db: AsyncSession,
        tenant_id: UUID,
        findings: list,
        repository=None,
        scan_job=None,
        base_url: str = "",
    ) -> list[DispatchResult]:
        """Create one ticket per finding via every active TICKETING channel.

        Returns a flat list of DispatchResult — one entry per
        (channel, finding) attempt. Failures are returned, not raised,
        so a misconfigured Jira project doesn't kill ticketing for the
        rest of the scan.

        Scope-aware: tenants can configure multiple ticketing channels
        with different `scope_level` values (organization / business_unit
        / project) and Vooda will route each finding to only the
        channels whose scope matches its repository. This enables
        teams with multiple products + boards to file findings from
        repo-A into project ENG and from repo-B into project SEC
        without cross-pollination. The `_get_scoped_channels` method
        on `dispatch()` has applied this rule for non-finding events
        since day one — bringing it here so multi-board ticketing
        works the same way. Bug fix 2026-04-27.
        """
        from apps.api.app.models.integration import IntegrationConfig
        from apps.api.app.models.finding import Classification, Severity, RemediationStatus
        from apps.api.app.models.repository import Repository

        results: list[DispatchResult] = []

        # ── 1. Find every active ticketing channel for this tenant ──
        # Notification channels (slack/teams/email/pagerduty) get the
        # existing summary call from `dispatch()` — they're not
        # appropriate for per-finding fan-out (would spam the channel
        # with 50 messages on a noisy scan).
        stmt = select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == tenant_id,
            IntegrationConfig.integration_type == "ticketing",
            IntegrationConfig.is_active == True,  # noqa: E712
        )
        channels = (await db.execute(stmt)).scalars().all()

        if not channels:
            logger.info("ticket_dispatch_no_channels", tenant=str(tenant_id))
            return results

        if not findings:
            logger.info("ticket_dispatch_no_findings", tenant=str(tenant_id),
                        channels=len(channels))
            return results

        # ── 1a. Resolve each finding's business_unit + ticketing
        #       override in a single bulk query (no N+1). We need:
        #       - business_unit_id for BU-scoped routing
        #       - ticketing_integration_id for per-repo override
        #         (the user's "Repo A → JIRA A" UX from 2026-04-27)
        repo_ids = {f.repository_id for f in findings if f.repository_id}
        bu_by_repo: dict = {}
        ticketing_override_by_repo: dict = {}
        if repo_ids:
            repo_rows = (await db.execute(
                select(
                    Repository.id,
                    Repository.business_unit_id,
                    Repository.ticketing_integration_id,
                ).where(Repository.id.in_(repo_ids))
            )).all()
            bu_by_repo = {r[0]: r[1] for r in repo_rows}
            ticketing_override_by_repo = {r[0]: r[2] for r in repo_rows}

        logger.info(
            "ticket_dispatch_started",
            tenant=str(tenant_id),
            channels=len(channels),
            findings=len(findings),
        )

        # ── 2. Per-channel push-rule + per-finding loop ─────────────
        for channel in channels:
            cfg = channel.config or {}

            # The four exclusion checkboxes default to True (UI default).
            # An explicit "false" string in the saved config disables
            # the exclusion (i.e. those findings WILL ticket).
            exclude_fp = cfg.get("_exclude_false_positive", "true") != "false"
            exclude_test = cfg.get("_exclude_test_credential", "true") != "false"
            exclude_accepted = cfg.get("_exclude_accepted_risk", "true") != "false"
            exclude_rotated = cfg.get("_exclude_rotated", "true") != "false"
            min_severity = cfg.get("_min_severity", "medium")
            trigger = cfg.get("_push_trigger", "on_true_positive")

            # `manual` opts out of automatic dispatch entirely — the
            # user wants to push selected findings via a UI button
            # (not yet wired) instead of every scan firing tickets.
            if trigger == "manual":
                logger.info("ticket_dispatch_manual_skip", channel=channel.provider,
                            integration_id=str(channel.id))
                continue

            channel_scope = channel.scope_level or "organization"

            for finding in findings:
                # ── Routing precedence:
                #   1. Per-repo override wins absolutely. If the
                #      finding's repository has ticketing_integration_id
                #      set, route ONLY to that integration — skip every
                #      other channel for this finding (including
                #      organization-wide catch-alls).
                #   2. Otherwise apply scope_level filtering against
                #      this channel: organization (no filter), BU
                #      (must match), project (exact repo match).
                # Bug fix / feature 2026-04-27 — gives dev teams the
                # "Repo A → JIRA A" UX they asked for.
                override = ticketing_override_by_repo.get(finding.repository_id)
                if override is not None:
                    if str(override) != str(channel.id):
                        continue
                    # Override matches this channel — fire regardless
                    # of scope_level. Falls through to push-rule checks.
                else:
                    # No per-repo override — apply scope_level filter.
                    if channel_scope == "business_unit":
                        finding_bu = bu_by_repo.get(finding.repository_id)
                        if not finding_bu or str(finding_bu) != str(channel.business_unit_id):
                            continue
                    elif channel_scope == "project":
                        if not finding.repository_id or str(finding.repository_id) != str(channel.repository_id):
                            continue
                    # `organization` scope: fires for all findings — no filter.

                if not self._should_ticket_finding(
                    finding,
                    min_severity=min_severity,
                    trigger=trigger,
                    exclude_fp=exclude_fp,
                    exclude_test=exclude_test,
                    exclude_accepted=exclude_accepted,
                    exclude_rotated=exclude_rotated,
                ):
                    continue

                # Dedup — has THIS finding already been ticketed on
                # THIS provider? The marker is stored as a tag like
                # `jira:VOOD-42`. Re-scans of unchanged findings
                # should not re-fire the same ticket.
                tag_prefix = f"{channel.provider}:"
                existing_tags = list(finding.tags or [])
                if any(isinstance(t, str) and t.startswith(tag_prefix) for t in existing_tags):
                    continue

                payload = self._build_finding_payload(
                    finding,
                    repository=repository,
                    scan_job=scan_job,
                    base_url=base_url,
                    cfg=cfg,
                )

                try:
                    result = await self._send_to_channel(channel, payload)
                except Exception as e:
                    result = DispatchResult(
                        channel=channel.provider,
                        success=False,
                        error=str(e)[:200],
                    )
                results.append(result)

                # Persist the dedup marker so the next scan skips
                # this finding for this provider.
                if result.success and result.details:
                    key = result.details.get("issue_key") or result.details.get("incident_number") or result.details.get("id")
                    if key:
                        existing_tags.append(f"{channel.provider}:{key}")
                        finding.tags = existing_tags

        logger.info(
            "ticket_dispatch_completed",
            tenant=str(tenant_id),
            attempted=len(results),
            succeeded=sum(1 for r in results if r.success),
        )
        return results

    @staticmethod
    def _should_ticket_finding(
        finding,
        *,
        min_severity: str,
        trigger: str,
        exclude_fp: bool,
        exclude_test: bool,
        exclude_accepted: bool,
        exclude_rotated: bool,
    ) -> bool:
        """Apply the saved push rules to decide if this finding tickets.

        Returns False (silently skip) when any rule excludes the
        finding. The dispatcher logs a per-channel summary, not a
        per-finding skip — that would be too noisy.
        """
        from apps.api.app.models.finding import Classification, Severity, RemediationStatus

        # Manual trigger means NEVER auto-dispatch — the user pushes
        # selected findings via a UI button instead. The outer loop in
        # dispatch_finding_tickets also short-circuits this, but
        # honoring it here makes the helper self-contained: any
        # caller using `_should_ticket_finding` directly (e.g. a UI
        # preview, a test fixture, a future per-finding API) gets
        # consistent semantics. Bug fix 2026-04-27.
        if trigger == "manual":
            return False

        # Severity floor.
        sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        sev_value = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        if sev_rank.get(sev_value, 2) < sev_rank.get(min_severity, 2):
            return False

        # Trigger gate.
        cls_value = finding.classification.value if hasattr(finding.classification, "value") else str(finding.classification or "")
        if trigger == "on_true_positive":
            # Only push findings the AI (or a human) has flagged as
            # true positives. NEEDS_REVIEW / NOT_ENOUGH_EVIDENCE wait
            # for triage to confirm.
            if cls_value not in (
                Classification.LIKELY_TRUE_POSITIVE.value,
                Classification.CONFIRMED_TRUE_POSITIVE.value,
            ):
                return False
        # `on_detection` → push everything that survives other rules.

        # Exclusions.
        if exclude_fp and cls_value in (
            Classification.LIKELY_FALSE_POSITIVE.value,
            Classification.CONFIRMED_FALSE_POSITIVE.value,
        ):
            return False
        if exclude_accepted and cls_value == Classification.ACCEPTED_RISK.value:
            return False

        # "Test credential" exclusion: tagged via path heuristic
        # (services/.../tasks.py:_derive_path_tags applies "test"
        # to fixture paths) or the source_metadata flag.
        if exclude_test:
            tags = finding.tags or []
            sm = finding.source_metadata or {}
            if "test" in tags or sm.get("is_test"):
                return False

        if exclude_rotated:
            rs_value = finding.remediation_status.value if hasattr(finding.remediation_status, "value") else str(finding.remediation_status or "")
            if rs_value == RemediationStatus.APPLIED.value:
                return False

        return True

    @staticmethod
    def _build_finding_payload(
        finding,
        *,
        repository=None,
        scan_job=None,
        base_url: str = "",
        cfg: Optional[dict] = None,
    ) -> "NotificationPayload":
        """Build a rich, ticket-ready payload for a single finding.

        The body is plain text + light markdown (works for Jira,
        ServiceNow descriptions, Linear). It includes everything a
        developer needs to act on the ticket without having to open
        Vooda first: file/line, masked value, severity, rule, AI
        verdict + confidence, code snippet, and a back-link.
        """
        cfg = cfg or {}

        sm = finding.source_metadata or {}
        masked_value = sm.get("masked_value") or sm.get("masked") or "(not captured)"
        secret_type = sm.get("secret_type") or sm.get("type") or finding.vulnerability_category
        validation_status = sm.get("validation_status") or "unverified"

        sev_value = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        cls_value = finding.classification.value if hasattr(finding.classification, "value") else str(finding.classification or "needs_review")

        # Location — combine line range only when the end differs.
        line_str = ""
        if finding.line_start:
            line_str = str(finding.line_start)
            if finding.line_end and finding.line_end != finding.line_start:
                line_str = f"{finding.line_start}–{finding.line_end}"

        repo_name = getattr(repository, "name", None) or "(unknown repository)"
        repo_url_part = getattr(repository, "remote_url", None) or ""
        commit_part = (finding.commit_sha or "")[:8]
        branch_part = finding.branch or ""

        ai_conf_pct = ""
        if finding.ai_confidence is not None:
            ai_conf_pct = f"{int(round(finding.ai_confidence * 100))}%"

        # Snippet — bound to keep ticket bodies under typical limits.
        snippet = (finding.code_snippet or "(no snippet captured)")[:1500]

        finding_url = ""
        if base_url and finding.id:
            finding_url = f"{base_url.rstrip('/')}/findings/{finding.id}"

        # Title: short, descriptive, severity-prefixed so it sorts
        # naturally in the Jira board ("[CRITICAL]" beats "[low]").
        # Filename rather than the full path keeps it scannable —
        # the body has the full path.
        filename = (finding.file_path or "").rsplit("/", 1)[-1] or finding.file_path or "?"
        title = f"[{sev_value.upper()}] {secret_type} in {filename}"
        if finding.line_start:
            title += f":{finding.line_start}"
        title = title[:240]  # leave room for the "[Vooda AI] " prefix

        body_lines = [
            f"**Severity**: {sev_value.upper()}",
            f"**Type**: {secret_type}",
            f"**Validation**: {validation_status}",
            f"**Classification**: {cls_value}",
        ]
        if finding.scanner_rule_id:
            body_lines.append(f"**Rule**: {finding.scanner_rule_id} ({finding.scanner_name})")
        if finding.cwe:
            body_lines.append(f"**CWE**: {finding.cwe}")
        if finding.cve:
            body_lines.append(f"**CVE**: {finding.cve}")

        body_lines.append("")
        body_lines.append("### Location")
        body_lines.append(f"**Repository**: {repo_name}")
        body_lines.append(f"**File**: {finding.file_path or '(unknown)'}")
        if line_str:
            body_lines.append(f"**Line**: {line_str}")
        if branch_part:
            body_lines.append(f"**Branch**: {branch_part}")
        if commit_part:
            body_lines.append(f"**Commit**: {commit_part}")
        if repo_url_part:
            body_lines.append(f"**Remote**: {repo_url_part}")

        body_lines.append("")
        body_lines.append("### Detected Value (masked)")
        body_lines.append(f"`{masked_value}`")

        if finding.ai_explanation:
            body_lines.append("")
            body_lines.append("### AI Analysis")
            if ai_conf_pct:
                body_lines.append(f"**Confidence**: {ai_conf_pct}")
            body_lines.append(finding.ai_explanation[:1500])

        if finding.description:
            body_lines.append("")
            body_lines.append("### Description")
            body_lines.append(finding.description[:1000])

        body_lines.append("")
        body_lines.append("### Code")
        body_lines.append("```")
        body_lines.append(snippet)
        body_lines.append("```")

        body_lines.append("")
        body_lines.append("### Remediation")
        body_lines.append(
            "1. **Rotate** this credential at the issuing provider IMMEDIATELY — "
            "treat it as compromised.\n"
            "2. **Remove** the value from the source file and re-commit.\n"
            "3. **Purge** it from git history (`git filter-repo` or BFG).\n"
            "4. **Replace** with a secret-manager reference (Vault, AWS Secrets "
            "Manager, GCP Secret Manager, env var)."
        )

        if finding_url:
            body_lines.append("")
            body_lines.append(f"**View in Vooda**: {finding_url}")

        body = "\n".join(body_lines)

        return NotificationPayload(
            title=title,
            body=body,
            severity=sev_value,
            event_type="finding_detected",
            resource_type="finding",
            resource_id=str(finding.id) if finding.id else None,
            url=finding_url or None,
            repository_id=str(finding.repository_id) if finding.repository_id else None,
            metadata={
                "rule_id": finding.scanner_rule_id,
                "scanner": finding.scanner_name,
                "secret_type": secret_type,
                "validation_status": validation_status,
                "ai_confidence": finding.ai_confidence,
            },
        )
