# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Notification Rules API — centralized control of which events trigger notifications.

Admins configure event types + severity thresholds here.
Channels (Slack, Teams, etc.) only define WHERE to deliver.
"""

from uuid import UUID
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func as sa_func

from apps.api.app.core.database import get_db
from apps.api.app.core.security import get_current_user
from apps.api.app.models.user import User
from apps.api.app.models.notification_rule import NotificationRule
from apps.api.app.models.notification import Notification

router = APIRouter()


# ── Notifications (user-visible, bell-backed) ────────────────

class NotificationResponse(BaseModel):
    id: UUID
    title: str
    body: Optional[str] = None
    notification_type: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    is_read: bool
    metadata: dict = {}
    created_at: str

    model_config = {"from_attributes": True}


@router.get("", response_model=list[NotificationResponse])
async def list_notifications(
    limit: int = Query(20, ge=1, le=100),
    unread_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the current user's recent notifications, newest first."""
    conditions = [Notification.tenant_id == user.tenant_id, Notification.user_id == user.id]
    if unread_only:
        conditions.append(Notification.is_read == False)  # noqa: E712
    q = await db.execute(
        select(Notification)
        .where(*conditions)
        .order_by(Notification.created_at.desc())
        .limit(limit)
    )
    rows = q.scalars().all()
    return [
        NotificationResponse(
            id=n.id,
            title=n.title,
            body=n.body,
            notification_type=n.notification_type,
            resource_type=n.resource_type,
            resource_id=n.resource_id,
            is_read=n.is_read,
            metadata=n.metadata_ or {},
            created_at=str(n.created_at),
        )
        for n in rows
    ]


@router.get("/unread-count")
async def unread_count(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = await db.execute(
        select(sa_func.count(Notification.id)).where(
            Notification.tenant_id == user.tenant_id,
            Notification.user_id == user.id,
            Notification.is_read == False,  # noqa: E712
        )
    )
    return {"count": q.scalar() or 0}


@router.post("/{notification_id}/read", status_code=204)
async def mark_read(
    notification_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Notification).where(
            Notification.id == notification_id,
            Notification.tenant_id == user.tenant_id,
            Notification.user_id == user.id,
        )
    )
    n = result.scalar_one_or_none()
    if not n:
        raise HTTPException(status_code=404, detail="Notification not found")
    n.is_read = True
    await db.flush()


@router.post("/read-all", status_code=204)
async def mark_all_read(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await db.execute(
        update(Notification)
        .where(
            Notification.tenant_id == user.tenant_id,
            Notification.user_id == user.id,
            Notification.is_read == False,  # noqa: E712
        )
        .values(is_read=True)
    )
    await db.flush()


# ── Notification Rules (existing — admin config) ─────────────


# ── Constants ────────────────────────────────────────────

DEFAULT_RULES = [
    {"event_type": "scan_complete",      "severity_threshold": "all",            "is_enabled": True},
    # WS-9 — scan failures should page just like completions notify. On by
    # default; the dispatcher already treats a missing rule as enabled, so
    # this row just makes it visible + toggleable in the settings UI.
    {"event_type": "scan_failed",        "severity_threshold": "all",            "is_enabled": True},
    {"event_type": "critical_finding",   "severity_threshold": "critical",       "is_enabled": True},
    {"event_type": "policy_violation",   "severity_threshold": "all",            "is_enabled": True},
    {"event_type": "remediation_ready",  "severity_threshold": "all",            "is_enabled": True},
    {"event_type": "finding_assigned",   "severity_threshold": "all",            "is_enabled": False},
    {"event_type": "patch_approved",     "severity_threshold": "all",            "is_enabled": True},
    {"event_type": "sla_breach",         "severity_threshold": "high_and_above", "is_enabled": True},
    {"event_type": "import_completed",   "severity_threshold": "all",            "is_enabled": False},
]

EVENT_LABELS = {
    "scan_complete":      "Scan Complete",
    "scan_failed":        "Scan Failed",
    "critical_finding":   "Critical Finding Detected",
    "policy_violation":   "Policy Violation",
    "remediation_ready":  "Remediation Ready",
    "finding_assigned":   "Finding Assigned",
    "patch_approved":     "Patch Approved / Rejected",
    "sla_breach":         "SLA Breach Warning",
    "import_completed":   "Import Completed",
}


# ── Schemas ──────────────────────────────────────────────

class NotificationRuleItem(BaseModel):
    # IMPORTANT: PUT /notifications/rules expects a JSON ARRAY of these
    # items as the request body — NOT an object wrapping them.  i.e.
    #   [{"event_type":"scan_completed","severity_threshold":"high","is_enabled":true}, ...]
    # rather than
    #   {"rules":[...]}    ← will 422
    # We can't surface that root-shape hint here, but the route handler's
    # docstring + the schema_extra below make it discoverable.
    event_type: str = Field(
        ...,
        examples=["scan_completed", "finding_critical", "finding_high"],
        description="Event type — see /notifications/rules GET for the catalog.",
    )
    severity_threshold: str = Field(
        "all", examples=["all", "high", "critical"],
    )
    is_enabled: bool = True

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "event_type": "scan_completed",
                "severity_threshold": "all",
                "is_enabled": True,
            }],
        },
    }

class NotificationRuleResponse(BaseModel):
    id: str
    event_type: str
    label: str
    severity_threshold: str
    is_enabled: bool

class NotificationRulesListResponse(BaseModel):
    rules: List[NotificationRuleResponse]


# ── Helpers ──────────────────────────────────────────────

async def _require_org_admin(db: AsyncSession, user) -> None:
    from apps.api.app.core.access_control import is_org_admin
    if not await is_org_admin(db, user):
        raise HTTPException(status_code=403, detail="Admin access required")


async def _seed_defaults(db: AsyncSession, tenant_id) -> list[NotificationRule]:
    """Create default notification rules for a tenant on first access."""
    rules = []
    for dflt in DEFAULT_RULES:
        rule = NotificationRule(
            tenant_id=tenant_id,
            event_type=dflt["event_type"],
            severity_threshold=dflt["severity_threshold"],
            is_enabled=dflt["is_enabled"],
        )
        db.add(rule)
        rules.append(rule)
    await db.flush()
    return rules


def _rule_to_response(rule: NotificationRule) -> dict:
    return {
        "id": str(rule.id),
        "event_type": rule.event_type,
        "label": EVENT_LABELS.get(rule.event_type, rule.event_type.replace("_", " ").title()),
        "severity_threshold": rule.severity_threshold,
        "is_enabled": rule.is_enabled,
    }


# ── Endpoints ────────────────────────────────────────────

@router.get("/rules")
async def list_notification_rules(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List all notification rules for this tenant. Auto-seeds defaults on first access."""
    await _require_org_admin(db, user)

    stmt = select(NotificationRule).where(NotificationRule.tenant_id == user.tenant_id)
    result = await db.execute(stmt)
    rules = list(result.scalars().all())

    # Auto-seed if empty (first visit)
    if not rules:
        rules = await _seed_defaults(db, user.tenant_id)
        await db.commit()

    return {"rules": [_rule_to_response(r) for r in rules]}


@router.put("/rules")
async def update_notification_rules(
    updates: List[NotificationRuleItem],
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Bulk update notification rules. Creates any missing rules."""
    await _require_org_admin(db, user)

    valid_thresholds = {"all", "critical", "high_and_above"}

    for item in updates:
        if item.severity_threshold not in valid_thresholds:
            raise HTTPException(status_code=400, detail=f"Invalid threshold: {item.severity_threshold}")

        # Find existing rule
        stmt = select(NotificationRule).where(
            NotificationRule.tenant_id == user.tenant_id,
            NotificationRule.event_type == item.event_type,
        )
        result = await db.execute(stmt)
        rule = result.scalar_one_or_none()

        if rule:
            rule.severity_threshold = item.severity_threshold
            rule.is_enabled = item.is_enabled
        else:
            # Create new rule
            rule = NotificationRule(
                tenant_id=user.tenant_id,
                event_type=item.event_type,
                severity_threshold=item.severity_threshold,
                is_enabled=item.is_enabled,
            )
            db.add(rule)

    await db.commit()

    # Audit log
    from apps.api.app.core.audit import log_audit
    await log_audit(
        db, user, "notification_rules_updated", "notification_rule", None,
        f"Updated {len(updates)} notification rules"
    )
    await db.commit()

    # Return full list
    stmt = select(NotificationRule).where(NotificationRule.tenant_id == user.tenant_id)
    result = await db.execute(stmt)
    rules = list(result.scalars().all())

    return {"rules": [_rule_to_response(r) for r in rules]}
