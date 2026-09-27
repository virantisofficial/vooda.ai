# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Edition gating — which features belong to a commercial licence.

One list, read by both the API and the UI. The UI greys a tile and shows
an Enterprise badge; the API refuses the call. Gating only the UI would
be cosmetic — the endpoints are reachable directly — so both sides read
`ENTERPRISE_FEATURES` and cannot drift apart.

This is a licence boundary, not a security control. The source is public
and the check is removable in a minute. What it buys is a boundary the
operator can see without reading the licence, and a deliberate act
rather than an accident if someone crosses it.

Set `EDITION=enterprise` to unlock. No key server, no phone home: a
scanner sold on "nothing leaves your network" cannot call home to ask
whether it is allowed to run.
"""
from __future__ import annotations

from fastapi import HTTPException, Request, status

from apps.api.app.core.config import settings


#: Feature key → the label the UI shows. Keys match the settings tiles in
#: apps/web/src/app/settings/admin/page.tsx, so the badge and the refusal
#: always describe the same thing.
ENTERPRISE_FEATURES: dict[str, str] = {
    "access_control": "Access Control",
    "audit": "Audit & Compliance",
    "audit_export": "Audit Export & Retention",
    "custom_detectors": "Custom Detectors",
    "schedules": "Scan Schedules",
    "webhooks": "Inbound Webhooks",
    "ticketing": "Ticketing",
    "notifications": "Notification Channels",
}

#: Which gated feature a provider belongs to, if any.
#:
#: Two categories, one rule: Community finds, verifies and triages
#: secrets; Enterprise carries the result out of Vooda — into a
#: tracker, or into the systems a team watches.
#:
#: Ticketing is taken whole rather than split. A half-gated category
#: left one tile in a row of three looking like a missing badge rather
#: than a decision, and the boundary was hard to state in a sentence.
#:
#: Linear and the SIEM channels are listed although neither is
#: advertised in PROVIDER_SCHEMAS — the dispatcher can still route to
#: them, and a provider gated everywhere except the one path that
#: actually sends is not gated.
#:
#: In-app notifications are deliberately absent. They are written
#: straight to the notifications table, not through a channel, so the
#: bell keeps working in every edition — including the signal that says
#: triage could not run, which a customer must never stop receiving
#: because of their licence.
ENTERPRISE_PROVIDER_FEATURES: dict[str, str] = {
    # Filing a finding into a tracker.
    "jira": "ticketing",
    "servicenow": "ticketing",
    "custom_ticketing": "ticketing",
    "linear": "ticketing",
    # Telling a system outside Vooda that a finding exists.
    "slack": "notifications",
    "teams": "notifications",
    "ms_teams": "notifications",
    "email": "notifications",
    "webhook": "notifications",
    "pagerduty": "notifications",
    "splunk": "notifications",
    "sentinel": "notifications",
    "datadog": "notifications",
}

#: Kept for the ticketing call sites and their tests.
ENTERPRISE_TICKETING_PROVIDERS: frozenset[str] = frozenset(
    p for p, f in ENTERPRISE_PROVIDER_FEATURES.items() if f == "ticketing"
)


def provider_feature(provider: str) -> "str | None":
    """The gated feature this provider belongs to, or None."""
    return ENTERPRISE_PROVIDER_FEATURES.get((provider or "").lower())


def provider_enabled(provider: str) -> bool:
    """True when this provider is available in the running edition."""
    feature = provider_feature(provider)
    return feature is None or feature_enabled(feature)


def ticketing_provider_enabled(provider: str) -> bool:
    """Narrower twin, kept so the ticketing contract reads as itself."""
    if (provider or "").lower() not in ENTERPRISE_TICKETING_PROVIDERS:
        return True
    return feature_enabled("ticketing")


#: HTTP methods that stay reachable even when their feature is gated.
#:
#: Access control is the one gate that can strand a tenant. Grants keep
#: enforcing after a downgrade — the check reads the grant rows, not the
#: edition — so a user scoped to a business unit stays scoped. Gating
#: every method would leave them locked out of repositories with no route
#: back, and no support call could fix it from inside the product.
#:
#: So CREATING scope is the Enterprise capability, while READING it (to
#: find what is still in force) and REMOVING it (to undo) stay open.
#: Gating those would trap people rather than upsell them.
GATED_FEATURE_ESCAPE_HATCHES: dict[str, tuple[str, ...]] = {
    "access_control": ("GET", "DELETE"),
}


def is_enterprise() -> bool:
    return str(getattr(settings, "EDITION", "community")).strip().lower() == "enterprise"


def feature_enabled(feature: str) -> bool:
    """True when `feature` is available in the running edition."""
    return is_enterprise() or feature not in ENTERPRISE_FEATURES


def method_exempt(feature: str, method: str) -> bool:
    """True when this HTTP method stays open despite the gate."""
    return method.upper() in GATED_FEATURE_ESCAPE_HATCHES.get(feature, ())


def require_enterprise(feature: str):
    """FastAPI dependency: refuse the call unless the edition allows it.

    402 rather than 403: this is not an authorisation failure — the
    caller's permissions are fine and no different login would help.
    Payment Required is the status that actually describes it, and it
    lets the UI tell the two cases apart.
    """
    def _guard(request: Request) -> None:
        if feature_enabled(feature):
            return
        if method_exempt(feature, request.method):
            return
        label = ENTERPRISE_FEATURES.get(feature, feature)
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=(
                f"{label} is available in Vooda Enterprise. "
                f"The Community edition includes the full scan engine, "
                f"detection, verification and AI triage. See https://vooda.ai/"
            ),
        )
    return _guard
