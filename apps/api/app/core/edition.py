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
}

#: Deliberately NOT gated, though they sit alongside the four above in
#: the same settings grid:
#:
#:   Suppressions and Rule Overrides are how an operator lives with a
#:   false positive. AI triage is good, not perfect, and when it gets a
#:   verdict wrong these are the only remedy — without them the same
#:   finding reappears on every scan with no recourse. Gating them would
#:   contradict the noise-reduction the product is built on, and it
#:   would push people away rather than upsell them.
#:
#: The gates above limit SCOPE (multi-team scoping, compliance tooling,
#: org-specific rules, scheduling). They do not degrade the scanner.

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
