# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Public, unauthenticated catalogue of built-in scanner rules.

Why a separate router?
----------------------
The existing GET /api/v1/rule-overrides/available-rules is mounted under
``admin`` scope (Sprint 1 of the API-key audit) because the rule-overrides
*router* is admin-only.  But the underlying built-in rule catalogue is
public information — every customer's docs page, the marketing site,
and partner integrations want to render "browse our 925+ rules" without
forcing the visitor to authenticate first.

This router exposes a stripped-down read-only view:
  GET /api/v1/public/scanner-rules
        → list of {rule_id, name, secret_type, severity, description}

It deliberately:
  * is mounted with NO scope dependency (truly public)
  * excludes tenant-private custom detectors (built-in only)
  * caches via HTTP headers (Cache-Control: 1 hour) since the catalogue
    only changes on rule-pack releases
  * supports ``?q=`` substring filter for the live docs page UI
"""

from typing import Optional

from fastapi import APIRouter, Query, Response

router = APIRouter()


@router.get("/scanner-rules")
async def list_public_scanner_rules(
    response: Response,
    q: Optional[str] = Query(
        None,
        max_length=200,
        description="Free-text substring filter on rule_id, name, or secret_type.",
    ),
    severity: Optional[str] = Query(
        None,
        regex="^(critical|high|medium|low|info)$",
        description="Filter by default severity.",
    ),
):
    """Public catalogue of built-in scanner rules — no auth required.

    Returns the full set of detectors Vooda ships with, in deterministic
    rule_id order.  Excludes tenant-private custom detectors (those live
    behind ``/api/v1/custom-detectors``).

    Caching: the catalogue is rebuilt only on rule-pack release, so the
    response is safe to cache for an hour at the CDN edge.
    """
    from packages.common.scanner_branding import brand_rule_id
    # get_all_rules() = built-in catalogue only (sync, no DB).  We
    # deliberately do NOT call get_all_rules_with_custom() here — that
    # would leak tenant-private custom detectors via an unauthenticated
    # endpoint.
    from services.secret_scan.detectors.registry import get_all_rules as get_builtin_rules

    # 1-hour edge cache.  ``public`` allows shared caches; ``s-maxage``
    # is honoured by CDNs; ``stale-while-revalidate`` keeps responses
    # snappy during a re-fetch.
    response.headers["Cache-Control"] = (
        "public, max-age=3600, s-maxage=3600, stale-while-revalidate=86400"
    )

    rules = get_builtin_rules()
    needle = (q or "").strip().lower()
    sev_filter = (severity or "").strip().lower()

    seen: set[str] = set()
    items: list[dict] = []
    for r in rules:
        display_id = brand_rule_id(r.rule_id) if r.rule_id else r.rule_id
        if not display_id or display_id in seen:
            continue
        if sev_filter and (r.severity or "").lower() != sev_filter:
            continue
        if needle:
            hay = f"{display_id} {r.rule_id or ''} {r.title or ''} {r.secret_type or ''}".lower()
            if needle not in hay:
                continue
        seen.add(display_id)
        items.append({
            "rule_id": display_id,
            "name": r.title,
            "secret_type": r.secret_type or None,
            "severity": r.severity or None,
            "cwe": getattr(r, "cwe", None),
            "verifier_available": bool(getattr(r, "verifier", None)),
            "description": (r.description or None) if r.description else None,
        })

    items.sort(key=lambda x: x["rule_id"])
    return {"total": len(items), "items": items}
