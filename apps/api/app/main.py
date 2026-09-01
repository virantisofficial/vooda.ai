# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import os
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from fastapi import Depends

from apps.api.app.core.config import settings
from apps.api.app.core.log_middleware import RequestContextMiddleware
from apps.api.app.core.security import require_scope
# Governance routers (policies, gates, nhi, cloud_connectors, vault_api, agents,
# supply_chain, policy_dsl, federation, migrations, quantum, universal_governance)
# removed 2026-05-16 — those product surfaces belong to dedicated specialists.
# Vooda focuses on best-in-class secret scanning.
from apps.api.app.core.edition import ENTERPRISE_FEATURES, is_enterprise, require_enterprise
from apps.api.app.routers import auth, repositories, scan_jobs, findings, metrics, audit, integrations, integrations_oauth, ai_models, users, roles, suppressions, sso, api_keys, reports, ws, saved_views, access, notification_rules, webhooks, push_protection, custom_detectors, scan_sources, rotation_events, incidents, rule_overrides, scanner_rules_public, imports
from packages.common.logging_config import configure_logging

# Configure logging FIRST — before any logger is used and before
# uvicorn / SQLAlchemy import their own handlers.  Idempotent, so it's
# also safe under uvicorn reload and multi-worker setups.  Bug fix
# 2026-05-09: previously every file called structlog.get_logger()
# without anyone calling structlog.configure(), so output was a mix
# of uvicorn's plain-text access logs and structlog's key=value
# defaults — and there was no central control of format / redaction /
# correlation IDs.  See packages/common/logging_config.py for the
# full pipeline.
configure_logging(
    service="api",
    version=settings.APP_VERSION,
    env=os.environ.get("VOODA_ENV", "production"),
)

logger = structlog.get_logger("vooda.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Refuse to serve before quietly encrypting credentials with a key
    # anyone reading this repository could derive.
    from apps.api.app.core.config import assert_production_secret_key

    assert_production_secret_key()
    logger.info("api.starting", version=settings.APP_VERSION)
    yield
    logger.info("api.shutting_down")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)


# ─── Per-principal rate limiting ────────────────────────────────
# slowapi limiter — bucket per (api_key_id > user_id > remote IP).
# Mounted here, before any router/middleware so the SlowAPIMiddleware
# wraps every request.  See core/rate_limit.py for the full design.
from apps.api.app.core.rate_limit import (  # noqa: E402
    limiter,
    rate_limit_exceeded_handler,
)
from slowapi.errors import RateLimitExceeded  # noqa: E402
from slowapi.middleware import SlowAPIMiddleware  # noqa: E402

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


# ─── Optimistic-lock conflict handler ────────────────────────────
# SQLAlchemy raises StaleDataError when an UPDATE driven by
# version_id_col matches zero rows — meaning another transaction
# beat us to the row.  Most of our triage endpoints rely on the
# session-lifecycle auto-commit in ``get_db`` (see
# core/database.py:22-31), so the error fires AFTER the handler
# returns and would otherwise surface to the client as a generic
# HTTP 500.  Converting it to a structured 409 here lets the UI
# treat it as a recoverable "your draft is stale — reload" prompt
# rather than a server bug.  Added 2026-05-19 with the version
# columns on SecretIncident + NormalizedFinding.
from sqlalchemy.orm.exc import StaleDataError  # noqa: E402
from fastapi import Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402


@app.exception_handler(StaleDataError)
async def _stale_data_error_handler(request: Request, exc: StaleDataError):
    return JSONResponse(
        status_code=409,
        content={
            "detail": {
                "error": "stale_version",
                "message": (
                    "Resource was modified by another writer; reload and retry."
                ),
            }
        },
    )

# Request-context middleware — registered BEFORE CORS so the
# request_id is bound for CORS-preflight handling too.  Per-request
# fields (request_id, method, path) flow into every logger.info()
# call inside the request automatically.
app.add_middleware(RequestContextMiddleware)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Request-ID"],
)

# Routers
#
# Scope enforcement (added 2026-05-24 as part of the API-key audit
# follow-up).  Each router is mounted with a router-level dependency
# that 403s any API-key request lacking the listed scope.  JWT sessions
# bypass — see core/security.py:require_scope() for the rules.
#
#   scope        → routers
#   "scan"       → repositories, scan-sources, scan-jobs, webhooks
#   "findings"   → findings, incidents
#   "reports"    → reports, metrics (metrics is read-only dashboard data
#                                    — analytics belong in the same scope)
#   "gate"       → push-protection
#   "admin"      → users, roles, suppressions, rule-overrides, sso,
#                  api-keys, integrations, custom-detectors, access,
#                  notification-rules, ai-models, audit, saved-views,
#                  rotation-events
#
# /auth and /ws are intentionally scope-free: auth IS the bootstrap, and
# WebSocket auth flows via a separate token-on-connect path.
@app.get("/api/v1/edition", tags=["edition"])
async def get_edition():
    """Which edition is running, and what it gates.

    Unauthenticated on purpose: the UI needs it to render the settings
    grid before any tile is clicked, and it reveals nothing beyond what
    the licence already states publicly.
    """
    return {
        "edition": "enterprise" if is_enterprise() else "community",
        "enterprise_features": ENTERPRISE_FEATURES,
        "gated": [] if is_enterprise() else sorted(ENTERPRISE_FEATURES),
    }


app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(
    repositories.router, prefix="/api/v1/repositories", tags=["repositories"],
    dependencies=[Depends(require_scope("scan"))],
)
# Flat scan-job access by id (Sprint S / WS-4) — deep-linkable page +
# the long-documented GET /scan-jobs/{id} polling endpoint.  Same "scan"
# scope as the nested repository scan endpoints.
app.include_router(
    scan_jobs.router, prefix="/api/v1/scan-jobs", tags=["scan-jobs"],
    dependencies=[Depends(require_scope("scan"))],
)
app.include_router(
    findings.router, prefix="/api/v1/findings", tags=["findings"],
    dependencies=[Depends(require_scope("findings"))],
)
# /incidents — Case-B aggregation: one row per unique credential
# (vs /findings which is per-location).  See routers/incidents.py.
app.include_router(
    incidents.router, prefix="/api/v1/incidents", tags=["incidents"],
    dependencies=[Depends(require_scope("findings"))],
)
app.include_router(
    metrics.router, prefix="/api/v1/metrics", tags=["metrics"],
    dependencies=[Depends(require_scope("reports"))],
)
app.include_router(
    audit.router, prefix="/api/v1/audit", tags=["audit"],
    dependencies=[Depends(require_scope("admin"))],
)
app.include_router(
    integrations.router, prefix="/api/v1/integrations", tags=["integrations"],
    dependencies=[Depends(require_scope("admin"))],
)
# OAuth 2.0 (3LO) flows for upstream providers (Atlassian today, more
# later). Mounted under the same /integrations prefix so the
# IntegrationConfig row a callback updates is co-located with where
# the rest of the integration management lives.
app.include_router(
    integrations_oauth.router, prefix="/api/v1/integrations/oauth", tags=["oauth"],
    dependencies=[Depends(require_scope("admin"))],
)
app.include_router(
    ai_models.router, prefix="/api/v1/ai-models", tags=["ai-models"],
    dependencies=[Depends(require_scope("admin"))],
)
app.include_router(
    users.router, prefix="/api/v1/users", tags=["users"],
    dependencies=[Depends(require_scope("admin"))],
)
app.include_router(
    roles.router, prefix="/api/v1/roles", tags=["roles"],
    dependencies=[Depends(require_scope("admin"))],
)
app.include_router(
    suppressions.router, prefix="/api/v1/suppressions", tags=["suppressions"],
    dependencies=[Depends(require_scope("admin"))],
)
# Rule overrides — proactive muting of scanner rules per repo / org-wide.
# Distinct from /suppressions which is reactive post-finding triage.  See
# models/rule_override.py for the rationale.
app.include_router(
    rule_overrides.router, prefix="/api/v1/rule-overrides", tags=["rule-overrides"],
    dependencies=[Depends(require_scope("admin"))],
)
# SSO router mounted WITHOUT a router-level scope dependency because
# the IdP-facing endpoints (/oidc/authorize, /oidc/callback,
# /saml/acs, /saml/metadata) are the unauthenticated bootstrap path
# — the browser hits them mid-handshake with no token of its own.
# The two config endpoints inside (POST /configure, GET /providers
# pre-config view) gate themselves via inline require_org_admin()
# checks; see routers/sso.py.  Sprint-1 had this scoped to admin at
# the router level, which broke the live OIDC/SAML flows — fixed
# 2026-05-24 as part of REC-2.
app.include_router(sso.router, prefix="/api/v1/sso", tags=["sso"])
app.include_router(
    api_keys.router, prefix="/api/v1/api-keys", tags=["api-keys"],
    dependencies=[Depends(require_scope("admin"))],
)
app.include_router(
    reports.router, prefix="/api/v1/reports", tags=["reports"],
    dependencies=[Depends(require_scope("reports"))],
)
app.include_router(ws.router, prefix="/api/v1/ws", tags=["websocket"])
app.include_router(
    saved_views.router, prefix="/api/v1/saved-views", tags=["saved-views"],
    dependencies=[Depends(require_scope("admin"))],
)
app.include_router(
    access.router, prefix="/api/v1/access", tags=["access-control"],
    dependencies=[Depends(require_scope("admin")), Depends(require_enterprise("access_control"))],
)
app.include_router(
    notification_rules.router, prefix="/api/v1/notifications", tags=["notifications"],
    dependencies=[Depends(require_scope("admin"))],
)
# The inbound receiver POST /webhooks/{provider} must be reachable
# without a Vooda token: GitHub/GitLab/Bitbucket authenticate each
# delivery with an HMAC signature header, not a bearer token. A
# router-level require_scope made every real provider webhook 401
# before the signature was ever checked, so inbound webhooks could not
# function. The receiver enforces its own security by verifying the
# HMAC signature and failing closed when no secret is configured
# (see routers/webhooks.py). The admin-only config endpoints in this
# router carry their own Depends(get_current_user).
app.include_router(
    webhooks.router, prefix="/api/v1/webhooks", tags=["webhooks"],
)
app.include_router(
    push_protection.router, prefix="/api/v1", tags=["push-protection"],
    dependencies=[Depends(require_scope("gate"))],
)
# Governance routers (nhi, cloud_connectors, agents, supply_chain, policy_dsl,
# federation, migrations, quantum, universal_governance) removed 2026-05-16.
# See the import block above for the architectural rationale.
#
# `vault` (Vault & Secret Managers — coverage checks + rotation write-back)
# is an enterprise-only feature and is NOT registered in the community
# edition. The router and its services remain in-tree but unreachable.
app.include_router(
    custom_detectors.router, prefix="/api/v1/custom-detectors", tags=["custom-detectors"],
    dependencies=[Depends(require_scope("admin")), Depends(require_enterprise("custom_detectors"))],
)
app.include_router(
    scan_sources.router, prefix="/api/v1/scan-sources", tags=["scan-sources"],
    dependencies=[Depends(require_scope("scan"))],
)
app.include_router(
    rotation_events.router, prefix="/api/v1", tags=["rotation-events"],
    dependencies=[Depends(require_scope("admin"))],
)
# CLI / CI findings-import (P0 two-way sync, UP side).  Mounted at bare
# /api/v1 because it owns two paths — /repositories/{id}/import/findings
# and /imports/scan.  NO router-level scope dependency on purpose: each
# endpoint self-gates with the write-only `findings:import` scope and needs
# the resolved `user` (for tenant derivation), which the per-endpoint
# Depends(require_scope("findings:import")) provides.  See routers/imports.py.
app.include_router(
    imports.router, prefix="/api/v1", tags=["imports"],
)

# Public, unauthenticated catalogue of built-in scanner rules.  Used by
# the docs site, marketing pages, and partner integrations to render
# "browse our 925+ rules" without forcing visitors to authenticate.
# Mounted with NO scope dependency on purpose — see router docstring.
app.include_router(
    scanner_rules_public.router, prefix="/api/v1/public", tags=["public"],
)


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "version": settings.APP_VERSION}


# Root-level /healthz alias for Coolify / Kubernetes / docker
# healthcheck conventions. Same response shape as /api/health.
# Kept un-prefixed so the docker healthcheck can curl
# `http://127.0.0.1:8000/healthz` without going through the /api/v1
# router or worrying about CORS.
@app.get("/healthz")
async def healthz():
    return {"status": "healthy", "version": settings.APP_VERSION}


@app.get("/api/about")
async def about():
    from packages.common.scanner_branding import get_sarif_tool_info, get_attribution_text
    return {
        "name": "Vooda AI Security Engine",
        "version": settings.APP_VERSION,
        "tool_info": get_sarif_tool_info(),
        "attribution": get_attribution_text(),
    }
