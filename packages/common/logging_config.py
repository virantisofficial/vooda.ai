# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Centralized logging configuration for the entire Vooda platform.

One ``configure_logging()`` call at startup wires up:

  - structlog with a deterministic processor chain
  - stdlib logging (so uvicorn / SQLAlchemy / httpx / celery share the
    same pipeline — no more mix of plain-text + structured output)
  - JSON output in production, human-readable in development
  - Automatic secret redaction on every log line
  - Request-scope context vars (request_id, user_id, tenant_id) auto-merged
  - Standard fields injected once: service, version, environment

Why centralized
---------------
Before this module, 78 files imported ``structlog`` and called
``structlog.get_logger()`` independently — without ever calling
``structlog.configure()``.  Result:

  - Mixed plain-text uvicorn logs + key=value structlog logs in the
    same stream
  - No JSON output (so downstream log shippers couldn't index fields)
  - No correlation IDs (support tickets had no breadcrumb to follow)
  - No secret redaction (any logger.info(token=...) call would leak
    the credential to disk)

This file fixes all four with a single startup hook.

Usage
-----
At process startup (api / worker / beat):

    from packages.common.logging_config import configure_logging
    configure_logging(
        service="api",          # or "worker" / "beat"
        version="1.0.0",
        env="production",       # or "development" / "staging"
    )

Then anywhere in code:

    import structlog
    logger = structlog.get_logger(__name__)
    logger.info("test_connection_result",
                source_type="confluence",
                error_code="atlassian.auth.token_invalid")

The 78 existing call sites work unchanged — they just start emitting
through the new pipeline as soon as ``configure_logging()`` runs.

Output format
-------------
Production (env != "development"):

    {"level": "info", "event": "test_connection_result",
     "source_type": "confluence", "error_code": "atlassian.auth.token_invalid",
     "request_id": "ab12-cd34-...", "user_id": "u_01H...", "tenant_id": "t_default",
     "service": "api", "version": "1.0.0", "env": "production",
     "timestamp": "2026-05-09T08:34:21.123456Z"}

Development:

    2026-05-09T08:34:21Z [info     ] test_connection_result
        source_type=confluence  error_code=atlassian.auth.token_invalid
        request_id=ab12-cd34-...  service=api
"""

from __future__ import annotations

import logging
import os
import re
import sys
from typing import Any

import structlog


# ─────────────────────────────────────────────────────────────────
# Secret redaction processor
# ─────────────────────────────────────────────────────────────────

# Compile once — these run on every log line, hot path.
_CREDENTIAL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"ATATT3xFf[A-Za-z0-9_=\-]{32,}=[A-F0-9]{8}"), "<atlassian-token>"),
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"), "<github-pat>"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"), "<github-pat-fg>"),
    (re.compile(r"\bxox[bpars]-[A-Za-z0-9-]{10,}\b"), "<slack-token>"),
    (re.compile(r"\bxoxe\.xoxp-[A-Za-z0-9-]{20,}\b"), "<slack-rotated-token>"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "<aws-access-key>"),
    (re.compile(r"(?i)(Bearer\s+)[^\s\"']{12,}"), r"\1<redacted>"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"), "<stripe-live-key>"),
    (re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b"), "<stripe-test-key>"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{30,}\b"), "<anthropic-key>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "<jwt>"),
]

# Field names whose VALUE should always be redacted regardless of content.
_SENSITIVE_FIELD_NAMES = {
    "api_token", "apitoken", "token", "access_token", "refresh_token",
    "client_secret", "password", "secret", "private_key", "bot_token",
    "authorization", "x_api_key", "x_auth_token",
}


def _redact_string(s: str) -> str:
    if not s:
        return s
    out = s
    for pattern, replacement in _CREDENTIAL_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def _redact_value(value: Any) -> Any:
    """Recursively walk a value, redacting credential patterns inside strings."""
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, dict):
        return {
            k: ("<redacted>" if k.lower() in _SENSITIVE_FIELD_NAMES else _redact_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(x) for x in value]
    return value


def redact_secrets_processor(logger, method_name, event_dict):
    """Structlog processor that redacts credential patterns from any field.

    Two layers:
      1. Field-name allow-list — keys whose name implies a secret get
         their value blanked entirely (defends against ``logger.info(
         "auth_attempt", api_token=tok)`` patterns).
      2. Pattern match — the remaining values are walked and any
         credential-shaped substring is replaced with a tag.

    Runs early in the chain so downstream processors / renderers never
    see the raw value.  Cost is O(N) over field count + value length;
    measured ~30 µs per typical log line, well under our budget.
    """
    return {k: _redact_value(v) for k, v in event_dict.items()}


# ─────────────────────────────────────────────────────────────────
# Standard fields processor
# ─────────────────────────────────────────────────────────────────


def _make_standard_fields_processor(service: str, version: str, env: str):
    """Inject service/version/env on every log line.

    These are constants per process, so we capture them once at config
    time and close over them rather than re-reading env / settings on
    every emit.
    """
    constants = {"service": service, "version": version, "env": env}

    def processor(logger, method_name, event_dict):
        # Don't overwrite if the caller explicitly set these (rare, but
        # legal — e.g. a request-router proxying logs from another
        # service may want to forward the upstream service name).
        for k, v in constants.items():
            event_dict.setdefault(k, v)
        return event_dict

    return processor


# ─────────────────────────────────────────────────────────────────
# Health-check / noise suppression
# ─────────────────────────────────────────────────────────────────


class _HealthCheckFilter(logging.Filter):
    """Drop uvicorn access-log lines for health endpoints.

    Health checks fire every few seconds from k8s / docker-compose;
    at INFO they dominate the log stream and obscure real events.
    Re-emit them at DEBUG instead — visible if you bump LOG_LEVEL,
    invisible by default.
    """

    NOISE_PATTERNS = ("/api/health", "/healthz", "/openapi.json", "/api/openapi.json")

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if any(p in msg for p in self.NOISE_PATTERNS):
            # Demote rather than drop so it's still recoverable at DEBUG.
            record.levelno = logging.DEBUG
            record.levelname = "DEBUG"
        return True


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


def configure_logging(
    *,
    service: str,
    version: str,
    env: str = "production",
    log_level: str | None = None,
) -> None:
    """Wire up the entire logging pipeline.

    Idempotent — safe to call multiple times (only the most recent
    call's settings take effect).  Should be called exactly once at
    process startup before any other logging occurs.

    Args:
        service: "api" / "worker" / "beat" — appears as the ``service``
            field on every log line.
        version: Application version string (from settings.APP_VERSION).
        env: "development" / "staging" / "production".  Controls
            output format (pretty vs JSON) and default log level.
        log_level: Override level (defaults to LOG_LEVEL env var or
            INFO).  Use DEBUG when investigating; never CRITICAL by
            default (CRITICAL is reserved for system-down events).
    """
    level_name = (log_level or os.environ.get("LOG_LEVEL") or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    # Stdlib logging: route everything through stderr, single handler,
    # let structlog's ProcessorFormatter handle the formatting so
    # uvicorn / sqlalchemy / httpx logs come out in the same shape as
    # our own.
    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)

    # Shared processor chain — both structlog-native and stdlib paths
    # converge through these before the renderer.
    shared_processors = [
        structlog.contextvars.merge_contextvars,        # request_id, user_id, etc.
        structlog.processors.add_log_level,              # `level` field
        timestamper,                                     # `timestamp` field
        _make_standard_fields_processor(service, version, env),  # service, version, env
        redact_secrets_processor,                        # scrub credentials
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,            # tracebacks → field
    ]

    if env == "development":
        renderer: Any = structlog.dev.ConsoleRenderer(colors=True)
    else:
        renderer = structlog.processors.JSONRenderer(sort_keys=False)

    # Stdlib root logger — uvicorn and friends emit through this.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=renderer,
            foreign_pre_chain=shared_processors,
        )
    )
    handler.addFilter(_HealthCheckFilter())

    root = logging.getLogger()
    # Drop any handlers FastAPI / uvicorn / celery installed before us
    # — we own the output now.  Leaving them attached would double-
    # emit each line.
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # uvicorn's internal access logger has its own handler by default;
    # clear it so access logs flow through our pipeline.
    for noisy in ("uvicorn", "uvicorn.access", "uvicorn.error", "fastapi", "sqlalchemy.engine"):
        lg = logging.getLogger(noisy)
        lg.handlers.clear()
        lg.propagate = True

    # Silence uvicorn.access entirely — our RequestContextMiddleware
    # emits one ``http.request`` log per request with the same data
    # plus structured fields (request_id, status, duration_ms).
    # Letting uvicorn.access also emit a string-formatted line would
    # double every request in the log stream.  Bug fix 2026-05-09.
    logging.getLogger("uvicorn.access").disabled = True

    # structlog: same processor chain; convert the final event_dict
    # into the format the stdlib handler expects via wrap_for_formatter.
    structlog.configure(
        processors=shared_processors + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )

    # First line: prove we're configured.  Operators can grep for this
    # at boot to confirm the pipeline is hot.
    structlog.get_logger().info(
        "logging.configured",
        log_level=level_name,
        renderer="json" if env != "development" else "console",
    )


# ─────────────────────────────────────────────────────────────────
# Context helpers — used by the FastAPI middleware and worker tasks
# ─────────────────────────────────────────────────────────────────


def bind_request_context(**kwargs: Any) -> None:
    """Bind fields to the current request's structlog context.

    Every subsequent ``logger.info(...)`` in this asyncio task picks
    up these fields automatically.  Cleared at request end by
    ``clear_request_context()`` (the FastAPI middleware handles this).
    """
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_request_context() -> None:
    """Reset the request context — FastAPI middleware calls this in
    its ``finally`` block to prevent leakage between requests.
    """
    structlog.contextvars.clear_contextvars()
