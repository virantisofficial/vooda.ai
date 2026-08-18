# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode
from typing import Annotated, Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Vooda AI"
    APP_VERSION: str = "0.1.1"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://vooda:vooda_dev_password@localhost:5432/vooda"
    DATABASE_URL_SYNC: str = "postgresql://vooda:vooda_dev_password@localhost:5432/vooda"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Auth
    #
    # This value is not only the JWT signing key: every integration
    # credential in the database — Vault tokens, cloud keys, Jira
    # passwords — is Fernet-encrypted with a key derived from it
    # (packages/common/encryption.py). A default or empty value means
    # anyone holding a copy of the database and a copy of this source
    # can decrypt all of it.
    #
    # The default below exists so imports and tests work. It is rejected
    # at startup in production by `assert_production_secret_key()`,
    # which is called from the API lifespan and the worker bootstrap —
    # the check deliberately lives there rather than in a validator so
    # that importing the settings never explodes.
    SECRET_KEY: str = "change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ALGORITHM: str = "HS256"

    # ── SSO kill switch — OFF by default, and it must stay off ──
    # The SAML assertion handler does NOT validate the IdP signature
    # (services/auth/sso.py:process_response parses the XML and trusts
    # the NameID as-is), so the ACS endpoint was a complete
    # unauthenticated auth bypass: a forged assertion for any email —
    # including admin — minted a valid session. OIDC is an unfinished
    # 501 stub. Until SSO is reimplemented on a vetted library
    # (python3-saml + xmlsec) with full signature/condition/replay
    # validation, the auth-accepting endpoints refuse every request.
    # Do NOT flip this on without that reimplementation.
    SSO_ENABLED: bool = False

    # Brute-force cap on POST /auth/login, counted per client IP.
    # Configurable because the limit is per *IP*, not per account: an
    # office behind one NAT gateway, or a deployment behind a proxy that
    # does not set X-Forwarded-For, shares a single budget across every
    # user and legitimately needs a higher ceiling. It is also what lets
    # the integration suite run more than once a minute.
    # Keep it as tight as your topology allows.
    AUTH_LOGIN_RATE_LIMIT: str = "10/minute"

    # AI
    AI_PROVIDER: str = "claude"  # claude | openai
    ANTHROPIC_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    AI_MODEL: str = "claude-sonnet-4-20250514"
    AI_MAX_TOKENS: int = 4096
    AI_TEMPERATURE: float = 0.1

    # AI Triage Batch
    AI_TRIAGE_BATCH_SIZE: int = 5
    AI_TRIAGE_MAX_CONCURRENT: int = 10
    AI_RATE_LIMIT_RPM: int = 60

    # Storage
    STORAGE_BACKEND: str = "local"  # local | s3
    STORAGE_PATH: str = "./storage"
    S3_BUCKET: Optional[str] = None
    S3_REGION: Optional[str] = None

    # Git clone/fetch wall-clock budget (Sprint A-1). The old hardcoded
    # 300s timed out large-history clones (live: aws-cdk) AND left the
    # git child running after asyncio.wait_for fired. 30 min is generous
    # for a full-history clone of a large monorepo over a slow link; the
    # helper that enforces it now also kills the git process group on
    # timeout so no orphan survives. Raise for pathologically large repos.
    GIT_FETCH_TIMEOUT_SECONDS: int = 1800

    # CORS
    # Accepted env-var formats (parsed by the validator below):
    #   - JSON list:   CORS_ORIGINS='["https://app.acme.com","https://acme.com"]'
    #   - CSV string:  CORS_ORIGINS=https://app.acme.com,https://acme.com
    #   - Single URL:  CORS_ORIGINS=https://app.acme.com
    # The default is a localhost dev origin; production must set this
    # to the customer's deployed hostname(s).
    #
    # The `NoDecode` annotation tells pydantic-settings to skip its
    # built-in JSON-parsing pass on this env var. Without it the
    # CSV-string form ("a,b") raises SettingsError BEFORE the
    # field_validator below ever runs, because EnvSettingsSource
    # tries to `json.loads()` list-shaped fields by default. With
    # NoDecode the raw string flows through to the validator, which
    # handles JSON / CSV / single-URL uniformly.
    CORS_ORIGINS: Annotated[list[str], NoDecode] = ["http://localhost:3000"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_cors_origins(cls, v):
        # pydantic-settings passes env vars as `str`; the model
        # default and any code-set value comes through as `list`.
        # Accept both, plus the comma-separated form because that's
        # what most deployment dashboards (Coolify, Render, Fly,
        # Railway) use for list-shaped env vars.
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return ["http://localhost:3000"]
            # JSON list?
            if v.startswith("["):
                import json
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return [str(x).strip() for x in parsed if str(x).strip()]
                except json.JSONDecodeError:
                    pass
            # Otherwise treat as CSV (or a single URL with no commas).
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    # Public web base URL — used when building deep-links into the
    # Vooda UI from outside the app (e.g. the "View in Vooda" link
    # at the bottom of every Jira ticket the dispatcher creates).
    # Override in .env / docker-compose for staging + prod.
    WEB_BASE_URL: str = "http://localhost:3001"

    # ── OAuth ──────────────────────────────────────────────────────
    # Public-reachable base URL for OAuth callback handlers. The
    # customer's Atlassian Developer Console app config must register
    # `${OAUTH_REDIRECT_BASE}/atlassian/callback` as an allowed
    # redirect URI. For local dev, leave as the API host. For prod,
    # set to the customer's deployed Vooda API URL (e.g.
    # `https://vooda.acme.com/api/v1/integrations/oauth`).
    OAUTH_REDIRECT_BASE: str = "http://localhost:8001/api/v1/integrations/oauth"
    # State-token signing — short-lived (10 min) HMAC over the
    # integration_id + tenant_id + nonce to pin the OAuth roundtrip
    # to a specific in-flight setup so a stolen `code` from one
    # tenant can't be redeemed against another's IntegrationConfig.
    OAUTH_STATE_TTL_SECONDS: int = 600

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 120

    # ── Credential verification (live provider API checks) ──────────
    # Global kill-switch for OUTBOUND credential verification. Default ON
    # for SaaS. Set VERIFICATION_ENABLED=false for air-gapped / regulated
    # deployments that forbid egress — scans still complete normally and
    # findings stay `not_validated` (never an error, never a hang). The
    # SSRF/egress guard (services/secret_verification/egress.py) is ALWAYS
    # enforced regardless of this flag.
    VERIFICATION_ENABLED: bool = True
    # Max concurrent in-flight credential verifications during a scan's verify
    # phase. The per-provider token bucket still throttles same-provider bursts,
    # so this caps total fan-out (DB session is never touched concurrently).
    VERIFICATION_CONCURRENCY: int = 8
    # Absolute wall-clock backstop (seconds) for the whole verify phase — if the
    # bounded-concurrent batch can't finish in this window, stragglers are
    # cancelled and their findings stay not_validated. Guarantees no hang.
    VERIFICATION_ABS_BUDGET_S: int = 120
    # When True, a finding whose credential is verified DEAD (status="inactive")
    # by an allowlisted provider is auto-suppressed (is_suppressed=True,
    # suppression_reason="verified_inactive") — reversible metadata, not deletion.
    # Only fires for the curated SUPPRESSION_ALLOWLIST (providers whose verifier
    # returns "inactive" only on a definitive 401/403/revoked rejection). Set
    # False to verify-and-label without suppressing.
    VERIFICATION_SUPPRESS_INACTIVE: bool = True

    model_config = {"env_file": ".env", "case_sensitive": True}


settings = Settings()


#: Values that must never protect real data. The empty string is the
#: one that actually happens: docker-compose passes `SECRET_KEY:
#: '${SECRET_KEY}'`, so an operator who never sets it in .env gets an
#: empty string rather than the default below — and the app used to
#: start and encrypt happily with it.
_UNSAFE_SECRET_KEYS = {"", "change-me-in-production", "secret", "changeme"}

#: 32 characters is the floor for a key feeding an AES-128 KDF. The
#: documented way to produce one is `openssl rand -hex 32`.
_MIN_SECRET_KEY_LENGTH = 32


def assert_production_secret_key() -> None:
    """Refuse to run in production with a guessable SECRET_KEY.

    Called from the API lifespan and the Celery worker bootstrap, not
    from a field validator: importing the settings must never raise, or
    every test and tooling script would need a key just to read config.

    Outside production this only warns, so `pytest` and a local
    `uvicorn` keep working. VOODA_ENV defaults to "production", so the
    strict path is the default and the lax one has to be asked for.
    """
    import os
    import structlog

    log = structlog.get_logger()
    key = (settings.SECRET_KEY or "").strip()
    env = os.environ.get("VOODA_ENV", "production").lower()

    if key in _UNSAFE_SECRET_KEYS:
        problem = "is unset or still the placeholder value"
    elif len(key) < _MIN_SECRET_KEY_LENGTH:
        problem = f"is only {len(key)} characters (minimum {_MIN_SECRET_KEY_LENGTH})"
    else:
        return

    message = (
        f"SECRET_KEY {problem}. It signs every session token and "
        f"encrypts every stored integration credential — Vault tokens, "
        f"cloud keys, ticketing passwords — so a guessable value means "
        f"anyone with a copy of the database can read all of them.\n"
        f"Generate one with:  openssl rand -hex 32\n"
        f"then set SECRET_KEY in your .env (or your platform's secret "
        f"store) and restart."
    )

    if env == "production":
        raise RuntimeError(message)

    log.warning("secret_key.insecure", env=env, detail=message.replace("\n", " "))
