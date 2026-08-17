# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Secret Validation Engine — verifies whether detected secrets are active.

Calls provider APIs to determine if a secret is still valid, revoked, or unknown.
Implements rate limiting, caching, timeout handling, and audit logging.
"""

import hashlib
import time
import structlog
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logger = structlog.get_logger()


class ValidationStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    NOT_VALIDATED = "not_validated"
    VALIDATION_ERROR = "validation_error"


@dataclass
class ValidationResult:
    status: ValidationStatus
    provider: str
    details: dict = field(default_factory=dict)
    error: Optional[str] = None
    validated_at: Optional[str] = None
    response_time_ms: int = 0


# In-memory cache: secret_hash -> (ValidationResult, timestamp)
_validation_cache: dict[str, tuple[ValidationResult, float]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour

# Rate limiting: provider -> (last_call_time, call_count_in_window)
_rate_limits: dict[str, list[float]] = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_CALLS = 30  # per provider per window


def _check_rate_limit(provider: str) -> bool:
    now = time.time()
    calls = _rate_limits.get(provider, [])
    calls = [t for t in calls if now - t < RATE_LIMIT_WINDOW]
    _rate_limits[provider] = calls
    if len(calls) >= RATE_LIMIT_MAX_CALLS:
        return False
    calls.append(now)
    _rate_limits[provider] = calls
    return True


def _cache_key(secret_value: str) -> str:
    return hashlib.sha256(secret_value.encode()).hexdigest()[:32]


def _get_cached(secret_value: str) -> Optional[ValidationResult]:
    key = _cache_key(secret_value)
    if key in _validation_cache:
        result, ts = _validation_cache[key]
        if time.time() - ts < CACHE_TTL_SECONDS:
            return result
        del _validation_cache[key]
    return None


def _set_cached(secret_value: str, result: ValidationResult):
    key = _cache_key(secret_value)
    _validation_cache[key] = (result, time.time())


# ── Provider registry ─────────────────────────────────────

_VALIDATORS: dict[str, "BaseValidator"] = {}


def register_validator(secret_type: str, validator: "BaseValidator"):
    _VALIDATORS[secret_type] = validator


def get_validator(secret_type: str) -> Optional["BaseValidator"]:
    return _VALIDATORS.get(secret_type)


class BaseValidator:
    provider: str = "unknown"
    timeout: int = 5

    async def validate(self, secret_value: str, context: dict = None) -> ValidationResult:
        raise NotImplementedError


# ── Main validation engine ────────────────────────────────

@dataclass
class ValidationAuditEntry:
    secret_type: str
    provider: str
    status: str
    response_time_ms: int
    timestamp: str
    error: Optional[str] = None


class SecretValidationEngine:
    def __init__(self):
        self._load_validators()
        self.audit_log: list[ValidationAuditEntry] = []

    def _load_validators(self):
        from services.secret_validation.validators.aws import AWSAccessKeyValidator
        from services.secret_validation.validators.github import GitHubTokenValidator
        from services.secret_validation.validators.gitlab import GitLabTokenValidator
        from services.secret_validation.validators.slack import SlackTokenValidator
        from services.secret_validation.validators.stripe import StripeKeyValidator
        from services.secret_validation.validators.twilio import TwilioValidator
        from services.secret_validation.validators.sendgrid import SendGridValidator
        from services.secret_validation.validators.npm import NpmTokenValidator
        from services.secret_validation.validators.generic import GenericHTTPValidator
        from services.secret_validation.validators.gcp import GCPAPIKeyValidator
        from services.secret_validation.validators.azure import AzureValidator
        from services.secret_validation.validators.pypi import PyPITokenValidator
        from services.secret_validation.validators.mailgun import MailgunValidator

        register_validator("aws_access_key", AWSAccessKeyValidator())
        register_validator("aws_secret_key", AWSAccessKeyValidator())
        register_validator("github_pat", GitHubTokenValidator())
        register_validator("github_pat_fine_grained", GitHubTokenValidator())
        register_validator("github_oauth", GitHubTokenValidator())
        register_validator("github_app_token", GitHubTokenValidator())
        register_validator("gitlab_pat", GitLabTokenValidator())
        register_validator("slack_bot_token", SlackTokenValidator())
        register_validator("slack_user_token", SlackTokenValidator())
        register_validator("stripe_secret_key", StripeKeyValidator())
        register_validator("twilio_account_sid", TwilioValidator())
        register_validator("twilio_auth_token", TwilioValidator())
        register_validator("sendgrid_api_key", SendGridValidator())
        register_validator("npm_token", NpmTokenValidator())
        register_validator("gcp_api_key", GCPAPIKeyValidator())
        register_validator("gcp_service_account", GCPAPIKeyValidator())
        register_validator("azure_ad_secret", AzureValidator())
        register_validator("azure_storage_key", AzureValidator())
        register_validator("pypi_token", PyPITokenValidator())
        register_validator("mailgun_api_key", MailgunValidator())

    async def validate_secret(
        self,
        secret_value: str,
        secret_type: str,
        context: Optional[dict] = None,
    ) -> ValidationResult:
        # Check cache first
        cached = _get_cached(secret_value)
        if cached:
            logger.debug("validation_cache_hit", secret_type=secret_type)
            return cached

        validator = get_validator(secret_type)
        if not validator:
            return ValidationResult(
                status=ValidationStatus.NOT_VALIDATED,
                provider=secret_type,
                error=f"No validator for secret type: {secret_type}",
            )

        # Rate limit check
        if not _check_rate_limit(validator.provider):
            logger.warning("validation_rate_limited", provider=validator.provider)
            return ValidationResult(
                status=ValidationStatus.UNKNOWN,
                provider=validator.provider,
                error="Rate limited — try again later",
            )

        start = time.time()
        try:
            result = await validator.validate(secret_value, context or {})
            result.response_time_ms = int((time.time() - start) * 1000)
            result.validated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            _set_cached(secret_value, result)

            self.audit_log.append(ValidationAuditEntry(
                secret_type=secret_type,
                provider=validator.provider,
                status=result.status.value,
                response_time_ms=result.response_time_ms,
                timestamp=result.validated_at or "",
            ))

            logger.info(
                "secret_validated",
                secret_type=secret_type,
                provider=validator.provider,
                status=result.status.value,
                response_time_ms=result.response_time_ms,
            )
            return result

        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            self.audit_log.append(ValidationAuditEntry(
                secret_type=secret_type,
                provider=validator.provider,
                status="validation_error",
                response_time_ms=elapsed,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                error=str(e)[:200],
            ))
            logger.error("validation_error", secret_type=secret_type, error=str(e)[:200])
            return ValidationResult(
                status=ValidationStatus.VALIDATION_ERROR,
                provider=validator.provider,
                error=str(e)[:200],
                response_time_ms=elapsed,
            )

    async def validate_batch(
        self,
        secrets: list[dict],
    ) -> list[ValidationResult]:
        """Validate multiple secrets. Each dict needs 'value' and 'secret_type' keys."""
        results = []
        for s in secrets:
            result = await self.validate_secret(
                s["value"],
                s["secret_type"],
                s.get("context"),
            )
            results.append(result)
        return results
