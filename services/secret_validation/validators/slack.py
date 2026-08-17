# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Slack token validator — uses auth.test API."""

import httpx
from services.secret_validation.engine import BaseValidator, ValidationResult, ValidationStatus


class SlackTokenValidator(BaseValidator):
    provider = "slack"
    timeout = 5

    async def validate(self, secret_value: str, context: dict = None) -> ValidationResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    "https://slack.com/api/auth.test",
                    headers={"Authorization": f"Bearer {secret_value}"},
                )
            data = resp.json()
            if data.get("ok"):
                return ValidationResult(
                    status=ValidationStatus.ACTIVE,
                    provider=self.provider,
                    details={"team": data.get("team"), "user": data.get("user"), "team_id": data.get("team_id")},
                )
            else:
                error = data.get("error", "unknown")
                status = ValidationStatus.INACTIVE if error in ("invalid_auth", "token_revoked", "account_inactive") else ValidationStatus.UNKNOWN
                return ValidationResult(status=status, provider=self.provider, details={"error": error})
        except httpx.TimeoutException:
            return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, error="Timeout")
        except Exception as e:
            return ValidationResult(status=ValidationStatus.VALIDATION_ERROR, provider=self.provider, error=str(e)[:200])
