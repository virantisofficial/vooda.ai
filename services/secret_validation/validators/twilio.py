# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Twilio credential validator."""

import httpx
from services.secret_validation.engine import BaseValidator, ValidationResult, ValidationStatus


class TwilioValidator(BaseValidator):
    provider = "twilio"
    timeout = 5

    async def validate(self, secret_value: str, context: dict = None) -> ValidationResult:
        context = context or {}
        account_sid = context.get("account_sid") or secret_value
        auth_token = context.get("auth_token") or secret_value

        if not account_sid.startswith("AC"):
            return ValidationResult(
                status=ValidationStatus.UNKNOWN,
                provider=self.provider,
                error="Twilio validation requires Account SID (AC prefix)",
            )
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json",
                    auth=(account_sid, auth_token),
                )
            if resp.status_code == 200:
                data = resp.json()
                return ValidationResult(
                    status=ValidationStatus.ACTIVE,
                    provider=self.provider,
                    details={"friendly_name": data.get("friendly_name"), "status": data.get("status")},
                )
            elif resp.status_code == 401:
                return ValidationResult(status=ValidationStatus.INACTIVE, provider=self.provider)
            else:
                return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, details={"response_code": resp.status_code})
        except httpx.TimeoutException:
            return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, error="Timeout")
        except Exception as e:
            return ValidationResult(status=ValidationStatus.VALIDATION_ERROR, provider=self.provider, error=str(e)[:200])
