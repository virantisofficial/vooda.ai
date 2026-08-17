# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Stripe key validator."""

import httpx
from services.secret_validation.engine import BaseValidator, ValidationResult, ValidationStatus


class StripeKeyValidator(BaseValidator):
    provider = "stripe"
    timeout = 5

    async def validate(self, secret_value: str, context: dict = None) -> ValidationResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    "https://api.stripe.com/v1/charges?limit=1",
                    auth=(secret_value, ""),
                )
            if resp.status_code == 200:
                return ValidationResult(
                    status=ValidationStatus.ACTIVE,
                    provider=self.provider,
                    details={"note": "Stripe key is active with charge read access"},
                )
            elif resp.status_code == 401:
                return ValidationResult(status=ValidationStatus.INACTIVE, provider=self.provider)
            else:
                return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, details={"response_code": resp.status_code})
        except httpx.TimeoutException:
            return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, error="Timeout")
        except Exception as e:
            return ValidationResult(status=ValidationStatus.VALIDATION_ERROR, provider=self.provider, error=str(e)[:200])
