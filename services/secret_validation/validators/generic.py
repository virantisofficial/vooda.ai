# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Generic HTTP validator — configurable URL + header template."""

import httpx
from services.secret_validation.engine import BaseValidator, ValidationResult, ValidationStatus


class GenericHTTPValidator(BaseValidator):
    provider = "generic"
    timeout = 5

    async def validate(self, secret_value: str, context: dict = None) -> ValidationResult:
        context = context or {}
        url = context.get("validation_url")
        header_name = context.get("header_name", "Authorization")
        header_prefix = context.get("header_prefix", "Bearer")

        if not url:
            return ValidationResult(
                status=ValidationStatus.NOT_VALIDATED,
                provider=self.provider,
                error="No validation_url provided in context",
            )

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    url,
                    headers={header_name: f"{header_prefix} {secret_value}" if header_prefix else secret_value},
                )
            if resp.status_code in (200, 201, 204):
                return ValidationResult(status=ValidationStatus.ACTIVE, provider=self.provider, details={"response_code": resp.status_code})
            elif resp.status_code in (401, 403):
                return ValidationResult(status=ValidationStatus.INACTIVE, provider=self.provider, details={"response_code": resp.status_code})
            else:
                return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, details={"response_code": resp.status_code})
        except httpx.TimeoutException:
            return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, error="Timeout")
        except Exception as e:
            return ValidationResult(status=ValidationStatus.VALIDATION_ERROR, provider=self.provider, error=str(e)[:200])
