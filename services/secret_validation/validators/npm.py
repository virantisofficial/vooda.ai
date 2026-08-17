# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""npm token validator."""

import httpx
from services.secret_validation.engine import BaseValidator, ValidationResult, ValidationStatus


class NpmTokenValidator(BaseValidator):
    provider = "npm"
    timeout = 5

    async def validate(self, secret_value: str, context: dict = None) -> ValidationResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    "https://registry.npmjs.org/-/whoami",
                    headers={"Authorization": f"Bearer {secret_value}"},
                )
            if resp.status_code == 200:
                data = resp.json()
                return ValidationResult(
                    status=ValidationStatus.ACTIVE,
                    provider=self.provider,
                    details={"username": data.get("username")},
                )
            elif resp.status_code == 401:
                return ValidationResult(status=ValidationStatus.INACTIVE, provider=self.provider)
            else:
                return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, details={"response_code": resp.status_code})
        except httpx.TimeoutException:
            return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, error="Timeout")
        except Exception as e:
            return ValidationResult(status=ValidationStatus.VALIDATION_ERROR, provider=self.provider, error=str(e)[:200])
