# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""PyPI token validator."""

import httpx
from services.secret_validation.engine import BaseValidator, ValidationResult, ValidationStatus


class PyPITokenValidator(BaseValidator):
    provider = "pypi"
    timeout = 5

    async def validate(self, secret_value: str, context: dict = None) -> ValidationResult:
        """Validate PyPI token by checking the simple API with auth."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    "https://upload.pypi.org/legacy/",
                    auth=("__token__", secret_value),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            # PyPI returns 405 for GET on upload endpoint if auth succeeds,
            # 401 if token is invalid
            if resp.status_code == 401:
                return ValidationResult(status=ValidationStatus.INACTIVE, provider=self.provider)
            elif resp.status_code in (200, 405, 400):
                return ValidationResult(status=ValidationStatus.ACTIVE, provider=self.provider, details={"note": "Token accepted by PyPI"})
            else:
                return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, details={"response_code": resp.status_code})
        except httpx.TimeoutException:
            return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, error="Timeout")
        except Exception as e:
            return ValidationResult(status=ValidationStatus.VALIDATION_ERROR, provider=self.provider, error=str(e)[:200])
