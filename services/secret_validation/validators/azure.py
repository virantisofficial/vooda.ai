# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Azure credential validator."""

import httpx
from services.secret_validation.engine import BaseValidator, ValidationResult, ValidationStatus


class AzureValidator(BaseValidator):
    provider = "azure"
    timeout = 5

    async def validate(self, secret_value: str, context: dict = None) -> ValidationResult:
        """Validate Azure credentials by attempting to get a management token."""
        context = context or {}
        tenant_id = context.get("tenant_id", "common")
        client_id = context.get("client_id")

        if not client_id:
            return ValidationResult(
                status=ValidationStatus.UNKNOWN,
                provider=self.provider,
                error="Azure validation requires client_id in context",
            )

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": secret_value,
                        "scope": "https://management.azure.com/.default",
                    },
                )
            if resp.status_code == 200:
                return ValidationResult(status=ValidationStatus.ACTIVE, provider=self.provider, details={"tenant_id": tenant_id})
            elif resp.status_code in (400, 401):
                data = resp.json()
                error = data.get("error", "")
                if error in ("invalid_client", "unauthorized_client"):
                    return ValidationResult(status=ValidationStatus.INACTIVE, provider=self.provider, details={"error": error})
                return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, details={"error": error})
            else:
                return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, details={"response_code": resp.status_code})
        except httpx.TimeoutException:
            return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, error="Timeout")
        except Exception as e:
            return ValidationResult(status=ValidationStatus.VALIDATION_ERROR, provider=self.provider, error=str(e)[:200])
