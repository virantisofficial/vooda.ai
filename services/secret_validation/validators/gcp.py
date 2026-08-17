# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""GCP credential validator."""

import httpx
from services.secret_validation.engine import BaseValidator, ValidationResult, ValidationStatus


class GCPAPIKeyValidator(BaseValidator):
    provider = "gcp"
    timeout = 5

    async def validate(self, secret_value: str, context: dict = None) -> ValidationResult:
        """Validate GCP API key by calling a lightweight Google API."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Use the Generative Language API as a lightweight check
                resp = await client.get(
                    f"https://generativelanguage.googleapis.com/v1beta/models?key={secret_value}",
                )
            if resp.status_code == 200:
                return ValidationResult(status=ValidationStatus.ACTIVE, provider=self.provider, details={"note": "API key is active"})
            elif resp.status_code in (400, 403):
                body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                error_msg = body.get("error", {}).get("message", "")
                if "API key not valid" in error_msg or "API_KEY_INVALID" in error_msg:
                    return ValidationResult(status=ValidationStatus.INACTIVE, provider=self.provider)
                # Key exists but this API isn't enabled — still active
                return ValidationResult(status=ValidationStatus.ACTIVE, provider=self.provider, details={"note": "Key valid but API not enabled"})
            else:
                return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, details={"response_code": resp.status_code})
        except httpx.TimeoutException:
            return ValidationResult(status=ValidationStatus.UNKNOWN, provider=self.provider, error="Timeout")
        except Exception as e:
            return ValidationResult(status=ValidationStatus.VALIDATION_ERROR, provider=self.provider, error=str(e)[:200])
