# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""AWS credential validator — uses STS GetCallerIdentity."""

import httpx
import hashlib
import hmac
import datetime

from services.secret_validation.engine import BaseValidator, ValidationResult, ValidationStatus


class AWSAccessKeyValidator(BaseValidator):
    provider = "aws"
    timeout = 5

    async def validate(self, secret_value: str, context: dict = None) -> ValidationResult:
        context = context or {}
        access_key = context.get("access_key_id") or secret_value
        secret_key = context.get("secret_access_key") or secret_value

        # Need both access key and secret key for AWS validation
        if not access_key.startswith("AKIA"):
            # This is probably a secret key, need the access key from context
            if not context.get("access_key_id"):
                return ValidationResult(
                    status=ValidationStatus.UNKNOWN,
                    provider=self.provider,
                    error="AWS validation requires both access key ID and secret key",
                )

        try:
            # Sign and call STS GetCallerIdentity
            now = datetime.datetime.utcnow()
            date_stamp = now.strftime("%Y%m%d")
            amz_date = now.strftime("%Y%m%dT%H%M%SZ")
            region = "us-east-1"
            service = "sts"
            host = "sts.amazonaws.com"

            # AWS Signature V4
            canonical_uri = "/"
            canonical_querystring = "Action=GetCallerIdentity&Version=2011-06-15"
            canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
            signed_headers = "host;x-amz-date"
            payload_hash = hashlib.sha256(b"").hexdigest()
            canonical_request = f"GET\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

            algorithm = "AWS4-HMAC-SHA256"
            credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
            string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"

            def _sign(key, msg):
                return hmac.new(key, msg.encode(), hashlib.sha256).digest()

            signing_key = _sign(
                _sign(
                    _sign(
                        _sign(f"AWS4{secret_key}".encode(), date_stamp),
                        region,
                    ),
                    service,
                ),
                "aws4_request",
            )
            signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
            authorization = f"{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"https://{host}/?{canonical_querystring}",
                    headers={
                        "Host": host,
                        "X-Amz-Date": amz_date,
                        "Authorization": authorization,
                    },
                )

            if resp.status_code == 200:
                return ValidationResult(
                    status=ValidationStatus.ACTIVE,
                    provider=self.provider,
                    details={"response_code": 200, "note": "Key is active"},
                )
            elif resp.status_code in (403, 401):
                return ValidationResult(
                    status=ValidationStatus.INACTIVE,
                    provider=self.provider,
                    details={"response_code": resp.status_code},
                )
            else:
                return ValidationResult(
                    status=ValidationStatus.UNKNOWN,
                    provider=self.provider,
                    details={"response_code": resp.status_code},
                )

        except httpx.TimeoutException:
            return ValidationResult(
                status=ValidationStatus.UNKNOWN,
                provider=self.provider,
                error="AWS STS request timed out",
            )
        except Exception as e:
            return ValidationResult(
                status=ValidationStatus.VALIDATION_ERROR,
                provider=self.provider,
                error=str(e)[:200],
            )
