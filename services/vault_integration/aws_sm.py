# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""AWS Secrets Manager integration."""

import structlog
from typing import Optional

from services.vault_integration.base import VaultProviderBase, VaultSecret

logger = structlog.get_logger()


class AWSSecretsManagerProvider(VaultProviderBase):
    provider = "aws_secrets_manager"

    def __init__(self, config: dict):
        self.region = config.get("region", "us-east-1")
        self.access_key_id = config.get("access_key_id", "")
        self.secret_access_key = config.get("secret_access_key", "")
        # Optional endpoint override. Real deployments need it for VPC
        # interface endpoints, FIPS endpoints and GovCloud, where the
        # default public hostname is either unreachable or not the one
        # policy allows. It is also what makes this provider testable
        # against an emulator rather than a live AWS account.
        self.endpoint_url = (config.get("endpoint_url") or "").strip() or None

    def _get_client(self):
        import boto3

        kwargs: dict = {"region_name": self.region}
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url
        # Blank keys mean "use the ambient credential chain" — instance
        # role, IRSA, or environment. Passing empty strings instead
        # makes botocore sign with an empty key and fail, so only set
        # them when both are actually present.
        if self.access_key_id and self.secret_access_key:
            kwargs["aws_access_key_id"] = self.access_key_id
            kwargs["aws_secret_access_key"] = self.secret_access_key
        return boto3.client("secretsmanager", **kwargs)

    async def test_connection(self) -> bool:
        try:
            client = self._get_client()
            client.list_secrets(MaxResults=1)
            return True
        except Exception as e:
            logger.error("aws_sm_connection_failed", error=str(e)[:200])
            return False

    async def list_secrets(self, prefix: str = "") -> list[VaultSecret]:
        secrets = []
        try:
            client = self._get_client()
            paginator = client.get_paginator("list_secrets")
            filters = []
            if prefix:
                filters.append({"Key": "name", "Values": [prefix]})

            for page in paginator.paginate(Filters=filters if filters else []):
                for s in page.get("SecretList", []):
                    secrets.append(VaultSecret(
                        path=s["Name"],
                        name=s["Name"].split("/")[-1],
                        created_at=s.get("CreatedDate"),
                        updated_at=s.get("LastChangedDate"),
                        metadata={"arn": s.get("ARN"), "rotation_enabled": s.get("RotationEnabled", False)},
                    ))
        except Exception as e:
            logger.error("aws_sm_list_failed", error=str(e)[:200])
        return secrets

    async def get_secret_metadata(self, path: str) -> Optional[dict]:
        try:
            client = self._get_client()
            resp = client.describe_secret(SecretId=path)
            return {
                "arn": resp.get("ARN"),
                "name": resp.get("Name"),
                "rotation_enabled": resp.get("RotationEnabled", False),
                "rotation_lambda": resp.get("RotationLambdaARN"),
                "last_rotated": str(resp.get("LastRotatedDate", "")),
                "last_accessed": str(resp.get("LastAccessedDate", "")),
                "versions": list(resp.get("VersionIdsToStages", {}).keys()),
            }
        except Exception as e:
            logger.error("aws_sm_metadata_failed", error=str(e)[:200])
        return None

    async def rotate_secret(self, path: str, new_value: str) -> bool:
        try:
            client = self._get_client()
            client.put_secret_value(SecretId=path, SecretString=new_value)
            return True
        except Exception as e:
            logger.error("aws_sm_rotate_failed", error=str(e)[:200])
            return False
