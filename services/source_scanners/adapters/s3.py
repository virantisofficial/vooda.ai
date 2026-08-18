# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""S3 source adapter — scans objects in S3 buckets for embedded secrets."""

from typing import AsyncIterator, Optional
from datetime import datetime, timezone

import httpx

from services.integration_errors.classifiers import classify_sdk_error
from services.source_scanners.base import SourceAdapter, ScanableContent
from services.source_scanners.file_routing import content_type_for_path


TEXT_EXTENSIONS = {".json", ".yaml", ".yml", ".env", ".conf", ".ini", ".toml", ".xml", ".properties", ".cfg",
                   ".txt", ".md", ".sh", ".bash", ".py", ".js", ".ts", ".rb", ".go", ".java", ".tf", ".hcl",
                   ".dockerfile", ".csv", ".log"}


class S3SourceAdapter(SourceAdapter):
    source_type = "s3"

    def __init__(self, access_key_id: str, secret_access_key: str, region: str,
                 bucket_name: str, prefix: str = "", file_extensions: str = "", max_object_size_mb: int = 10):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.region = region
        self.bucket_name = bucket_name
        self.prefix = prefix
        self.ext_filter = set(e.strip() for e in file_extensions.split(",") if e.strip()) if file_extensions else TEXT_EXTENSIONS
        self.max_size = max_object_size_mb * 1_000_000
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Probe via ``head_bucket`` — single round-trip, exercises both
        IAM and bucket existence.

        boto3 raises ClientError with a code attribute (NoSuchBucket /
        AccessDenied / InvalidAccessKeyId / SignatureDoesNotMatch) —
        the SDK classifier reads the message text to map to the right
        s3.* code with appropriate fix steps.
        """
        ctx = {
            "adapter": "s3",
            "bucket": self.bucket_name,
            "region": self.region,
        }
        try:
            import boto3
            s3 = boto3.client(
                "s3",
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=self.region,
            )
            s3.head_bucket(Bucket=self.bucket_name)
            return {"status": "success", "message": f"Connected to s3://{self.bucket_name}"}
        except Exception as exc:
            err = classify_sdk_error(exc, provider="s3", context=ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        import boto3
        self._updated_sync_state = dict(sync_state)
        last_modified_after = sync_state.get("last_modified_after", "1970-01-01T00:00:00Z")

        s3 = boto3.client("s3", aws_access_key_id=self.access_key_id,
                          aws_secret_access_key=self.secret_access_key, region_name=self.region)

        paginator = s3.get_paginator("list_objects_v2")
        params = {"Bucket": self.bucket_name, "MaxKeys": 1000}
        if self.prefix:
            params["Prefix"] = self.prefix

        latest_modified = last_modified_after

        for page in paginator.paginate(**params):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                modified = obj["LastModified"].isoformat()
                size = obj.get("Size", 0)

                # Skip if not modified since last scan
                if modified <= last_modified_after:
                    continue

                # Skip non-text files
                ext = "." + key.rsplit(".", 1)[-1] if "." in key else ""
                if ext.lower() not in self.ext_filter:
                    continue

                # Skip oversized objects
                if size > self.max_size:
                    continue

                try:
                    response = s3.get_object(Bucket=self.bucket_name, Key=key)
                    content = response["Body"].read().decode("utf-8", errors="replace")[:500_000]
                except Exception:
                    continue

                if content.strip():
                    yield ScanableContent(
                        source_locator=f"s3://{self.bucket_name}/{key}",
                        content=content,
                        # Route prose extensions (.md/.txt/.rst/.csv/.log)
                        # to "page" so COLLAB rules fire on free-form
                        # content; structured files stay at "file" so the
                        # strict CODE rules handle them.
                        content_type=content_type_for_path(key, default="file"),
                        timestamp=obj["LastModified"],
                        deep_link_url=f"https://s3.console.aws.amazon.com/s3/object/{self.bucket_name}?prefix={key}",
                        metadata={"bucket": self.bucket_name, "key": key, "size": size},
                    )

                if modified > latest_modified:
                    latest_modified = modified

        self._updated_sync_state["last_modified_after"] = latest_modified

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
