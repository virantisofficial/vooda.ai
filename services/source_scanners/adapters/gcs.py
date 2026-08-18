# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Google Cloud Storage source adapter — scans objects in GCS buckets
for embedded secrets.

Auth model: **HMAC keys (S3-compatible)**, not service-account JSON.
GCS exposes an S3-compatible XML API under ``storage.googleapis.com``,
and the canonical auth path for that surface is HMAC keys generated
at console.cloud.google.com/storage/settings → Interoperability.  Two
strings (access_key_id + secret_access_key), no JSON file, no OAuth
client setup — same shape and risk profile as AWS S3 credentials.

This is the right auth choice for Vooda because:

  - It works on every GCP organization, including the security-mature
    ones that enforce ``iam.disableServiceAccountKeyCreation`` (GCS
    HMAC keys are not service-account JSON keys; the org policy
    doesn't apply).
  - It's the auth path GCP officially documents for S3-compatible
    tooling, so customers using Terraform / boto3 against GCS
    already know how to generate these keys.
  - It uses the same boto3 client we already depend on for AWS S3 —
    no new SDK, no new code paths to maintain.

Service-account JSON keys are deliberately NOT used here, mirroring
the decision to remove them from Workspace integrations.  The shape
is identical at scan time (boto3 against an S3 endpoint), so this
adapter is ~95% the same as the AWS S3 adapter — we just point
``endpoint_url`` at GCS, normalize the region to "auto" (GCS doesn't
require a regional endpoint), and adjust the deep-link URL to point
at the GCP Cloud Console rather than the AWS Console.
"""

from typing import AsyncIterator

from services.integration_errors.classifiers import classify_sdk_error
from services.source_scanners.base import SourceAdapter, ScanableContent
from services.source_scanners.file_routing import content_type_for_path


# Shared with the S3 adapter — same heuristic for "is this a text file".
TEXT_EXTENSIONS = {
    ".json", ".yaml", ".yml", ".env", ".conf", ".ini", ".toml", ".xml", ".properties", ".cfg",
    ".txt", ".md", ".sh", ".bash", ".py", ".js", ".ts", ".rb", ".go", ".java", ".tf", ".hcl",
    ".dockerfile", ".csv", ".log",
}

# GCS's S3-compatible XML API endpoint.  Same hostname for every
# region — GCS does not require a regional endpoint suffix (the
# bucket's actual region is determined server-side from the bucket
# metadata).  This is documented at
# cloud.google.com/storage/docs/aws-simple-migration.
GCS_S3_ENDPOINT = "https://storage.googleapis.com"


class GCSSourceAdapter(SourceAdapter):
    source_type = "gcs"

    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
        bucket_name: str,
        prefix: str = "",
        file_extensions: str = "",
        max_object_size_mb: int = 10,
    ):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.bucket_name = bucket_name
        self.prefix = prefix
        self.ext_filter = (
            set(e.strip() for e in file_extensions.split(",") if e.strip())
            if file_extensions
            else TEXT_EXTENSIONS
        )
        self.max_size = max_object_size_mb * 1_000_000
        self._updated_sync_state: dict = {}

    def _boto_client(self):
        """Build a boto3 S3 client pointed at GCS's S3-compatible endpoint.

        Region must be set to something (boto3 requires it for the
        signing flow), but the actual region doesn't matter for GCS —
        the bucket's region is resolved server-side.  ``us-east1`` is
        a safe default that always exists.
        """
        import boto3
        return boto3.client(
            "s3",
            endpoint_url=GCS_S3_ENDPOINT,
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key,
            region_name="us-east1",
        )

    async def test_connection(self) -> dict:
        """Probe via ``head_bucket`` — single round-trip, validates both
        the HMAC credentials and bucket access.

        boto3 raises ClientError for bad creds / missing bucket /
        access denied; the SDK classifier routes these to s3.* error
        codes (the codes are S3-protocol errors, which GCS speaks).
        """
        ctx = {
            "adapter": "gcs",
            "bucket": self.bucket_name,
        }
        try:
            client = self._boto_client()
            client.head_bucket(Bucket=self.bucket_name)
            return {"status": "success", "message": f"Connected to gs://{self.bucket_name}"}
        except Exception as exc:
            err = classify_sdk_error(exc, provider="s3", context=ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        """Walk every object in the configured bucket, yield text-like
        ones as ScanableContent.

        Same paging + incremental cursor pattern as the AWS S3 adapter
        — GCS's S3-compatible API supports list_objects_v2 with the
        same shape, so we get pagination and modified-since filtering
        for free.
        """
        self._updated_sync_state = dict(sync_state)
        last_modified_after = sync_state.get("last_modified_after", "1970-01-01T00:00:00Z")

        client = self._boto_client()
        paginator = client.get_paginator("list_objects_v2")
        params = {"Bucket": self.bucket_name, "MaxKeys": 1000}
        if self.prefix:
            params["Prefix"] = self.prefix

        latest_modified = last_modified_after

        for page in paginator.paginate(**params):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                modified = obj["LastModified"].isoformat()
                size = obj.get("Size", 0)

                if modified <= last_modified_after:
                    continue

                ext = "." + key.rsplit(".", 1)[-1] if "." in key else ""
                if ext.lower() not in self.ext_filter:
                    continue

                if size > self.max_size:
                    continue

                try:
                    response = client.get_object(Bucket=self.bucket_name, Key=key)
                    content = response["Body"].read().decode("utf-8", errors="replace")[:500_000]
                except Exception:
                    continue

                if content.strip():
                    yield ScanableContent(
                        source_locator=f"gs://{self.bucket_name}/{key}",
                        content=content,
                        # Same routing as S3: prose-like extensions land
                        # at "page" so the COLLAB ruleset fires on free
                        # text, structured files stay at "file" for the
                        # strict CODE ruleset.
                        content_type=content_type_for_path(key, default="file"),
                        timestamp=obj["LastModified"],
                        deep_link_url=(
                            f"https://console.cloud.google.com/storage/browser/"
                            f"{self.bucket_name}/{key};tab=live_object"
                        ),
                        metadata={"bucket": self.bucket_name, "key": key, "size": size},
                    )

                if modified > latest_modified:
                    latest_modified = modified

        self._updated_sync_state["last_modified_after"] = latest_modified

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
