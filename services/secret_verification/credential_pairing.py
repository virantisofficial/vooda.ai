# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""
Credential Pairing Module — Stage 3.

Many providers issue credentials as a pair (or triple) that must be
combined for verification:

    AWS:        access_key_id + secret_access_key
    Azure AD:   client_id + client_secret + tenant_id
    GCP SA:     JSON key file (has private_key, client_email, project_id)
    Snowflake:  account + user + password
    PayPal:     client_id + client_secret
    MongoDB Atlas: public_key + private_key + org_id
    Stripe Connect: secret_key + account_id
    Twilio:     account_sid + auth_token
    BrowserStack: username + access_key
    Trello:     api_key + user_token
    Mailjet:    public_key + private_key
    Jira:       email + api_token + domain

This module finds credential pairs within a repository's scan findings
by looking for complementary secret types in proximity (typically same
file, within N lines of each other).

Design:
  - Non-invasive: runs at verification time, not at scan time.
  - Reuses existing detection rules — no new scanner rules needed.
  - Proximity-based: looks within the same file, within ±30 lines.
  - Returns enriched source_metadata with both values populated so the
    dispatcher can call the multi-cred verifier.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class CredentialPair:
    """Describes a multi-credential verification target."""
    primary_secret_type: str           # e.g. "aws_access_key"
    partner_secret_types: list[str]    # e.g. ["aws_secret_key"]
    verifier_key: str                  # key in VERIFIERS dispatcher (e.g. "aws_paired")
    # Regex patterns to find partners directly in the primary's file if they
    # were missed by the scanner (e.g., a 40-char base64 AWS secret that has
    # too-low entropy to trigger its own rule).
    partner_inline_regex: dict[str, str] = None


# ── Pair Definitions ─────────────────────────────────────────


# Known pairs mapped by primary secret type
# Key format: (primary_provider, partner_roles_expected)
KNOWN_PAIRS: list[CredentialPair] = [
    CredentialPair(
        primary_secret_type="aws_access_key_id",
        partner_secret_types=["aws_secret_access_key", "aws_secret"],
        verifier_key="aws_paired",
        partner_inline_regex={
            # AWS secret keys are 40-char base64 — search for them near an AWS
            # access key ID on the same line range
            "aws_secret": r'(?i)(?:aws_?secret_?access_?key|aws_?secret|secret_?access_?key)[\s:="\']+([A-Za-z0-9/+=]{40})',
        },
    ),
    CredentialPair(
        primary_secret_type="twilio_account_sid",
        partner_secret_types=["twilio_auth_token"],
        verifier_key="twilio_paired",
        partner_inline_regex={
            "twilio_auth_token": r'(?i)(?:twilio_?auth_?token|twilio_?token|auth_?token)[\s:="\']+([A-Fa-f0-9]{32})',
        },
    ),
    CredentialPair(
        primary_secret_type="azure_client_id",
        partner_secret_types=["azure_client_secret", "azure_tenant_id"],
        verifier_key="azure_ad_paired",
        partner_inline_regex={
            "azure_client_secret": r'(?i)(?:client_?secret|azure_?client_?secret|AZURE_?CLIENT_?SECRET)[\s:="\']+([A-Za-z0-9_.~-]{34,80})',
            "azure_tenant_id": r'(?i)(?:tenant_?id|azure_?tenant_?id|AZURE_?TENANT_?ID)[\s:="\']+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
        },
    ),
    CredentialPair(
        primary_secret_type="paypal_client_id",
        partner_secret_types=["paypal_client_secret"],
        verifier_key="paypal_paired",
        partner_inline_regex={
            "paypal_client_secret": r'(?i)(?:paypal_?client_?secret|PAYPAL_?CLIENT_?SECRET)[\s:="\']+([A-Z0-9_-]{60,90})',
        },
    ),
    CredentialPair(
        primary_secret_type="mongodb_atlas_public_key",
        partner_secret_types=["mongodb_atlas_private_key"],
        verifier_key="mongodb_atlas_paired",
        partner_inline_regex={
            "mongodb_atlas_private_key": r'(?i)(?:mongo|atlas)_?(?:private|priv)_?(?:key|api_key)[\s:="\']+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
        },
    ),
    CredentialPair(
        primary_secret_type="mailjet_public_key",
        partner_secret_types=["mailjet_private_key"],
        verifier_key="mailjet_paired",
        partner_inline_regex={
            "mailjet_private_key": r'(?i)(?:mailjet_?(?:private|secret)_?key|MJ_APIKEY_PRIVATE)[\s:="\']+([a-f0-9]{32})',
        },
    ),
    CredentialPair(
        primary_secret_type="snowflake_account",
        partner_secret_types=["snowflake_user", "snowflake_password"],
        verifier_key="snowflake_paired",
        partner_inline_regex={
            "snowflake_user": r'(?i)(?:snowflake_?user|SNOWFLAKE_?USER)[\s:="\']+([A-Za-z0-9_]+)',
            "snowflake_password": r'(?i)(?:snowflake_?password|SNOWFLAKE_?PWD?)[\s:="\']+([^\s"\'\r\n]{8,64})',
        },
    ),
    CredentialPair(
        primary_secret_type="stripe_publishable_key",
        partner_secret_types=["stripe_secret_key", "stripe_account_id"],
        verifier_key="stripe_connect_paired",
        partner_inline_regex={
            "stripe_account_id": r'\b(acct_[A-Za-z0-9]{16,})\b',
        },
    ),
]

# ── Runtime Pairing Helpers ───────────────────────────────────


def _read_file_safely(file_path: str, max_bytes: int = 200_000) -> str:
    """Read file content for pairing-regex search. Returns empty on any error."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return ""


def find_partner_credential(
    primary_secret_type: str,
    primary_file_path: str,
    primary_line: int,
    all_findings: list,
    repo_root: str = "",
    proximity_lines: int = 30,
) -> Optional[dict]:
    """
    Given a primary credential (e.g. AWS access key), find its partner(s)
    in the same file. Searches in two places:
      1. Other NormalizedFindings in the same file with matching secret types.
      2. Direct regex scan of the file's content using partner_inline_regex,
         for partners that never triggered their own rule.

    Returns a dict like {"aws_secret": "wJalrXUtnFEMI..."} or None if no
    partner found.
    """
    # 1. Look up the pair spec
    pair_spec = None
    for p in KNOWN_PAIRS:
        if p.primary_secret_type == primary_secret_type:
            pair_spec = p
            break
    if pair_spec is None:
        return None

    partners: dict[str, str] = {}

    # 2. Try existing findings first — same file, within proximity, matching type
    for f in all_findings:
        if not f or f.file_path != primary_file_path:
            continue
        f_type = _get_secret_type(f)
        if f_type in pair_spec.partner_secret_types:
            # Proximity check
            line_delta = abs((f.line_start or 0) - (primary_line or 0))
            if line_delta <= proximity_lines:
                value = _get_raw_value(f)
                if value:
                    partners[f_type] = value

    # 3. For partners still missing, scan the file content directly
    still_missing = [pt for pt in pair_spec.partner_secret_types if pt not in partners]
    if still_missing and pair_spec.partner_inline_regex:
        full_path = _resolve_file_path(primary_file_path, repo_root)
        content = _read_file_safely(full_path)
        if content:
            # Bracket the search window around primary_line for file-proximity
            lines = content.split("\n")
            lo = max(0, (primary_line or 1) - proximity_lines - 1)
            hi = min(len(lines), (primary_line or 1) + proximity_lines)
            search_window = "\n".join(lines[lo:hi])
            for pt in still_missing:
                pattern = pair_spec.partner_inline_regex.get(pt)
                if not pattern:
                    continue
                m = re.search(pattern, search_window)
                if m:
                    # Group 1 is the value
                    partners[pt] = m.group(1)

    if partners:
        partners["_pair_key"] = pair_spec.verifier_key
        return partners
    return None


def _get_secret_type(finding) -> str:
    """Extract secret_type from a finding object or dict."""
    if hasattr(finding, "source_metadata") and finding.source_metadata:
        return (finding.source_metadata or {}).get("secret_type", "")
    if hasattr(finding, "raw_data") and finding.raw_data:
        return (finding.raw_data or {}).get("secret_type", "")
    if isinstance(finding, dict):
        return (finding.get("source_metadata") or finding.get("raw_data") or {}).get("secret_type", "")
    return ""


def _get_raw_value(finding) -> str:
    """Extract raw value from a finding's source_metadata."""
    for attr in ("source_metadata", "raw_data"):
        data = getattr(finding, attr, None) if not isinstance(finding, dict) else finding.get(attr)
        if data:
            v = data.get("_raw_value_for_verification") or data.get("_raw_value")
            if v:
                return v
    return ""


def _resolve_file_path(file_path: str, repo_root: str = "") -> str:
    """Turn a relative file_path into an absolute path for reading."""
    import os
    if os.path.isabs(file_path):
        return file_path
    if repo_root:
        return os.path.join(repo_root, file_path)
    return file_path


def enrich_source_metadata_with_pair(
    source_metadata: dict,
    partners: dict,
) -> dict:
    """
    Return a new dict combining the primary's source_metadata with the
    partner values (so the dispatcher lambda can read them via sm.get()).
    """
    enriched = dict(source_metadata or {})
    # Copy each partner role under a consistent key the verifier expects.
    # For example: partners = {"aws_secret_key": "xyz"} and the AWS lambda
    # expects sm.get("aws_secret_key"), so we just merge.
    for k, v in partners.items():
        if k.startswith("_"):
            continue
        enriched[k] = v
    enriched["_pair_key"] = partners.get("_pair_key")
    return enriched
