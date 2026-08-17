# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""GCP secret detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-GCP-001",
        title="GCP API Key",
        secret_type="gcp_api_key",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(AIza[0-9A-Za-z\-_]{35})(?:[^A-Za-z0-9]|$)',
        keywords=["AIza"],
        confidence=0.95,
        description="Google Cloud Platform API key detected.",
        fix_hint="Restrict key scope in GCP Console → APIs & Services → Credentials. Use service accounts instead.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GCP-002",
        title="GCP Service Account Key",
        secret_type="gcp_service_account",
        severity="critical",
        pattern=r'"type"\s*:\s*"service_account"[\s\S]{0,500}"private_key"\s*:\s*"-----BEGIN',
        keywords=["service_account", "private_key"],
        confidence=0.98,
        description="GCP service account JSON key file detected. Grants full API access for the service account.",
        fix_hint="Delete key in GCP Console → IAM → Service Accounts. Use Workload Identity Federation.",
        multiline=True,
    ),
    SecretRule(
        rule_id="VOODA-SEC-GCP-003",
        title="GCP OAuth Client Secret",
        secret_type="gcp_oauth_secret",
        severity="high",
        # Anchored on something actually Google-specific. The previous
        # pattern matched a bare `client_secret = <24+ chars>`, which is
        # the OAuth2 field name every provider uses — so a MuleSoft,
        # Okta or Auth0 client secret was reported as a Google
        # credential, and at 0.70 it outranked the vendor-anchored rules
        # that had it right. Attribution is not cosmetic: it decides
        # which console the responder opens to rotate the thing.
        #
        # Both real shapes still match — an explicitly Google-named
        # variable, or Google's own GOCSPX- token format under any name.
        # Google-named variables only. The token format itself is
        # already covered by the GOCSPX- prefix rule in
        # trufflehog_port_v4, which matches regardless of variable name,
        # so nothing is lost by dropping the bare `client_secret` branch
        # here — and dropping it is the point.
        pattern=r'(?:GOOGLE_CLIENT_SECRET|google[_-]?client[_-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{24,})["\']?',
        keywords=["GOOGLE_CLIENT_SECRET", "GOCSPX-"],
        confidence=0.70,
        description="Google OAuth client secret detected.",
        fix_hint="Regenerate in GCP Console → APIs & Services → Credentials. Use OAuth flow server-side only.",
    ),
]
