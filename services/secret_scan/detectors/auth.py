# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Authentication and identity provider detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-OAUTH-001",
        title="OAuth Client Secret",
        secret_type="oauth_client_secret",
        severity="high",
        # Accepts the PHP/Ruby `=>` fat arrow as well as `=` and `:`.
        # AWS-002 used to carry a bare `client_secret` alternative and
        # was the only rule handling `'client_secret' => '...'`; when
        # that alternative was removed — it was branding every vendor's
        # OAuth secret as an AWS key — the arrow form stopped being
        # detected at all. A mislabel is bad, a miss is worse.
        # Quotes are optional too, for `client_secret: value` in YAML.
        pattern=r'(?:client_secret|CLIENT_SECRET|clientSecret)["\']?\s*(?:=>|[=:])\s*["\']?([A-Za-z0-9\-_]{20,})["\']?',
        keywords=["client_secret", "CLIENT_SECRET", "clientSecret"],
        confidence=0.70,
        description="OAuth 2.0 client secret. Grants ability to exchange authorization codes for tokens.",
        fix_hint="Rotate the client secret in your OAuth provider. Store in environment variables.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-JWT-001",
        title="Hardcoded JSON Web Token",
        secret_type="jwt",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)(?:[^A-Za-z0-9]|$)',
        keywords=["eyJ"],
        confidence=0.80,
        description="Hardcoded JWT. May contain claims and grant access to APIs.",
        fix_hint="JWTs should be generated at runtime, not hardcoded. Check expiration and revoke if needed.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-AUTH0-001",
        title="Auth0 Client Secret",
        secret_type="auth0_client_secret",
        severity="high",
        pattern=r'(?:auth0_client_secret|AUTH0_CLIENT_SECRET|AUTH0_SECRET)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{32,})["\']?',
        keywords=["auth0_client_secret", "AUTH0_CLIENT_SECRET", "AUTH0_SECRET"],
        confidence=0.85,
        description="Auth0 client secret for application authentication.",
        fix_hint="Rotate in Auth0 Dashboard → Applications → Settings.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-OKTA-001",
        title="Okta API Token",
        secret_type="okta_api_token",
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(00[A-Za-z0-9\-_]{40,})(?:[^A-Za-z0-9]|$)',
        keywords=["okta", "OKTA"],
        # WS6 2026-06-05: the ``00``-prefix + 40 chars matches any base64/hex
        # blob starting "00". The file-level ``keywords`` only requires "okta"
        # SOMEWHERE in the file; tighten to "okta" within the proximity window so
        # an unrelated 00-blob in an okta-mentioning file stops matching. A real
        # Okta token always sits near an okta domain / OKTA_ var / SDK ref.
        post_filter_keywords=["okta"],
        post_filter_window=300, post_filter_direction="both",
        confidence=0.60,
        description="Okta API token. Grants administrative access to identity management.",
        fix_hint="Revoke at Okta Admin → Security → API → Tokens.",
    ),
]
