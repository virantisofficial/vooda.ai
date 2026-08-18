# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Generic secret detectors for common patterns."""

from services.secret_scan.detectors.base import SecretRule


# Code-side `surface_excluded` for generic patterns: prevents the
# strict / quoted / code-tuned variants below from also firing on
# collaboration-tool content where their FP rate would be wrong
# AND a purpose-built variant in `generic_collab.py` already
# handles those surfaces. Reverted 2026-05-03 from the earlier
# confidence_by_context approach — separate rules per surface
# turned out cleaner than juggling per-context confidences on a
# single pattern.
_CODE_EXCLUDE_COLLAB = ["message", "page", "comment"]


RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-GEN-001",
        title="Generic API Key Assignment",
        secret_type="generic_api_key",
        severity="high",
        pattern=r"""(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-_+/=]{16,})['\"]?""",
        keywords=["api_key", "api-key", "apikey", "api_secret", "api-secret"],
        confidence=0.70,
        surface_excluded=_CODE_EXCLUDE_COLLAB,
        description="Generic API key detected via variable name pattern.",
        fix_hint="Move to environment variables or a secret manager.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GEN-002",
        title="Generic Secret Assignment",
        secret_type="generic_secret",
        severity="high",
        pattern=r"""(?:secret[_-]?key|secret_token|app[_-]?secret|signing[_-]?key|encryption[_-]?key)\s*[=:]\s*['\"]([A-Za-z0-9\-_+/=]{16,})['\"]""",
        keywords=["secret_key", "secret-key", "secret_token", "app_secret", "signing_key", "encryption_key"],
        confidence=0.75,
        surface_excluded=_CODE_EXCLUDE_COLLAB,
        description="Generic secret or signing key detected via variable name pattern.",
        fix_hint="Move to environment variables or a secret manager.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GEN-003",
        title="Hardcoded Password",
        secret_type="generic_password",
        severity="high",
        # Negative lookahead `(?!['\"])` removed as REDUNDANT (Option
        # B-1b manual rewrite, 2026-05-24).  The lookahead was meant
        # to ensure the first captured character wasn't a quote, but
        # the immediately-following character class `[^\s'\"]` already
        # excludes quotes.  So the assertion provably can never fail
        # — `\"` (the literal we just consumed) is followed by some
        # char from `[^\s'\"]`, which by construction is not a quote.
        # Dropping the lookahead moves this rule to the re2 fast
        # path without changing detection semantics.
        pattern=r"""(?:password|passwd|pwd|pass)\s*[=:]\s*['\"]([^\s'\"]{8,})['\"]""",
        keywords=["password", "passwd", "pwd"],
        # Calibrated 2026-04-25 from gold-validated production data:
        # 13/59 TP (22%) across 8 corpora — generic regex match on
        # any `password = "..."` literal includes a lot of test
        # scaffolding and example values. Lower confidence pushes the
        # finding into AI/human review rather than auto-treatment.
        # Original: 0.65.
        confidence=0.30,
        surface_excluded=_CODE_EXCLUDE_COLLAB,
        description="Hardcoded password detected.",
        fix_hint="Never hardcode passwords. Use environment variables, secret managers, or credential vaults.",
    ),
    SecretRule(
        # Default/weak credentials are SPECIFICALLY the most dangerous
        # passwords to flag — they almost always mean "we never
        # changed the default". GEN-003's `{8,}` floor explicitly
        # excludes them (admin/root/1234 are < 8 chars). This rule
        # complements GEN-003 by catching short, well-known weak
        # passwords from a curated allow-list. Surfaced after real
        # Jira TRUF-5 detection miss on `password = "admin"` —
        # 2026-04-30. Severity CRITICAL (default credentials = full
        # access if it's a real config).
        rule_id="VOODA-SEC-GEN-003-WEAK",
        title="Default / Weak Credential",
        secret_type="weak_password",
        severity="critical",
        # Tier B 2026-06-08: the key alternation used to include
        # `user(?:name)?|login`, which made the rule fire on default
        # USERNAMES (`username="kafkaadmin"`, `user: root`, `login: guest`).
        # A default username is not a credential leak — only a default
        # PASSWORD is — so those were the #1 FP source: value-level ground
        # truth over the 100-repo benchmark showed 1,610 of 2,041 FP (and the
        # 113 user/login "TP", which on inspection are usernames / doc comments
        # (`# password: admin`) / variable references, NOT secrets) came from
        # the user/login branch. Gating to the password-family keys aligns the
        # rule with its actual purpose (catch default PASSWORDS) and is
        # recall-safe: a real default password (`password = "admin"`) still
        # fires. Pinned by test_tier_b_gen003weak_key_gate.py.
        pattern=(
            r"""(?i)(?:password|passwd|pwd|pass)"""
            r"""\s*[=:]\s*['\"]?"""
            r"""(admin|administrator|root|toor|guest|default|"""
            r"""password|passw0rd|p@ssword|p@ssw0rd|"""
            r"""1234|12345|123456|1234567|12345678|"""
            r"""qwerty|letmein|welcome|changeme|temp|"""
            r"""abc123|secret)"""
            # Require a NON-code terminator after the weak value (closing quote,
            # whitespace, ; , ) ] } or end-of-line) so the rule fires on a real
            # literal (`password = "admin"`, `PWD=admin`) but NOT on Rust/code
            # idioms where the "value" is an identifier/call — `config.password
            # = Default::default()` / `password = password.clone()` — the #1 FP
            # on Rust repos. re2-safe (no lookahead); recall-safe (quoted AND
            # bare env-style literals still match).
            r"""(?:['\"]|[\s;,)\]}]|$)"""
        ),
        keywords=["password", "passwd", "pwd", "pass"],
        # Confidence 0.70 = "real signal, route through AI/human triage
        # rather than auto-treat". The whitelist + mandatory `[=:]`
        # connector make this materially more precise than the generic
        # GEN-003 regex, but we have not yet measured FP rate on
        # collaboration-tool prose ("comment that says `# user: admin
        # owns the cron`" being the canonical worry case). Bumping
        # past 0.70 should wait for that calibration.
        #
        # 2026-05-03 update: surface_targeting / surface_excluded
        # shipped on SecretRule (services/secret_scan/detectors/base.py).
        # GEN-003 (the quoted-only code variant) is now suppressed
        # on collaboration content via surface_excluded; a separate
        # GEN-003-COLLAB in detectors/generic_collab.py handles
        # message / page / comment surfaces with a relaxed regex.
        # WEAK still bridges the SHORT canonical bad password gap
        # both rules have (their length floors exclude admin/1234).
        confidence=0.70,
        description=(
            "A canonical weak / default credential (admin, root, 1234, "
            "etc.) appears next to a credential-shaped variable name. "
            "Default credentials are the #1 cause of breach in "
            "infrastructure misconfigurations."
        ),
        fix_hint=(
            "Rotate to a strong randomly-generated password and store "
            "it in a secret manager (Vault, AWS Secrets Manager, etc.). "
            "Default credentials must never reach production."
        ),
    ),
    SecretRule(
        rule_id="VOODA-SEC-GEN-004",
        title="Bearer Token (Hardcoded)",
        secret_type="bearer_token",
        severity="high",
        pattern=r"""['\"]Bearer\s+([A-Za-z0-9\-_.~+/]{20,})['\"]""",
        keywords=["Bearer"],
        confidence=0.80,
        description="Hardcoded Bearer authentication token in source code.",
        fix_hint="Tokens should be loaded from environment or fetched at runtime via OAuth flow.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GEN-005",
        title="Basic Auth (Hardcoded)",
        secret_type="basic_auth",
        severity="high",
        pattern=r"""['\"]Basic\s+([A-Za-z0-9+/=]{20,})['\"]""",
        keywords=["Basic"],
        confidence=0.80,
        description="Hardcoded Basic authentication credentials (base64-encoded username:password).",
        fix_hint="Use credential managers or environment variables for HTTP Basic auth.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GEN-006",
        title="Generic Connection String",
        secret_type="generic_connection_string",
        severity="high",
        pattern=r'[a-z]+://[^:\s]+:[^@\s]+@[^\s/]+',
        keywords=["://"],
        # Calibrated 2026-04-25: 1/33 TP (3%) on gold-validated data —
        # the regex matches any URL with embedded auth (`scheme://u:p@h`),
        # which is overwhelmingly test fixtures and documentation
        # examples (`http://test:test@localhost`, etc). Original: 0.75.
        confidence=0.30,
        surface_excluded=_CODE_EXCLUDE_COLLAB,
        description="Connection string with embedded credentials detected.",
        fix_hint="Use environment variables for connection strings. Separate credentials from URLs.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GEN-007",
        title="Private Key (Generic PEM)",
        secret_type="generic_private_key",
        severity="critical",
        pattern=r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----',
        keywords=["BEGIN", "PRIVATE KEY"],
        confidence=0.90,
        description="Generic private key in PEM format detected.",
        fix_hint="Remove private keys from source code. Use a key management service or vault.",
        multiline=True,
    ),
    SecretRule(
        rule_id="VOODA-SEC-GEN-008",
        title="Authorization Header Token",
        secret_type="auth_header_token",
        severity="high",
        pattern=r"""(?:authorization|Authorization|AUTHORIZATION)\s*[=:]\s*['\"](?:Bearer|Token|Basic)\s+([A-Za-z0-9\-_.~+/=]{20,})['\"]""",
        keywords=["authorization", "Authorization", "AUTHORIZATION"],
        confidence=0.80,
        description="Hardcoded authorization header with embedded token.",
        fix_hint="Load authorization tokens from environment variables or credential store.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GEN-009",
        title="Generic API Key (Variable Assignment)",
        secret_type="generic_api_key_broad",
        severity="medium",
        # Calibrated 2026-04-25: 2/17 TP (12%) on gold-validated data.
        # Broad pattern matching any `access_token=...`-style assignment
        # picks up many test stubs and SDK example snippets. Confidence
        # lowered from 0.65 (kept in pattern below — search for confidence=).
        pattern=r"""(?:^|[\s;,{(])(?:access_token|auth_token|bearer_token|client_secret"""
                r"""|api_token|app_token|app_key|app_secret"""
                r"""|secret_key_base|master_key|service_key|service_token"""
                r"""|private_token|personal_token|oauth_token|oauth_secret"""
                r"""|consumer_key|consumer_secret"""
                r"""|access_key_secret|account_key)"""
                r"""\s*[=:]\s*['"]?([A-Za-z0-9\-_+/=.]{16,200})['"]?""",
        keywords=[
            "access_token", "auth_token", "bearer_token", "client_secret",
            "api_token", "app_token", "app_key", "app_secret",
            "secret_key_base", "master_key", "service_key", "service_token",
            "private_token", "personal_token", "oauth_token", "oauth_secret",
            "consumer_key", "consumer_secret", "access_key_secret", "account_key",
        ],
        confidence=0.30,
        description="Potential API key or secret detected via variable name pattern. Lower confidence — review recommended.",
        fix_hint="If this is a real credential, move it to environment variables or a secret manager.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-GEN-010",
        title="Token in Custom Auth Header",
        secret_type="auth_header_token_broad",
        severity="high",
        pattern=r"""['"]?(?:X-Api-Key|X-Auth-Token|X-Access-Token)['"]?\s*[=:]\s*['"]?([A-Za-z0-9\-_.~+/=]{20,})['"]?""",
        keywords=["X-Api-Key", "X-Auth-Token", "X-Access-Token"],
        confidence=0.75,
        description="Token value in custom HTTP authentication header (X-Api-Key, X-Auth-Token).",
        fix_hint="Never hardcode auth header values. Load from environment or credential store.",
    ),
    # VOODA-SEC-GEN-011 ─ password-reset / auth-link nonces
    #
    # Covers identifiers like ``ADMIN_PASSWORD_LINK = "375afe..."`` where
    # the existing config-key rule misses because the keyword
    # (``PASSWORD``) is followed by an additional suffix (``_LINK``,
    # ``_TOKEN``, etc.) rather than the assignment operator. These
    # nonces are functionally equivalent to the account's password for
    # the account they reset.
    #
    # Added 2026-04-19 after the WebGoat benchmark surfaced it as the
    # only genuine scan-precision gap vs Gitleaks.
    SecretRule(
        rule_id="VOODA-SEC-GEN-011",
        title="Hardcoded Password-Reset / Auth-Link Nonce",
        secret_type="password_reset_nonce",
        severity="high",
        pattern=(
            r"""(?:^|[\s;,{(])"""
            # identifier with a secret-relevant word in the middle plus
            # a ``_LINK`` / ``_TOKEN`` / ``_URL`` / ``_NONCE`` / ``_CODE`` / ``_HASH``
            # suffix. The leading ``ADMIN`` / ``USER`` / ``ACCOUNT`` / ``AUTH``
            # / ``RESET`` prefix keeps this from matching innocuous names.
            r"""(?:ADMIN|USER|ACCOUNT|AUTH|RESET)_?"""
            r"""(?:PASSWORD|RESET|TOKEN|SECRET|AUTH|ACCESS)_?"""
            r"""(?:LINK|NONCE|URL|CODE|HASH|KEY|TOKEN)"""
            r"""\s*[=:]\s*"""
            r"""["']?"""
            # value: hex or general alnum — ≥16 chars to avoid trivial tokens.
            r"""([A-Fa-f0-9]{16,128}|[A-Za-z0-9_\-+/=]{20,200})"""
            r"""["']?"""
        ),
        keywords=[
            "PASSWORD_LINK", "PASSWORD_URL", "PASSWORD_NONCE",
            "PASSWORD_TOKEN", "PASSWORD_HASH", "PASSWORD_CODE",
            "RESET_TOKEN", "RESET_LINK", "RESET_URL", "RESET_NONCE",
            "AUTH_TOKEN_URL", "ACCESS_TOKEN_URL",
            "ADMIN_PASSWORD", "USER_PASSWORD", "ACCOUNT_RESET",
        ],
        confidence=0.70,
        description=(
            "Hardcoded nonce used in password-reset or auth-link flows. "
            "Compromise is equivalent to stealing the account's password "
            "for the account the nonce resets."
        ),
        fix_hint=(
            "Generate these nonces at runtime with a cryptographically "
            "random source (e.g. UUID4, secrets.token_urlsafe). Never "
            "commit a fixed value to source control."
        ),
    ),
]
