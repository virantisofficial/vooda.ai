# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""R3 — classic credential-FILE detectors (Opus×Vooda benchmark recall gaps).

The 20-repo benchmark (leaky-repo) surfaced textbook credential files that no
rule covered. Each rule here is gated on a file-format-specific KEY NAME or
structure (not a bare value shape), so false-positive risk is minimal while the
canonical leak vectors are caught. All patterns are re2-compatible (no
lookahead / lookbehind / backreferences; bounded repetition only). The captured
group (group 1) is always the secret VALUE — the engine extracts group(1).

Deliberately NOT included: Rails `config/master.key` (a bare 32-hex blob) — a
filename-only gate would need engine-side path awareness and a bare-hex value is
otherwise a real FP risk; tracked separately.
"""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    # ── AWS shared-credentials INI (~/.aws/credentials) ──────────────
    # `[default]\naws_access_key_id = …\naws_secret_access_key = <40 b64>`.
    # The AKIA access-key-id is already caught by AWS-001, but the *secret*
    # access key (the high-value half) is missed when the id isn't AKIA-shaped
    # (leaky-repo ships non-AKIA fakes). Key name `aws_secret_access_key` is
    # AWS-specific → near-zero FP. Value: 20-50 base64 chars (canonical 40).
    SecretRule(
        rule_id="VOODA-SEC-AWS-CREDS-INI-001",
        title="AWS Secret Access Key (credentials file)",
        secret_type="aws_secret_access_key",
        severity="critical",
        pattern=r"aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+]{20,50})",
        keywords=["aws_secret_access_key"],
        confidence=0.93,
        description="AWS secret access key assigned in an INI/credentials file.",
        fix_hint="Rotate the key in IAM; store credentials in a secret manager, not ~/.aws/credentials in a repo.",
        cwe="CWE-798",
    ),

    # ── .npmrc registry auth (token + basic-auth) ────────────────────
    # `//registry.npmjs.org/:_authToken=<token>` and `_auth=<base64 user:pass>`.
    # `_authToken`/`_auth` are npm-registry-specific keys. Value 8+ non-space
    # (UUID / base64 / hex tokens). `_auth = true`-style booleans are < 8 chars
    # and excluded; `always-auth=` does not contain the `_auth` key literal.
    SecretRule(
        rule_id="VOODA-SEC-NPMRC-TOKEN-001",
        title="npm Registry Auth Token (.npmrc)",
        secret_type="npm_token",
        severity="high",
        # case_sensitive: npm config keys are lowercase, so this stops the rule
        # FP-ing on SCREAMING_SNAKE code constants like `BASIC_AUTH` / `X_PASSWORD`
        # (caught 6 FP on WebGoat's BasicAuthentication.java in the benchmark
        # re-run). `_password` dropped — too generic; `_authToken` / `_auth`
        # (base64 basic-auth) are npm-specific enough.
        pattern=r"(?:_authToken|_auth)\s*=\s*['\"]?([A-Za-z0-9+/=._~-]{8,})",
        keywords=["_authtoken", "_auth"],
        case_sensitive=True,
        confidence=0.9,
        description="npm registry auth token or basic-auth blob in an .npmrc file.",
        fix_hint="Revoke the token (npm token revoke); use a CI secret / OIDC instead of committing .npmrc.",
        cwe="CWE-798",
    ),

    # ── .netrc machine/login/password ────────────────────────────────
    # `machine HOST [login USER] [account A] password PASS` (one-line or
    # multi-line). Bounded {0,80} gap keeps it re2-safe and allows the optional
    # login/account tokens between `machine` and `password`.
    SecretRule(
        rule_id="VOODA-SEC-NETRC-CREDS-001",
        title="Credentials in .netrc",
        secret_type="netrc_password",
        severity="high",
        # Strict netrc grammar: machine HOST, then only login/account/port/macdef
        # stanzas, then password VALUE. Forbids arbitrary prose between machine
        # and password (e.g. "machine foo.com ... the password manager"), so the
        # rule only fires on real netrc structure.
        pattern=r"machine\s+[A-Za-z0-9.-]+(?:\s+(?:login|account|port|macdef)\s+\S+)*\s+password\s+(\S{4,})",
        keywords=["machine"],
        confidence=0.85,
        description="Password stored in a .netrc machine/login/password stanza.",
        fix_hint="Remove credentials from .netrc; use a credential helper or env vars.",
        cwe="CWE-798",
    ),

    # ── wp-config.php sensitive define() constants ───────────────────
    # `define( 'DB_PASSWORD', 'value' );` and the auth keys/salts. Constant
    # name is in a WordPress-specific allowlist → low FP. Value 6+ chars; the
    # default `put your unique phrase here` placeholders are caught by the
    # engine's placeholder gate.
    SecretRule(
        rule_id="VOODA-SEC-WPCONFIG-SECRET-001",
        title="WordPress wp-config.php Secret",
        secret_type="wordpress_config_secret",
        severity="high",
        pattern=(r"define\(\s*['\"](?:DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|"
                 r"NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['\"]\s*,"
                 r"\s*['\"]([^'\"\s]{4,})['\"]"),
        keywords=["db_password", "auth_key", "nonce_key", "auth_salt", "logged_in_key"],
        confidence=0.9,
        description="Hardcoded WordPress DB password or auth key/salt in wp-config.php.",
        fix_hint="Move secrets to environment variables / a secret manager; regenerate the WP salts.",
        cwe="CWE-798",
    ),
]
