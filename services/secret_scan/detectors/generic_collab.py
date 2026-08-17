# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Generic detectors targeted at collaboration-tool content
(Slack messages, Confluence pages, Jira descriptions, Notion pages,
GitHub Issue / PR bodies, ServiceNow tickets, etc.) and at code
*comments* — both surfaces are free-form prose and follow the same
relaxed-quoting trade-off.

Why a separate module from `generic.py`
- Collaboration content is free-form prose with copy-pasted snippets.
  People type `password=hdgshui@sn12` directly without quotes; they
  don't write `password = "hdgshui@sn12"` like they would in code.
- The strict / quoted regex in generic.py catches code-shaped writes
  but misses the bulk of real disclosures in collab content. We
  proved this in the Slack E2E (2026-05-03) — `hdgshui@sn12` was a
  real disclosure and we missed it entirely.
- Inverting the trade-off here: relaxed value matching, paid for by
  a stricter value SHAPE filter and a hardened placeholder filter
  so the FP rate stays manageable.

Each rule is targeted via `surface_targeting` to the four free-form
content_type values (`message`, `page`, `comment`, plus prose-shaped
file extensions routed to `page` by file_routing.content_type_for_path).
The companion code rules in generic.py carry `surface_excluded` for
the same set so the two cohorts never overlap. A finding fires from
EXACTLY ONE of the two rules per match.

Confidence is set fresh against the collab noise floor, not via
context overrides on the code rule. Reverted from the earlier
confidence_by_context approach — separate rules per surface turned
out cleaner than juggling per-context confidences.
"""
from __future__ import annotations

from services.secret_scan.detectors.base import SecretRule


# Collaboration content types — see services/source_scanners/base.py
# for the canonical list. The three below are the only ones where
# the relaxed-quoting trade-off makes sense:
#   message — Slack / Teams / Mattermost chat
#   page    — Jira description, Confluence / Notion page,
#             Salesforce Case description, GH Issue body, .md/.txt
#             files in cloud storage (via file_routing helper), etc.
#   comment — issue / PR / page comment threads AND code comments
#             extracted by engine.scan_file's comment-aware phase.
#
# The `file` content_type (S3 .env, OneDrive .yaml, Box .json) is
# DELIBERATELY NOT in this list — structured files use the code-side
# regexes. Per-extension routing in file adapters maps prose
# extensions (.md/.txt/.rst) to `page` so the COLLAB rules still fire.
_COLLAB_SURFACES = ["message", "page", "comment"]


# Strict value SHAPE for collab patterns. Allows the typical chars
# in a real password / token / api key, blocks the typical chars in
# a code expression / format string / template variable. Picked to
# reject the most common FP shapes:
#   - whitespace anywhere → would break prose match
#   - `<`, `>` → blocks `<your-token>` style placeholders
#   - `${`, `%` → blocks template variables
#   - `(`, `)` → blocks function calls like `password=getenv("X")`
#   - `;`, `,` → blocks list/dict literals
#   - `:` is OK (URLs have it); `=` is OK (some tokens contain it)
_VALUE_SHAPE_8 = r"[A-Za-z0-9!@#$%^&*+\-_./?=]{8,}"
_VALUE_SHAPE_10 = r"[A-Za-z0-9!@#$%^&*+\-_./?=]{10,}"
_VALUE_SHAPE_16 = r"[A-Za-z0-9!@#$%^&*+\-_./?=]{16,}"
_VALUE_SHAPE_20 = r"[A-Za-z0-9!@#$%^&*+\-_./?=]{20,}"


RULES: list[SecretRule] = [

    SecretRule(
        # Hardcoded password — collab variant. Quotes are optional;
        # value shape is strict; placeholder filter catches the
        # `password=YOUR_VALUE_HERE` documentation pattern.
        # Keyword list expanded 2026-05-03 to include passphrase /
        # passcode and the common DB-prefixed variants people type
        # in chat ("the prod db_password is...").
        rule_id="VOODA-SEC-GEN-003-COLLAB",
        title="Hardcoded Password (collab)",
        secret_type="generic_password",
        severity="high",
        pattern=(
            r"""(?:password|passwd|pwd|pass|passphrase|passcode"""
            r"""|db[_-]?pass(?:word|wd)?|admin[_-]?pass(?:word|wd)?"""
            r"""|root[_-]?pass(?:word|wd)?|user[_-]?pass(?:word|wd)?"""
            r""")\s*[=:]\s*['\"]?"""
            + r"(" + _VALUE_SHAPE_8 + r")"
            + r"""['\"]?"""
        ),
        keywords=["password", "passwd", "pwd", "passphrase", "passcode",
                  "db_password", "db-password", "admin_password", "admin-password",
                  "root_password", "user_password"],
        # 0.65 = above the surface-it threshold but below the
        # quoted-rule's confidence (0.70-class) — the cost is the
        # higher noise floor of free-form text. AI triage downstream
        # filters most genuine FPs (the doc-style placeholders the
        # value-shape filter doesn't catch).
        confidence=0.65,
        surface_targeting=_COLLAB_SURFACES,
        description=(
            "Hardcoded password in collaboration-tool content (Slack "
            "message, Confluence page, Jira description, etc.) or in a "
            "code comment. Free-form text where the value isn't quoted; "
            "value-shape constraints + placeholder filtering keep the "
            "FP rate manageable."
        ),
        fix_hint="Rotate immediately. Move to a secret manager and reference via env var.",
    ),

    SecretRule(
        # Generic API key — collab variant. Same shape contract as
        # the password rule. Bumped to 16-char minimum because API
        # keys are deterministically longer than passwords.
        # Keyword list expanded 2026-05-03 — the `x_api_key` /
        # `customer_key` / `integration_key` shapes appear regularly
        # in B2B SaaS docs (Stripe, Twilio, etc.) that get pasted
        # into Jira tickets.
        rule_id="VOODA-SEC-GEN-001-COLLAB",
        title="Generic API Key (collab)",
        secret_type="generic_api_key",
        severity="high",
        pattern=(
            r"""(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token"""
            r"""|x[_-]?api[_-]?key|customer[_-]?key|integration[_-]?key"""
            r"""|access[_-]?key|access[_-]?token|auth[_-]?key|auth[_-]?token"""
            r""")\s*[=:]\s*['\"]?"""
            + r"(" + _VALUE_SHAPE_16 + r")"
            + r"""['\"]?"""
        ),
        keywords=["api_key", "api-key", "apikey", "api_secret", "api-secret",
                  "api_token", "x_api_key", "x-api-key", "customer_key",
                  "customer-key", "integration_key", "integration-key",
                  "access_key", "access-key", "access_token", "access-token",
                  "auth_key", "auth-key", "auth_token", "auth-token"],
        confidence=0.65,
        surface_targeting=_COLLAB_SURFACES,
        description="Generic API key disclosed in collaboration-tool content or code comment.",
        fix_hint="Rotate the key in the issuing provider's console. Move to a secret manager.",
    ),

    SecretRule(
        # Generic secret / signing key — collab variant.
        # Keyword list expanded 2026-05-03 with the JWT/session/CSRF
        # variants that show up constantly in framework discussions.
        rule_id="VOODA-SEC-GEN-002-COLLAB",
        title="Generic Secret Assignment (collab)",
        secret_type="generic_secret",
        severity="high",
        pattern=(
            r"""(?:secret[_-]?key|secret_token|app[_-]?secret|signing[_-]?key"""
            r"""|encryption[_-]?key|client[_-]?secret|shared[_-]?secret"""
            r"""|jwt[_-]?secret|session[_-]?secret|csrf[_-]?token"""
            r"""|csrf[_-]?secret|cookie[_-]?secret|hmac[_-]?secret"""
            r"""|hmac[_-]?key|master[_-]?secret|master[_-]?key"""
            r""")\s*[=:]\s*['\"]?"""
            + r"(" + _VALUE_SHAPE_16 + r")"
            + r"""['\"]?"""
        ),
        keywords=["secret_key", "secret-key", "secret_token", "app_secret",
                  "signing_key", "encryption_key", "client_secret",
                  "shared_secret", "shared-secret", "jwt_secret", "jwt-secret",
                  "session_secret", "session-secret", "csrf_token", "csrf-token",
                  "csrf_secret", "csrf-secret", "cookie_secret", "cookie-secret",
                  "hmac_secret", "hmac-secret", "hmac_key", "hmac-key",
                  "master_secret", "master-secret", "master_key", "master-key"],
        confidence=0.65,
        surface_targeting=_COLLAB_SURFACES,
        description="Generic secret / signing key disclosed in collaboration-tool content or code comment.",
        fix_hint="Rotate the secret. Use a secret manager (Vault / AWS SM / etc.).",
    ),

    SecretRule(
        # Connection string with embedded credentials — collab variant.
        # Same regex as the code rule (URLs are URLs regardless of
        # surface), but tuned higher because a real `postgres://u:p@h`
        # in a Slack message is much more likely to be a live
        # connection string than a code fixture.
        rule_id="VOODA-SEC-GEN-006-COLLAB",
        title="Connection String with Credentials (collab)",
        secret_type="generic_connection_string",
        severity="high",
        pattern=r'[a-z]+://[^:\s]+:[^@\s]+@[^\s/]+',
        keywords=["://"],
        confidence=0.55,
        surface_targeting=_COLLAB_SURFACES,
        description=(
            "Connection string with inline username:password disclosed "
            "in collaboration-tool content or code comment. Slightly "
            "cooler confidence than the credential-name rules above "
            "because URLs in docs (README copy-paste, etc.) are "
            "genuinely common."
        ),
        fix_hint="Move credentials to env vars. Connection strings should never be checked in.",
    ),

    SecretRule(
        # Bearer token assignment — relaxed for collab. Authorization
        # headers get pasted into chat constantly during debugging
        # ("here's the curl I used: -H 'Authorization: Bearer ey...'").
        rule_id="VOODA-SEC-GEN-004-COLLAB",
        title="Bearer Token (collab)",
        secret_type="bearer_token",
        severity="high",
        pattern=r"""[Bb]earer\s+([A-Za-z0-9\-_.~+/=]{20,})""",
        keywords=["bearer", "Bearer", "BEARER"],
        confidence=0.70,
        surface_targeting=_COLLAB_SURFACES,
        description="Bearer token disclosed in collaboration-tool content or code comment (often via pasted curl / debug output).",
        fix_hint="Rotate the token at the issuing provider. Strip Authorization headers before pasting in chat / tickets.",
    ),

    # ── New rules added 2026-05-03 — Phase 2 expansion ──
    # These cover credential shapes that are common in support
    # tickets / debug-paste content but were uncovered by the
    # initial collab cohort.

    SecretRule(
        # HTTP Basic auth header — `Authorization: Basic <base64>`.
        # The base64 typically decodes to `user:password`. Engine's
        # base64-decode pass would re-fire the credential rule on the
        # decoded text, but matching the wrapper directly gives us a
        # cleaner finding with the right rule_id and fix-hint.
        rule_id="VOODA-SEC-GEN-005-COLLAB",
        title="HTTP Basic Auth Header (collab)",
        secret_type="http_basic_auth",
        severity="high",
        pattern=r"""[Aa]uthorization\s*:\s*[Bb]asic\s+([A-Za-z0-9+/=]{16,})""",
        keywords=["Basic ", "basic ", "Authorization", "authorization"],
        confidence=0.70,
        surface_targeting=_COLLAB_SURFACES,
        description=(
            "HTTP Basic Auth header disclosed in collaboration-tool "
            "content or code comment — the base64 value typically "
            "decodes to `username:password`. Common in pasted curl / "
            "debug output."
        ),
        fix_hint="Rotate the credentials. Use OAuth / token-based auth instead of Basic. Strip Authorization headers before pasting.",
    ),

    SecretRule(
        # JDBC connection URL — `jdbc:driver://user:pass@host/db`.
        # The standard `[a-z]+://` GEN-006 rule catches `postgres://`
        # but not `jdbc:postgresql://` because of the extra `jdbc:`
        # prefix. Real apps and docs constantly use the JDBC form.
        rule_id="VOODA-SEC-GEN-008-COLLAB",
        title="JDBC Connection String (collab)",
        secret_type="generic_connection_string",
        severity="high",
        pattern=r"""jdbc:[a-z]+://[^:\s]+:[^@\s]+@[^\s/]+""",
        keywords=["jdbc:"],
        confidence=0.70,
        surface_targeting=_COLLAB_SURFACES,
        description=(
            "JDBC connection string with inline username:password "
            "disclosed in collaboration-tool content. Common in app "
            "config docs pasted into Jira / Confluence / Slack."
        ),
        fix_hint="Move credentials to env vars / secret manager. Reference via JNDI lookup in production.",
    ),

    SecretRule(
        # ODBC / SQL Server style connection string with embedded
        # password. Form: `Server=...;Database=...;User Id=...;Pwd=...;`.
        # Keyword pre-filter requires "Pwd" or "Password" to be near
        # `Server=` / `Driver=` to keep this from firing on every
        # `password=` write the GEN-003 rule already catches.
        rule_id="VOODA-SEC-GEN-009-COLLAB",
        title="ODBC Connection String (collab)",
        secret_type="generic_connection_string",
        severity="high",
        pattern=(
            r"""(?:Server|Driver|Data\s+Source)\s*=\s*[^;]+;"""
            r"""(?:[^;]*;)*?"""
            r"""\s*(?:Pwd|Password)\s*=\s*([^;\s]{6,})"""
        ),
        keywords=["Server=", "Driver=", "Data Source"],
        confidence=0.75,
        surface_targeting=_COLLAB_SURFACES,
        description=(
            "ODBC / SQL Server connection string with inline password "
            "disclosed in collaboration-tool content. The ODBC format is "
            "uncommon enough in non-credential contexts that we lean "
            "into a higher confidence."
        ),
        fix_hint="Use Windows / Active Directory authentication, or move the password to a credential vault.",
    ),

    SecretRule(
        # Webhook URLs with embedded tokens — Slack webhook URLs
        # contain the trigger secret in the path itself. Same for
        # Discord, Microsoft Teams incoming webhooks. Anyone with the
        # URL can post to the channel as the bot.
        # The generic `[a-z]+://...:...@host` rule won't catch these
        # (no `:` separator before host), so a dedicated rule is
        # necessary.
        rule_id="VOODA-SEC-GEN-010-COLLAB",
        title="Webhook URL with Embedded Token (collab)",
        secret_type="webhook_url",
        severity="high",
        pattern=(
            r"""https://(?:"""
            r"""hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"""
            r"""|discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"""
            r"""|[a-z0-9.\-]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9\-@/]+"""
            r"""|(?:api\.)?pagerduty\.com/integration/[A-Za-z0-9]+"""
            r"""|api\.opsgenie\.com/v[12]/json/[a-z]+\?apiKey=[A-Za-z0-9\-]+"""
            r""")"""
        ),
        keywords=["hooks.slack.com", "discord.com/api/webhooks",
                  "discordapp.com/api/webhooks", "webhook.office.com",
                  "pagerduty.com/integration", "opsgenie.com"],
        confidence=0.80,
        surface_targeting=_COLLAB_SURFACES,
        description=(
            "Webhook URL with embedded trigger token / signing secret "
            "disclosed in collaboration-tool content. Anyone holding the "
            "URL can post to the receiving channel — the URL IS the "
            "credential."
        ),
        fix_hint="Rotate the webhook in the receiving service. Treat webhook URLs as secrets — never paste in tickets / chat.",
    ),
]
