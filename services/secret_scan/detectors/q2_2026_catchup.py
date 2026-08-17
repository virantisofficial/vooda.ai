# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Q2 2026 detector catch-up.

Surfaced via a quarterly audit against the public TruffleHog detector
list. Each provider here was either entirely missing from Vooda's
library or insufficiently covered for enterprise use cases.

Tier A (distinctive prefix → high-confidence regex)
- Artifactory (JFrog) — AKCp* identity / reference tokens
- Alibaba Cloud — LTAI* AccessKey ID + paired secret

Tier B (no distinctive prefix → keyword-anchored, lower confidence)
- AlienVault OTX — 64-char hex API keys
- AppDynamics — controller API tokens
- Agora — App ID + App Certificate (32-hex)
- MuleSoft Anypoint — OAuth client_id / client_secret
- Autodesk Forge — bearer tokens

Tier-B confidence is calibrated lower (0.50–0.65) so the AI triage
layer downstream can demote noisy matches without us needing to
guess the right cutoff up-front. Each rule has a placeholder-rejection
test in tests/secret_scan/test_q2_2026_catchup.py to lock in TP/FP
behaviour against canonical doc examples.

When tuning these later, prefer:
  * Anchoring on a credential-shaped variable name (`api_token`,
    `access_key_id`, …) over loose entropy; the keyword pre-filter
    makes the regex phase cheap so the cost is small.
  * A deliberate `case_sensitive=True` for fixed-format prefixes
    that aren't actually case-insensitive in the wild.
"""

from services.secret_scan.detectors.base import SecretRule


RULES: list[SecretRule] = [
    # ── Tier A: distinctive prefix ─────────────────────────────────

    SecretRule(
        # JFrog Artifactory identity/reference tokens. Format:
        # `AKCp` followed by 50–100 base62 chars depending on token
        # type (identity vs reference vs deploy).
        # https://jfrog.com/help/r/jfrog-platform-administration-documentation/access-tokens
        rule_id="VOODA-SEC-ARTIFACTORY-001",
        title="JFrog Artifactory Identity Token",
        secret_type="artifactory_identity_token",
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(AKCp[A-Za-z0-9]{50,100})(?:[^A-Za-z0-9]|$)',
        keywords=["AKCp"],
        confidence=0.92,
        case_sensitive=True,
        description=(
            "JFrog Artifactory identity / reference token detected. "
            "AKCp-prefixed tokens grant authenticated access to your "
            "Artifactory instance (read or write depending on scope)."
        ),
        fix_hint=(
            "Revoke the token in Artifactory → User Profile → "
            "Generate Identity Token / Manage Tokens. Replace with a "
            "scoped token issued via the access API."
        ),
    ),
    SecretRule(
        # Alibaba Cloud AccessKey ID. Modern format: LTAI + 12 to 20
        # alphanumeric chars (uppercase + lowercase + digits).
        # AccessKey ID is the public half; the secret half (next rule)
        # is what actually grants access — but seeing the ID in source
        # is itself a strong indicator the secret is nearby.
        rule_id="VOODA-SEC-ALIBABA-AKID-001",
        title="Alibaba Cloud AccessKey ID",
        secret_type="alibaba_accesskey_id",
        # Escalated high → critical 2026-05-22 (Track-A Phase 5,
        # Option A): VOODA-SEC-ALI-001 was being consolidated INTO
        # this canonical and ALI-001 carried critical severity.
        # Preserving the worst-case classification so the
        # consolidation doesn't de-escalate the threat level.
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(LTAI[0-9A-Za-z]{12,20})(?:[^A-Za-z0-9]|$)',
        keywords=["LTAI"],
        confidence=0.90,
        case_sensitive=True,
        description=(
            "Alibaba Cloud AccessKey ID detected. Paired with an "
            "AccessKey Secret it grants programmatic access to ECS, "
            "RDS, OSS, ACM, and most other Alibaba Cloud services."
        ),
        fix_hint=(
            "Rotate in Alibaba Cloud RAM Console → AccessKeys. Prefer "
            "RAM roles (STS) for compute-resident workloads instead of "
            "long-lived AccessKey pairs."
        ),
    ),
    SecretRule(
        # Alibaba Cloud AccessKey Secret. 30 alphanumeric chars; no
        # distinctive prefix, so we anchor on the variable name.
        # Confidence lower than the AKID rule because pure-shape
        # matches against arbitrary 30-char strings would have
        # a high false-positive rate.
        rule_id="VOODA-SEC-ALIBABA-AKSECRET-001",
        title="Alibaba Cloud AccessKey Secret",
        secret_type="alibaba_accesskey_secret",
        severity="high",
        pattern=(
            r'(?:alibaba|aliyun|ali)[_-]?(?:access[_-]?key[_-]?secret|secret)'
            r'\s*[=:]\s*[\'\"]([A-Za-z0-9]{30})[\'\"]'
        ),
        keywords=["alibaba_access", "aliyun_access", "ali_access", "alibaba_secret", "aliyun_secret"],
        confidence=0.78,
        description=(
            "Alibaba Cloud AccessKey Secret detected near a credential-"
            "shaped variable name. Combined with the matching AKID it "
            "is full programmatic access."
        ),
        fix_hint="Rotate in RAM Console. Use STS short-lived tokens or RAM roles where possible.",
    ),

    # ── Tier B: keyword-anchored ───────────────────────────────────

    SecretRule(
        # AlienVault OTX — 64-char hex API keys. No prefix; we anchor
        # on the variable name. Frequently shared across security
        # researchers in tickets and Slack messages.
        rule_id="VOODA-SEC-ALIENVAULT-001",
        title="AlienVault OTX API Key",
        secret_type="alienvault_otx_key",
        severity="high",
        pattern=(
            r'(?:alienvault|otx)[_-]?(?:api[_-]?key|token)'
            r'\s*[=:]\s*[\'\"]?([0-9a-f]{64})[\'\"]?'
        ),
        keywords=["alienvault", "otx_api_key", "otx_token"],
        confidence=0.9,
        description=(
            "AlienVault OTX API key detected. Read access to threat "
            "intelligence pulses; not destructive on its own but "
            "should still be rotated if leaked."
        ),
        fix_hint="Regenerate at otx.alienvault.com → Settings → API Integration.",
    ),

    SecretRule(
        # AppDynamics — Controller API tokens. Format is
        # alphanumeric of variable length; we anchor on the
        # variable name + paired account.
        rule_id="VOODA-SEC-APPDYNAMICS-001",
        title="AppDynamics API Token",
        secret_type="appdynamics_api_token",
        severity="high",
        pattern=(
            r'(?:appdynamics|appd)[_-]?(?:api[_-]?(?:token|key)|access[_-]?token|token|key)'
            r'\s*[=:]\s*[\'\"]?([A-Za-z0-9_\-]{32,64})[\'\"]?'
        ),
        keywords=["appdynamics", "appd_api", "appd_token", "appd_key"],
        confidence=0.60,
        description=(
            "AppDynamics controller API token detected. Grants access "
            "to APM dashboards, alert configuration, and metric data."
        ),
        fix_hint="Revoke in Controller → Settings → API Clients. Replace with a scoped client.",
    ),

    SecretRule(
        # Agora App ID + App Certificate are both 32-hex strings; we
        # rely on the variable name to disambiguate from generic
        # uuids/hashes elsewhere.
        rule_id="VOODA-SEC-AGORA-001",
        title="Agora App Certificate",
        secret_type="agora_app_certificate",
        severity="high",
        pattern=(
            r'agora[_-]?(?:app[_-]?certificate|app[_-]?secret|primary[_-]?certificate)'
            r'\s*[=:]\s*[\'\"]?([0-9a-f]{32})[\'\"]?'
        ),
        keywords=["agora_app_certificate", "agora_app_secret", "agora_primary"],
        confidence=0.9,
        description=(
            "Agora App Certificate detected. The App Certificate is "
            "what generates RTC/RTM tokens — leaking it lets an "
            "attacker authenticate users into your real-time channels."
        ),
        fix_hint="Rotate in Agora Console → App → Project Management.",
    ),

    SecretRule(
        # MuleSoft Anypoint OAuth client_id is 32-char alphanumeric.
        # Same shape as a hex hash, so we anchor on the variable name.
        rule_id="VOODA-SEC-ANYPOINT-CLIENT-ID-001",
        title="MuleSoft Anypoint OAuth Client ID",
        secret_type="anypoint_client_id",
        severity="medium",
        pattern=(
            r'(?:anypoint|mulesoft)[_-]?(?:client[_-]?id|connected[_-]?app[_-]?id)'
            r'\s*[=:]\s*[\'\"]?([0-9a-f]{32})[\'\"]?'
        ),
        keywords=["anypoint_client", "mulesoft_client", "anypoint_connected", "mulesoft_connected"],
        confidence=0.88,
        description=(
            "MuleSoft Anypoint OAuth client_id detected. The id is the "
            "public half of the credential pair; treat alongside the "
            "client_secret as a unit when rotating."
        ),
        fix_hint="Rotate the connected app in Anypoint → Access Management → Connected Apps.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-ANYPOINT-CLIENT-SECRET-001",
        title="MuleSoft Anypoint OAuth Client Secret",
        secret_type="anypoint_client_secret",
        severity="high",
        pattern=(
            r'(?:anypoint|mulesoft)[_-]?(?:client[_-]?secret|connected[_-]?app[_-]?secret)'
            r'\s*[=:]\s*[\'\"]?([0-9a-f]{32,64})[\'\"]?'
        ),
        keywords=["anypoint_client_secret", "mulesoft_client_secret"],
        confidence=0.9,
        description=(
            "MuleSoft Anypoint OAuth client_secret detected. Combined "
            "with the client_id this grants the connected app's full "
            "scope — frequently includes admin rights to deploy."
        ),
        fix_hint="Rotate the connected app in Anypoint → Access Management → Connected Apps.",
    ),

    SecretRule(
        # Autodesk Forge / Platform Services bearer tokens are
        # 100+ alphanumeric chars (the JWT-shaped ones decode to
        # ~600 bytes). Anchored on the variable name.
        rule_id="VOODA-SEC-AUTODESK-001",
        title="Autodesk Platform Services Token",
        secret_type="autodesk_token",
        severity="high",
        pattern=(
            r'(?:autodesk|forge|aps)[_-]?(?:access[_-]?token|client[_-]?secret|bearer)'
            r'\s*[=:]\s*[\'\"]?([A-Za-z0-9_\-\.]{40,400})[\'\"]?'
        ),
        keywords=["autodesk_access", "forge_access", "aps_access",
                  "autodesk_client_secret", "forge_client_secret"],
        confidence=0.88,
        description=(
            "Autodesk Platform Services (formerly Forge) credential "
            "detected. Grants access to BIM 360 / ACC project data, "
            "Forge Viewer model translations, and account-wide APIs."
        ),
        fix_hint="Rotate in aps.autodesk.com → My Apps. Prefer 2-legged short-lived tokens.",
    ),
]
