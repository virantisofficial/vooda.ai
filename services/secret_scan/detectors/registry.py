# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Auto-discovers and aggregates all detector rules."""

import importlib
import os
from services.secret_scan.detectors.base import SecretRule


# Rule-ID aliases — deprecated rule IDs that map onto their canonical
# replacement.  Populated during Track-A Phase 5 (2026-05-22), when
# the original Option A duplicate-consolidation work landed.  Each
# entry below removed a rule from its detector module file and
# routes any historical query for the deprecated id (suppressions,
# notification rules, audit log filters) to the canonical id that
# now exclusively detects that pattern.
#
# Use ``resolve_rule_id_alias(rid)`` to translate any user-supplied
# rule_id before applying it as a filter.  Unknown ids pass through
# unchanged.
#
# Audit log rows from BEFORE the migration are intentionally NOT
# rewritten; the alias map is sufficient to reconstruct meaning at
# query time.
RULE_ID_ALIASES: dict = {
    "VOODA-SEC-ALI-001":               "VOODA-SEC-ALIBABA-AKID-001",
    "VOODA-SEC-DATABRICKS-001":        "VOODA-SEC-DATABRICKS-PAT-001",
    "VOODA-SEC-POSTMARK-001":          "VOODA-SEC-POSTMARK-API-001",
    "VOODA-SEC-PERPLEXITY-001":        "VOODA-SEC-PERPLEXITY-PPLX-001",
    "VOODA-SEC-GROQ-001":              "VOODA-SEC-GROQ-GSK-001",
    "VOODA-SEC-ETHERSCAN-001":         "VOODA-SEC-ETHERSCAN-CONTEXT-001",
    "VOODA-SEC-CLICKUP-001":           "VOODA-SEC-CLICKUP-V2-001",
    "VOODA-SEC-BREVO-API-001":         "VOODA-SEC-SENDINBLUE-V3-001",
    "VOODA-SEC-SENDINBLUE-BREVO-001":  "VOODA-SEC-SENDINBLUE-V3-001",
    "VOODA-SEC-SLACK-WEBHOOK-002":     "VOODA-SEC-SLACK-WEBHOOK-001",
    "VOODA-SEC-CI-GITLAB-DEPLOY-001":  "VOODA-SEC-GITLAB-DEPLOY-TOKEN-001",
    "VOODA-SEC-TERRAFORM-CLOUD-001":   "VOODA-SEC-TERRAFORM-CLOUD-V2-001",
    "VOODA-SEC-LINODE-V4-001":         "VOODA-SEC-LINODE-PAT-001",
    "VOODA-SEC-HETZNER-API-001":       "VOODA-SEC-HETZNER-CLOUD-001",
    "VOODA-SEC-FIREWORKS-AI-001":      "VOODA-SEC-FIREWORKS-AI-V2-001",
    "VOODA-SEC-WOOCOMMERCE-CS-001":    "VOODA-SEC-WOOCOMMERCE-PAIR-001",
    "VOODA-SEC-FLY-API-V2-001":        "VOODA-SEC-FLY-MACAROON-001",
    "VOODA-SEC-PULUMI-BACKEND-001":    "VOODA-SEC-PULUMI-V2-001",
    "VOODA-SEC-DEEPSEEK-V2-001":       "VOODA-SEC-DEEPSEEK-SK-001",
    "VOODA-SEC-INFURA-PROJECT-001":    "VOODA-SEC-INFURA-URL-001",

    # Track-A Recommendation #1 (2026-05-22): the GitHub ghs_ token
    # format is identical for both App installation tokens (critical)
    # and Actions ephemeral GITHUB_TOKEN (was medium).  Phase 5
    # deferred this because the regex match alone couldn't pick a
    # severity — runtime context is required.  Resolution: consolidate
    # under the critical-severity rule (worst-case classification
    # preserved); the verifier disambiguates type by calling GitHub's
    # /app or /repos endpoint to confirm scope + remaining lifetime.
    "VOODA-SEC-GITHUB-ACTIONS-TOKEN-001": "VOODA-SEC-GITHUB-APP-INSTALLATION-001",
}


def resolve_rule_id_alias(rule_id: str) -> str:
    """Return the canonical rule_id for a (possibly deprecated) id.

    Unknown ids — custom-detector rule_ids, current rule_ids that
    were never aliased — pass through unchanged.  Safe to call on
    any user-supplied rule_id before using it as a query filter.
    """
    if not rule_id:
        return rule_id
    return RULE_ID_ALIASES.get(rule_id, rule_id)

_DETECTOR_MODULES = [
    "aws", "gcp", "azure", "github", "gitlab", "bitbucket",
    "stripe", "slack", "twilio", "sendgrid",
    "database", "crypto", "cloud_misc", "cicd",
    "auth", "communication", "generic",
    "payment", "saas", "cloud_infra", "devtools",
    "ai_ml", "productivity", "analytics", "database_ext", "messaging", "cms",
    "social", "enterprise", "cloud_providers_ext", "cicd_ext", "misc",
    "gitleaks_batch1", "gitleaks_batch2", "gitleaks_batch3", "gitleaks_batch4", "gitleaks_batch5",
    "trufflehog_final", "final_push",
    # "quantum_vulnerable" DISABLED 2026-06-03: the QUANTUM-* family detects USE
    # of quantum-vulnerable crypto (ECDSA/P-256/DSA/RSA-2048/Ed25519/weak-TLS) —
    # code-posture/compliance signals, NOT leaked secrets. Benchmark across ~46
    # repos: 736 findings, 0 real secrets, ~98% FP (every match is an algorithm
    # name in crypto source). Category error in the secret stream. Definitions
    # retained in quantum_vulnerable.py for a future crypto-posture feature.
    "kubernetes",
    "partner_patterns",
    "trufflehog_port",
    "trufflehog_port_v2",
    "trufflehog_port_v3",
    "trufflehog_port_v4",
    "trufflehog_port_v5",
    # R3 (Opus×Vooda benchmark): classic credential-FILE detectors —
    # AWS shared-credentials INI, .npmrc tokens, .netrc, wp-config.php.
    "credential_files",
    # Quarterly catch-up batches — most recent last so they win the
    # last-wins dedup if they refine an earlier rule.
    "q2_2026_catchup",
    # Collaboration-tool variants — relaxed-quoting patterns
    # targeted at message / page / comment surfaces. Companion code
    # rules in `generic.py` carry surface_excluded so the two never
    # double-fire.
    "generic_collab",
]

_cached_rules: list[SecretRule] | None = None


def get_all_rules() -> list[SecretRule]:
    """Aggregate rules from every detector module with last-wins dedup.

    When two modules define the same rule_id, we keep the LAST occurrence —
    the modules listed later in _DETECTOR_MODULES (trufflehog_port_v3, v2,
    v1, partner_patterns) contain refinements and context-aware variants of
    earlier gitleaks_batch rules and should take precedence.
    """
    global _cached_rules
    if _cached_rules is not None:
        return _cached_rules

    rules_by_id: dict[str, SecretRule] = {}
    for module_name in _DETECTOR_MODULES:
        mod = importlib.import_module(f"services.secret_scan.detectors.{module_name}")
        module_rules = getattr(mod, "RULES", [])
        for r in module_rules:
            # Last-wins: later module definition overrides earlier one
            rules_by_id[r.rule_id] = r

    _cached_rules = list(rules_by_id.values())
    return _cached_rules


def get_rules_by_type(secret_type: str) -> list[SecretRule]:
    return [r for r in get_all_rules() if r.secret_type == secret_type]


def get_rule_by_id(rule_id: str) -> SecretRule | None:
    for r in get_all_rules():
        if r.rule_id == rule_id:
            return r
    return None


def get_rule_count() -> int:
    return len(get_all_rules())


def get_custom_rules_sync(tenant_id, db_session) -> list[SecretRule]:
    """
    Load enabled custom detectors for a tenant from the DB and convert to SecretRule objects.
    Uses a synchronous DB session (for use inside Celery worker tasks).
    Custom rules are NOT cached in _cached_rules — they are per-tenant and per-scan.
    """
    from apps.api.app.models.custom_detector import CustomDetector
    from sqlalchemy import select

    result = db_session.execute(
        select(CustomDetector).where(
            CustomDetector.tenant_id == tenant_id,
            CustomDetector.is_enabled == True,
        )
    )
    detectors = result.scalars().all()

    custom_rules = []
    for d in detectors:
        custom_rules.append(SecretRule(
            rule_id=d.rule_id,
            title=d.title,
            secret_type=d.secret_type,
            severity=d.severity,
            pattern=d.pattern,
            keywords=d.keywords or [],
            confidence=d.confidence or 0.9,
            description=d.description or "",
            fix_hint=d.fix_hint or "",
            cwe=d.cwe or "CWE-798",
            multiline=d.multiline or False,
        ))
    return custom_rules


async def get_custom_rules_async(tenant_id, db_session) -> list[SecretRule]:
    """
    Async version — load enabled custom detectors for a tenant.
    For use inside async FastAPI/worker contexts.
    """
    from apps.api.app.models.custom_detector import CustomDetector
    from sqlalchemy import select

    result = await db_session.execute(
        select(CustomDetector).where(
            CustomDetector.tenant_id == tenant_id,
            CustomDetector.is_enabled == True,
        )
    )
    detectors = result.scalars().all()

    custom_rules = []
    for d in detectors:
        custom_rules.append(SecretRule(
            rule_id=d.rule_id,
            title=d.title,
            secret_type=d.secret_type,
            severity=d.severity,
            pattern=d.pattern,
            keywords=d.keywords or [],
            confidence=d.confidence or 0.9,
            description=d.description or "",
            fix_hint=d.fix_hint or "",
            cwe=d.cwe or "CWE-798",
            multiline=d.multiline or False,
        ))
    return custom_rules


async def get_all_rules_with_custom(tenant_id, db_session) -> list[SecretRule]:
    """Merge built-in (cached) + tenant-specific custom rules from DB."""
    builtin = get_all_rules()
    custom = await get_custom_rules_async(tenant_id, db_session)
    return builtin + custom
