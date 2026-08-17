#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Build the full T1/T2/T3/T4 tier classification for unverified providers.

Cross-references:
    services/secret_scan/detectors/registry.py — what providers we DETECT
    services/secret_verification/verifier.py    — what providers we VERIFY

The gap (detected but not verified) is partitioned into four tiers based
on the effort needed to ship a verifier:

    T1 — Easy:     Bearer token + GET endpoint, ~1-2 hrs each
    T2 — Medium:   Paired creds / OAuth / SigV4, ~4-8 hrs each
    T3 — Hard:     No public endpoint (self-hosted DevOps platforms)
    T4 — Impossible: Generic patterns, private-key blobs, DB connection strings

Output: /tmp/unverified_tiers.json
"""
from __future__ import annotations
import sys
import re
import json
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from services.secret_scan.detectors.registry import get_all_rules  # noqa: E402

# ─── T4: truly unverifiable ────────────────────────────────────
# Generic patterns, crypto material, DB connection strings.  No
# provider to probe against, even with credentials.
T4_GENERIC = {
    "generic", "api", "http", "https", "ftp", "smtp", "ssh", "ldap",
    "rdp", "snmp", "imap", "pop3", "vnc", "amqp", "amqps", "tls",
    "pgp", "gpg", "gpgsig", "rsa", "pem", "pkcs", "x509",
    "age", "wpa", "wifi",
    "jwt", "basic", "bearer", "oauth", "openid",
    "1pass", "lastpass", "bitwarden_export",
    "db", "sql", "mongo", "redis", "postgres", "mysql", "mssql",
    "oracle", "sqlite", "couchdb", "cassandra", "kafka",
    "url", "uri", "env", "envvar", "connection", "connstr",
    "sha", "md5", "base64", "hex",
}

# ─── T3: hard — needs runtime URL or custom auth ───────────────
T3_HARD = {
    "akeyless", "argocd", "bamboo", "consul", "drone", "harbor",
    "jenkins", "jfrog", "portainer", "teamcity",
}

# ─── T2: medium — paired creds / OAuth / signing ───────────────
T2_MEDIUM = {
    "ado", "adp", "akamai", "alchemy", "ali", "alibaba", "amplitude",
    "anypoint", "atlassian", "braintree", "ibm", "infura", "klarna",
    "linkedin", "minio", "miro", "nexmo", "ovh", "plivo", "quicknode",
    "razorpay", "reddit", "ringcentral", "spotify", "telnyx", "tencent",
    "tiktok", "vonage", "wasabi", "yandex",
}


def main() -> None:
    # Map provider namespace from rule_id
    rules = get_all_rules()
    provider_to_rules: Dict[str, List[str]] = {}
    for r in rules:
        m = re.match(r"VOODA-SEC-([A-Z0-9_]+)", r.rule_id)
        if m:
            p = m.group(1).lower()
            provider_to_rules.setdefault(p, []).append(r.rule_id)

    # Existing verifier providers
    src = (REPO_ROOT / "services" / "secret_verification" / "verifier.py").read_text()
    verifier_providers = set(re.findall(r'provider="([a-z_]+)"', src))
    verifier_providers.discard("unknown")

    unverified = sorted(set(provider_to_rules.keys()) - verifier_providers)

    tiers: Dict[str, List[dict]] = {"T1": [], "T2": [], "T3": [], "T4": []}
    for p in unverified:
        rules_for = provider_to_rules.get(p, [])
        entry = {
            "provider": p,
            "rule_count": len(rules_for),
            "sample_rule": rules_for[0] if rules_for else None,
        }
        if p in T4_GENERIC:
            tiers["T4"].append(entry)
        elif p in T3_HARD:
            tiers["T3"].append(entry)
        elif p in T2_MEDIUM:
            tiers["T2"].append(entry)
        else:
            tiers["T1"].append(entry)

    print("=== UNVERIFIED PROVIDER TIER BREAKDOWN ===")
    print(f"Detected providers (total):  {len(provider_to_rules)}")
    print(f"Verified providers:          {len(verifier_providers)}")
    print(f"Unverified gap:              {len(unverified)}")
    print(f"  T1 (Bearer + simple GET):  {len(tiers['T1'])}")
    print(f"  T2 (paired/OAuth/SigV4):   {len(tiers['T2'])}")
    print(f"  T3 (hard / self-hosted):   {len(tiers['T3'])}")
    print(f"  T4 (truly unverifiable):   {len(tiers['T4'])}")
    realistic = len(tiers["T1"]) + len(tiers["T2"])
    final = len(verifier_providers) + realistic
    total = len(verifier_providers) + len(unverified)
    print(f"\nT1+T2 realistic backfill target: {realistic}")
    print(f"Projected coverage after backfill: {final}/{total} = {final * 100.0 / total:.1f}%")

    Path("/tmp/unverified_tiers.json").write_text(json.dumps(tiers, indent=2))
    print("\nWrote /tmp/unverified_tiers.json")


if __name__ == "__main__":
    main()
