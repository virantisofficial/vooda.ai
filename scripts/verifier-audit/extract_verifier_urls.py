#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Extract every URL each verifier hits, grouped by verifier function.

Walks ``services/secret_verification/verifier.py`` and pulls out the
HTTPS endpoint each ``async def verify_X(...)`` function probes. Handles
both plain string URLs and f-string URLs with ``{placeholder}`` segments.

Output:
    /tmp/verifier_urls.json   — one entry per verifier with extracted URL(s)
    /tmp/verifier_no_url.json — verifier names where no URL pattern matched
                                (usually means URL is built entirely from
                                runtime args — e.g. webhook destinations)

Used by:
    check_verifier_reachability.py — consumes /tmp/verifier_urls.json
    .github/workflows/verifier-reachability.yml — weekly CI run

Maintained at /Users/neo/Desktop/Vooda/scripts/verifier-audit/.
Last regenerated 2026-05-19.
"""
from __future__ import annotations
import re
import json
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "services" / "secret_verification" / "verifier.py"

# Default substitutions for common placeholder vars so static reachability
# checks resolve to a hittable hostname. None of these are real
# credentials — they just unblock the DNS lookup.
SUBS = {
    "domain": "example.com", "dc": "us1", "account": "acct",
    "host": "api.example.com", "region": "us-east-1",
    "subdomain": "tenant", "instance": "instance",
    "user": "user", "site": "site", "username": "user",
    "workspace": "ws", "project": "proj", "tenant_id": "tenant",
    "org": "org", "team": "team", "endpoint": "ep", "service": "svc",
    "shop": "shop", "key": "k", "id": "1",
}

# URL chars are either a "normal" non-special char (NOT { or }), OR a
# complete {placeholder}.  Repeating that group lets us span multiple
# placeholders within one URL — e.g. https://{host}/{path}/{id}.
URL_RE = re.compile(
    r'(?:f|rf|fr)?["\']?(https?://(?:[^\s"\'`)\\\{\}]|\{[a-zA-Z_][a-zA-Z0-9_]*\})+)'
)
FUNC_RE = re.compile(r"^async def (verify_[a-z0-9_]+)\(")
# These are internal helpers, not per-provider verifiers, so we drop them
# from the report.
INTERNAL_HELPERS = ("verify_ai", "verify_auth", "verify_finding", "verify_findings_batch")


def fix_placeholders(url: str) -> str:
    """Substitute known {var} placeholders so the URL is hittable."""
    def repl(m: re.Match) -> str:
        return SUBS.get(m.group(1), "x")
    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", repl, url)


def main() -> None:
    src = SRC.read_text()
    verifiers: Dict[str, List[str]] = {}
    current: str | None = None
    buf: List[str] = []

    for line in src.splitlines():
        m = FUNC_RE.match(line)
        if m:
            if current is not None:
                verifiers[current] = sorted({fix_placeholders(u) for u in buf})
            current = m.group(1)
            buf = []
        elif current:
            for match in URL_RE.finditer(line):
                buf.append(match.group(1).rstrip(",.;:"))

    if current is not None:
        verifiers[current] = sorted({fix_placeholders(u) for u in buf})

    for k in INTERNAL_HELPERS:
        verifiers.pop(k, None)

    no_url = sorted(k for k, v in verifiers.items() if not v)
    have_url = {k: v for k, v in verifiers.items() if v}

    flat = []
    for name, urls in sorted(have_url.items()):
        # Filter docs/help URLs — they aren't probe endpoints
        api_urls = [u for u in urls if not any(m in u for m in [".com/docs", ".com/help", "/docs/", "/help/"])]
        chosen = api_urls[0] if api_urls else urls[0]
        flat.append({"verifier": name, "url": chosen, "all_urls": urls})

    out_dir = Path("/tmp")
    (out_dir / "verifier_urls.json").write_text(json.dumps(flat, indent=2))
    (out_dir / "verifier_no_url.json").write_text(json.dumps(no_url, indent=2))

    print(f"Total verifiers parsed:   {len(verifiers)}")
    print(f"  With extractable URL:   {len(have_url)}")
    print(f"  No URL (runtime-built): {len(no_url)}")
    print(f"\nWrote {out_dir / 'verifier_urls.json'}")
    print(f"Wrote {out_dir / 'verifier_no_url.json'}")


if __name__ == "__main__":
    main()
