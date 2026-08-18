#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Hit each verifier endpoint unauthenticated and record outcome.

The goal is *reachability*, not credential validation — we just confirm:
  • DNS resolves
  • TCP/TLS handshake completes
  • Some HTTP response comes back (any status; 401/403 is actually ideal
    because it proves the endpoint exists and requires auth)
  • No timeout / DNS-fail / TLS-fail

Outcomes:
    OK_AUTH      - endpoint reachable, returned 401/403 (auth gating works)
    OK_PUBLIC    - endpoint reachable, returned 200/204
    OK_OTHER_4XX - reachable, 4xx other than 401/403
    REDIRECT     - reachable, 3xx
    WARN_5XX     - reachable, server-side error                 <-- INVESTIGATE
    DNS_FAIL     - hostname does not resolve                    <-- BROKEN
    CONNECT_FAIL - DNS OK but no TCP                            <-- BROKEN
    TIMEOUT      - no response within budget                    <-- BROKEN
    TLS_FAIL     - TLS handshake error                          <-- BROKEN
    OTHER_FAIL   - something else

Used by:
    .github/workflows/verifier-reachability.yml (weekly cron)

Exit code:
    0 - no real failures (DNS/CONNECT/TIMEOUT/TLS/5XX are absent OR are
        on placeholder URLs that don't resolve because customer config
        wasn't substituted — those are filtered out via PLACEHOLDER_HOSTS).
    1 - one or more verifiers are genuinely unreachable.
"""
from __future__ import annotations
import json
import socket
import ssl
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import http.client

CONCURRENCY = 30
TIMEOUT_SEC = 8

# Hosts where the URL is a templated placeholder filled at runtime from
# customer config.  We can't resolve these without real credentials, so
# they're allowed to DNS-fail in the static reachability run.  This
# list should stay tight — if a real provider DNS dies, we want to see it.
PLACEHOLDER_HOSTS = {
    "acme.com", "chat.acme.com", "acme.service-now.com",
    "x-dsn.algolia.net",  # algolia uses {app_id}-dsn — substituted to literal "x"
    "host", "x",          # f"https://{host}" / f"https://{domain}" → unsubstituted
    "example.com",        # SUBS["domain"] default
    "api.example.com",    # SUBS["host"] default
    "accounts.zoho.us-east-1",  # zoho is region-routed at runtime, no fallback
}


def normalise(url: str) -> str:
    """Replace remaining ``{placeholder}`` segments with benign values.

    The extractor already substitutes known placeholders, but the
    fallback for unknown ones is the literal string ``x`` — keeping
    parsing simple at the cost of an invalid hostname.  We filter
    those out via PLACEHOLDER_HOSTS rather than guess what the right
    domain should be.
    """
    import re
    return re.sub(r"\{[^}]+\}", "x", url)


def check(item: dict) -> dict:
    verifier = item["verifier"]
    raw_url = item["url"]
    url = normalise(raw_url)
    out = {"verifier": verifier, "url": raw_url, "tested_url": url}

    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname:
            out["status"] = "OTHER_FAIL"
            out["detail"] = "no hostname"
            return out

        try:
            socket.gethostbyname(parsed.hostname)
        except socket.gaierror as e:
            out["status"] = "DNS_FAIL"
            out["detail"] = str(e)
            out["is_placeholder"] = parsed.hostname in PLACEHOLDER_HOSTS
            return out

        scheme = parsed.scheme or "https"
        port = parsed.port or (443 if scheme == "https" else 80)
        host = parsed.hostname
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT_SEC, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT_SEC)
            conn.request("GET", path, headers={"User-Agent": "Vooda-Verifier-Health/1.0"})
            resp = conn.getresponse()
            out["http_status"] = resp.status
            resp.read(0)
            conn.close()
        except socket.timeout:
            out["status"] = "TIMEOUT"
            return out
        except ssl.SSLError as e:
            out["status"] = "TLS_FAIL"
            out["detail"] = str(e)
            return out
        except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
            out["status"] = "CONNECT_FAIL"
            out["detail"] = str(e)[:200]
            return out

        sc = out["http_status"]
        if sc in (401, 403):
            out["status"] = "OK_AUTH"
        elif sc in (200, 204):
            out["status"] = "OK_PUBLIC"
        elif 300 <= sc < 400:
            out["status"] = "REDIRECT"
        elif 500 <= sc < 600:
            out["status"] = "WARN_5XX"
        else:
            out["status"] = "OK_OTHER_4XX"
        return out

    except Exception as e:
        out["status"] = "OTHER_FAIL"
        out["detail"] = repr(e)[:200]
        return out


def main() -> int:
    data = json.loads(Path("/tmp/verifier_urls.json").read_text())
    start = time.time()
    results = []

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futures = [ex.submit(check, item) for item in data]
        for i, fut in enumerate(as_completed(futures), 1):
            results.append(fut.result())
            if i % 20 == 0 or i == len(futures):
                print(f"  {i}/{len(futures)} checked ({time.time() - start:.1f}s)", file=sys.stderr)

    from collections import Counter
    tally = Counter(r["status"] for r in results)
    print("\n=== REACHABILITY TALLY ===")
    for k in ["OK_AUTH", "OK_PUBLIC", "REDIRECT", "OK_OTHER_4XX", "WARN_5XX",
              "DNS_FAIL", "CONNECT_FAIL", "TIMEOUT", "TLS_FAIL", "OTHER_FAIL"]:
        print(f"  {k:14s} {tally.get(k, 0)}")

    results.sort(key=lambda r: (r["status"], r["verifier"]))
    Path("/tmp/verifier_reachability.json").write_text(json.dumps(results, indent=2))

    broken_states = {"DNS_FAIL", "CONNECT_FAIL", "TIMEOUT", "TLS_FAIL", "WARN_5XX", "OTHER_FAIL"}
    broken = [r for r in results if r["status"] in broken_states]
    real_broken = [r for r in broken if not r.get("is_placeholder")]
    Path("/tmp/verifier_broken.json").write_text(json.dumps(broken, indent=2))

    print(f"\nElapsed: {time.time() - start:.1f}s")
    print(f"Wrote full report: /tmp/verifier_reachability.json")
    print(f"Wrote broken-only: /tmp/verifier_broken.json ({len(broken)} entries)")

    if real_broken:
        print(f"\n!! {len(real_broken)} verifier(s) genuinely broken:")
        for r in real_broken:
            print(f"   {r['status']:12s} {r['verifier']:35s} -> {r.get('tested_url') or r['url']}")
        return 1
    print("\nAll real endpoints reachable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
