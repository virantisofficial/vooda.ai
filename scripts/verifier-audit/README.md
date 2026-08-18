# Verifier audit scripts

Tooling to keep the 250+ live secret verifiers honest and to plan
backfill work for the ~360 unverified detected providers.

## What's here

| Script | What it does |
|---|---|
| `extract_verifier_urls.py` | Parses every `async def verify_*` in `services/secret_verification/verifier.py`, pulls out the probe URL (including f-strings with `{placeholder}` segments), writes `/tmp/verifier_urls.json` |
| `check_verifier_reachability.py` | Probes each extracted URL unauthenticated to confirm DNS/TCP/TLS/HTTP. Exits non-zero if any *real* (non-placeholder) endpoint is unreachable. Used by the weekly CI job |
| `build_unverified_tier_list.py` | Cross-references detection rules vs. verifier coverage, sorts the gap into T1/T2/T3/T4 by buildability |

## Running locally

```bash
# From repo root
python3 scripts/verifier-audit/extract_verifier_urls.py
python3 scripts/verifier-audit/check_verifier_reachability.py
python3 scripts/verifier-audit/build_unverified_tier_list.py
```

All scripts write to `/tmp/` and use stdlib only (no extra installs).

## CI

`.github/workflows/verifier-reachability.yml` runs the extract + check
pair every Monday at 06:00 UTC and posts a job summary. A real
breakage (provider sunset, DNS change) opens a notification through
the workflow_run path; placeholder URLs (per-customer subdomains) are
allowlisted in `check_verifier_reachability.py:PLACEHOLDER_HOSTS`.

## Why this exists

Discovered 2026-05-19 while auditing our 252-verifier surface: two
verifiers (`verify_fauna_key`, `verify_xata_key`) were probing
endpoints whose providers had been sunset months earlier. The
verifiers silently returned `status="error"` on every finding for
those providers — invisible regression with no CI to catch it. This
toolkit closes that gap and gives the team a one-command read on the
state of the verification surface.

## When to update

- **PLACEHOLDER_HOSTS** in `check_verifier_reachability.py`: add a host
  when you ship a new verifier whose URL is per-customer (Okta-style
  `{domain}.okta.com`, ServiceNow per-instance, Mattermost self-host, etc.)
- **T2_MEDIUM / T3_HARD sets** in `build_unverified_tier_list.py`:
  update when you add new detectors for paired-credential or
  self-hosted-only providers, so the tier projection stays accurate.
