# Security Policy

Vooda is a security product. We take vulnerabilities in it seriously, and we'd rather hear about a problem from you than from an incident.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately, either way:

- **GitHub Private Vulnerability Reporting** — the "Report a vulnerability" button under this repository's **Security** tab. This is the preferred route; it keeps the discussion attached to the repo and private until we publish an advisory.
- **Email** — **security@vooda.ai**

### What to include

The more of this you can give us, the faster we can act:

- What kind of issue it is (RCE, auth bypass, SSRF, secret exposure, injection, …)
- Which component — API, worker, web UI, CLI, a specific detector, a scanner integration
- The affected version or commit
- Step-by-step reproduction, ideally with a minimal proof of concept
- What an attacker gets out of it
- Any suggested fix, if you have one

Please **redact any real credentials** from your report. If a live secret is genuinely necessary to demonstrate the issue, tell us and we'll arrange a secure channel.

## What happens next

| When | What |
|---|---|
| Within **48 hours** | We acknowledge your report |
| Within **5 business days** | We confirm the issue and give you an initial assessment |
| Ongoing | We keep you updated at least every 7 days until it's resolved |
| On fix | We agree a disclosure date with you and credit you in the advisory |

We aim to ship fixes for critical issues within 30 days of confirmation. If we need longer, we'll explain why rather than go quiet.

## Disclosure

We practise coordinated disclosure. We'll work with you on timing and we won't sit on a fix. If we disagree about severity or timeline, we'll say so directly and explain our reasoning — we won't just stop replying.

We'll credit you by name or handle in the advisory unless you'd rather stay anonymous. Just tell us which.

## Scope

**In scope** — anything in this repository:

- The API (`apps/api`), worker (`apps/worker`), and web UI (`apps/web`)
- The scan engine and detector rule pack (`services/secret_scan`)
- Secret verification (`services/secret_verification`)
- The CLI and pre-commit hook (`cli/`)
- Scanner and source integrations (`services/source_scanners`, `services/git_integration`)
- Authentication, authorization, and session handling
- The default Docker Compose deployment

**Out of scope:**

- Findings that require an already-compromised host or an already-authenticated administrator
- Missing hardening headers with no demonstrable impact
- Volumetric denial of service
- Vulnerabilities in third-party dependencies with no exploitable path through Vooda — please report those upstream, though do tell us so we can bump the pin
- Social engineering of Virantis staff or users
- Automated scanner output pasted without a working proof of concept

### Two things that look like vulnerabilities but aren't

1. **This repository contains secret-shaped strings by design.** `tests/` holds a deliberate corpus of planted, non-functional credentials — that's what a secret scanner's test suite is made of. If your scanner alerts on this repo, that's expected. If you find a credential here that is *live*, that absolutely is a vulnerability and we want to know immediately.

2. **The default deployment ships with known default credentials** and is intended for local evaluation. Running the default Compose file on a public network without changing them is a misconfiguration, not a vulnerability — but see `DEPLOYMENT.md` before exposing an instance.

## Safe harbour

If you make a good-faith effort to comply with this policy, we will not pursue or support legal action against you for your research. We consider such research authorised, and we'll do what we can to make that clear to third parties if it comes up.

Good faith means: don't access, modify, or destroy data that isn't yours; don't degrade the service for others; don't pivot beyond what's needed to demonstrate the issue; and give us reasonable time to fix it before going public.

## Supported versions

Vooda is pre-1.0. Security fixes land on the default branch and in the latest release. We do not currently backport to older releases.

## Bug bounty

We do not run a paid bounty programme yet. We do credit every valid report, and we'll tell you plainly if that changes.
