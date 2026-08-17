# How Vooda Verifies Your Secrets

**Audience:** Security architects, procurement reviewers, compliance officers evaluating Vooda before granting it access to source repositories and allowing it to touch third-party APIs.

**TL;DR:** Vooda's verifier **only makes read-only calls** to provider APIs to check whether a detected credential is still live. It never writes, modifies, or deletes anything in any third-party system. This document explains exactly what calls we make, which we don't, and how that guarantee is enforced in code.

---

## 1. The pipeline — where verification fits

When Vooda scans your repository, a finding flows through four stages:

| Stage | What Vooda does | Touches provider APIs? |
|---|---|:-:|
| **1. Detect** | Regex + entropy + structured-file analysis across the full detector library. | No — entirely local. |
| **2. Verify** | For findings with a known provider, call the provider's own "is this key valid?" endpoint. | **Yes — the subject of this doc.** |
| **3. Triage** | Classify as active/inactive/error; escalate severity for active secrets; emit rotation-event telemetry. | No — local DB work. |
| **4. Remediate** | Guide customer to rotate via `fix_hint` per rule. | No — text only. |

Stages 1, 3, 4 never touch external systems. Stage 2 is the only outbound plane.

---

## 2. What the verifier does (and doesn't) do

### It DOES

- Make a **single HTTP request per credential** to the provider's designated "who am I" / "is this token valid" endpoint. Examples:
  - GitHub: `GET /user`
  - AWS: SigV4-signed `POST /` to STS for `GetCallerIdentity` (the canonical no-permission read)
  - Slack: `POST /api/auth.test` (Slack's dedicated validator endpoint)
  - Stripe: `GET /v1/charges?limit=1` (read-only list, no side effects)
  - 240+ other providers, each with a documented-as-read-only check
- Parse the response for identity fields (email, account ID, scope list) to populate the **Blast Radius panel** in the Vooda UI
- Cache the result in Redis for **6 hours** keyed by `(tenant_id, secret_hash)` so we don't re-hit the provider for duplicate findings within that window

### It explicitly DOES NOT

- Call `PUT`, `DELETE`, or `PATCH` on any provider endpoint
- Create, modify, or delete any resource in your provider accounts
- Send email, SMS, push notifications, or any other user-visible action
- Log in as you, start sessions, create tokens, exchange grants beyond what's needed for OAuth-token validation itself
- Store your actual secret values beyond what's needed to re-verify (hashes are stored long-term; raw values are held in memory during one pass and then discarded)
- Enumerate your resources by default — the opt-in feature in section 5 covers that separately

---

## 3. The non-destructive guarantee is enforced by a test in CI

We don't ask you to trust a prose promise. We enforce it in code.

The file `tests/test_verifier_non_destructive.py` statically analyzes the verifier module's AST and **rejects** any HTTP call that:

1. Uses `PUT`, `DELETE`, or `PATCH` — always fails, no exceptions
2. Uses `POST` to a URL not on an explicit allowlist — each allowlist entry has a comment explaining why it's non-destructive (auth-check endpoints, OAuth token exchange, GraphQL queries, AWS SigV4 reads, etc.)
3. Uses `client.request()` / `client.stream()` with a non-safe method — catches attempts to bypass the method-shortcut API

The test runs:
- On every `git commit` locally (via `.pre-commit-config.yaml`)
- On every push and PR in CI

If a future change accidentally wires a destructive call, the commit is rejected before it lands. You can inspect or re-run the test yourself:

```bash
pytest tests/test_verifier_non_destructive.py
# or standalone:
python3 tests/test_verifier_non_destructive.py
```

Exit code 0 = clean, 1 = violation found with file:line.

### Current allowlist of non-destructive POSTs

As of 2026-04-19, these POST endpoints are allowlisted with per-line justification:

| Endpoint | Why it's non-destructive |
|---|---|
| `sts.amazonaws.com` | `GetCallerIdentity` — reads caller ARN, zero permissions required, no state change |
| `slack.com/api/auth.test` | Slack's documented token validator; POST by convention |
| `api.cohere.ai/v1/check-api-key` | Cohere's dedicated key-validation endpoint |
| `api.perplexity.ai/chat/completions` | *Removed* — now uses `GET /v1/models` (no credits consumed) |
| `api.dropboxapi.com/2/users/get_current_account` | Dropbox API quirk: read-only but POST-only |
| `api.ashbyhq.com/apiKey.info` | Ashby's key-info lookup |
| `api.linear.app/graphql`, `api.monday.com/v2`, `backboard.railway.app/graphql/v2` | GraphQL queries (transport uses POST by spec for reads) |
| `db.fauna.com/` | FaunaDB read query via FQL POST |
| `login.microsoftonline.com`, `api-m.paypal.com`, `api-m.sandbox.paypal.com`, `test.travel.api.amadeus.com`, `travel.api.amadeus.com`, `oauth2.googleapis.com` | OAuth2 token exchanges — mint a token, don't mutate your data |
| `*.snowflakecomputing.com/session/v1/login-request` | Snowflake session-token mint; no DDL/DML |
| `api.uptimerobot.com/v2/getAccountDetails` | Read-only despite POST |
| `checkout-test.adyen.com/v70/paymentMethods`, `checkout-live.adyen.com/v70/paymentMethods` | Lists payment-method types for the account; no charge, no customer data written |

---

## 4. What data we keep

### About your secrets
- **SHA-256 hash** (first 32 hex chars) for deduplication and rotation telemetry — kept in our DB
- **Secret prefix** (first 12 chars) visible in API responses for customer UX — kept in our DB
- **Raw value** only in memory during a single verification pass; never persisted to disk or long-term storage

### About verification results (cached 6 hours in Redis)
- Status (active / inactive / error)
- Provider identity fields from the validation response (account ID, ARN, scope list, user email) — the same data the provider already gave us
- Our computed risk level + blast-radius summary

### About rotation events (persisted long-term)
When a credential transitions `active → inactive` between two verification passes, we record an append-only audit row with timestamps. This drives the Mean-Time-To-Rotation metric. Schema documented in `apps/api/app/models/rotation_event.py`.

---

## 5. Optional: Live blast-radius enumeration (OFF by default)

For deeper customer visibility, Vooda can **optionally** make 1–3 additional read-only calls per active credential to enumerate what resources the credential can reach. Currently supported for:

- **GitHub** — `GET /user/repos?per_page=1`, `GET /user/orgs`, `GET /user/emails` (3 extra calls, surfaces repo count + org count)
- **GitLab** — `GET /projects?membership=true&per_page=1`, `GET /groups` (2 extra calls)
- **AWS** — SigV4-signed `GET s3.amazonaws.com/` (ListBuckets) + `GET iam.amazonaws.com/?Action=ListAccountAliases` (2 extra calls)

**Enabled by:** setting environment variable `VOODA_BLAST_RADIUS_ENUMERATE=1` on the Vooda worker. OFF by default.

**Safety guarantees that remain in force even when enabled:**
- All calls are GET / read-only; no writes
- Bounded output — Vooda stores at most 5 sample resource names (e.g. bucket names), never contents
- Each sub-call is individually try/except-wrapped so `AccessDenied` on one degrades to "we have what we can see" rather than breaking the core verification
- Same D1 audit test enforces the new endpoints don't introduce destructive calls
- Calls inherit the same Redis token-bucket rate limiter (max 30 req/sec per provider default, stricter for Slack/Twilio/Stripe/Jira)

**Why this is optional:**
- Some compliance frameworks require pre-approval for any third-party touching the cloud control plane
- CloudTrail / audit logs will show Vooda's IP making `ListBuckets` / `ListAccountAliases` calls — you may want to whitelist or annotate
- Enabling burns ~2-3× the API quota per credential

---

## 6. Rate limiting and provider courtesy

Vooda enforces a **cross-process token-bucket rate limiter** keyed by provider. The same Redis-backed bucket is shared across all worker processes, so even when several scans run in parallel we never exceed the per-provider budget. Conservative defaults:

| Provider | Burst | Sustained |
|---|:-:|:-:|
| Slack | 5 | 2/sec |
| Twilio / Jira | 10 | 5/sec |
| Stripe | 15 | 8/sec |
| GitHub / AWS / GitLab | 20–30 | 10–20/sec |
| Default | 20 | 10/sec |

We send every request with `User-Agent: Vooda-Verifier/1.0` so providers can identify our traffic.

---

## 7. What to look at if you want to verify the above

| Claim | Where to check |
|---|---|
| "Only GET/HEAD + allowlisted POST" | `tests/test_verifier_non_destructive.py` — run it, read the allowlist |
| "Test runs on every commit + CI" | `.pre-commit-config.yaml` + the GitHub Actions workflow file |
| "Hash-only long-term storage" | `apps/api/app/models/finding.py` — `NormalizedFinding.source_metadata` schema |
| "6-hour cache TTL" | `services/secret_verification/verification_cache.py` |
| "Rate-limit buckets + defaults" | `services/secret_verification/rate_limiter.py` |
| "Blast-radius enumeration is opt-in" | `services/secret_verification/verifier.py` — search `_ENUMERATE_ENABLED` |
| "Rotation events are append-only" | `apps/api/app/models/rotation_event.py` |

All paths are in the open-sourced repo and reviewable.

---

## 8. Who to contact

Questions about the verifier layer, the D1 audit, or anything in this document → open an issue on the repo or reach your Vooda account contact. For security-reviewer-specific questions (threat model, data retention, subprocessor list), ask for the separate *Vooda Security Addendum*.
