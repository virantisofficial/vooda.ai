# Vooda Platform Reference

> Detailed reference for the Vooda platform: architecture, navigation, API routers, and configuration.
> For an introduction, start with the [README](../README.md).

## Overview

Vooda AI is a self-hosted secret scanning platform. It finds leaked credentials across code and 20+ other sources, verifies whether they still work, and runs an AI triage pass to cut the false positives — so teams review real exposures, not noise.

## Key Features

- **Secret detection rules** (regex + signatures + Shannon entropy) covering AWS, GCP, Azure, GitHub, GitLab, Stripe, Slack, Twilio, databases, CI/CD, private keys, and dozens more — including weak / quantum-vulnerable key detection (RSA < 3072-bit, ECDSA, DSA).
- **Scans 20+ sources, not just code** — Git repos and full history plus team chat (Slack, Microsoft Teams, Mattermost), docs and wikis (Confluence, Notion, SharePoint), tickets (Jira, ServiceNow, Linear, Asana, GitHub / Bitbucket Issues, Azure DevOps Boards), cloud storage (S3, GCS, Azure Blob, Box), CI/CD logs, container images, and Postman collections — all through one detection-plus-triage pipeline.
- **AI-powered triage** (Claude, OpenAI, Gemini, or any local / OpenAI-compatible model) with batch processing, confidence calibration, and evidence enrichment to reduce false positives. A local model means $0 per-token cost and no data leaving your network.
- **Live secret verification** — where it can be done safely, Vooda checks a candidate credential against its provider so a revoked key and a live production key aren't the same alert.
- **Push protection** with pre-commit blocking and CI/CD gate checks via the CLI.
- **Secret-manager coverage** — checks which leaked credentials are already managed by HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager, with rotation guidance and rotation write-back.
- **Incident management** — findings roll up into deduplicated incidents with triage disposition, severity, and rotation tracking.
- **Custom detectors and rule overrides** — add your own detection rules and tune or suppress built-ins per repo or source.
- **Enterprise SSO** (SAML 2.0, OIDC) — _temporarily disabled_ pending a security hardening pass; see the README roadmap.
- **Ticketing integration** with Jira, ServiceNow, Linear, and custom webhooks.
- **Notifications** via Slack, Microsoft Teams, and email.
- **Inbound webhooks** — receive push / PR events from GitHub, GitLab, and Bitbucket to trigger scans, with fail-closed HMAC verification.
- **Compliance reporting** and exportable finding reports.
- **RBAC** — users, roles, business-unit access grants, API keys, and a full audit log.

## Architecture

| Layer | Technology |
|-------|-----------|
| Backend API | FastAPI (Python 3.12) |
| Database | PostgreSQL 16 |
| Cache / Queue | Redis 7 |
| Task Workers | Celery |
| Frontend | Next.js 15, React 19, Tailwind CSS |
| Real-time | WebSocket via Redis Pub/Sub |
| Containerization | Docker Compose |
| Auth | JWT (SSO / SAML 2.0 / OIDC temporarily disabled — see README) |

Backed by a modular router layer, a relational schema, and an automated test suite.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/virantisofficial/vooda.ai.git
cd vooda.ai

# Configure environment (set POSTGRES_PASSWORD and SECRET_KEY)
cp .env.example .env
cp docker-compose.override.example.yml docker-compose.override.yml

# Start all services (the API auto-runs migrations on startup)
docker compose up -d

# To seed demo data manually:
docker compose exec api python -m infra.scripts.seed
```

**Access the platform:**

| Resource | URL |
|----------|-----|
| Web UI | http://localhost:3001 |
| API Docs (Swagger) | http://localhost:8001/api/docs |
| OpenAPI Schema | http://localhost:8001/api/openapi.json |
| Health Check | http://localhost:8001/api/health |

**Credentials:** `admin@vooda.ai` — there is no default password; the seed
script generates one and prints it once, or set `SEED_ADMIN_PASSWORD`
before seeding to choose your own.

## Navigation

The platform organizes into six primary sections accessible from the sidebar:

| # | Section | Path | Description |
|---|---------|------|-------------|
| 1 | **Dashboard** | `/dashboard` | Unified KPIs — security score, total secrets, open incidents, and mean time to remediate (MTTR) |
| 2 | **Repositories** | `/repositories` | Connect GitHub, GitLab, and Bitbucket repos; trigger scans; view scan history and artifacts |
| 3 | **Sources** | `/sources` | Connect and scan non-git sources — chat, docs and wikis, tickets, cloud storage, CI/CD logs, and container images |
| 4 | **Secrets** | `/findings` | Finding triage with AI classification, severity filtering, incidents, and rotation tracking |
| 5 | **Integrations** | `/integrations` | AI provider, webhook receivers, vault connections, ticketing, and notification channels (Slack, Teams, email) |
| 6 | **Settings** | `/settings/admin` | User management, roles, suppression rules, scan schedules, compliance reports, and organization configuration |

## API

Full API documentation is available at `http://localhost:8001/api/docs` when the platform is running. See also [api-guide.md](api-guide.md) for usage examples and CI/CD integration patterns.

### API Routers

The API exposes its routers under `/api/v1/`:

| Prefix | Purpose |
|--------|---------|
| `/auth` | Login and token refresh |
| `/repositories` | Repository CRUD and scan triggers |
| `/scan-sources` | Non-git source configuration (chat, docs, tickets, storage, CI, images) |
| `/scan-jobs` | Scan job status and history |
| `/findings` | Finding queries, triage, bulk actions |
| `/incidents` | Deduplicated incident rollups and disposition |
| `/suppressions` | Suppression rule management |
| `/custom-detectors` | Custom detection rules |
| `/rule-overrides` | Per-repo / per-source rule tuning |
| `/saved-views` | Custom finding views |
| `/metrics` | Dashboard KPIs and snapshots |
| `/reports` | Compliance and analytics reports |
| `/ai-models` | AI provider configuration |
| `/integrations`, `/integrations/oauth` | Integration configs and OAuth callbacks |
| `/notifications` | Notification rule configuration |
| `/webhooks` | Inbound webhook receivers |
| `/vault` | Secret-manager coverage and rotation write-back |
| `/sso` | SAML / OIDC endpoints (currently disabled — return `503`) |
| `/users`, `/roles`, `/access` | RBAC: users, roles, business-unit access grants |
| `/api-keys` | API key management |
| `/audit` | Audit event log |
| `/ws` | Real-time scan progress (WebSocket) |

## How It Works

1. **Connect a source.** A Git repo (GitHub / GitLab / Bitbucket) or any of the 20+ non-git sources.
2. **Detect.** Detection rules and regex flag credential candidates in the content.
3. **Verify.** Where safe, each candidate is checked against its provider to see whether it's still live.
4. **Triage.** An AI model classifies each finding as true or false positive with a confidence score.
5. **Act.** Real findings become incidents; route them to Jira / ServiceNow / Linear, alert via Slack / Teams / email, block them at commit time with push protection, and confirm which are already vault-managed.

## Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Backend Framework | FastAPI | -- |
| Language (Backend) | Python | 3.12 |
| Database | PostgreSQL | 16 |
| Cache / Message Broker | Redis | 7 |
| Task Queue | Celery | -- |
| Frontend Framework | Next.js | 15 |
| UI Library | React | 19 |
| CSS Framework | Tailwind CSS | -- |
| Containerization | Docker Compose | v2 |
| ORM | SQLAlchemy (async) | 2.x |
| Migrations | Alembic | -- |
| Authentication | JWT (SSO disabled — see README) | -- |
| Real-time | WebSocket + Redis Pub/Sub | -- |
| AI Providers | Anthropic Claude, OpenAI, Google Gemini, or local / OpenAI-compatible | -- |

## Project Structure

```
vooda.ai/
  apps/
    api/          # FastAPI backend (routers, models, schemas, core)
    web/          # Next.js frontend (App Router, components, pages)
    worker/       # Celery worker (scan + triage tasks)
  services/       # Domain service modules (secret_scan, ai_triage,
                  # source_scanners, secret_verification, vault_integration, …)
  packages/       # Shared utilities (encryption, git_url, constants)
  infra/
    docker/       # Dockerfiles for api, web, and cli
    scripts/      # DB init, seed scripts
  tests/          # automated test suite
  docs/           # Architecture, deployment, API, integration guides
  docker-compose.yml
```

## Documentation

### Platform
- [Architecture Overview](architecture.md) — system design, services, database schema, frontend structure
- [Deployment Guide](deployment.md) — Docker Compose setup, environment variables, scaling
- [API Guide](api-guide.md) — endpoint reference, authentication, CI/CD integration

### Integrations
- [Slack Integration](slack-integration.md) — bot OAuth setup, scopes, channel scanning, sweep behavior
- [Jira Integration](jira-integration.md) — Atlassian token setup, ticket attribution, dedicated service-account pattern
- [Atlassian OAuth](oauth-atlassian.md) — OAuth 2.0 flow for Jira / Confluence sources

### Engine internals
- [Verifier Guarantees](verifier-guarantees.md) — what inline credential validation does and doesn't promise

## License

Source-available under the [Vooda Community Licence, Version 1.0](../LICENSE.md). Free for non-commercial use; business or for-profit use requires a commercial licence. See the [README](../README.md#license) for the plain-language summary.
